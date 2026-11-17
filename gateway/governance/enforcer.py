"""Decision Enforcer (ticket §8).

Turns one-or-more per-tool-call Decisions into:
  * the response object Hermes actually receives, and
  * an EnforcementResult recorded in the audit log.

Guarantees:
  * Batch safety (§10 test 9): if ANY proposed tool call is DENY / REQUIRE_REVIEW,
    the whole assistant turn is withheld — no partial release.
  * DENY keeps the session alive: tool_calls are stripped and replaced with a
    plain assistant message carrying a Traditional-Chinese `user_message` plus a
    structured `agent_feedback` block. The user always sees a reason.
  * Auto re-plan is capped (REPLAN_MAX_ATTEMPTS, default 2). The same coarse
    reason code repeating in a session stops the auto loop and asks the user.
  * REQUIRE_REVIEW -> caller raises 409 GOVERNANCE_REVIEW_REQUIRED (no auto retry
    until a verifiable approval token exists — not in MVP).
  * MODIFY -> only verifiable argument rewrites / obligation narrowing.
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from gateway.governance import approvals
from gateway.governance.adapters.base import HarnessAdapter
from gateway.governance.decision_orchestrator import OrchestrationOutcome
from gateway.governance.schemas import (
    AgentFeedback,
    EnforcementResult,
    Verdict,
)

_VERDICT_SEVERITY = {
    Verdict.ALLOW: 0,
    Verdict.MODIFY: 1,
    Verdict.REQUIRE_REVIEW: 2,
    Verdict.DENY: 3,
}

# rego reason code  ->  coarse PUBLIC code (no policy internals leak to Hermes)
_PUBLIC_CODE = [
    ("EXTERNAL_SENSITIVE_TRANSFER", "EXTERNAL_SENSITIVE_TRANSFER_DENIED"),
    ("DANGEROUS_TOOL_DENIED", "DANGEROUS_TOOL_DENIED"),
    ("DANGEROUS_SHELL_COMMAND", "DANGEROUS_TOOL_DENIED"),
    ("SHELL_COMMAND_NEEDS_REVIEW", "HUMAN_REVIEW_REQUIRED"),
    ("PATH_DENIED", "PROTECTED_PATH_DENIED"),
    ("EXECUTE_FROM_UNTRUSTED_DIR", "PROTECTED_PATH_DENIED"),
    ("PATH_OUTSIDE_WORKSPACE", "HUMAN_REVIEW_REQUIRED"),
    ("EGRESS_FORBIDDEN_MARKER", "EGRESS_CONTENT_BLOCKED"),
    ("EGRESS_SENSITIVE_TASK_TO_ENDPOINT", "EGRESS_CONTENT_BLOCKED"),
    ("EGRESS_SENSITIVE_FIELD", "EGRESS_CONTENT_BLOCKED"),
    ("FORBIDDEN_DISCLOSURE", "OUTPUT_CONTENT_BLOCKED"),
    ("OUTPUT_RECIPIENT_NOT_CLEARED", "OUTPUT_CONTENT_BLOCKED"),
    ("CHILD_GRANT_EXCEEDS_PARENT", "DELEGATION_EXCEEDS_GRANT"),
    ("PARENT_MAY_NOT_SPAWN", "DELEGATION_EXCEEDS_GRANT"),
    ("AUTONOMY_OVER_CEILING", "AUTONOMY_EXCEEDS_CEILING"),
    ("SPAWN_UNKNOWN_CAPABILITY", "AUTONOMY_EXCEEDS_CEILING"),
    ("UNKNOWN_TOOL", "UNRECOGNIZED_ACTION"),
    ("UNKNOWN_HARNESS", "UNRECOGNIZED_ACTION"),
    ("UNKNOWN_EVENT_TYPE", "UNRECOGNIZED_ACTION"),
    ("SCHEMA_VERSION_UNSUPPORTED", "UNRECOGNIZED_ACTION"),
    ("SOFT_ADVICE_UNAVAILABLE", "GOVERNANCE_SERVICE_UNAVAILABLE"),
    ("SOFT_ADVICE_MISSING", "GOVERNANCE_SERVICE_UNAVAILABLE"),
    ("HARD_PDP_", "GOVERNANCE_SERVICE_UNAVAILABLE"),
    ("SOFT_ADVICE_DENY", "RISK_ADVISORY_BLOCK"),
    ("TOOL_REVIEW_REQUIRED", "HUMAN_REVIEW_REQUIRED"),
]

# Shown to the end user. Keep each to: (1) can't do this, (2) what to try next.
_USER_MESSAGE = {
    "EXTERNAL_SENSITIVE_TRANSFER_DENIED": (
        "無法完成：這會把敏感資料傳到外部。"
        "改成只給去識別化摘要、或指定內部目的地再試；仍需要的話可請人工審核。"
    ),
    "DANGEROUS_TOOL_DENIED": (
        "無法完成：這項操作風險太高，已被擋下。"
        "改用唯讀方式、縮小範圍再試；仍需要的話可請人工審核。"
    ),
    "DELEGATION_EXCEEDS_GRANT": (
        "無法完成：要開的子代理權限太大。"
        "縮小它的工具與資料範圍、降低自主度再試；仍需要的話可請人工審核。"
    ),
    "AUTONOMY_EXCEEDS_CEILING": (
        "無法完成：要求的自主度超過上限。"
        "降低自主度再試；仍需要的話可請人工審核。"
    ),
    "UNRECOGNIZED_ACTION": (
        "無法完成：這項操作無法被辨識，已依安全預設擋下。"
        "改用支援的工具、或換個說法再試；仍需要的話可請人工審核。"
    ),
    "RISK_ADVISORY_BLOCK": (
        "無法完成：風險評估過高。"
        "移除高風險部分、縮小影響範圍再試；仍需要的話可請人工審核。"
    ),
    "GOVERNANCE_SERVICE_UNAVAILABLE": (
        "暫時無法完成：安全檢查服務不可用，這次操作被擋下（對話不受影響）。"
        "稍後再試一次；持續發生請告知管理者。"
    ),
    "HUMAN_REVIEW_REQUIRED": (
        "這項操作需要人工審核才能進行。對話會保留，核准後可再繼續。"
    ),
    "POLICY_DENIED": (
        "無法完成：這項操作不被允許。"
        "調整做法再試；仍需要的話可請人工審核。"
    ),
    "PROTECTED_PATH_DENIED": (
        "無法完成：目標路徑是受保護的位置（金鑰／憑證／系統設定），或程式來自暫存／下載目錄。"
        "改用專案內的路徑、縮小範圍再試；仍需要的話可請人工審核。"
    ),
    "EGRESS_CONTENT_BLOCKED": (
        "無法完成：工具讀到的內容不允許送往這個模型端點。"
        "縮小工具的查詢範圍、或改用去識別化的方式再試。"
    ),
    "OUTPUT_CONTENT_BLOCKED": (
        "無法完成：回覆內容不符合輸出政策。"
        "換個不含受限內容的問法、或縮小範圍再試。"
    ),
}

_ALTERNATIVES = {
    "EXTERNAL_SENSITIVE_TRANSFER_DENIED": [
        "redact_sensitive_fields", "use_approved_internal_destination", "request_human_review",
    ],
    "DANGEROUS_TOOL_DENIED": ["use_read_only_tool", "reduce_scope", "request_human_review"],
    "DELEGATION_EXCEEDS_GRANT": ["reduce_subagent_scope", "lower_autonomy", "request_human_review"],
    "AUTONOMY_EXCEEDS_CEILING": ["lower_autonomy", "request_human_review"],
    "UNRECOGNIZED_ACTION": ["use_supported_tool", "fix_request_format", "request_human_review"],
    "RISK_ADVISORY_BLOCK": ["reduce_scope", "remove_high_risk_steps", "request_human_review"],
    "GOVERNANCE_SERVICE_UNAVAILABLE": ["retry_later", "request_human_review"],
    "HUMAN_REVIEW_REQUIRED": ["request_human_review", "adjust_and_resubmit"],
    "POLICY_DENIED": ["adjust_and_resubmit", "request_human_review"],
}


def _advisory_from_ciso(sa) -> Optional[dict]:
    """Phase D — the CISO's non-binding flag when OPA did NOT act on it.
    Returns a small dict when the advisor said anything other than a clean
    low-risk ALLOW; None otherwise. This is recorded, not enforced.
    """
    if sa is None:
        return None
    advice = sa.advice.value if hasattr(sa.advice, "value") else str(sa.advice)
    score = getattr(sa, "risk_score", 0) or 0
    try:
        floor = int(os.environ.get("CISO_ADVISORY_SCORE_MIN", "50"))
    except ValueError:
        floor = 50
    if advice == "ALLOW" and score < floor:
        return None
    return {
        "source": "ciso",
        "advice": advice,
        "risk_score": score,
        "risk_level": sa.risk_level.value if hasattr(sa.risk_level, "value") else str(sa.risk_level),
        "reason_codes": list(getattr(sa, "reason_codes", []) or [])[:6],
        "note": (sa.explanation or "")[:300] or None,
        "binding": False,
    }


def public_code(reason_codes: list[str]) -> str:
    for rc in reason_codes:
        for needle, code in _PUBLIC_CODE:
            if rc.startswith(needle) or needle in rc:
                return code
    return "POLICY_DENIED"


@dataclass
class _SessionState:
    denies_by_code: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_replans: int = 0


class ReplanTracker:
    """Per-session dedup of auto re-plan loops (ticket §8: cap auto re-plan,
    stop on a repeated coarse reason). Backed by SQLite when a db path is
    available so the cap survives a gateway restart; the in-memory map is the
    fast path and the fallback if the DB is unwritable (degrading the loop cap
    is a UX regression, never a security fail-open — the per-request verdict is
    unaffected)."""

    _SCHEMA = (
        "CREATE TABLE IF NOT EXISTS replan_state ("
        " session_id TEXT NOT NULL, code TEXT NOT NULL,"
        " code_count INTEGER NOT NULL DEFAULT 0,"
        " total INTEGER NOT NULL DEFAULT 0,"
        " updated REAL NOT NULL,"
        " PRIMARY KEY (session_id, code));"
    )

    def __init__(self, max_attempts: int | None = None, db_path: str | None = None) -> None:
        self.max_attempts = max_attempts or int(os.environ.get("REPLAN_MAX_ATTEMPTS", "2"))
        self._sessions: dict[str, _SessionState] = defaultdict(_SessionState)
        self._db_path = db_path if db_path is not None else os.environ.get("AUDIT_DB_PATH")
        self._db_ok = False
        if self._db_path:
            try:
                parent = os.path.dirname(self._db_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with self._connect() as c:
                    c.execute(self._SCHEMA)
                self._db_ok = True
            except Exception:  # noqa: BLE001 - fall back to in-memory
                self._db_ok = False

    def _connect(self):
        import sqlite3

        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    _NO_SESSION = {"", "unknown-session", "unknown", "-", None}

    def register_deny(self, session_id: str, code: str) -> tuple[int, bool]:
        # Cross-request loop detection needs a stable session id. When the
        # harness sends none (e.g. an unmodified Hermes), we cannot correlate
        # turns — report attempt 1 / REPLAN and rely on the harness' own
        # loop guard. Never STOP on a phantom shared "unknown-session".
        if session_id in self._NO_SESSION:
            return 1, False
        if self._db_ok:
            try:
                return self._register_db(session_id, code)
            except Exception:  # noqa: BLE001
                self._db_ok = False  # stop trying; use memory from here
        return self._register_mem(session_id, code)

    def _register_mem(self, session_id: str, code: str) -> tuple[int, bool]:
        st = self._sessions[session_id]
        st.denies_by_code[code] += 1
        st.total_replans += 1
        stop = st.denies_by_code[code] > 1 or st.total_replans > self.max_attempts
        return st.total_replans, stop

    def _register_db(self, session_id: str, code: str) -> tuple[int, bool]:
        import time as _t

        with self._connect() as c:
            c.execute(
                "INSERT INTO replan_state (session_id, code, code_count, total, updated)"
                " VALUES (?, ?, 1, 1, ?)"
                " ON CONFLICT(session_id, code) DO UPDATE SET"
                " code_count = code_count + 1, total = total + 1, updated = excluded.updated",
                (session_id, code, _t.time()),
            )
            row = c.execute(
                "SELECT code_count, (SELECT COALESCE(SUM(total),0) FROM replan_state WHERE session_id=?)"
                " FROM replan_state WHERE session_id=? AND code=?",
                (session_id, session_id, code),
            ).fetchone()
            c.commit()
        code_count, total = int(row[0]), int(row[1])
        stop = code_count > 1 or total > self.max_attempts
        return total, stop

    def reset(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        if self._db_ok:
            try:
                with self._connect() as c:
                    c.execute("DELETE FROM replan_state WHERE session_id=?", (session_id,))
                    c.commit()
            except Exception:  # noqa: BLE001
                pass


@dataclass
class EnforcementDispatch:
    result: EnforcementResult
    response: dict[str, Any]
    transport: str            # "inband" | "http_error"
    http_status: int | None = None
    error_code: str | None = None


class Enforcer:
    def __init__(self, adapter: HarnessAdapter, tracker: ReplanTracker | None = None) -> None:
        self.adapter = adapter
        self.tracker = tracker or ReplanTracker()

    def enforce(
        self,
        *,
        raw_response: dict[str, Any],
        outcomes: list[OrchestrationOutcome],
        approval_token: str | None = None,
    ) -> EnforcementDispatch:
        if not outcomes:
            # nothing was proposed -> pass through untouched
            return EnforcementDispatch(
                result=EnforcementResult(outcome="ALLOW", event_id="-", reason_codes=["NO_PROPOSED_ACTION"]),
                response=raw_response,
                transport="inband",
            )

        worst = max(outcomes, key=lambda o: _VERDICT_SEVERITY[o.decision.decision])
        verdict = worst.decision.decision
        session_id = worst.event.source.session_id
        event_id = worst.event.event_id
        all_reason_codes = sorted({rc for o in outcomes for rc in o.decision.reason_codes})

        sa = worst.soft_advice
        ciso_note = None
        if sa is not None:
            ciso_note = {
                "advice": sa.advice.value if hasattr(sa.advice, "value") else str(sa.advice),
                "risk_level": sa.risk_level.value if hasattr(sa.risk_level, "value") else str(sa.risk_level),
                "risk_score": sa.risk_score,
                "explanation": sa.explanation or None,
                "availability": sa.availability.value if hasattr(sa.availability, "value") else str(sa.availability),
            }
        # Phase D — was the CISO consulted, and did it flag something without
        # binding? (A skipped fast-path advice is tagged CISO_NOT_CONSULTED_FASTPATH.)
        _skipped = bool(sa and "CISO_NOT_CONSULTED_FASTPATH" in (sa.reason_codes or []))
        advisory = _advisory_from_ciso(sa) if not _skipped else None

        if verdict == Verdict.ALLOW:
            return EnforcementDispatch(
                result=EnforcementResult(
                    outcome="ALLOW", event_id=event_id, reason_codes=all_reason_codes,
                    hold="ADVISORY" if advisory else "NONE",
                    advisory=advisory,
                    escalated=not _skipped,
                    escalate_reason=None if not _skipped else "fastpath_no_escalation",
                ),
                response=raw_response,
                transport="inband",
            )

        if verdict == Verdict.REQUIRE_REVIEW:
            # Check if this is CISO_UNCERTAIN case -> present menu instead of blocking
            ciso_uncertain = (sa and sa.confidence.value == "UNCERTAIN" if hasattr(sa.confidence, "value")
                            else sa and str(sa.confidence) == "UNCERTAIN")

            if ciso_uncertain:
                # Present human review menu with options
                pub = public_code(all_reason_codes)
                return _present_human_review_menu(
                    event=worst.event,
                    decision=worst.decision,
                    reason_codes=all_reason_codes,
                    soft_advice=sa,
                    ciso_note=ciso_note,
                    pub_code=pub,
                    event_id=event_id,
                )

        if verdict == Verdict.MODIFY:
            before = _snapshot_tool_calls(raw_response)
            modified = self.adapter.enforce(raw_response, worst.decision)
            after = _snapshot_tool_calls(modified)
            return EnforcementDispatch(
                result=EnforcementResult(
                    outcome="MODIFY",
                    event_id=event_id,
                    reason_codes=all_reason_codes,
                    modification={"before": before, "after": after,
                                  "obligations": worst.decision.obligations.model_dump(mode="json")},
                    agent_feedback=AgentFeedback(
                        action="PROCEED_MODIFIED",
                        reason_code=public_code(all_reason_codes),
                        event_id=event_id,
                    ),
                ),
                response=modified,
                transport="inband",
            )

        if verdict == Verdict.REQUIRE_REVIEW:
            pub = public_code(all_reason_codes)

            # A valid, human-minted approval token bound to THIS action's stable
            # fingerprint releases it (obligations still recorded). Anything less
            # -> stays blocked (409). Never auto-retried.
            ok, why = approvals.verify(approval_token, approvals.fingerprint_for_event(worst.event))
            if ok:
                return EnforcementDispatch(
                    result=EnforcementResult(
                        outcome="ALLOW",
                        event_id=event_id,
                        reason_codes=[*all_reason_codes, f"HUMAN_APPROVED:{why}"],
                        modification={"obligations": worst.decision.obligations.model_dump(mode="json")},
                        agent_feedback=AgentFeedback(action="PROCEED_MODIFIED", reason_code=pub,
                                                    event_id=event_id),
                    ),
                    response=raw_response,
                    transport="inband",
                )

            result = EnforcementResult(
                outcome="REQUIRE_REVIEW",
                event_id=event_id,
                reason_codes=[*all_reason_codes, f"APPROVAL_TOKEN:{why}"],
                hold="REVIEW_HOLD",   # action is STOPPED, waiting for approval
                advisory=advisory,
                user_message=_USER_MESSAGE["HUMAN_REVIEW_REQUIRED"],
                agent_feedback=AgentFeedback(
                    action="STOP_AUTO_REPLAN",
                    blocked_action=worst.event.proposed_action.canonical_name,
                    reason_code=pub,
                    adjustable_conditions=_ALTERNATIVES.get(pub, []),
                    event_id=event_id,
                ),
                session_continues=True,
                ciso=ciso_note,
            )
            # Default: deliver in-band (assistant message, tool call dropped) so
            # the harness shows the reason and does NOT retry-loop. Opt into the
            # 409 error form with GOVERNANCE_REVIEW_AS_HTTP_ERROR=1.
            if os.environ.get("GOVERNANCE_REVIEW_AS_HTTP_ERROR", "0") == "1":
                return EnforcementDispatch(
                    result=result, response=_review_error_body(event_id, pub),
                    transport="http_error", http_status=409,
                    error_code="GOVERNANCE_REVIEW_REQUIRED",
                )
            return EnforcementDispatch(
                result=result,
                response=_deny_response_body(raw_response, result),
                transport="inband",
            )

        # ---- DENY ----------------------------------------------------------
        pub = public_code(all_reason_codes)
        attempt, stop = self.tracker.register_deny(session_id, pub)
        feedback_action = "STOP_AUTO_REPLAN" if stop else "REPLAN"
        user_msg = _USER_MESSAGE.get(pub, _USER_MESSAGE["POLICY_DENIED"])
        if stop:
            user_msg = user_msg + " 已多次被同一原因擋下，請換個做法或直接說明你的需求。"

        feedback = AgentFeedback(
            action=feedback_action,
            blocked_action=worst.event.proposed_action.canonical_name,
            reason_code=pub,
            allowed_alternatives=_ALTERNATIVES.get(pub, _ALTERNATIVES["POLICY_DENIED"]),
            adjustable_conditions=_ALTERNATIVES.get(pub, []),
            event_id=event_id,
        )
        result = EnforcementResult(
            outcome="DENY",
            event_id=event_id,
            reason_codes=all_reason_codes,
            user_message=user_msg,
            agent_feedback=feedback,
            replan_attempt=attempt,
            session_continues=True,
            ciso=ciso_note,
        )
        return EnforcementDispatch(
            result=result,
            response=_deny_response_body(raw_response, result),
            transport="inband",
        )


# --------------------------------------------------------------------------- #
# response shaping helpers (OpenAI chat-completion schema)
# --------------------------------------------------------------------------- #
def _present_human_review_menu(
    *,
    event,
    decision,
    reason_codes: list[str],
    soft_advice,
    ciso_note,
    pub_code: str,
    event_id: str,
) -> EnforcementDispatch:
    """When CISO is uncertain, present a menu of options for human decision."""
    menu_options = [
        {
            "action": "allow",
            "label": "允許執行",
            "description": "批准這項操作，套用 CISO 建議的義務限制",
            "risk": soft_advice.risk_level.value if hasattr(soft_advice.risk_level, "value") else str(soft_advice.risk_level),
            "requires_approval_token": True,
        },
        {
            "action": "deny",
            "label": "拒絕",
            "description": "擋下這項操作，Hermes 可以重新規劃",
            "risk": "blocked",
            "requires_approval_token": False,
        },
        {
            "action": "modify",
            "label": "修改後執行",
            "description": "人類指定修改內容，然後執行",
            "risk": "conditional",
            "requires_approval_token": True,
        },
    ]

    result = EnforcementResult(
        outcome="REQUIRE_HUMAN_REVIEW",
        event_id=event_id,
        reason_codes=[*reason_codes, "CISO_UNCERTAIN"],
        hold="REVIEW_HOLD",
        user_message=(
            f"這項操作需要人類決策。\n\n"
            f"CISO 信心度：不確定\n"
            f"原因：{soft_advice.escalation_reason or '需要人類審查'}\n\n"
            f"請選擇下列選項之一。"
        ),
        advisory={
            "ciso_reasoning": soft_advice.ciso_reasoning or None,
            "escalation_reason": soft_advice.escalation_reason or None,
            "risk_score": soft_advice.risk_score,
            "risk_level": soft_advice.risk_level.value if hasattr(soft_advice.risk_level, "value") else str(soft_advice.risk_level),
        },
        ciso=ciso_note,
        session_continues=True,
    )

    # Encode menu in a structured response
    response_body = {
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": result.user_message,
                },
                "dciso_governance": {
                    "status": "REQUIRE_HUMAN_REVIEW",
                    "event_id": event_id,
                    "menu_options": menu_options,
                    "ciso_analysis": {
                        "reasoning": soft_advice.ciso_reasoning,
                        "escalation_reason": soft_advice.escalation_reason,
                        "confidence": "UNCERTAIN",
                        "risk_score": soft_advice.risk_score,
                    },
                    "agent_feedback": {
                        "action": "PRESENT_MENU",
                        "reason_code": pub_code,
                        "event_id": event_id,
                    },
                },
            }
        ],
        "dciso_governance": {
            "status": "REQUIRE_HUMAN_REVIEW",
            "event_id": event_id,
            "menu_options": menu_options,
        },
    }

    return EnforcementDispatch(
        result=result,
        response=response_body,
        transport="inband",
    )


def _snapshot_tool_calls(response: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for choice in response.get("choices", []) or []:
        for tc in (choice.get("message") or {}).get("tool_calls") or []:
            fn = tc.get("function") or {}
            out.append({"name": fn.get("name"), "arguments": fn.get("arguments")})
    return out


def _deny_response_body(raw_response: dict[str, Any], result: EnforcementResult) -> dict[str, Any]:
    """Strip tool_calls; replace with a plain assistant message the user sees.
    The model's own tool call NEVER reaches Hermes."""
    governance_note = {
        "dciso_governance": {
            "status": "DENIED",
            "event_id": result.event_id,
            "reason_code": result.agent_feedback.reason_code if result.agent_feedback else None,
            "agent_feedback": result.agent_feedback.model_dump(mode="json") if result.agent_feedback else None,
            "session_continues": True,
        }
    }
    resp = dict(raw_response)
    resp["choices"] = [
        {
            "index": 0,
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": result.user_message,
                "tool_calls": None,
            },
            "dciso_governance": governance_note["dciso_governance"],
        }
    ]
    resp.setdefault("dciso_governance", governance_note["dciso_governance"])
    return resp


def _review_error_body(event_id: str, public_reason: str) -> dict[str, Any]:
    return {
        "error": {
            "message": (
                "此操作需人工審核 (GOVERNANCE_REVIEW_REQUIRED)。對話保留，"
                "在核准前不會自動重試。"
            ),
            "type": "governance_review_required",
            "code": "GOVERNANCE_REVIEW_REQUIRED",
            "event_id": event_id,
            "reason_code": public_reason,
            "review_url": os.environ.get("REVIEW_URL_TEMPLATE", "http://REVIEW-PLACEHOLDER/{event_id}").format(
                event_id=event_id
            ),
        }
    }
