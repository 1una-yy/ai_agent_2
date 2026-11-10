"""LiteLLM proxy interception entry point (ticket §10 Task 2).

Registered in config.yaml as:

    litellm_settings:
      callbacks: gateway.callbacks.governance_callback.governance_handler_instance

Hooks used (verified against LiteLLM docs 2026-09-01):
  * async_pre_call_hook          -> establish governance context on the request
  * async_post_call_success_hook -> govern proposed tool calls, enforce, audit
  * async_post_call_failure_hook -> ensure the user always sees a reason

Fail-closed: every governance path that raises is converted to a DENY of the
current action (HTTP 4xx with a user-readable body). A governance bug must
never let an ungoverned tool call through.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import time
from typing import Any, Optional

try:  # available inside the LiteLLM image
    from litellm.integrations.custom_logger import CustomLogger
except Exception:  # pragma: no cover - allows import in plain test env
    class CustomLogger:  # type: ignore
        pass

try:  # FastAPI ships in the LiteLLM image; fall back for the bare test env
    from fastapi import HTTPException as _HTTPException
except Exception:  # pragma: no cover
    class _HTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int = 500, detail=None, headers=None) -> None:
            self.status_code = status_code
            self.detail = detail
            super().__init__(str(detail))

from gateway.governance import output_scan
from gateway.governance.audit import AuditWriter
from gateway.governance.decision_orchestrator import DecisionOrchestrator
from gateway.governance.enforcer import EnforcementDispatch, Enforcer, ReplanTracker
from gateway.governance.normalizer import select_adapter
from gateway.governance.schemas import (
    SCHEMA_VERSION,
    EnforcementPhase,
    EnforcementResult,
    EventType,
    GovernanceBlock,
    GovernanceEvent,
    ProposedAction,
    Source,
    Task,
)

_OUTPUT_POLICY_DEFAULT = {
    "enabled": True,
    "forbidden_markers": ["INTERNAL ONLY", "DO NOT DISTRIBUTE", "機密", "不得外流"],
    "external_recipient_blocks_classes": ["PHI", "PII", "SECRET", "confidential", "internal"],
}
_OUTPUT_DENY_ZH = "回覆內容不符合輸出政策，已擋下。請縮小範圍或改用不含受限內容的問法。"
_OUTPUT_REVIEW_ZH = "這個回覆需要人工審核，暫時無法提供。"
_SENSITIVE_CLASSES = {"PHI", "PII", "SECRET", "confidential", "internal"}

_GOV_ERROR_ZH = (
    "治理層發生內部錯誤，為安全起見已拒絕本次操作（對話與其他安全操作不受影響）。"
    "請稍後重試；若持續發生請聯絡管理者。"
)


def _meta(data: dict[str, Any]) -> dict[str, Any]:
    for key in ("metadata", "litellm_metadata"):
        m = data.get(key)
        if isinstance(m, dict) and m:
            return m
    psr = data.get("proxy_server_request") or {}
    body = psr.get("body") or {}
    if isinstance(body.get("metadata"), dict):
        return body["metadata"]
    return {}


def _as_dict(response: Any) -> dict[str, Any]:
    if isinstance(response, dict):
        return response
    for attr in ("model_dump", "dict"):
        fn = getattr(response, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:  # noqa: BLE001
                continue
    return json.loads(json.dumps(response, default=lambda o: getattr(o, "__dict__", str(o))))


def _has_tool_calls(resp: dict[str, Any]) -> bool:
    for ch in resp.get("choices", []) or []:
        if (ch.get("message") or {}).get("tool_calls"):
            return True
    return False


class GovernanceReject(_HTTPException):
    """Raised to block a response. Subclasses HTTPException so LiteLLM/FastAPI
    propagate the structured body faithfully (status + JSON detail)."""

    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        self.body = body
        super().__init__(status_code=status_code, detail=body)


class GovernanceCallback(CustomLogger):
    def __init__(self) -> None:
        super().__init__()
        self._tracker = ReplanTracker()
        self._orchestrator = DecisionOrchestrator()
        self._audit = AuditWriter()
        self._enforce_unknown_harness = os.environ.get("ENFORCE_UNKNOWN_HARNESS", "1") == "1"
        self._output_gate = os.environ.get("DCISO_OUTPUT_GATE", "1") != "0"
        self._output_max_scan = int(os.environ.get("DCISO_OUTPUT_MAX_SCAN", "200000"))
        self._output_policy_cache: Optional[dict] = None
        self._egress_gate = os.environ.get("DCISO_EGRESS_GATE", "1") != "0"
        self._egress_policy_cache: Optional[dict] = None

    # ------------------------------------------------------------------ #
    # request phase
    # ------------------------------------------------------------------ #
    async def async_pre_call_hook(
        self, user_api_key_dict, cache, data: dict, call_type: Optional[str]
    ):
        if call_type not in (None, "completion", "acompletion", "chat_completion"):
            return data

        # Streaming IS governed — by buffering in
        # async_post_call_streaming_iterator_hook (buffer -> same Soft/Hard
        # pipeline -> replay if ALLOW, replace if DENY/MODIFY/REVIEW). Set
        # ALLOW_UNGOVERNED_STREAMING=1 only to bypass that (not recommended).
        if data.get("stream") and os.environ.get("ALLOW_UNGOVERNED_STREAMING", "0") == "1":
            data.setdefault("metadata", {}).setdefault("dciso_runtime", {})["ungoverned_stream"] = True

        md = data.get("metadata")
        if not isinstance(md, dict):
            md = {}
            data["metadata"] = md
        md.setdefault("dciso_runtime", {})["t_start"] = time.perf_counter()
        md["dciso_runtime"]["call_id"] = data.get("litellm_call_id")

        # Egress boundary (Phase B): tool results in this request are about to be
        # sent to a model endpoint. "Local read" is not "may ship anywhere".
        try:
            await self._govern_tool_results(data, self._resolved_meta(data))
        except GovernanceReject:
            raise
        except Exception:  # noqa: BLE001 - egress gate must not break the request
            pass
        # Phase E — mark when the request leaves us, so the response pass can
        # split "model time" (this -> post_call) from "governance time".
        md["dciso_runtime"]["t_precall_done"] = time.perf_counter()
        return data

    # ------------------------------------------------------------------ #
    # response phase — the enforcement point
    # ------------------------------------------------------------------ #
    async def async_post_call_success_hook(self, data: dict, user_api_key_dict, response):
        try:
            return await self._govern_response(data, response)
        except GovernanceReject:
            raise
        except Exception as exc:  # noqa: BLE001 - governance bug => fail closed
            self._safe_audit_error(data, response, exc)
            raise GovernanceReject(
                403,
                {
                    "error": {
                        "message": _GOV_ERROR_ZH,
                        "type": "governance_internal_error",
                        "code": "GOVERNANCE_FAIL_CLOSED",
                        "detail_class": type(exc).__name__,
                    }
                },
            ) from exc

    def _resolved_meta(self, data: dict) -> dict:
        """Request metadata, with a deployment-level default harness applied when
        the client did not declare one. This is an operator declaration ('this
        gateway fronts <harness>'), not model-output guessing — an explicit but
        *wrong* harness_type still fails closed as UNKNOWN_HARNESS."""
        md = dict(_meta(data))
        if "harness_type" not in md:
            dh = os.environ.get("GATEWAY_DEFAULT_HARNESS")
            if dh:
                md["harness_type"] = dh
                md.setdefault("_dciso_harness_defaulted", True)
        return md

    async def _evaluate(self, data: dict, resp_dict: dict):
        """Run the governance pipeline over a (already assembled) response dict.

        Returns an EnforcementDispatch, or None when there is nothing to govern
        (plain response) — in which case a passthrough audit row is written."""
        md = self._resolved_meta(data)
        adapter = select_adapter(md)
        approval_token = (md.get("dciso") or {}).get("approval_token")

        if adapter is None:
            if not _has_tool_calls(resp_dict):
                return await self._output_or_passthrough(
                    data, resp_dict, md, passthrough_reason="NO_ADAPTER_PLAIN_RESPONSE")
            if not self._enforce_unknown_harness:
                return None
            event = self._unknown_harness_event(md)
            outcome = await self._orchestrator.evaluate(event)
            dispatch = Enforcer(_NullAdapter(), self._tracker).enforce(
                raw_response=resp_dict, outcomes=[outcome], approval_token=approval_token
            )
            self._write_audit_row(event, outcome, dispatch, data, resp_dict)
            return dispatch

        events = adapter.normalize_response({**data, "metadata": md}, resp_dict)
        if not events:
            return await self._output_or_passthrough(
                data, resp_dict, md, passthrough_reason="NO_PROPOSED_ACTION")

        outcomes = await asyncio.gather(*(self._orchestrator.evaluate(ev) for ev in events))
        dispatch = Enforcer(adapter, self._tracker).enforce(
            raw_response=resp_dict, outcomes=list(outcomes), approval_token=approval_token
        )
        for ev, oc in zip(events, outcomes):
            self._write_audit_row(ev, oc, dispatch, data, resp_dict)
        return dispatch

    async def _govern_response(self, data: dict, response):
        rt = data.setdefault("metadata", {}).setdefault("dciso_runtime", {})
        rt["t_gov_start"] = time.perf_counter()
        resp_dict = _as_dict(response)
        dispatch = await self._evaluate(data, resp_dict)
        if dispatch is None:
            return response
        return self._apply(response, resp_dict, dispatch)

    def _attach_timings(self, result, data: dict, outcome=None) -> None:
        """Phase E — record the model/governance time split on the audit result."""
        if result is None:
            return
        rt = (data.get("metadata") or {}).get("dciso_runtime") or {}
        now = time.perf_counter()
        t = {}
        if rt.get("t_gov_start"):
            t["governance_ms"] = round((now - rt["t_gov_start"]) * 1000.0, 1)
            if rt.get("t_precall_done"):
                t["model_ms"] = round((rt["t_gov_start"] - rt["t_precall_done"]) * 1000.0, 1)
        if outcome is not None:
            t["ciso_ms"] = round(getattr(outcome, "ciso_ms", 0.0), 1)
            t["opa_ms"] = round(getattr(outcome, "opa_ms", 0.0), 1)
        try:
            result.timings = t
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ #
    # streaming — buffer, govern with the SAME pipeline, then replay/replace
    # ------------------------------------------------------------------ #
    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data):
        if os.environ.get("ALLOW_UNGOVERNED_STREAMING", "0") == "1":
            async for chunk in response:
                yield chunk
            return

        chunks: list[Any] = []
        try:
            async for chunk in response:
                chunks.append(chunk)
        except Exception:  # noqa: BLE001 - upstream stream error: pass what we have
            pass

        assembled = _assemble_stream(chunks)
        try:
            dispatch = await self._evaluate(request_data, assembled)
        except GovernanceReject as gr:
            for c in _synth_stream_chunks(chunks, _reject_text(gr)):
                yield c
            return
        except Exception as exc:  # noqa: BLE001 - governance bug => fail closed
            self._safe_audit_error(request_data, assembled, exc)
            for c in _synth_stream_chunks(chunks, _GOV_ERROR_ZH):
                yield c
            return

        if dispatch is None or dispatch.result.outcome == "ALLOW":
            for c in chunks:                       # untouched replay
                yield c
            return

        # MODIFY -> keep the (rewritten) tool call, NO narration text. Emitting
        # any content here makes Hermes treat the turn as an error and retry.
        if dispatch.result.outcome == "MODIFY":
            governed = _as_dict_choices(dispatch.response)
            gov_tool_calls = _first_choice_tool_calls(governed)
            for c in _synth_stream_chunks(chunks, "", tool_calls=gov_tool_calls):
                yield c
            return

        # DENY / REQUIRE_REVIEW -> replace the turn with the CISO's message
        # (tool calls dropped). Delivered in-band so the Hermes session survives.
        governed = _as_dict_choices(dispatch.response)
        if dispatch.transport == "http_error":
            text = _reject_text_from_body(dispatch.response)
        else:
            text = _augment_deny_text(
                _first_choice_content(governed) or _GOV_ERROR_ZH, dispatch.result
            )
        for c in _synth_stream_chunks(chunks, text):
            yield c

    # ------------------------------------------------------------------ #
    # failure phase
    # ------------------------------------------------------------------ #
    async def async_post_call_failure_hook(
        self, request_data: dict, original_exception, user_api_key_dict, traceback_str: str = ""
    ):
        if isinstance(original_exception, GovernanceReject):
            # already an OpenAI-compatible governance body; let it surface as-is
            return original_exception
        return None

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _apply(self, response, resp_dict: dict, dispatch):
        if dispatch.transport == "http_error":
            raise GovernanceReject(dispatch.http_status or 409, dispatch.response)
        if dispatch.result.outcome in ("DENY", "MODIFY", "REQUIRE_REVIEW"):
            self._mutate_in_place(response, dispatch)
        return response

    @staticmethod
    def _mutate_in_place(response, dispatch) -> None:
        new = dispatch.response
        try:
            choices = response.choices
        except AttributeError:
            if isinstance(response, dict):
                response.update(new)
            return
        new_choices = new.get("choices", [])
        for i, nc in enumerate(new_choices):
            if i >= len(choices):
                break
            msg = getattr(choices[i], "message", None)
            nmsg = nc.get("message", {})
            if msg is not None:
                if dispatch.result.outcome in ("DENY", "REQUIRE_REVIEW"):
                    msg.content = _augment_deny_text(nmsg.get("content") or "", dispatch.result)
                    msg.tool_calls = None
                elif dispatch.result.outcome == "MODIFY":
                    # output-phase redaction rewrites the answer text
                    if nmsg.get("content") is not None:
                        msg.content = nmsg["content"]
                    for j, ntc in enumerate(nmsg.get("tool_calls") or []):
                        try:
                            response.choices[i].message.tool_calls[j].function.arguments = (
                                ntc["function"]["arguments"]
                            )
                        except Exception:  # noqa: BLE001
                            pass
            try:
                choices[i].finish_reason = nc.get("finish_reason", choices[i].finish_reason)
            except Exception:  # noqa: BLE001
                pass
        # DENY / REVIEW collapse to a single assistant turn
        if dispatch.result.outcome in ("DENY", "REQUIRE_REVIEW") and len(choices) > 1:
            del choices[1:]

    def _unknown_harness_event(self, md: dict) -> GovernanceEvent:
        return GovernanceEvent(
            schema_version=SCHEMA_VERSION,
            event_id=_uuid(),
            timestamp=_now(),
            event_type=EventType.UNKNOWN,
            enforcement_phase=EnforcementPhase.MODEL_RESPONSE_PRE_EXECUTION,
            source=Source(
                harness_type=str(md.get("harness_type", "unknown")),
                harness_instance_id=str(md.get("harness_instance_id", "unknown")),
                agent_id=str(md.get("agent_id", "unknown")),
                session_id=str(md.get("session_id", "unknown-session")),
            ),
            task=Task(task_id=_uuid()),
            proposed_action=ProposedAction(native_name="unknown", canonical_name="unknown"),
            governance=GovernanceBlock(),
        )

    # ---- audit --------------------------------------------------------
    def _write_audit_row(self, event, outcome, dispatch, data, resp_dict) -> None:
        self._attach_timings(getattr(dispatch, "result", None), data, outcome)
        self._audit_writer_write(
            event=event,
            soft_advice=outcome.soft_advice,
            decision=outcome.decision,
            enforcement=dispatch.result,
            raw_request=_redactable_request(data),
            raw_response=resp_dict,
            latency_ms=outcome.latency_ms,
            error_class=outcome.error_class,
        )

    # ------------------------------------------------------------------ #
    # Output side (Phase A) — govern a model answer before delivery.
    # Fast path (no scan hit, non-sensitive task, non-external recipient)
    # returns "FASTPATH" and never consults the CISO. Otherwise OPA decides
    # on the pre-computed scan signals (counts + recipient class, not text).
    # ------------------------------------------------------------------ #
    async def _output_or_passthrough(self, data, resp_dict, md, *, passthrough_reason: str):
        """No tool call in the response -> run the output-side gate. Returns an
        EnforcementDispatch (mutation), or None after writing a cheap audit row."""
        try:
            result = await self._govern_output(data, resp_dict, md)
        except GovernanceReject:
            raise
        except Exception:  # noqa: BLE001 - output gate must never break delivery
            result = None
        if isinstance(result, EnforcementDispatch):
            return result
        reason = "OUTPUT_FASTPATH_ALLOW" if result == "FASTPATH" else passthrough_reason
        self._audit_passthrough(data, resp_dict, md, reason=reason)
        return None

    async def _get_output_policy(self) -> dict:
        if self._output_policy_cache is None:
            fetched = None
            try:
                fetched = await self._orchestrator.opa.get_data("dciso/output_policy")
            except Exception:  # noqa: BLE001 - fall back to the built-in default
                fetched = None
            self._output_policy_cache = fetched if isinstance(fetched, dict) else _OUTPUT_POLICY_DEFAULT
        return self._output_policy_cache

    async def _govern_output(self, data: dict, resp_dict: dict, md: dict):
        if not self._output_gate:
            return None
        policy = await self._get_output_policy()
        if not policy.get("enabled", True):
            return None
        text = _first_choice_content(resp_dict)
        if not text:
            return None

        dciso_md = md.get("dciso") or {}
        recipient = str(dciso_md.get("recipient", "user")).lower()
        classes = list(((dciso_md.get("task") or {}).get("data_classification")) or [])
        blocks = set(policy.get("external_recipient_blocks_classes",
                               _OUTPUT_POLICY_DEFAULT["external_recipient_blocks_classes"]))
        sensitive = bool(set(classes) & blocks)

        sig = output_scan.scan_text(text, policy.get("forbidden_markers"), self._output_max_scan)

        # fast path — nothing interesting, cheap audit, no CISO, no OPA
        if not sig.any_hit and not sensitive and recipient != "external":
            return "FASTPATH"

        esc_reason = ("forbidden_hit" if sig.forbidden_hits else
                      "sensitive_task" if sensitive else
                      "external_recipient" if recipient == "external" else None)
        escalate = esc_reason is not None
        event = self._output_event(md, sig, recipient, classes)
        event.correlation_id = data.get("litellm_call_id") or event.correlation_id
        outcome = await self._orchestrator.evaluate(event, consult_ciso=escalate)
        verdict = outcome.decision.decision.value if hasattr(outcome.decision.decision, "value") \
            else str(outcome.decision.decision)

        governed = copy.deepcopy(_as_dict_choices(resp_dict))
        if verdict == "DENY":
            _set_first_choice(governed, _OUTPUT_DENY_ZH, drop_tools=True)
        elif verdict == "REQUIRE_REVIEW":
            _set_first_choice(governed, _OUTPUT_REVIEW_ZH, drop_tools=True)
        elif verdict == "MODIFY":
            _set_first_choice(governed, output_scan.redact(text, self._output_max_scan), drop_tools=False)

        dispatch = EnforcementDispatch(
            result=EnforcementResult(
                outcome=verdict if verdict in ("DENY", "MODIFY", "REQUIRE_REVIEW") else "ALLOW",
                event_id=event.event_id,
                reason_codes=list(outcome.decision.reason_codes),
                hold="REVIEW_HOLD" if verdict == "REQUIRE_REVIEW" else "NONE",
                escalated=escalate,
                escalate_reason=esc_reason if escalate else "fastpath_no_escalation",
                redacted=verdict == "MODIFY",
            ),
            response=governed,
            transport="inband",
        )
        try:
            self._write_audit_row(event, outcome, dispatch, data, resp_dict)
        except GovernanceReject:
            raise
        except Exception:  # noqa: BLE001 - output audit is best-effort
            pass
        return dispatch

    def _output_event(self, md: dict, sig, recipient: str, classes: list) -> GovernanceEvent:
        return GovernanceEvent(
            schema_version=SCHEMA_VERSION,
            event_id=_uuid(),
            timestamp=_now(),
            event_type=EventType.MODEL_OUTPUT_PROPOSED,
            enforcement_phase=EnforcementPhase.MODEL_OUTPUT_PRE_DELIVERY,
            source=Source(
                harness_type=str(md.get("harness_type", "openai-compatible")),
                harness_instance_id=str(md.get("harness_instance_id", "unknown")),
                agent_id=str(md.get("agent_id", "main-agent")),
                session_id=str((md.get("dciso") or {}).get("session_id",
                               md.get("session_id", "unknown-session"))),
            ),
            task=Task(task_id=_uuid(), data_classification=classes),
            proposed_action=ProposedAction(
                native_name="model_output", canonical_name="model_output",
                arguments={**sig.as_signal_dict(), "recipient_class": recipient},
            ),
            governance=GovernanceBlock(),
        )

    # ------------------------------------------------------------------ #
    # Egress side (Phase B) — tool results about to be sent to a model.
    # ------------------------------------------------------------------ #
    _EGRESS_POLICY_DEFAULT = {
        "enabled": True, "default_dest_class": "external",
        "route_mode_dest_class": {"ollama": "local", "proxy": "approved",
                                  "demo": "external", "test": "local"},
        "sensitive_field_markers": ["password", "secret", "api_key", "private_key",
                                    "ssn", "credit card"],
        "forbidden_markers": ["INTERNAL ONLY", "DO NOT DISTRIBUTE", "機密", "不得外流"],
        "class_rules": {
            "local": {"max_result_kb": 4096, "redact_credentials": True,
                      "block_forbidden": False, "block_if_sensitive_task": False,
                      "block_sensitive_fields": False},
            "approved": {"max_result_kb": 1024, "redact_credentials": True,
                         "block_forbidden": True, "block_if_sensitive_task": False,
                         "block_sensitive_fields": False},
            "external": {"max_result_kb": 256, "redact_credentials": True,
                         "block_forbidden": True, "block_if_sensitive_task": True,
                         "block_sensitive_fields": True},
        },
        "withheld_notice": "[治理] 這段工具結果因含受限內容或超出政策範圍，未送往模型。",
    }

    async def _get_egress_policy(self) -> dict:
        if self._egress_policy_cache is None:
            fetched = None
            try:
                fetched = await self._orchestrator.opa.get_data("dciso/egress_policy")
            except Exception:  # noqa: BLE001
                fetched = None
            self._egress_policy_cache = fetched if isinstance(fetched, dict) else self._EGRESS_POLICY_DEFAULT
        return self._egress_policy_cache

    def _dest_class(self, data: dict, policy: dict) -> str:
        forced = os.environ.get("DCISO_EGRESS_DEST_CLASS")
        if forced:
            return forced.lower()
        model = str(data.get("model") or "")
        for marker in policy.get("approved_model_markers", []):
            if marker and str(marker) in model:
                return "approved"
        rm = os.environ.get("GATEWAY_ROUTE_MODE", "")
        by_rm = (policy.get("route_mode_dest_class") or {}).get(rm)
        return str(by_rm or policy.get("default_dest_class", "external")).lower()

    async def _govern_tool_results(self, data: dict, md: dict) -> None:
        if not self._egress_gate:
            return
        msgs = data.get("messages")
        if not isinstance(msgs, list):
            return
        tool_idxs = [i for i, m in enumerate(msgs)
                     if isinstance(m, dict) and m.get("role") in ("tool", "function")]
        if not tool_idxs:
            return

        policy = await self._get_egress_policy()
        if not policy.get("enabled", True):
            return
        dest = self._dest_class(data, policy)
        rule = (policy.get("class_rules") or {}).get(dest) \
            or self._EGRESS_POLICY_DEFAULT["class_rules"]["external"]
        max_bytes = int(rule.get("max_result_kb", 256)) * 1024
        dciso_md = md.get("dciso") or {}
        classes = list(((dciso_md.get("task") or {}).get("data_classification")) or [])

        any_governed = False
        for i in tool_idxs:
            m = msgs[i]
            text = m.get("content")
            if isinstance(text, list):  # multimodal tool content -> join text parts
                text = " ".join(str(p.get("text", "")) if isinstance(p, dict) else str(p)
                                for p in text)
            text = text if isinstance(text, str) else ("" if text is None else str(text))

            sig = output_scan.scan_payload(
                text, forbidden_markers=policy.get("forbidden_markers"),
                sensitive_field_markers=policy.get("sensitive_field_markers"),
                max_bytes=max_bytes, max_scan=self._output_max_scan)

            if dest == "local" and not sig.any_hit and not sig.oversize:
                continue  # fast path — leave it, batch-audit below

            any_governed = True
            esc_reason = ("forbidden_hit" if sig.forbidden_hits else
                          "sensitive_field" if sig.sensitive_field_hits else
                          "sensitive_task" if (set(classes) & _SENSITIVE_CLASSES) else
                          "external_dest" if dest == "external" else None)
            escalate = esc_reason is not None
            event = self._egress_event(md, sig, dest, classes)
            event.correlation_id = data.get("litellm_call_id") or event.correlation_id
            outcome = await self._orchestrator.evaluate(event, consult_ciso=escalate)
            verdict = outcome.decision.decision
            verdict = verdict.value if hasattr(verdict, "value") else str(verdict)
            codes = list(outcome.decision.reason_codes)

            if verdict in ("DENY", "REQUIRE_REVIEW"):
                m["content"] = policy.get("withheld_notice",
                                          self._EGRESS_POLICY_DEFAULT["withheld_notice"])
                m_outcome = verdict
            elif verdict == "MODIFY":
                new = text
                if "EGRESS_REDACT_CREDENTIAL" in codes:
                    new = output_scan.redact(new, self._output_max_scan)
                if "EGRESS_TRUNCATE_OVERSIZE" in codes:
                    new = output_scan.truncate_bytes(new, max_bytes)
                m["content"] = new
                m_outcome = "MODIFY"
            else:
                m_outcome = "ALLOW"

            self._audit_egress_row(event, outcome, m_outcome, codes, data,
                                   escalate, esc_reason)

        if not any_governed:
            self._audit_passthrough(data, {}, md, reason=f"EGRESS_FASTPATH_ALLOW:{dest}")

    def _egress_event(self, md: dict, sig, dest: str, classes: list) -> GovernanceEvent:
        return GovernanceEvent(
            schema_version=SCHEMA_VERSION, event_id=_uuid(), timestamp=_now(),
            event_type=EventType.TOOL_RESULT_PROPOSED,
            enforcement_phase=EnforcementPhase.TOOL_RESULT_PRE_SEND,
            source=Source(
                harness_type=str(md.get("harness_type", "openai-compatible")),
                harness_instance_id=str(md.get("harness_instance_id", "unknown")),
                agent_id=str(md.get("agent_id", "main-agent")),
                session_id=str((md.get("dciso") or {}).get(
                    "session_id", md.get("session_id", "unknown-session"))),
            ),
            task=Task(task_id=_uuid(), data_classification=classes),
            proposed_action=ProposedAction(
                native_name="tool_result", canonical_name="tool_result",
                arguments={**sig.as_signal_dict(), "dest_class": dest},
            ),
            governance=GovernanceBlock(),
        )

    def _audit_egress_row(self, event, outcome, m_outcome: str, codes: list, data: dict,
                          escalated: bool = True, esc_reason: str | None = None) -> None:
        try:
            self._write_audit_row(
                event, outcome,
                EnforcementDispatch(
                    result=EnforcementResult(
                        outcome=m_outcome, event_id=event.event_id, reason_codes=codes,
                        hold="REVIEW_HOLD" if m_outcome == "REQUIRE_REVIEW" else "NONE",
                        escalated=escalated,
                        escalate_reason=esc_reason if escalated else "fastpath_no_escalation",
                        redacted=m_outcome == "MODIFY"),
                    response={}, transport="inband"),
                data, {})
        except GovernanceReject:
            raise
        except Exception:  # noqa: BLE001 - egress audit is best-effort
            pass

    def _audit_passthrough(self, data, resp_dict, md, reason: str) -> None:
        event = GovernanceEvent(
            schema_version=SCHEMA_VERSION,
            event_id=_uuid(),
            timestamp=_now(),
            event_type=EventType.UNKNOWN,
            enforcement_phase=EnforcementPhase.MODEL_RESPONSE_PRE_EXECUTION,
            source=Source(
                harness_type=str(md.get("harness_type", "unknown")),
                harness_instance_id=str(md.get("harness_instance_id", "unknown")),
                agent_id=str(md.get("agent_id", "main-agent")),
                session_id=str(md.get("session_id", "unknown-session")),
            ),
            task=Task(task_id=_uuid()),
            proposed_action=ProposedAction(native_name="-", canonical_name="-"),
            governance=GovernanceBlock(),
        )
        _res = EnforcementResult(outcome="ALLOW", event_id=event.event_id,
                                 reason_codes=[reason],
                                 escalated=False, escalate_reason="fastpath_no_escalation")
        self._attach_timings(_res, data)
        try:
            self._audit_writer_write(
                event=event, soft_advice=None, decision=None, enforcement=_res,
                raw_request=_redactable_request(data), raw_response=resp_dict,
                latency_ms=(_res.timings or {}).get("governance_ms"), error_class=None,
            )
        except Exception:  # noqa: BLE001 - passthrough audit is best-effort
            pass

    def _audit_writer_write(self, **kw) -> None:
        try:
            self._audit.write(**kw)
        except Exception as exc:  # noqa: BLE001
            # ticket §10 Task 6: audit failure => sensitive action fails closed
            raise GovernanceReject(
                403,
                {"error": {"message": _GOV_ERROR_ZH, "type": "governance_audit_failure",
                           "code": "AUDIT_WRITE_FAILED", "detail_class": type(exc).__name__}},
            ) from exc

    def _safe_audit_error(self, data, response, exc) -> None:
        try:
            md = _meta(data)
            event = self._unknown_harness_event(md)
            from gateway.governance.schemas import EnforcementResult

            self._audit.write(
                event=event, soft_advice=None, decision=None,
                enforcement=EnforcementResult(outcome="DENY", event_id=event.event_id,
                                              reason_codes=["GOVERNANCE_FAIL_CLOSED"],
                                              user_message=_GOV_ERROR_ZH),
                raw_request=_redactable_request(data), raw_response=_as_dict(response),
                latency_ms=None, error_class=f"callback:{type(exc).__name__}",
            )
        except Exception:  # noqa: BLE001
            pass


class _NullAdapter:
    name = "unknown"

    def matches(self, md):  # pragma: no cover
        return False

    def normalize_request(self, request):  # pragma: no cover
        return []

    def normalize_response(self, request, response):  # pragma: no cover
        return []

    def enforce(self, response, decision):
        return response


def _redactable_request(data: dict) -> dict:
    return {
        "model": data.get("model"),
        "n_messages": len(data.get("messages", []) or []),
        "has_tools": bool(data.get("tools")),
        "metadata": _meta(data),
    }


def _uuid() -> str:
    import uuid

    return str(uuid.uuid4())


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# streaming helpers — assemble deltas, re-emit / replace
# --------------------------------------------------------------------------- #
def _chunk_dict(chunk: Any) -> dict[str, Any]:
    if isinstance(chunk, dict):
        return chunk
    for attr in ("model_dump", "dict"):
        fn = getattr(chunk, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:  # noqa: BLE001
                pass
    return {"choices": [{"delta": {"content": getattr(chunk, "content", "") or ""}}]}


def _assemble_stream(chunks: list[Any]) -> dict[str, Any]:
    """Reconstruct a non-streaming-shaped response dict from streamed deltas
    (content concatenated; tool_calls accumulated by index)."""
    content_parts: list[str] = []
    tool_calls: dict[int, dict[str, Any]] = {}
    finish_reason = None
    template_id = "chatcmpl-streamed"
    model = None
    for ch in chunks:
        d = _chunk_dict(ch)
        template_id = d.get("id") or template_id
        model = d.get("model") or model
        for choice in d.get("choices", []) or []:
            finish_reason = choice.get("finish_reason") or finish_reason
            delta = choice.get("delta") or {}
            if delta.get("content"):
                content_parts.append(delta["content"])
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                slot = tool_calls.setdefault(
                    idx, {"id": tc.get("id"), "type": "function",
                          "function": {"name": "", "arguments": ""}}
                )
                if tc.get("id"):
                    slot["id"] = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["function"]["name"] = fn["name"]
                if fn.get("arguments"):
                    slot["function"]["arguments"] += fn["arguments"]
    tcs = [tool_calls[i] for i in sorted(tool_calls)] or None
    return {
        "id": template_id,
        "object": "chat.completion",
        "model": model or "governed-model",
        "choices": [{
            "index": 0,
            "finish_reason": finish_reason or ("tool_calls" if tcs else "stop"),
            "message": {
                "role": "assistant",
                "content": "".join(content_parts) or None,
                "tool_calls": tcs,
            },
        }],
    }


def _as_dict_choices(obj: Any) -> dict[str, Any]:
    return obj if isinstance(obj, dict) else _as_dict(obj)


def _first_choice_content(resp: dict[str, Any]) -> Optional[str]:
    try:
        return (resp["choices"][0]["message"] or {}).get("content")
    except (KeyError, IndexError, TypeError):
        return None


def _set_first_choice(resp: dict[str, Any], content: str, *, drop_tools: bool) -> None:
    """Rewrite choices[0].message for the output-governance phase."""
    try:
        msg = resp["choices"][0].setdefault("message", {})
    except (KeyError, IndexError, TypeError):
        return
    msg["content"] = content
    if drop_tools:
        msg["tool_calls"] = None
    try:
        resp["choices"][0]["finish_reason"] = "stop"
        del resp["choices"][1:]
    except (KeyError, IndexError, TypeError):
        pass


def _first_choice_tool_calls(resp: dict[str, Any]):
    try:
        return (resp["choices"][0]["message"] or {}).get("tool_calls")
    except (KeyError, IndexError, TypeError):
        return None


def _augment_deny_text(base_text: str, result: Any) -> str:
    """What the END USER sees on a DENY / REVIEW: just the short plain-language
    reason + what to do next. The machine-readable agent_feedback and the CISO
    assessment stay in the audit / dashboard, not in the chat.

    Set DCISO_VERBOSE_DENY=1 to append the ```dciso_governance``` JSON block
    (for debugging or agent-driven re-planning)."""
    if os.environ.get("DCISO_VERBOSE_DENY", "0") != "1":
        return base_text

    fb = getattr(result, "agent_feedback", None)
    if fb is None:
        return base_text
    payload: dict[str, Any] = {
        "status": "DENIED" if getattr(result, "outcome", "") == "DENY" else "REVIEW_REQUIRED",
        "event_id": result.event_id,
        "agent_feedback": fb.model_dump(mode="json"),
        "session_continues": True,
    }
    ciso = getattr(result, "ciso", None)
    if ciso:
        payload["ciso"] = ciso
    block = json.dumps(payload, ensure_ascii=False, indent=2)
    return f"{base_text}\n\n```dciso_governance\n{block}\n```"


def _reject_text(gr: "GovernanceReject") -> str:
    return _reject_text_from_body(getattr(gr, "body", None) or getattr(gr, "detail", None))


def _reject_text_from_body(body: Any) -> str:
    if isinstance(body, dict):
        err = body.get("error") or body
        msg = err.get("message") if isinstance(err, dict) else None
        if msg:
            code = err.get("code")
            return f"{msg}" + (f"（{code}）" if code else "")
    return _GOV_ERROR_ZH


try:  # real streaming chunk types inside the LiteLLM image
    from litellm.types.utils import Delta as _Delta
    from litellm.types.utils import ModelResponseStream as _MRS
    from litellm.types.utils import StreamingChoices as _SChoices
except Exception:  # pragma: no cover
    _MRS = _SChoices = _Delta = None


def _synth_stream_chunks(template_chunks: list[Any], text: str, tool_calls=None):
    """Yield a valid `chat.completion.chunk` sequence carrying `text` (and
    optional tool_calls) in place of the original stream. Uses LiteLLM's real
    stream types so downstream clients (Hermes) accept it as a completion."""
    base = _chunk_dict(template_chunks[0]) if template_chunks else {}
    cid = base.get("id") or "chatcmpl-governed"
    model = base.get("model") or "governed-model"

    norm_tcs = None
    if tool_calls:
        norm_tcs = []
        for i, tc in enumerate(tool_calls):
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            norm_tcs.append({
                "index": i,
                "id": (tc.get("id") if isinstance(tc, dict) else None) or f"call_{i}",
                "type": "function",
                "function": {"name": fn.get("name", ""), "arguments": fn.get("arguments", "")},
            })

    def _mk(delta: dict, finish=None):
        if _MRS is not None:
            return _MRS(
                id=cid, model=model,
                choices=[_SChoices(index=0, delta=_Delta(**delta), finish_reason=finish)],
            )
        return {"id": cid, "object": "chat.completion.chunk", "model": model,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}

    if text or not norm_tcs:
        yield _mk({"role": "assistant", "content": text})
    elif norm_tcs:
        yield _mk({"role": "assistant"})
    if norm_tcs:
        yield _mk({"tool_calls": norm_tcs})
        yield _mk({}, finish="tool_calls")
    else:
        yield _mk({}, finish="stop")


# LiteLLM loads THIS instance (not the class).
governance_handler_instance = GovernanceCallback()
