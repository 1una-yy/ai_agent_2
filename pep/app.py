"""Execution-side Policy Enforcement Point (Layer 2).

The LiteLLM callback (Layer 1) governs what the model *proposes*. This service
governs what the harness is *about to actually run* — it is called by a Hermes
`pre_tool_call` shell hook, right before Hermes dispatches a tool.

    Hermes → pre_tool_call hook → POST /govern → CISO advisor + OPA → decision
                                       ↓
             {} = allow   |   block   |   modify (rewrite args)

Same GovernanceEvent schema, same Soft/Hard pipeline, same audit store — only
`enforcement_phase = tool_execution_pre_dispatch`. Fail-closed: any error here
returns a block (and the hook is also configured `fail_closed: true`).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from gateway.governance.adapters.hermes import HermesAdapter
from gateway.governance.audit import AuditWriter
from gateway.governance.decision_orchestrator import DecisionOrchestrator
from gateway.governance.enforcer import public_code
from gateway.governance.schemas import Verdict

APP_VERSION = "0.1.0"
app = FastAPI(title="DCISO Execution PEP", version=APP_VERSION)

_adapter = HermesAdapter()
_orch = DecisionOrchestrator()
_audit = AuditWriter()

# Short block messages — returned to the model as the tool result.
_BLOCK_MSG = {
    "DANGEROUS_TOOL_DENIED": "無法執行：此工具風險太高，已在執行前擋下。改用唯讀方式或縮小範圍。",
    "EXTERNAL_SENSITIVE_TRANSFER_DENIED": "無法執行：這會把敏感資料送到外部。改用去識別化摘要或內部目的地。",
    "IFC_CLEARANCE_VIOLATION": "無法執行：資料等級高於目的地授權，已在執行前擋下。",
    "DELEGATION_EXCEEDS_GRANT": "無法執行：子代理權限超出授權，已在執行前擋下。縮小範圍再試。",
    "GOVERNANCE_SERVICE_UNAVAILABLE": "暫時無法執行：安全檢查服務不可用，已擋下。稍後再試。",
    "HUMAN_REVIEW_REQUIRED": "此工具執行需人工核准。",
    "PROTECTED_PATH_DENIED": "無法執行：目標是受保護的路徑（金鑰／憑證／系統設定），或要執行暫存／下載目錄裡的程式。改用專案內路徑再試。",
}
_GENERIC_BLOCK = "無法執行：這項操作不被安全政策允許。"


class HookPayload(BaseModel):
    hook_event_name: str | None = None
    tool_name: str | None = None
    tool_input: dict[str, Any] | Any | None = None
    session_id: str | None = None
    cwd: str | None = None
    extra: dict[str, Any] | None = None


@app.get("/health/liveness")
async def liveness() -> dict[str, str]:
    return {"status": "alive", "version": APP_VERSION}


@app.get("/health/policy")
async def policy_ready() -> dict[str, Any]:
    # cheap reachability probe of the hard PDP
    ok = True
    try:
        import httpx

        async with httpx.AsyncClient(timeout=2.0) as c:
            r = await c.post(f"{_orch.opa.query_url}", json={"input": {}})
        ok = r.status_code == 200
    except Exception:  # noqa: BLE001
        ok = False
    return {"ready": ok, "version": APP_VERSION}


def _block_message(reason_codes: list[str], user_message: str | None) -> str:
    if user_message:
        return user_message
    pub = public_code(reason_codes)
    return _BLOCK_MSG.get(pub, _GENERIC_BLOCK)


@app.post("/govern")
async def govern(p: HookPayload) -> dict[str, Any]:
    # non-tool events (pre_llm_call, session lifecycle) — nothing to govern
    if not p.tool_name:
        return {}

    try:
        if not isinstance(p.tool_input, dict):
            p.tool_input = {"_value": p.tool_input} if p.tool_input is not None else {}
        event = _adapter.normalize_tool_execution(p.model_dump())
        outcome = await _orch.evaluate(event)
        decision = outcome.decision
        reason_codes = decision.reason_codes

        try:
            from gateway.governance.schemas import EnforcementResult

            _audit.write(
                event=event, soft_advice=outcome.soft_advice, decision=decision,
                enforcement=EnforcementResult(
                    outcome=decision.decision.value, event_id=event.event_id,
                    reason_codes=reason_codes,
                    hold="REVIEW_HOLD" if decision.decision == Verdict.REQUIRE_REVIEW else "NONE",
                    user_message=_block_message(reason_codes, None)
                    if decision.decision != Verdict.ALLOW else None,
                ),
                raw_request={"layer": "execution_pep", "tool": p.tool_name,
                             "arg_keys": sorted((p.tool_input or {}).keys()), "cwd": p.cwd},
                raw_response=None, latency_ms=outcome.latency_ms, error_class=outcome.error_class,
            )
        except Exception as exc:  # noqa: BLE001 - audit failure => fail closed
            return {"action": "block",
                    "message": _BLOCK_MSG["GOVERNANCE_SERVICE_UNAVAILABLE"],
                    "dciso": {"event_id": event.event_id, "error": f"audit:{type(exc).__name__}"}}

        if decision.decision == Verdict.ALLOW:
            return {}

        if decision.decision == Verdict.MODIFY:
            overrides = decision.obligations.argument_overrides or {}
            if overrides:
                new_args = dict(p.tool_input or {})
                new_args.update(overrides)
                return {"action": "modify", "args": new_args,
                        "dciso": {"event_id": event.event_id, "reason_codes": reason_codes}}
            # nothing safely rewriteable -> block rather than run as-is
            return {"action": "block",
                    "message": _block_message(reason_codes, None) + "（需調整參數）",
                    "dciso": {"event_id": event.event_id, "reason_codes": reason_codes}}

        # DENY / REQUIRE_REVIEW
        return {"action": "block",
                "message": _block_message(reason_codes, None),
                "dciso": {"event_id": event.event_id, "outcome": decision.decision.value,
                          "reason_code": public_code(reason_codes)}}

    except Exception as exc:  # noqa: BLE001 - governance bug => fail closed
        return {"action": "block",
                "message": _BLOCK_MSG["GOVERNANCE_SERVICE_UNAVAILABLE"],
                "dciso": {"error": type(exc).__name__}}
