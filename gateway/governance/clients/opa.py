"""OPA Hard PDP client (ticket §10 Task 5).

Every failure mode maps to DENY_CURRENT_ACTION:
  * transport error / timeout
  * non-200
  * 200 but no `result` key  (undefined decision -> OPA returns this)
  * `result` present but missing/invalid `decision`
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from gateway.governance.schemas import Decision, GovernanceEvent, SoftAdvice, Verdict


class OPAClient:
    def __init__(
        self,
        base_url: str | None = None,
        decision_path: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("OPA_URL", "http://opa:8181")).rstrip("/")
        self.decision_path = (
            decision_path or os.environ.get("OPA_DECISION_PATH", "dciso/governance/decision")
        ).strip("/")
        self.timeout = timeout or float(os.environ.get("OPA_TIMEOUT_SECONDS", "3"))

    @property
    def query_url(self) -> str:
        return f"{self.base_url}/v1/data/{self.decision_path}?strict-builtin-errors=true"

    async def decide(self, event: GovernanceEvent, advice: SoftAdvice) -> Decision:
        # advice is folded into the event exactly as the schema prescribes:
        # it only ever lands in governance.soft_advice.
        event = event.model_copy(deep=True)
        event.governance.soft_advice = advice

        body: dict[str, Any] = {"input": event.model_dump(mode="json")}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.query_url, json=body)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            return Decision.fail_closed("HARD_PDP_UNREACHABLE", [type(exc).__name__])

        if resp.status_code != 200:
            return Decision.fail_closed("HARD_PDP_HTTP_ERROR", [str(resp.status_code)])

        try:
            payload = resp.json()
        except ValueError:
            return Decision.fail_closed("HARD_PDP_BAD_JSON")

        if "result" not in payload:
            # Undefined decision path -> OPA omits `result`. Treat as DENY.
            return Decision.fail_closed("HARD_PDP_UNDEFINED_DECISION")

        result = payload["result"]
        if not isinstance(result, dict) or "decision" not in result:
            return Decision.fail_closed("HARD_PDP_NO_DECISION_FIELD")

        try:
            decision = Decision.model_validate(result)
        except Exception as exc:  # noqa: BLE001 - any validation failure => fail closed
            return Decision.fail_closed("HARD_PDP_SCHEMA_MISMATCH", [type(exc).__name__])

        if decision.decision not in set(Verdict):
            return Decision.fail_closed("HARD_PDP_UNKNOWN_VERDICT")
        return decision

    async def precheck(self, event: GovernanceEvent) -> list[str] | None:
        """Cheap hard-policy-only pre-check, meant to run BEFORE the (possibly
        20-40s) CISO call. Queries `hard_deny_reasons` — the subset of
        `deny_reasons` that never depends on soft_advice (see
        policy/agent_governance.rego) — so it is safe to call with the event
        exactly as normalized, soft_advice still unset.

        Returns:
          * a non-empty list  -> the final verdict will be DENY regardless of
            what CISO says; the caller may skip consulting CISO entirely.
          * an empty list     -> no hard-rule denial; proceed with the normal
            CISO -> OPA flow.
          * None              -> the pre-check itself could not be evaluated
            (timeout, bad response, ...). This is NOT a decision either way —
            callers must fall through to the normal flow, which has its own
            fail-closed handling if OPA is genuinely unreachable.
        """
        url = f"{self.base_url}/v1/data/dciso/governance/hard_precheck"
        body: dict[str, Any] = {"input": event.model_dump(mode="json")}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=body)
        except (httpx.TimeoutException, httpx.TransportError):
            return None

        if resp.status_code != 200:
            return None
        try:
            payload = resp.json()
        except ValueError:
            return None

        result = payload.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("reasons"), list):
            return None
        return [str(r) for r in result["reasons"]]

    async def get_data(self, subpath: str) -> Any:
        """Read a plain data document, e.g. get_data("dciso/output_policy").
        Returns None on any failure — callers must have a safe default."""
        url = f"{self.base_url}/v1/data/{subpath.strip('/')}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
            if resp.status_code != 200:
                return None
            return resp.json().get("result")
        except (httpx.TimeoutException, httpx.TransportError, ValueError):
            return None
