"""Client for the AI CISO advisor service (ticket §10 Task 4).

The advisor is a SEPARATE service (separate identity / memory / tools). This
client sends it only the minimized GovernanceEvent and expects the fixed
SoftAdvice JSON schema back.

Hard rules:
  * timeout (default 2-5s) -> SoftAdvice.unavailable(UNAVAILABLE)
  * transport error        -> SoftAdvice.unavailable(UNAVAILABLE)
  * non-200 / bad JSON / schema mismatch -> SoftAdvice.unavailable(UNPARSEABLE)
  * a parse failure is NEVER treated as ALLOW.
The Hard PDP then decides what an unavailable advice means (fail closed for
sensitive actions).
"""

from __future__ import annotations

import os

import httpx

from gateway.governance.schemas import (
    AdviceAvailability,
    GovernanceEvent,
    SoftAdvice,
)

# Fields the advisor is allowed to see. Everything else (raw messages, tool
# argument bodies, provider metadata) is withheld here — defence in depth on
# top of whatever the service itself minimizes.
_ALLOWED_EVENT_FIELDS = {
    "schema_version",
    "event_id",
    "timestamp",
    "event_type",
    "enforcement_phase",
    "source",
    "task",
    "proposed_action",
    "governance",
}


def _minimize(event: GovernanceEvent) -> dict:
    dump = event.model_dump(mode="json")
    minimized = {k: v for k, v in dump.items() if k in _ALLOWED_EVENT_FIELDS}
    # never forward a previously attached advice back to the advisor
    minimized.get("governance", {}).pop("soft_advice", None)
    # tool argument *values* can carry payloads; keep only the key names
    pa = minimized.get("proposed_action", {})
    if isinstance(pa.get("arguments"), dict):
        pa["argument_keys"] = sorted(pa["arguments"].keys())
        pa["arguments"] = {}
    return minimized


class CISOAdvisorClient:
    def __init__(self, url: str | None = None, timeout: float | None = None) -> None:
        self.url = (url or os.environ.get("CISO_ADVISOR_URL", "http://ciso-advisor:9000")).rstrip("/")
        self.timeout = timeout or float(os.environ.get("CISO_TIMEOUT_SECONDS", "4"))

    async def advise(self, event: GovernanceEvent) -> SoftAdvice:
        payload = {"event": _minimize(event)}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.url}/advise", json=payload)
        except httpx.TimeoutException:
            return SoftAdvice.unavailable(AdviceAvailability.UNAVAILABLE, "CISO advisor timed out")
        except httpx.TransportError as exc:
            return SoftAdvice.unavailable(
                AdviceAvailability.UNAVAILABLE, f"CISO advisor transport error: {type(exc).__name__}"
            )

        if resp.status_code != 200:
            return SoftAdvice.unavailable(
                AdviceAvailability.UNPARSEABLE, f"CISO advisor HTTP {resp.status_code}"
            )
        try:
            data = resp.json()
        except ValueError:
            return SoftAdvice.unavailable(AdviceAvailability.UNPARSEABLE, "CISO advisor non-JSON body")

        try:
            advice = SoftAdvice.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            return SoftAdvice.unavailable(
                AdviceAvailability.UNPARSEABLE, f"CISO advisor schema mismatch: {type(exc).__name__}"
            )
        # The service must not self-declare availability; this client owns it.
        advice.availability = AdviceAvailability.OK
        return advice
