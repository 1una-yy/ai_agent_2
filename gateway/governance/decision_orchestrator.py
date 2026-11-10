"""Decision orchestration (ticket §3, §10 Task 2).

Flow per GovernanceEvent:

    OPA hard pre-check  --no soft_advice-dependent hit?-->  skip CISO entirely, DENY now
            |  (clean)
            v
    CISO advisor  --SoftAdvice-->  fold into governance.soft_advice
                                        |
                                        v
                                   OPA Hard PDP  --Decision--> (final)

The pre-check only ever consults `hard_deny_reasons` — the subset of the
Rego's `deny_reasons` that does NOT depend on soft_advice (dangerous tool
class, dangerous shell command, path policy, child-grant / IFC violations).
It can never produce an ALLOW, MODIFY or REQUIRE_REVIEW on its own, and it
never substitutes for the real CISO -> OPA evaluation when nothing hard-denies
— it only lets a guaranteed-DENY skip the (possibly 20-40s) CISO round-trip.

Precedence is enforced by OPA itself; this module only guarantees:
  * soft advice is obtained (or a fail-closed placeholder is used) whenever
    the final verdict could actually depend on it
  * any orchestration exception collapses to DENY_CURRENT_ACTION
  * soft advice never bypasses OPA
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from gateway.governance.clients.ciso_advisor import CISOAdvisorClient
from gateway.governance.clients.opa import OPAClient
from gateway.governance.schemas import (
    AdviceAvailability,
    Decision,
    GovernanceEvent,
    RiskLevel,
    SoftAdvice,
    Verdict,
)


@dataclass
class OrchestrationOutcome:
    event: GovernanceEvent
    soft_advice: SoftAdvice
    decision: Decision
    latency_ms: float          # total: CISO + OPA
    error_class: str | None = None
    ciso_ms: float = 0.0       # Phase E — advisor wall time (0 if fast-path skip)
    opa_ms: float = 0.0        # Phase E — hard PDP wall time


class DecisionOrchestrator:
    def __init__(
        self,
        ciso: CISOAdvisorClient | None = None,
        opa: OPAClient | None = None,
    ) -> None:
        self.ciso = ciso or CISOAdvisorClient()
        self.opa = opa or OPAClient()

    async def evaluate(
        self, event: GovernanceEvent, *, consult_ciso: bool = True
    ) -> OrchestrationOutcome:
        started = time.perf_counter()
        error_class: str | None = None
        ciso_ms = 0.0
        opa_ms = 0.0

        # 0. Hard pre-check — only when we'd otherwise pay for a CISO call.
        #    A hit means the final verdict is DENY no matter what CISO says,
        #    so skip that round-trip and return immediately. `hard_deny_reasons`
        #    is proven (policy/tests/agent_governance_test.rego) to never
        #    include a SOFT_ADVICE_* reason, so this is safe to evaluate before
        #    soft_advice exists — it cannot pre-empt a decision that actually
        #    needed CISO's input.
        if consult_ciso:
            _p0 = time.perf_counter()
            try:
                hard_hits = await self.opa.precheck(event)
            except Exception:  # noqa: BLE001 - precheck is an optimization, never fatal
                hard_hits = None
            opa_ms += (time.perf_counter() - _p0) * 1000.0

            if hard_hits:
                advice = SoftAdvice(
                    advice=Verdict.DENY, risk_score=100, risk_level=RiskLevel.CRITICAL,
                    reason_codes=["CISO_SKIPPED_HARD_PRECHECK_DENY"],
                    explanation="hard policy already denies this action; CISO was not consulted",
                )
                decision = Decision(
                    decision=Verdict.DENY,
                    reason_codes=hard_hits,
                    policy_version=event.governance.policy_version or "unknown",
                )
                event.governance.soft_advice = advice
                event.governance.policy_version = decision.policy_version
                latency_ms = (time.perf_counter() - started) * 1000.0
                return OrchestrationOutcome(
                    event=event,
                    soft_advice=advice,
                    decision=decision,
                    latency_ms=latency_ms,
                    error_class=error_class,
                    ciso_ms=0.0,
                    opa_ms=round(opa_ms, 2),
                )
            # hard_hits is [] (clean) or None (precheck unreachable) -> fall
            # through to the normal CISO -> OPA flow below either way.

        # 1. Soft policy — advisory only, failures never raise past the client.
        #    The output-side fast path skips it entirely (consult_ciso=False):
        #    a benign answer does not need the expensive content read.
        if not consult_ciso:
            advice = SoftAdvice(
                advice=Verdict.ALLOW, risk_score=0, risk_level=RiskLevel.LOW,
                reason_codes=["CISO_NOT_CONSULTED_FASTPATH"],
                explanation="fast path — no escalation condition met",
            )
        else:
            _c0 = time.perf_counter()
            try:
                advice = await self.ciso.advise(event)
            except Exception as exc:  # noqa: BLE001 - defence in depth
                error_class = f"ciso:{type(exc).__name__}"
                advice = SoftAdvice.unavailable(
                    AdviceAvailability.UNAVAILABLE, f"advisor call raised {type(exc).__name__}"
                )
            ciso_ms = (time.perf_counter() - _c0) * 1000.0

        # 2. Hard policy — final authority. Any failure -> fail closed.
        _o0 = time.perf_counter()
        try:
            decision = await self.opa.decide(event, advice)
        except Exception as exc:  # noqa: BLE001
            error_class = (error_class + "; " if error_class else "") + f"opa:{type(exc).__name__}"
            decision = Decision.fail_closed("HARD_PDP_ORCHESTRATION_ERROR", [type(exc).__name__])
        opa_ms += (time.perf_counter() - _o0) * 1000.0

        event.governance.soft_advice = advice
        event.governance.policy_version = decision.policy_version

        latency_ms = (time.perf_counter() - started) * 1000.0
        return OrchestrationOutcome(
            event=event,
            soft_advice=advice,
            decision=decision,
            latency_ms=latency_ms,
            error_class=error_class,
            ciso_ms=round(ciso_ms, 2),
            opa_ms=round(opa_ms, 2),
        )
