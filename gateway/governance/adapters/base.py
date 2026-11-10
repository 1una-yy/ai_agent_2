"""Pluggable interfaces (ticket §14).

Adding a new harness (OpenClaw, ...) means adding a HarnessAdapter + mapping
tests ONLY. The Hard PDP API, the Policy Advisor API and the audit schema do
not change.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from gateway.governance.schemas import Decision, GovernanceEvent, SoftAdvice


@runtime_checkable
class HarnessAdapter(Protocol):
    name: str

    def matches(self, request_metadata: dict[str, Any]) -> bool:
        """True if this adapter owns the request. MUST decide from explicit
        metadata (e.g. harness_type), never by guessing from model output."""
        ...

    def normalize_request(self, request: dict[str, Any]) -> list[GovernanceEvent]:
        ...

    def normalize_response(
        self, request: dict[str, Any], response: dict[str, Any]
    ) -> list[GovernanceEvent]:
        ...

    def enforce(self, response: dict[str, Any], decision: Decision) -> dict[str, Any]:
        """Apply a Decision to the raw provider response before it returns to
        the harness. Deterministic; no risk judgement here."""
        ...


@runtime_checkable
class PolicyAdvisor(Protocol):
    async def advise(self, event: GovernanceEvent) -> SoftAdvice:
        ...


@runtime_checkable
class HardPolicyDecisionPoint(Protocol):
    async def decide(self, event: GovernanceEvent, advice: SoftAdvice) -> Decision:
        ...
