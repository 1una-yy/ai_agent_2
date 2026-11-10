"""Wire contracts for the DCISO Governance Gateway.

These schemas are the *stable interface* between components (ticket §6, §14):

    Harness Adapter  --produces-->  GovernanceEvent
    Policy Advisor   --produces-->  SoftAdvice        (fills governance.soft_advice)
    Hard PDP (OPA)   --produces-->  Decision          (final authority)
    Enforcer         --produces-->  EnforcementResult

Rules baked in here:
  * A raw Hermes request is NEVER handed straight to policy — it is normalized
    into a GovernanceEvent first.
  * SoftAdvice is advisory only. It can never widen a Hard limit.
  * Anything unparseable / missing is the caller's cue to fail closed — these
    models raise on malformed input rather than silently defaulting to ALLOW.
"""

from __future__ import annotations

import enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "0.1.0"


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class EventType(str, enum.Enum):
    AGENT_SPAWN = "agent.spawn"
    TOOL_EXECUTE_PROPOSED = "tool.execute.proposed"
    # A tool result about to be sent to a model endpoint (egress boundary).
    TOOL_RESULT_PROPOSED = "tool.result.proposed"
    # A model-authored final answer about to be delivered to the recipient.
    MODEL_OUTPUT_PROPOSED = "model.output.proposed"
    # Unknown/unclassified — adapters must map here rather than guess; policy
    # then applies default-deny.
    UNKNOWN = "unknown"


class EnforcementPhase(str, enum.Enum):
    MODEL_REQUEST_PRE_DISPATCH = "model_request_pre_dispatch"
    MODEL_RESPONSE_PRE_EXECUTION = "model_response_pre_execution"
    # Layer 2 — the harness is about to actually run the tool (Hermes
    # pre_tool_call hook). This governs real side effects, not a proposal.
    TOOL_EXECUTION_PRE_DISPATCH = "tool_execution_pre_dispatch"
    # Egress side — a tool result about to be sent to a model endpoint. "Local
    # read" is not "may ship to an external model"; checked at the send edge.
    TOOL_RESULT_PRE_SEND = "tool_result_pre_send"
    # Output side — a model answer about to reach the recipient. Fast rules by
    # default; only escalates to the CISO on explicit conditions.
    MODEL_OUTPUT_PRE_DELIVERY = "model_output_pre_delivery"


class Verdict(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MODIFY = "MODIFY"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AdviceAvailability(str, enum.Enum):
    OK = "OK"
    UNAVAILABLE = "UNAVAILABLE"          # timeout / transport error
    UNPARSEABLE = "UNPARSEABLE"          # returned something, not valid schema


# Autonomy / capability ladders are ordered; helpers below compare them.
AUTONOMY_LADDER = ["L0", "L1", "L2", "L3", "L4"]
CAPABILITY_LADDER = ["C0", "C1", "C2", "C3", "C4"]


def autonomy_rank(value: str) -> int:
    try:
        return AUTONOMY_LADDER.index(value)
    except ValueError:  # unknown rung -> treat as max so policy stays strict
        return len(AUTONOMY_LADDER)


# --------------------------------------------------------------------------- #
# GovernanceEvent (ticket §6)
# --------------------------------------------------------------------------- #
class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")
    harness_type: str
    harness_instance_id: str
    agent_id: str
    session_id: str


class Task(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str
    parent_task_id: Optional[str] = None
    purpose: str = ""
    data_classification: list[str] = Field(default_factory=list)


class ProposedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    native_name: str
    canonical_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    resource: Optional[str] = None
    destination: Optional[str] = None


class GrantConstraints(BaseModel):
    """Parent grant a child spawn must stay within (ticket §7 rule 4)."""
    model_config = ConfigDict(extra="forbid")
    max_autonomy: str = "L0"
    max_subagent_depth: int = 0
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    data_scope: list[str] = Field(default_factory=list)
    ttl_seconds: Optional[int] = None


class GovernanceBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requested_autonomy: str = "L0"
    capability_level: str = "C0"
    odd_state: str = "NORMAL"
    subagent_depth: int = 0
    parent_grant: Optional[GrantConstraints] = None
    soft_advice: Optional["SoftAdvice"] = None
    policy_version: Optional[str] = None


class GovernanceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = SCHEMA_VERSION
    event_id: str
    timestamp: str                       # RFC3339
    event_type: EventType
    enforcement_phase: EnforcementPhase
    source: Source
    task: Task
    proposed_action: ProposedAction
    governance: GovernanceBlock
    # Correlation for the audit chain / dashboard timeline.
    correlation_id: Optional[str] = None


# --------------------------------------------------------------------------- #
# SoftAdvice — CISO advisor output (ticket §6)
# --------------------------------------------------------------------------- #
class SuggestedObligations(BaseModel):
    model_config = ConfigDict(extra="forbid")
    read_only: bool = False
    max_autonomy: str = "L1"
    max_subagent_depth: int = 0
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)


class SoftAdvice(BaseModel):
    """Advisory only. `availability` != OK means the Hard PDP must assume the
    worst for sensitive actions (fail closed)."""
    model_config = ConfigDict(extra="forbid")
    advice: Verdict
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    reason_codes: list[str] = Field(default_factory=list)
    explanation: str = ""
    suggested_obligations: SuggestedObligations = Field(default_factory=SuggestedObligations)
    availability: AdviceAvailability = AdviceAvailability.OK

    @classmethod
    def unavailable(cls, why: AdviceAvailability, detail: str = "") -> "SoftAdvice":
        return cls(
            advice=Verdict.DENY,
            risk_score=100,
            risk_level=RiskLevel.CRITICAL,
            reason_codes=["SOFT_ADVICE_UNAVAILABLE"],
            explanation=detail or "CISO advisor did not return a usable answer.",
            availability=why,
        )


GovernanceBlock.model_rebuild()


# --------------------------------------------------------------------------- #
# Decision — OPA / Hard PDP output (ticket §6)
# --------------------------------------------------------------------------- #
class Obligations(BaseModel):
    model_config = ConfigDict(extra="forbid")
    read_only: bool = True
    max_autonomy: str = "L1"
    max_subagent_depth: int = 0
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    # MODIFY may carry concrete argument rewrites (verifiable only).
    argument_overrides: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Verdict
    reason_codes: list[str] = Field(default_factory=list)
    obligations: Obligations = Field(default_factory=Obligations)
    policy_version: str = "unknown"

    @classmethod
    def fail_closed(cls, code: str, detail_codes: Optional[list[str]] = None) -> "Decision":
        return cls(
            decision=Verdict.DENY,
            reason_codes=[code, *(detail_codes or [])],
            obligations=Obligations(read_only=True, max_autonomy="L0",
                                    max_subagent_depth=0, allowed_tools=[], denied_tools=["*"]),
            policy_version="fail-closed",
        )


# --------------------------------------------------------------------------- #
# EnforcementResult — what the enforcer decided to do (ticket §8)
# --------------------------------------------------------------------------- #
class AgentFeedback(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["REPLAN", "STOP_AUTO_REPLAN", "PROCEED_MODIFIED"] = "REPLAN"
    blocked_action: Optional[str] = None
    reason_code: Optional[str] = None
    allowed_alternatives: list[str] = Field(default_factory=list)
    adjustable_conditions: list[str] = Field(default_factory=list)
    event_id: Optional[str] = None


class EnforcementResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: Literal["ALLOW", "DENY", "MODIFY", "REQUIRE_REVIEW"]
    event_id: str
    reason_codes: list[str] = Field(default_factory=list)
    # Human-facing, Traditional Chinese, always shown to the user on DENY.
    user_message: Optional[str] = None
    agent_feedback: Optional[AgentFeedback] = None
    replan_attempt: int = 0
    session_continues: bool = True
    # For MODIFY: before/after snapshot for audit.
    modification: Optional[dict[str, Any]] = None
    # CISO advisor summary shown to the user on DENY/REVIEW (advice, risk, why).
    ciso: Optional[dict[str, Any]] = None
    # Phase D — honest semantics. `hold` distinguishes an action that is
    # actually STOPPED and waiting for approval ("REVIEW_HOLD") from one that
    # merely got a soft flag but still proceeded ("ADVISORY"). `advisory` is
    # the CISO's non-binding flag when it did NOT change the outcome.
    hold: Literal["NONE", "REVIEW_HOLD", "ADVISORY"] = "NONE"
    advisory: Optional[dict[str, Any]] = None
    # was the expensive CISO consulted, and why (escalation reason) / why not
    escalated: bool = True
    escalate_reason: Optional[str] = None
    # did the gateway redact/truncate content on this decision
    redacted: bool = False
    # Phase E — time split for this decision, milliseconds. Keys: ciso_ms,
    # opa_ms, governance_ms (pipeline incl. enforce), model_ms (upstream model).
    timings: dict[str, float] = Field(default_factory=dict)
