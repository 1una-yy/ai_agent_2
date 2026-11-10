# Governance Event & Decision contracts

Authoritative definitions: `gateway/governance/schemas.py` (pydantic, `extra="forbid"`).
This doc is the human-readable mirror. `schema_version` = **0.1.0**.

## GovernanceEvent

Produced by a `HarnessAdapter` from a raw model response. The raw Hermes
request is **never** passed to policy directly.

```jsonc
{
  "schema_version": "0.1.0",
  "event_id": "uuid",
  "timestamp": "RFC3339",
  "event_type": "agent.spawn | tool.execute.proposed | unknown",
  "enforcement_phase": "model_response_pre_execution",
  "source": {
    "harness_type": "hermes",
    "harness_instance_id": "hermes-business-01",
    "agent_id": "main-agent",
    "session_id": "opaque-session-id"
  },
  "task": {
    "task_id": "uuid",
    "parent_task_id": null,
    "purpose": "user task summary (<=500 chars)",
    "data_classification": ["internal"]          // PHI | PII | SECRET | internal | ...
  },
  "proposed_action": {
    "native_name": "delegate_task",
    "canonical_name": "agent.spawn",             // generic tools: canonical == native
    "arguments": { },
    "resource": null,
    "destination": null
  },
  "governance": {
    "requested_autonomy": "L1",                  // L0..L4
    "capability_level": "C1",                    // C0..C4
    "odd_state": "NORMAL",
    "subagent_depth": 0,
    "parent_grant": null,                        // GrantConstraints for spawns
    "soft_advice": null,                         // filled by the orchestrator
    "policy_version": null                       // filled from the OPA response
  },
  "correlation_id": "litellm_call_id::tool_call_id"
}
```

## SoftAdvice (CISO advisor → `governance.soft_advice`)

```jsonc
{
  "advice": "ALLOW | DENY | MODIFY | REQUIRE_REVIEW",
  "risk_score": 0,                               // 0..100
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "reason_codes": ["STRING_CODE"],
  "explanation": "short",
  "suggested_obligations": {
    "read_only": false, "max_autonomy": "L1", "max_subagent_depth": 0,
    "allowed_tools": [], "denied_tools": []
  },
  "availability": "OK | UNAVAILABLE | UNPARSEABLE"   // owned by the gateway client, not the service
}
```

Parse failure / timeout ⇒ `availability != OK` and `advice = DENY` (fail closed
for sensitive actions, decided by OPA). It is **never** treated as ALLOW.

## Decision (OPA → final)

```jsonc
{
  "decision": "ALLOW | DENY | MODIFY | REQUIRE_REVIEW",
  "reason_codes": ["HARD_POLICY_CODE"],
  "obligations": {
    "read_only": true, "max_autonomy": "L1", "max_subagent_depth": 0,
    "allowed_tools": ["read_file"], "denied_tools": ["terminal", "send_email"],
    "argument_overrides": { }                    // MODIFY only, verifiable rewrites
  },
  "policy_version": "v0.1.0"
}
```

OPA response with no `result` / no `decision` ⇒ gateway synthesises
`Decision.fail_closed(...)` = DENY.

## EnforcementResult (audited; drives what Hermes receives)

```jsonc
{
  "outcome": "ALLOW | DENY | MODIFY | REQUIRE_REVIEW",
  "event_id": "uuid",
  "reason_codes": ["..."],                       // raw (audit only)
  "user_message": "繁體中文說明（DENY/REVIEW 時必填）",
  "agent_feedback": {
    "action": "REPLAN | STOP_AUTO_REPLAN | PROCEED_MODIFIED",
    "blocked_action": "canonical name",
    "reason_code": "COARSE_PUBLIC_CODE",         // no policy internals
    "allowed_alternatives": ["redact_sensitive_fields", "..."],
    "adjustable_conditions": ["..."],
    "event_id": "uuid"
  },
  "replan_attempt": 0,
  "session_continues": true,
  "modification": { "before": [...], "after": [...], "obligations": {...} }  // MODIFY
}
```

## DENY / REQUIRE_REVIEW as delivered to Hermes (in-band, session preserved)

The assistant message's `tool_calls` are set to `null`; `content` becomes a
**short plain-language sentence** — what can't be done + what to try next
(templates in `enforcer._USER_MESSAGE`). No JSON, no CISO score, no internals:
the end user only sees why it stopped and how to proceed. The model's original
tool call never reaches Hermes.

The machine-readable part (`agent_feedback`, `reason_codes`, the CISO
assessment) lives in the **audit row / dashboard**, not the chat. Set
`DCISO_VERBOSE_DENY=1` to also append a fenced ```` ```dciso_governance ````
JSON block to `content` (for debugging or agent-driven re-planning).

REQUIRE_REVIEW is delivered the same way by default. Set
`GOVERNANCE_REVIEW_AS_HTTP_ERROR=1` for the HTTP `409`
`{"error":{"code":"GOVERNANCE_REVIEW_REQUIRED", ...}}` form instead. The gateway
never auto-retries either way.

### Releasing a reviewed action (verifiable approval token)

`gateway/governance/approvals.py` implements a minimal, server-signed,
short-TTL HMAC token **bound to a stable fingerprint** of the action
(`sha256(session_id + canonical_name + arguments)`), not the ephemeral
`event_id`, so it survives the resubmission.

1. A human approves the specific proposed action out of band.
2. A review system (here: `demo/mint-approval.py`) mints a token with the
   shared `GOVERNANCE_APPROVAL_SECRET`.
3. The client resubmits the **same** action with
   `metadata.dciso.approval_token = "<token>"`.
4. The enforcer calls `approvals.verify(...)`. On success the action is released
   and audited as `outcome=ALLOW` with `reason_codes += ["HUMAN_APPROVED:..."]`.
   On any failure (`no_token` / `expired` / `bad_signature` /
   `fingerprint_mismatch` / `no_server_secret`) it stays blocked (409).

An approval token only lifts **REQUIRE_REVIEW**. It can never rescue a hard
**DENY** (`test_token_does_not_rescue_a_hard_deny`). If `GOVERNANCE_APPROVAL_SECRET`
is unset, no token is ever accepted — the safe default.
