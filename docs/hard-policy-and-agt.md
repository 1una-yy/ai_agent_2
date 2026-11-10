# Hard policy & Microsoft's Agent Governance Toolkit (AGT / ACS)

<https://github.com/microsoft/agent-governance-toolkit> — MIT licensed. Its core
is the **Agent Control Specification (ACS)**: a stateless, deterministic,
fail-closed policy runtime that intercepts agent actions *before* execution.

**Our OPA/Rego hard PDP maps onto ACS almost 1:1** — same philosophy (deny by
default, fail closed, no reliance on prompt safety), and ACS treats **Rego as a
first-class policy type**. You can adopt AGT at three levels; we ship level 1
now and give you the path to 2 and 3.

---

## Concept crosswalk

| This project | ACS / AGT | Notes |
|---|---|---|
| `GovernanceEvent` (ticket §6) | the `snapshot` for an intervention point | our event becomes `input.snapshot`; `policy_target` selects `proposed_action` |
| `EnforcementPhase.model_response_pre_execution` | `pre_tool_call` intervention point (also `pre_subagent_spawn`) | ACS defines 8 points; we govern the pre-execution one |
| CISO advisor → `governance.soft_advice` | an **annotator** output under `annotations.<name>` | ACS annotators are exactly "LLM/classifier risk assessment before the policy"; ours is `annotations.ciso` |
| OPA/Rego decision (final) | a `rego` **policy** bound to the intervention point | `agent_governance.rego` is bindable as-is |
| **Verdicts** | | |
| `ALLOW` | `allow` | |
| `DENY` | `deny` | |
| `MODIFY` (+ `obligations.argument_overrides`) | `transform` (replaces `policy_target`) | ACS `transform` returns a rewritten target; our MODIFY rewrites tool-call args |
| `REQUIRE_REVIEW` (409 + approval token) | `escalate` | ACS `escalate` → host obligation to get human approval; our approval-token flow matches |
| (fold into ALLOW + obligations) | `warn` | we don't emit a distinct warn; obligations carry the caution |
| `Decision.fail_closed(...)` on any error | `deny` with a reserved `runtime_error:*` reason | identical: "any error during evaluation MUST yield a `deny` verdict" |
| append-only SQLite audit | ACS tamper-evident audit / Merkle commitment | ours is append-only-in-code; Merkle chaining is a follow-on |

### Reason-code alignment

Our fail-closed codes now carry an ACS-equivalent (see `policy/data.json` →
`acs_crosswalk`), so an ACS host can normalise them:

| ours | ACS reserved reason |
|---|---|
| `UNKNOWN_TOOL` | `runtime_error:tool_unknown` |
| `HARD_PDP_UNREACHABLE` / `HARD_PDP_*` | `runtime_error:policy_invocation_failed` |
| `HARD_PDP_UNDEFINED_DECISION` / `HARD_PDP_NO_DECISION_FIELD` | `runtime_error:policy_output_invalid` |
| `SOFT_ADVICE_UNAVAILABLE_*` | `runtime_error:annotation_timeout` / `runtime_error:annotation_failed` |
| `SCHEMA_VERSION_UNSUPPORTED` | `runtime_error:manifest_invalid` |
| `APPROVAL_TOKEN:fingerprint_mismatch` | `runtime_error:approval_action_mismatch` |
| streaming that can't be assembled | `runtime_error:streaming_unsupported` |

Our domain codes (`EXTERNAL_SENSITIVE_TRANSFER_DENIED`,
`DANGEROUS_TOOL_DENIED:*`, `AUTONOMY_DOWNGRADED_TO_CEILING`, …) stay as-is —
they are policy `reason` values, not runtime errors.

---

## Level 1 — vocabulary & reason alignment (shipped)

- Verdict crosswalk above; `EnforcementResult.outcome` already uses the four
  names that map cleanly to `allow` / `deny` / `transform` / `escalate`.
- `policy/data.json` gains `acs_crosswalk` (fail-closed → ACS reserved reason)
  and `owasp_agentic_top10` (rule → OWASP category). Pure data — decisions
  unchanged, `opa test` still 18/18.
- Nothing else changes. Your PDP is already "AGT-shaped".

## Level 2 — ACS information-flow control for the sensitive-data rule (shipped)

ACS uses the lattice `public < internal < confidential < secret` and a
"no write down" rule: *deny a flow unless the sink clearance dominates every
source label.*

`agent_governance.rego` now implements this directly (`policy/data.json` →
`ifc`):

- `data_class_clearance`: `internal`→1, `PII`/`PHI`→2 (confidential), `SECRET`→3.
- sink clearance: approved internal destination → 2; `null` destination (no
  egress) → 3; external/unknown → 1.
- `deny_reasons contains "IFC_CLEARANCE_VIOLATION" if ifc_source_level > ifc_sink_level`.

So `PHI → external` and `SECRET → approved-internal` are both denied by the
lattice; plain `internal → external` is not. The original
`EXTERNAL_SENSITIVE_TRANSFER_DENIED` rule is kept alongside — either fires the
same DENY. Tune `external_destination_clearance` to `0` in `data.json` to also
block plain-internal egress. Tests: `test_ifc_*` in
`policy/tests/agent_governance_test.rego`.

## Level 3 — bind our PDP as an ACS `rego` policy (full interop)

Ship an ACS **manifest** that makes this gateway a drop-in ACS host: our
`agent_governance.rego` is the bound policy, the CISO advisor is an `llm`
annotator, and the intervention points are `pre_tool_call` and
`pre_subagent_spawn`. See [`acs-manifest.example.yaml`](./acs-manifest.example.yaml).

With that manifest, any ACS runtime (the AGT Rust `policy-engine`, or an SDK
`AgentControl` in Python/TS/.NET/Go) can run our hard policy unchanged, and the
992-test ACS conformance suite becomes applicable. The gateway's
`OPAClient`/orchestrator would be replaced by (or wrapped around) an ACS
dispatcher — the `HardPolicyDecisionPoint` Protocol (ticket §14) already makes
that a swap, not a rewrite.

---

## What NOT to claim

We are **aligned with** ACS, not **ACS-conformant**. Full conformance means
passing AGT's RFC-2119 spec + 992 conformance tests, adopting the exact policy
input shape, and the tamper-evident audit commitment. Those are Level 3+ work,
tracked as next-phase.
