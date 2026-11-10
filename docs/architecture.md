# Architecture

## Position

```
User
  │
  ▼
AI agent  (UNMODIFIED — Hermes, Claude Code, Cursor, Aider, LangChain,
  │        AutoGen, CrewAI, a raw OpenAI SDK script, …)
  │  OpenAI-compatible POST /v1/chat/completions   (stream=false, MVP)
  │  Authorization: Bearer <GATEWAY_MASTER_KEY>     ← only token the agent holds
  │  (generic adapter governs any client; HermesAdapter adds the delegate_task
  │   mapping + optional Layer 2 hook when harness_type == "hermes")
  ▼
LiteLLM Governance Gateway  ─ gateway/config.yaml + gateway/callbacks/governance_callback.py
  ├─ async_pre_call_hook          establish governance context
  ├─ async_post_call_success_hook THE enforcement point (below)
  └─ async_post_call_failure_hook always surface a readable reason
        │
        ├─ Hermes Adapter (deterministic)      gateway/governance/adapters/hermes.py
        │     delegate_task → agent.spawn ; other tools → tool.execute.proposed
        ├─ Governance Event Normalizer         gateway/governance/normalizer.py + schemas.py
        ├─ Decision Orchestrator               gateway/governance/decision_orchestrator.py
        │     ├─► CISO Advisor  (SOFT)         ciso-advisor/  →  SoftAdvice
        │     │      CISO_MODE = rule | llm | hermes
        │     │      hermes = a separate TOOL-LESS Hermes (~/.hermes-ciso), its
        │     │      own model straight to Ollama (never back through this
        │     │      gateway). Output clamped to SoftAdvice; rule engine is the
        │     │      fast fallback. Runs as a host sidecar on :9009.
        │     └─► OPA / Rego    (HARD, final)  policy/        →  Decision
        ├─ Decision Enforcer                   gateway/governance/enforcer.py
        └─ Audit / Evidence Writer             gateway/governance/audit.py  → SQLite
  │
  ▼
LiteLLM provider router  ──►  OpenAI (demo)  |  mock-llm (test)

Governance Dashboard (read-only)  viewer/  ──reads──►  the same SQLite audit store
```

## Decision precedence (ticket §3)

```
un-parseable / governance service error   → DENY_CURRENT_ACTION   (never fail open)
Hard Policy DENY                          → DENY
Hard Policy REQUIRE_REVIEW                → 409 GOVERNANCE_REVIEW_REQUIRED
Hard Policy MODIFY                        → apply obligations, then continue
Hard Policy ALLOW                         → ALLOW
Soft advice                               → risk_context only; can tighten, never widen
```

`fail closed` = the dangerous **action** does not cross the gate. The Hermes
process, session and conversation keep running; the user gets a readable reason
and can replan.

## Two enforcement layers

| | where | governs | how |
|---|---|---|---|
| **Layer 1 — model-side** (always on) | LiteLLM `CustomLogger` callback | what the model *proposes* — tool calls / sub-agent spawns in the chat completion (streaming + non-streaming) | rewrite / replace the response before Hermes sees it |
| **Layer 2 — execution-side** (opt-in, `dciso plug --exec-pep`) | Hermes `pre_tool_call` shell hook → `pep/` service | what Hermes is *about to actually run* — every tool dispatch, incl. calls issued by skills/plugins | `{}` allow / `block` / `modify args`, `fail_closed: true` |

Both layers use the same `GovernanceEvent` schema, the same CISO + OPA pipeline,
and the same audit store (`enforcement_phase` distinguishes them —
`model_response_pre_execution` vs `tool_execution_pre_dispatch`). Layer 2 is a
config-level Hermes hook, **not** a source modification.

## Governance boundaries (target model)

Each hop in a turn has its own purpose and its own cost profile — same gateway,
same policy store, different check strength.

| boundary | `enforcement_phase` | purpose | cost | status |
|---|---|---|---|---|
| tool execution (pre-dispatch) | `tool_execution_pre_dispatch` | control what the system can *do* — command / args / path / authorization | enforcing | Layer 2 (opt-in); command-level + path policy done (Phase C) |
| tool result → model | `tool_result_pre_send` | control whether *this data* may go to *this endpoint* (local / approved / external) | fast rules, escalate on hit | **Phase B — done** |
| model answer → recipient | `model_output_pre_delivery` | is this answer OK for *this recipient*? forbidden disclosure, credential leak, internal→external | fast path; CISO only on escalation | **Phase A — done** |

Phases A & B: a deterministic scan (credential regexes + forbidden / sensitive
markers + size) produces counts/types (never raw text) for OPA. The output
boundary runs in `async_post_call_success_hook`; the egress boundary runs in
`async_pre_call_hook` over the outgoing `role:tool` messages. A clean, low-risk
case takes the fast path and never touches the CISO. On a hard block the tool
result is swapped for a withheld notice so the model reports the gap rather
than inventing an answer.

## Still not governed

- The real side effects *inside* a tool once it has started (Layer 2 gates the
  dispatch, not mid-execution), cron / memory writes not routed through a tool
  call, MCP server internals.
- Streaming is governed but **buffered** (held until the turn completes), not
  incremental.

## Pluggability (ticket §14)

`HarnessAdapter`, `PolicyAdvisor`, `HardPolicyDecisionPoint` are Protocols in
`gateway/governance/adapters/base.py`. A new harness = a new adapter + mapping
tests; the Hard Policy API, advisor API and audit schema are unchanged.

## Trust boundaries

| Component | Trusted for | NOT trusted for |
|---|---|---|
| Hermes + its model | producing proposals | any authorization decision |
| CISO Advisor (+ its prompt/memory/tools) | risk narrative / suggested obligations | final allow/deny; its JSON is validated, a parse failure ≠ ALLOW |
| OPA / Rego bundle | the final, reproducible decision | reading free-form LLM text; it only consumes validated fields |
| Audit store | evidence of what happened | — (write failure ⇒ sensitive action fails closed) |
