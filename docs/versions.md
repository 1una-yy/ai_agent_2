# Pinned versions & official-doc verification log

> Ticket §1/§13/§16: pin every image/package; re-check official docs before implementing.
> Update this file whenever a version is bumped, and include it in the §15 report.

## Test status (this machine, 2026-09-01)

| Suite | Command | Result |
|---|---|---|
| Rego unit | `opa test policy/` | 22 / 22 (incl. ACS information-flow lattice) |
| Python unit + integration | `pytest -q` | 71 / 71 |
| Shell scripts | `bash -n` | all OK |
| Compose / config / JSON | yaml + json load | all OK |
| **Live stack** `docker compose` (test mode) | `make up` | 5/5 containers healthy from a clean start |
| **Live e2e** | `tests/e2e/run-e2e.sh` | 20 / 20 |
| **Demos** | `make demo-safe / demo-deny / demo-delegate` | all PASS (ALLOW passthrough / DENY tool-call withheld / MODIFY autonomy downgraded) |

### Fixes made during live bring-up (2026-09-01)
- LiteLLM resolves `callbacks:` as a path relative to the **config file's directory** → config moved to `/app/config.yaml` (was `/app/gateway/config.yaml`, which made it look for `/app/gateway/gateway/...`).
- `GovernanceReject` now subclasses `fastapi.HTTPException` so LiteLLM propagates the structured error body.
- MODIFY on a spawn now rewrites the child's `autonomy` / `depth` args to the policy ceiling (not just the tool set).
- Audit `reason_codes` column now stores batch-level codes (matches the `outcome` column).
- OPA container healthcheck uses `/opa eval` (the image is distroless — no shell/wget).
- Gateway healthcheck `start_period=45s` (LiteLLM cold start).
- **Streaming is now governed** (buffered) — required because an unmodified
  `hermes chat` streams the main turn. mock-llm now also emits SSE so the
  offline stack exercises it (`make up` + e2e streaming checks).
- **`GATEWAY_DEFAULT_HARNESS=hermes`** — an unmodified Hermes does not send
  `metadata.harness_type`; the gateway assumes the one harness it fronts.
  An explicit wrong value still fails closed as UNKNOWN_HARNESS.

## Verification pass — 2026-09-01

| Component | Pinned | Source checked | Notes |
|---|---|---|---|
| LiteLLM proxy | `ghcr.io/berriai/litellm:v1.89.3@sha256:8f3517476b8293ccc1c3b0da7940d8dabbfe64b013454113f5a3cb68265c439b` | docs.litellm.ai, hub.docker.com, github releases | `main-stable` alias == v1.89.3 at check time. **Supply-chain advisory:** PyPI `litellm` 1.82.7 / 1.82.8 were compromised (2026-03-24, credential harvester); avoid that range. v1.89.3 is post-fix. **Digest pinned 2026-09-01.** |
| OPA | `openpolicyagent/opa:1.19.0@sha256:8523599954435a3659954ad51ee0304d22bd97576f16cdb02e5e39f38ff3962a` | github.com/open-policy-agent/opa releases | OPA 1.x => Rego v1 by default. Digest pinned. |
| Python (services) | `python:3.12-slim@sha256:e5c9fa26ffb76e11e0f054f30dc2523a2f9693f0c36c0cf1e39b27e152d899fc` | — | sidecars (ciso-advisor, mock-llm, viewer). Digest pinned. |
| httpx | pin in each `requirements.txt` | — | async client for OPA + CISO calls. |
| FastAPI / uvicorn | pin in each `requirements.txt` | — | viewer, mock-llm, ciso-advisor. |

## LiteLLM interception API (verified 2026-09-01)

Using **`CustomLogger` callbacks** (not guardrails), registered in `config.yaml`:

```yaml
litellm_settings:
  callbacks: governance_callback.governance_handler_instance   # instance, not class
```

| Hook | Role here |
|---|---|
| `async_pre_call_hook(user_api_key_dict, cache, data, call_type)` | Normalize request → request-phase GovernanceEvent; may reject by returning str / raising. |
| `async_post_call_success_hook(data, user_api_key_dict, response)` | Intercept `tool_calls`; run Soft+Hard policy; enforce (can rewrite/replace response). Non-streaming only. |
| `async_post_call_failure_hook(request_data, original_exception, user_api_key_dict, traceback_str)` | Return a typed HTTPException so the user always sees a reason (never blank / bare 500). |
| `async_post_call_streaming_iterator_hook(user_api_key_dict, response, request_data)` | **Implemented (buffered).** Buffers all chunks, assembles the full message (tool_calls accumulated by delta `index`), runs the SAME Soft/Hard pipeline, then replays the original chunks if ALLOW / emits a synthetic assistant stream carrying the繁中 reason if DENY·MODIFY·REVIEW. Not incremental — a governed stream is held until the turn completes. |

## OPA REST API (verified 2026-09-01)

- Query: `POST {OPA_URL}/v1/data/{OPA_DECISION_PATH}` with body `{"input": <GovernanceEvent+advice>}`.
- Success: `{"result": {"decision": ..., "reason_codes": [...], "obligations": {...}, "policy_version": ...}}`.
- Undefined rule ⇒ HTTP 200 **without** a `result` key ⇒ treated as `DENY` (fail closed).
- `?strict-builtin-errors=true` set on every query.

## Hermes Agent (verified 2026-09-01, docs only — re-verify on real install)

- Config dir default `~/.hermes`; override with `HERMES_HOME`.
- Secrets in `~/.hermes/.env`; behaviour in `~/.hermes/config.yaml`; CLI `hermes config set ...`.
- Custom OpenAI-compatible endpoint via env: `OPENAI_BASE_URL` ("custom endpoint (VLLM, SGLang, etc.)") + `OPENAI_API_KEY`.
- Sub-agent delegation ("spawn isolated subagents") exists.
- Security env: `HERMES_WRITE_SAFE_ROOT`, `HERMES_YOLO_MODE`, `HERMES_REDACT_SECRETS`.

### Real-Hermes integration — verified 2026-09-01 against **Hermes Agent v0.21.0**

- **`provider: custom` IS required.** Env `OPENAI_BASE_URL` alone is not enough —
  Hermes' model resolver falls back to OpenRouter and 401s. `enable-routing.sh`
  now sets `model.provider=custom`, `model.default=governed-model`,
  `model.base_url`, `model.api_key` (via `hermes config set`, or writes
  `config.yaml` directly if the `hermes` binary is absent). Confirmed:
  `hermes chat` → gateway → governed response.
- **Streaming**: Hermes streams the main turn. The buffered streaming hook must
  yield real `litellm.types.utils.ModelResponseStream` objects (not dicts) or
  Hermes rejects the governed turn as an API error and retries. Fixed.
- **Model name**: `gateway/config.yaml` now has a `model_name: "*"` wildcard so
  any model string Hermes sends (`governed-model`, `openai/governed-model`, …)
  is routed to the one governed upstream — a governance gateway must not be
  side-steppable by model name.
- **No-bypass proven**: with the `gateway` container stopped, `hermes chat`
  produces no completion (0 tool calls, no reply). `verify-routing.sh` now does
  this by actually stopping the container.
- **`delegate_task` (R1)** still unconfirmed on a build where the model emits it
  — the mapping is a config file (`HERMES_MAPPING_PATH`); capture the real
  `proposed_action.native_name` from the dashboard if a spawn shows as
  `UNKNOWN_TOOL`.
- **`hermes config set model.<key>`** is the sanctioned scripted path;
  `hermes config` (no args) prints the resolved config. `hermes setup` /
  `hermes model` are interactive.

### Hardening added 2026-09-01 (post-MVP)

- **All image digests pinned** (litellm / opa / python:3.12-slim → `@sha256:`).
- **Approval tokens are one-time-use** — a SQLite nonce ledger (`approval_nonce`
  in the audit DB) spends a token on first successful `verify`; replay →
  `already_used`. Ledger unavailable ⇒ still HMAC+TTL+fingerprint bound (note in
  the reason), never fail-open.
- **Replan tracker persists** to SQLite — the auto-replan cap survives a gateway
  restart; DB failure degrades to in-memory (UX only, not a security fail-open).
- **ACS information-flow lattice** in the Rego (AGT alignment Level 2) —
  `IFC_CLEARANCE_VIOLATION` on write-down.
- **Dashboard** gains a stats header (counts by outcome, sessions, avg latency,
  top reason codes, most-blocked actions) + `/api/stats`.
- **`dciso guided`** — a narrated 7-step live walk-through (ALLOW / DENY×2 /
  MODIFY / REVIEW / approval-token release + replay / OPA-down fail-closed).

### Real-Hermes-loop fixes (2026-09-02)
- **Streaming MODIFY** emitted the fail-closed error text (MODIFY has no
  `content`) → Hermes treated the turn as an error and retried 50× until its
  `loop_subagent_cap`. Now the streaming MODIFY branch emits only the rewritten
  tool call, no narration.
- **REQUIRE_REVIEW is delivered in-band by default** (assistant message, tool
  call stripped) instead of a 409 — a 409 on a tool call also makes Hermes
  retry-loop. Opt back into the 409 with `GOVERNANCE_REVIEW_AS_HTTP_ERROR=1`.
- **Missing session id**: an unmodified Hermes sends no `session_id`, so every
  turn collapsed to `"unknown-session"` and the persistent replan tracker hit
  its repeat-code STOP almost immediately. The tracker now treats
  unknown/empty session ids as "no cross-request memory" (attempt 1, never
  STOP); the harness' own loop guard is the backstop. Set
  `metadata.dciso.session_id` to re-enable cross-turn loop detection.
- **CISO explanation surfaced**: DENY/REVIEW messages now carry the advisor's
  `advice / risk_level / explanation` in the `dciso_governance` block (and, in
  LLM mode, a `資安長評估：…` line in the prose).
- **mock-llm** stops proposing tool calls once the last message is a tool
  result, and never re-proposes a spawn while one is in flight — so a real
  Hermes doesn't retry-loop in offline test mode.
- New: `dciso reset [--audit]` (clear replan counters / audit trail),
  `dciso unmapped` (find tool names to add to `HERMES_MAPPING_PATH`).

### Real model via a LOGIN — `GATEWAY_ROUTE_MODE=proxy` (2026-09-02)
- New route mode routes the gateway (and optionally the CISO) through
  **`hermes proxy`** — Hermes' local OpenAI-compatible server that attaches an
  OAuth credential (Nous Portal / xAI) upstream. No static API key anywhere; the
  Business Hermes still holds only the gateway token.
- `dciso login` / `dciso proxy start|stop|status|models` / `dciso up-proxy`
  (`--ciso-llm` to also make the CISO a real LLM; default `CISO_MODE=rule`).
- compose: `extra_hosts: host.docker.internal:host-gateway` on gateway +
  ciso-advisor so the containers reach the host-bound proxy; `hermes proxy`
  bound `0.0.0.0:8645` by `dciso`.
- Model id is **double-prefixed**: `openai/<proxy-id>` (LiteLLM strips the first
  `openai/`; the proxy id keeps its own provider prefix, e.g.
  `openai/upstage/solar-pro4:free`).
- **Verified 2026-09-02** against a live Nous Portal login: real Hermes → gateway
  → proxy → real model, ALLOW returns a real answer, a shell tool call is
  DENied, dashboard records it. (Free `:free` model ids work on a zero-balance
  account; paid ids need Portal credits. The OAuth bearer is short-lived —
  re-run `dciso login` if `dciso proxy status` isn't "ready".)
### Phase E — model vs governance time, measured separately (2026-09-07)
- "governance < 300ms" was an unqualified guess. Each decision now records a
  time split in `EnforcementResult.timings` (and a `timings` audit column,
  added by an additive migration): `model_ms` (upstream model, pre_call→
  post_call), `governance_ms` (the pipeline incl. enforce), `ciso_ms`, `opa_ms`.
- `DecisionOrchestrator.evaluate` splits its own wall time into `ciso_ms` /
  `opa_ms`; the callback measures `governance_ms` and derives `model_ms` from a
  `t_precall_done` marker set at the end of `async_pre_call_hook`.
- **Dashboard** stat cards: `model ms`, `gov ms · fast`, `gov ms · escalated`
  (governance avg split by whether the CISO was consulted).
- **Measured 2026-09-07** live (CISO-as-Hermes, `gemma4:31b`):
  - fast path (plain answer, no CISO/OPA): `governance_ms ≈ 40`.
  - escalated (tool call, CISO consulted): `governance_ms ≈ 35 000`, of which
    `ciso_ms ≈ 35 150` — the CISO **model call** is the entire cost; `opa_ms`
    stayed ~17ms. Switching the CISO to `--ciso rule` collapses that back to
    low tens of ms.
- 125 pytest (2 orchestrator + 1 callback) / 48 opa green.
- **Phases A–E complete.** The three boundaries (tool exec / tool result→model
  / model answer→recipient) all governed, each with a fast path; CISO/OPA split
  and timing are now visible and honest.

### Phase D — honest outcome semantics + phase-aware dashboard (2026-09-07)
- The dashboard could show `REQUIRE_REVIEW` while the action had actually been
  delivered (in-band message) — a soft flag reading like a real pause. And a
  CISO "review" flag on an OPA "ALLOW" was silently dropped.
- `EnforcementResult` gains honest fields, persisted in `enforcement_json`:
  - `hold`: `NONE` | `REVIEW_HOLD` (action **stopped**, awaiting approval) |
    `ADVISORY` (soft-flagged but **proceeded**).
  - `advisory`: the CISO's non-binding note (`advice`, `risk_score`,
    `reason_codes`, `binding:false`) when it did **not** change the outcome —
    triggered by a non-ALLOW advice or `risk_score >= CISO_ADVISORY_SCORE_MIN`
    (default 50).
  - `escalated` / `escalate_reason`: was the expensive CISO consulted, and why
    (`forbidden_hit` / `sensitive_task` / `external_recipient` / …) or
    `fastpath_no_escalation`.
  - `redacted`: did the gateway redact/truncate content on this decision.
- CISO ↔ OPA split is now visible: OPA's `reason_codes` are binding; the CISO's
  read is `advisory` unless it forced a DENY/CRITICAL.
- Phase A/B events now carry the request's `litellm_call_id` as
  `correlation_id`, so the dashboard can group one round's phases.
- **Dashboard**: phase column is `①提議 / ②執行前 / ③結果→模型 / ④回答→使用者`;
  new "semantics" column shows `⏸ 已擋下·待核准` / `⚑ 資安長示警·已放行 (score)` /
  `✂ 已遮蔽/截斷` / `⚡ 快速路徑`.
- Not in D: a multi-approver queue/UI — the existing HMAC approval-token flow
  (one-time nonce, fingerprint-bound) still provides "resume after approval".
- **Verified 2026-09-07** live: read-only `ls` shell call → `ALLOW` /
  `hold: ADVISORY` / `advisory: REQUIRE_REVIEW (75)`; `send_email` proposal →
  `REQUIRE_REVIEW` / `hold: REVIEW_HOLD`.
- 122 pytest (4 enforcer) / 48 opa green.

### Phase C — execution-side path & authorization policy (2026-09-07)
- The shell command-level policy already ran at Layer 2 (the PEP shares OPA).
  Phase C adds **target-path checks** that apply at BOTH the model-proposal
  (`model_response_pre_execution`) and execution (`tool_execution_pre_dispatch`)
  phases — the Hermes hook keeps `event_type == tool.execute.proposed`.
- `policy/data.json` `path_policy`: candidate paths are pulled from explicit
  file-arg keys AND from path-shaped tokens in a shell command.
  - `denied_markers` (`.ssh`, `id_rsa`, `.aws/credentials`, `/etc/shadow`,
    `.env`, `.git/config`, `.npmrc`, `.kube/config`, `known_hosts`, …) → DENY
    `PATH_DENIED:<marker>` for any file/shell tool.
  - an interpreter first token (`python`/`bash`/`node`/`./…`) + a path token
    under `/tmp/`, `/var/tmp/`, `…/downloads/` → DENY `EXECUTE_FROM_UNTRUSTED_DIR`
    (the "ran a downloaded program" case).
  - `write_tools` (or a destructive shell binary) with a target outside
    `workspace_roots` (when that list is set) → REQUIRE_REVIEW
    `PATH_OUTSIDE_WORKSPACE` (the authorization-scope check).
- `enforcer._PUBLIC_CODE` + `_USER_MESSAGE` gain `PROTECTED_PATH_DENIED`,
  `EGRESS_CONTENT_BLOCKED`, `OUTPUT_CONTENT_BLOCKED`; `pep._BLOCK_MSG` gains the
  path message.
- **Verified 2026-09-07** live at the PEP (`POST /govern`):
  `read_file /home/…/.ssh/id_rsa` → `block` `PATH_DENIED:.ssh`,`PATH_DENIED:id_rsa`;
  `terminal python /tmp/payload.py` → `block` `EXECUTE_FROM_UNTRUSTED_DIR`;
  `terminal ls -la ~/Desktop` → `{}` (allow). All rows
  `enforcement_phase = tool_execution_pre_dispatch`.
- 118 pytest (+2 real-opa) / 48 opa (+7 path-policy) green.

### Phase B — egress governance: tool result → model endpoint (2026-09-07)
- The tool result → model hop was ungoverned: "local read" implicitly meant
  "may ship anywhere". Now a tool result is checked **at the send edge**, in
  `async_pre_call_hook` — the `role:tool` / `role:function` messages of the
  outgoing request.
- **Destination class** — `local` / `approved` / `external`, from
  `GATEWAY_ROUTE_MODE` via `egress_policy.route_mode_dest_class` (ollama→local,
  proxy→approved, demo→external), overridable with `DCISO_EGRESS_DEST_CLASS`,
  plus `approved_model_markers` matched against `data["model"]`.
- **Per-class rules** (`policy/data.json` `egress_policy.class_rules`):
  `max_result_kb`, `redact_credentials`, `block_forbidden`,
  `block_if_sensitive_task`, `block_sensitive_fields`. `local` is lenient
  (redact creds, keep the rest on-prem); `external` is strict (block on
  forbidden marker / sensitive task / sensitive field name, tight size cap).
- `output_scan.scan_payload()` reuses the credential regexes + adds
  sensitive-field markers + a byte-size check; `truncate_bytes()` for oversize.
  New rego block (`tool_result_pre_send`): DENY `EGRESS_FORBIDDEN_MARKER` /
  `EGRESS_SENSITIVE_TASK_TO_ENDPOINT` / `EGRESS_SENSITIVE_FIELD`; MODIFY
  `EGRESS_REDACT_CREDENTIAL` / `EGRESS_TRUNCATE_OVERSIZE`.
- **On DENY the tool result is replaced with a withheld notice** so the model
  reports the limitation instead of hallucinating over missing data.
- **Fast path**: `local` dest + clean scan + not oversize → forwarded
  untouched, one cheap `EGRESS_FASTPATH_ALLOW` audit row, no OPA/CISO.
  CISO consulted only on escalation (forbidden / sensitive-field hit,
  sensitive task, external dest).
- Knobs: `DCISO_EGRESS_GATE`, `DCISO_EGRESS_DEST_CLASS`; compose wires both
  plus the Phase-A `DCISO_OUTPUT_*` into the gateway env.
- **Verified 2026-09-07** live (real gateway + Ollama):
  - local dest, tool result with an AWS key → `tool.result.proposed / MODIFY /
    EGRESS_REDACT_CREDENTIAL`; the model answer referred to "a redacted AWS
    access key" — the key never reached Ollama.
  - external dest, tool result headed `INTERNAL ONLY` → `tool.result.proposed
    / DENY / EGRESS_FORBIDDEN_MARKER`; the model replied that it could not read
    the file rather than summarising the withheld roadmap.
- 116 pytest (3 scan + 3 callback) / 41 opa (7 egress-phase) green.

### Phase A — output-side governance with a fast path (2026-09-07)
- Model answers with **no tool call** were completely ungoverned (straight
  `NO_PROPOSED_ACTION` passthrough). Now they go through an output gate.
- `gateway/governance/output_scan.py`: cheap deterministic scan — regexes for
  common credential formats (AWS/GitHub/Slack/Google/OpenAI keys, private-key
  blocks, JWTs, bearer tokens, `secret=…` assignments) + caller-supplied
  forbidden-disclosure markers. Emits **counts + types + sha256 + length**,
  never the raw text.
- New `EnforcementPhase.MODEL_OUTPUT_PRE_DELIVERY` / `EventType.MODEL_OUTPUT_PROPOSED`.
  New rego block (guarded by the phase): forbidden marker → DENY
  `FORBIDDEN_DISCLOSURE`; sensitive/internal class + `recipient_class==external`
  → DENY `OUTPUT_RECIPIENT_NOT_CLEARED`; credential hit → MODIFY
  `REDACT_OUTPUT_CREDENTIAL` (the gateway swaps in `output_scan.redact()`).
- **Fast path**: clean scan + non-sensitive task + non-external recipient →
  ALLOW with a cheap audit row (`OUTPUT_FASTPATH_ALLOW`), **OPA and the CISO are
  not called**. `DecisionOrchestrator.evaluate(event, consult_ciso=False)` skips
  the CISO entirely; it's only consulted on an escalation condition (forbidden
  hit, sensitive task, external recipient).
- `policy/data.json` `output_policy` block; `OPAClient.get_data()` lets the
  gateway read it (built-in default on failure). Knobs: `DCISO_OUTPUT_GATE`,
  `DCISO_OUTPUT_MAX_SCAN`.
- Scope: non-streaming path. Streaming output-gate + real recipient model +
  `confirm` verdict come in later phases (C/D).
- **Verified 2026-09-07** live (real gateway + Ollama): a clean answer →
  `OUTPUT_FASTPATH_ALLOW`, no OPA/CISO hit; an answer echoing
  `AWS_ACCESS_KEY_ID=AKIA…EXAMPLE` → delivered as
  `AWS_ACCESS_KEY_ID=[已遮蔽:aws_access_key_id]`, audit
  `model.output.proposed / MODIFY / REDACT_OUTPUT_CREDENTIAL`.
- 110 pytest (5 scan + 3 callback) / 34 opa (5 output-phase) green.

### CISO-as-Hermes is now the DEFAULT on the real-model path (2026-09-07)
- `dciso up-ollama <model>` runs the CISO as a tool-less Hermes with no flag.
  The var `CISO_MODE` no longer influences `up-ollama` — opt out explicitly:
  `--ciso rule` (instant, containerised — CI / slow box / no Ollama) or
  `--ciso llm` (one direct model call, `CISO_LLM_*`).
- Unchanged: `dciso up` (offline test / `guided`) and compose still default to
  `rule` (no model is available there). `.env` `CISO_MODE` governs those.
- Trade-off is explicit in the startup banner: ~20–45s/verdict, rule engine
  auto-fallback on timeout. Everything downstream (OPA authority, shell policy,
  generic adapter, audit, plug/unplug) is identical regardless of CISO mode.

### Govern ANY OpenAI-compatible agent — generic adapter, no hooks (2026-09-07)
- Layer 1 was Hermes-only in practice: `select_adapter` returned `None` for any
  other `harness_type` → blanket `UNKNOWN_HARNESS` DENY.
- New `gateway/governance/adapters/generic.py` `GenericOpenAIAdapter`: holds all
  the (already generic) normalization + ALLOW/MODIFY enforcement, keyed off the
  standard `choices[].message.tool_calls[].function` shape every OpenAI-compatible
  client emits. Registered LAST as a **catch-all**, so any agent pointed at the
  gateway `base_url` is governed with no source patch and **no `pre_tool_call`
  hook** — Claude Code, Cursor, Aider, LangChain/LangGraph, AutoGen, CrewAI, a
  raw OpenAI SDK script, …
- `hermes.py` is now a thin `HermesAdapter(GenericOpenAIAdapter)`: explicit
  `harness_type == "hermes"` selection, NARROW `delegate_task→agent.spawn`
  mapping (unchanged), keeps `normalize_tool_execution` for the optional Layer 2.
- Generic sub-agent detection: a tool call named like a delegation primitive
  (`delegate_task`, `spawn_agent`, `create_subagent`, `Task`, `handoff`,
  `transfer_to_agent`, …) → canonical `agent.spawn`. Extend with
  `DCISO_DELEGATION_TOOLS` / `DCISO_MAPPING_PATH`.
- `policy/data.json` `known_harness_types` broadened (`openai-compatible`,
  `langchain`, `claude-code`, `cursor`, `aider`, `crewai`, …); an unrecognised
  value is normalised to `openai-compatible` so it still classifies.
- `GATEWAY_DEFAULT_HARNESS` now honours an explicit empty value (`${VAR-hermes}`
  not `${VAR:-hermes}`); `dciso up-ollama … --agent generic` sets it empty and
  prints `agent scope : any OpenAI-compatible client`. `DCISO_GENERIC_ADAPTER=0`
  restores strict Hermes-only.
- Docs: `docs/govern-any-agent.md` (plug table per client, unplug = revert
  base_url, Layer-1-only caveat).
- **Verified 2026-09-07** live: request with `metadata.harness_type=cursor` →
  audit row `harness_type: cursor`; request with no metadata + `list_files`
  proposal → `openai-compatible` / ALLOW; no-metadata `credential_access`
  proposal → DENY `DANGEROUS_TOOL_DENIED`. 101 pytest (17 new generic-adapter
  tests) / 29 opa green.

### CISO advisor can now BE a Hermes (`CISO_MODE=hermes`) (2026-09-07)
- The Soft-policy advisor was a ~200-line rule/LLM service. New third mode:
  the advisor **is a separate, tool-less Hermes instance**.
  - Own home `~/.hermes-ciso` (`ciso-hermes/setup.sh`), own persona
    (`SOUL.md`), **own model straight to Ollama — never through the gateway**
    (that would recurse). Invoked with `hermes -z … --ignore-user-config
    --ignore-rules -t ""` so it has no toolsets.
  - `ciso-advisor/app.py`: `_hermes_engine` spawns the one-shot, `_extract_json`
    tolerates prose around the JSON, `_sanitize` (shared with `_llm_engine`)
    clamps the reply to the fixed `SoftAdvice` schema — the Hermes output is
    still untrusted, still can't authorise anything, OPA still decides.
  - **Fast fallback**: `CISO_HERMES_FALLBACK=rule` (default) → on
    timeout/error/bad-output the rule engine answers instead, tagged
    `CISO_HERMES_FALLBACK_RULE` + the failure code. `=deny` → fail closed.
- Runs as a **host sidecar** (not in Docker — it needs the host `hermes`):
  `dciso up-ollama <model> --ciso hermes` scaffolds `~/.hermes-ciso` if
  missing, starts the advisor on `0.0.0.0:9009` (so the containers can reach
  it via `host.docker.internal` — same reason `hermes proxy` binds 0.0.0.0;
  `HOST_CISO_BIND=127.0.0.1` to keep it host-only), stops the containerised
  advisor, and brings the stack up with `docker-compose.ciso-hermes.yml`
  (disables the containerised advisor, repoints gateway+pep at
  `host.docker.internal:9009`, forces their gateway→advisor HTTP timeout to
  90s — a `hermes -z` on a 30B model runs ~18–45s, well past the default 4s).
  `dciso down` stops the sidecar.
- `dciso ciso-hermes setup|test|status|remove`. `dciso status` shows the mode.
- **Latency**: a `hermes -z` one-shot against a 30B+ model is ~30–60s
  (fixed bootstrap + model load dominate). Default `CISO_HERMES_TIMEOUT=60`.
  Expect the rule fallback to carry many calls; when the Hermes does answer,
  the dashboard shows its verdict as the soft advice. Warm `hermes serve` or a
  rule pre-filter for the murky middle are possible later optimisations.
- **Verified 2026-09-07** end to end (real gateway + Ollama `gpt-oss:120b`
  business model + CISO Hermes on `gemma4:31b`):
  - `rm -rf ~/Desktop/hello` proposal → DENY `DANGEROUS_SHELL_COMMAND:rm`,
    audit `soft_availability: OK`, CISO Hermes answered in ~18s.
  - `ls ~/Desktop/hello` proposal → ALLOW `POLICY_ALLOW`, tool call passes
    through; the CISO Hermes flagged it `REQUIRE_REVIEW` but the Hard PDP
    read the command, saw it read-only, and allowed it (soft can't loosen,
    and doesn't over-tighten here because the rego ignores soft REVIEW).
  - 5 new pytest cases (missing-binary→rule fallback, no-fallback→fail-closed,
    health, JSON extraction, sanitiser clamps). 84 pytest / 29 opa green.

### Shell command-level policy — stop over-blocking read-only commands (2026-09-07)
- Problem: with real Hermes + Ollama, `gpt-oss:120b` proposes the `terminal`
  tool for *everything* (list / read / delete alike), so the old
  "`terminal` is in the `deny` class" rule made **every** request DENY —
  "唯讀資料夾hello" was blocked the same as "刪資料夾hello".
- Fix: `terminal`/`shell`/`bash`/… now get judged on the **command**, not the
  tool name. New `dciso.shell` block in `policy/data.json`
  (`readonly_binaries`, `destructive_binaries`, `destructive_patterns`,
  `metachars`, `arg_keys`) + shell helpers in `agent_governance.rego`
  (`is_shell_tool`, `shell_cmd`, `shell_first_token`, `shell_has_metachar`,
  `shell_has_blocked`, `shell_readonly`).
- Semantics:
  - single read-only binary (`ls`, `cat`, `find`, `grep`, `stat`, `wc`, …),
    no metacharacters, no blocked substring → **ALLOW**.
  - destructive first token (`rm`, `mv`, `chmod`, `dd`, `curl`, `sudo`, …) or a
    destructive pattern (`rm -rf`, `git push`, `pip install`, fork-bomb, …) →
    **DENY** `DANGEROUS_SHELL_COMMAND:<token>`.
  - anything else — unknown binary, a read-only binary with `;`/`|`/`&&`/
    redirects, or no command at all → **REQUIRE_REVIEW**
    `SHELL_COMMAND_NEEDS_REVIEW` (bare `terminal` with empty args → DENY).
- Non-shell `deny`-class tools (`credential_access`, `db_write`, `ssh`, …) are
  unaffected — still DENY.
- `enforcer._PUBLIC_CODE`: `DANGEROUS_SHELL_COMMAND` → user-facing
  `DANGEROUS_TOOL_DENIED`, `SHELL_COMMAND_NEEDS_REVIEW` → `HUMAN_REVIEW_REQUIRED`.
- The CISO advisor is unchanged: it never sees the command string (the
  orchestrator strips `arguments` values before calling it), so it still flags
  *every* shell tool as `REQUIRE_REVIEW` (score 60). That is fine — the rego
  only tightens on a CISO **DENY/CRITICAL**, never on REVIEW/MODIFY, so the
  Hard PDP's command-level ALLOW stands. Demo narrative: "advisor flagged the
  shell call, Hard Policy read the actual command (`ls`), confirmed read-only,
  allowed it."
- **Verified 2026-09-07** through the real adapter + real OPA
  (`tests/integration/test_real_opa.py`):
  `terminal` + `rm -rf /data` → DENY, `terminal` + `ls -la /tmp` → ALLOW,
  bare `terminal` → DENY, and `ls -la` still ALLOW even when the CISO stub
  returns `REQUIRE_REVIEW` (`test_real_soft_review_does_not_overblock_readonly_shell`).
- 79 pytest / 29 opa (7 new shell rego tests + 1 integration test) green.

### End-user DENY message trimmed (2026-09-07)
- The DENY / REVIEW message shown in the chat is now **one short sentence**
  (what can't be done + what to try next). The `dciso_governance` JSON block and
  the `資安長評估: rule-engine score=…` line are gone from `content` — that
  detail is in the audit / dashboard. `DCISO_VERBOSE_DENY=1` restores the block.
- Templates rewritten shorter (`enforcer._USER_MESSAGE`, `pep._BLOCK_MSG`).
- e2e / guided now verify DENY via the audit reason codes, not chat scraping.
- 78 pytest / 22 opa / 19 e2e green.

### Layer 2 — execution-side PEP (2026-09-07)
- New `pep/` service (`POST /govern`, port 127.0.0.1:8710) reuses the governance
  core; new `EnforcementPhase.TOOL_EXECUTION_PRE_DISPATCH`.
- `hermes-hook/dciso-precall-hook.sh` is a Hermes **`pre_tool_call` shell hook**
  (declared in `~/.hermes/config.yaml` `hooks:` — config, not a source patch),
  `fail_closed: true`. It calls the PEP before Hermes dispatches any tool and
  returns `{}` (allow) / `{"action":"block",…}` / `{"action":"modify","args":…}`.
- `dciso plug --exec-pep` installs the hook + `hooks_auto_accept: true`;
  `unplug` restores config.yaml and removes the hook script.
- Dashboard gains a **layer** column (`L1·model` / `L2·exec`).
- **Verified 2026-09-07**: real Hermes + Ollama — an allowed `read_file` records
  both an L1 (`model_response_pre_execution`) and an L2
  (`tool_execution_pre_dispatch`) audit row; `terminal` is stopped at L1 before
  execution; PEP failure / audit-write failure → the hook blocks (fail-closed).
- 77 pytest (6 new PEP tests) / 22 opa still green.

### Route mode `ollama` — LAN / local Ollama server (2026-09-02)
- `GATEWAY_ROUTE_MODE=ollama` + `OLLAMA_BASE_URL` / `OLLAMA_MODEL`.
  `dciso up-ollama [model]`, `dciso ollama-models`.
- entrypoint uses LiteLLM's `ollama_chat/<model>` provider (Ollama `/api/chat`,
  translates tool calls); `api_base` has no `/v1`. LAN IP is reachable from the
  gateway container directly (no `extra_hosts`).
- **Verified 2026-09-02** against `192.168.47.77:11434`, model `gpt-oss:120b`:
  real Hermes → gateway → Ollama, plain chat returns a real answer, a
  `terminal` tool call is DENied, dashboard records it. Best "real model" path
  for this user (strong local model, no API cost, no login expiry, private).
  Pick a model with the `tools` capability (`gpt-oss:120b`, `qwen3.5:122b`,
  `nemotron-3-super:120b`, `gemma4:31b`).

- `policy/data.json` tool lists broadened to real-world names (`run_shell`,
  `bash`, `write_file`, `query_database`, `get_secret`, `upload`, `ssh`, …) so a
  real model's tool call classifies instead of falling to `UNKNOWN_TOOL`. OPA
  now runs with `--watch` (hot-reload on policy edits). 22/22 rego tests hold.

### Still open

- [ ] install.sh SHA-256 + reviewed commit/tag (whoever installs Hermes records it).
- [ ] `delegate_task` real native name (R1) on a build that emits spawns (`dciso unmapped` helps).
- [ ] Network-egress lockdown at the infra layer; TLS on the gateway; secrets out of `.env`.
- [ ] Incremental (non-buffered) streaming enforcement.
