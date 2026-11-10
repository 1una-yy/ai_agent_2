# DCISO Governance Gateway (MVP · DCISO-GW-MVP-001)

A **pluggable, external governance layer** for AI agent harnesses. It sits
between an agent (phase 1: **Hermes**) and the real LLM provider as an
OpenAI-compatible proxy, and governs the model's **proposed** tool calls and
sub-agent spawns **without modifying the agent**.

- **Soft policy** — an independent *AI CISO advisor* produces risk advice.
- **Hard policy** — an independent **OPA/Rego** PDP makes the final,
  reproducible, default-deny decision. Soft advice can only tighten it.
- **Fail closed, not fail dead** — if a governance service is down, only the
  *current action* is denied (with a readable Traditional-Chinese reason); the
  Hermes session keeps running and can replan.
- **Governance Dashboard** — a read-only page showing every decision and its
  full pipeline.

> **Scope (read this).** Two layers: **Layer 1** (always on) governs what the
> model *proposes* — tool calls / sub-agent spawns in the chat completion
> (streaming buffered, not incremental). **Layer 2** (opt-in,
> `dciso plug --exec-pep`) governs what Hermes is *about to actually run*, via a
> `pre_tool_call` hook. Still not covered: side effects *inside* a running tool,
> and anything not routed through a tool call (some cron / memory writes, MCP
> internals).

---

## Use it (3 commands)

```bash
git clone https://github.com/<owner>/dciso-governance-gateway.git
cd dciso-governance-gateway
./install.sh
```

Then plug the CISO in front of your Hermes agent, and pull it out when you're done:

```bash
./bin/dciso plug          # route Hermes through the CISO (edits only ~/.hermes, with backup)
hermes chat -q "run: rm -rf /tmp/x"    # -> denied, command never runs, session continues
./bin/dciso unplug        # restore Hermes exactly as it was
```

Dashboard: <http://127.0.0.1:8900>. Full walkthrough: **[`docs/USER-GUIDE.md`](docs/USER-GUIDE.md)**.

For a stage demo, one command narrates every outcome (ALLOW / DENY / MODIFY /
REQUIRE_REVIEW / approval-token release + replay / fail-closed):

```bash
./bin/dciso guided        # add --auto for no pauses
```

`dciso` also has `demo` (real OpenAI), `verify` (prove no-bypass), `unmapped`
(find tool names to map), `status`, `doctor`, `down`, `destroy`.

Basing the hard policy on Microsoft's Agent Governance Toolkit / ACS:
**[`docs/hard-policy-and-agt.md`](docs/hard-policy-and-agt.md)**.

---

## Repository map

| Path | What |
|---|---|
| `gateway/` | LiteLLM proxy config + `callbacks/governance_callback.py` + `governance/` core (schemas, normalizer, adapters, orchestrator, enforcer, audit, OPA/CISO clients) |
| `policy/` | `agent_governance.rego`, `data.json`, `tests/` (18 unit tests) |
| `ciso-advisor/` | Soft-policy service (rule engine / real-LLM), system prompt, security skill, response schema |
| `mock-llm/` | Offline deterministic OpenAI-compatible model for tests/demos |
| `viewer/` | Read-only Governance Dashboard (FastAPI, single page) |
| `pep/` + `hermes-hook/` | Layer-2 execution-side PEP + the Hermes `pre_tool_call` hook |
| `hermes/` | install (review-first), `enable-routing` / `disable-routing` / `verify-routing`, isolated-profile examples |
| `tests/` | `unit/`, `integration/` (pytest), `e2e/` (live-stack bash) |
| `demo/` | `run-safe-request.sh`, `run-denied-tool-call.sh`, `run-delegation-review.sh` |
| `docs/` | architecture, threat-model, governance-event, operating-sop, versions |

---

## Quickstart — empty machine to demo

### 0. Prerequisites
Docker (with Compose v2). For running tests locally: `opa` on PATH and a Python
3.11+ env with `tests/requirements.txt`.

### 1. Configure
```bash
git clone <this repo> && cd dciso-governance-gateway
cp .env.example .env
# edit .env: set GATEWAY_MASTER_KEY. For demo mode also set a real OPENAI_API_KEY.
```

### 2. Start the stack (test mode — offline, no API key needed)
```bash
make up
make smoke        # a plain completion routed through the gateway
```
Dashboard: <http://127.0.0.1:8900>

### 3. Run the three demos
```bash
make demo-safe        # plain chat            -> ALLOW (passthrough)
make demo-deny        # external PHI transfer -> DENY  (tool call stripped, reason shown)
make demo-delegate    # L4 delegation         -> MODIFY / REQUIRE_REVIEW
```
Watch each one land in the dashboard; click a row to see
request → GovernanceEvent → CISO advice → OPA decision → what Hermes received.

### 4. Demo with the REAL Hermes + real OpenAI
```bash
# .env has a real OPENAI_API_KEY (gateway + advisor only)
make demo-up                                  # gateway routes to OpenAI, CISO uses an LLM

# get Hermes (review-first; never pipe|bash)
./hermes/install-hermes-linux-wsl.sh review   # then: ... run-installer   (or: ... git)

export HERMES_HOME="$PWD/.hermes-governed-test"
./hermes/enable-routing.sh                     # PLUG IN: writes gateway base_url + token only
HERMES_HOME=$HERMES_HOME hermes chat -q "只回覆 HERMES_GATEWAY_OK，不要呼叫工具"
./hermes/verify-routing.sh                     # no bypass, no provider key, source unmodified

# ... drive Hermes through real tasks; watch the dashboard govern in real time ...

./hermes/disable-routing.sh                    # PULL OUT: restores the profile, Hermes un-governed
```

### 5. Tests
```bash
make test        # opa test (18) + pytest unit+integration (65)
make test-opa
make test-py     # real-OPA integration tests need `opa` on PATH or $OPA_BIN
make e2e         # live end-to-end (stack must be up in test mode)
make sample-evidence   # regenerate docs/sample-evidence.jsonl
```

A committed sample evidence chain (5 scenarios through the real pipeline) is at
[`docs/sample-evidence.jsonl`](docs/sample-evidence.jsonl).

---

## How the guarantees are met (ticket §11)

| DoD item | Where |
|---|---|
| Hermes unmodified; only external config changes | `hermes/enable-routing.sh` (env only), `verify-routing.sh` check 5 |
| Non-streaming chat + tool calls supported | `gateway/config.yaml`, `governance_callback.py` |
| `delegate_task` → `agent.spawn`, governed before returning | `adapters/hermes.py`, `test_delegate_task_maps_to_agent_spawn` |
| CISO advises, cannot allow | `clients/ciso_advisor.py` (schema-validated, parse-fail ≠ ALLOW), rego rule 7 |
| OPA is the only final authority | `decision_orchestrator.py`, `policy/agent_governance.rego` |
| CISO=ALLOW + OPA=DENY ⇒ DENY | `policy/tests/...test_phi_external_denied_despite_soft_allow`, `test_orchestrator.py` |
| No fail-open; session stays alive; readable reason | `Decision.fail_closed`, `GovernanceReject`, `enforcer.py`, `test_audit_write_failure_fails_closed` |
| Streaming not governed ⇒ refused, not passed through | `governance_callback.async_pre_call_hook`, `test_streaming_request_is_refused_fail_closed` |
| `REQUIRE_REVIEW` only released by a verifiable approval token | `gateway/governance/approvals.py`, `test_approvals.py` |
| Hermes has no provider credential; egress verifiable | `hermes/env.example`, `verify-routing.sh` checks 1 & 4 |
| Every decision audited with policy version + reason + correlation id | `audit.py`, dashboard |
| All Rego + gateway + (e2e) Hermes tests pass | `make test`, `tests/e2e/` |
| README = full SOP another engineer can follow | this file + `docs/operating-sop.md` |
| Layer 1 governs proposed calls; Layer 2 (opt-in) governs actual execution | `docs/architecture.md`, `pep/`, `test_pep.py` |

## Troubleshooting

- **`make up` fails with `failed to prepare extraction snapshot ... parent snapshot does not exist`** — transient BuildKit cache corruption, not a repo problem. Run `docker builder prune -af` and `make up` again.
- **`gateway` container `Exited`** — check `docker compose logs gateway`. LiteLLM cold start is ~30–45 s; `docker compose ps` may show `health: starting` for a bit.
- **Everything through Hermes gets `UNKNOWN_HARNESS` DENY** — set `GATEWAY_DEFAULT_HARNESS=hermes` (default in compose) so requests without `metadata.harness_type` are still governed.

## Versions

Pinned and verified 2026-09-01 — see [`docs/versions.md`](docs/versions.md).
LiteLLM `v1.89.3` · OPA `1.19.0`. Re-check official docs before each deploy.

## REQUIRE_REVIEW → release with a verifiable approval token

`REQUIRE_REVIEW` returns HTTP 409 and is never auto-retried. To release a
reviewed action, a human approves it and mints a short-TTL HMAC token bound to
that exact action, then the client resubmits the **same** request carrying it:

```bash
export GOVERNANCE_APPROVAL_SECRET=...   # same value the gateway has
python demo/mint-approval.py --session sess-1 --tool send_email \
    --args '{"to":"ops@corp.internal"}' --ttl 900 --approver alice
# resubmit with  metadata.dciso.approval_token = "<token>"
```
A forged/expired/wrong-action token stays blocked; a token never rescues a hard
DENY. With no secret set, no token is ever accepted (safe default). See
`docs/governance-event.md`.

## Known MVP limitations / next phase

- Streaming governance is **buffered** (the turn is held until complete), not
  truly incremental — fine for correctness, adds latency on long streamed turns.
- Approval tokens: add a one-time-use nonce ledger; move minting behind a real
  review service with its own authn.
- Approval tokens have no one-time-use nonce yet (valid until TTL expiry).
- Real execution-side PEP (filesystem/DB/MCP/network side effects).
- Hermes open items R1–R5 in `docs/versions.md` (confirm on a live install).
