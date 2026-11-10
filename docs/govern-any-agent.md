# Govern any AI agent (no hooks)

Layer 1 — the LiteLLM interception — is **agent-agnostic**. Any client that
speaks the OpenAI `/v1/chat/completions` schema is governed the moment its
`base_url` points at the gateway. No source patch, **no `pre_tool_call` hook**,
no per-agent integration.

```
your agent  ──OpenAI /v1/chat/completions──►  DCISO gateway (LiteLLM)
                                               ├─ real provider (Ollama / OpenAI / …)
                                               ├─ CISO advisor  (soft)
                                               ├─ OPA / Rego     (hard, decides)
                                               └─ audit  ──►  dashboard :8900
```

The gateway intercepts the model's reply, normalizes every proposed
`tool_calls[].function` into a `GovernanceEvent` (generic OpenAI adapter),
runs CISO + OPA, and rewrites the reply before your agent sees it:
ALLOW passes through, DENY / REQUIRE_REVIEW replace the tool calls with a short
reason, MODIFY rewrites the arguments.

## Plug (any agent)

Point the agent at the gateway and give it the gateway token **instead of** a
real provider key:

```bash
OPENAI_BASE_URL=http://127.0.0.1:4000/v1
OPENAI_API_KEY=<GATEWAY_MASTER_KEY from .env>
```

| agent | how |
|---|---|
| **OpenAI SDK / LangChain / LlamaIndex** | set `base_url` + `api_key` as above (or `OPENAI_BASE_URL` / `OPENAI_API_KEY` env) |
| **Claude Code** | `ANTHROPIC_BASE_URL` is not OpenAI-shaped — use its OpenAI-compatible mode / a model alias pointed at `http://127.0.0.1:4000/v1` |
| **Cursor** | Settings → Models → OpenAI API key = gateway token, Base URL = `http://127.0.0.1:4000/v1` |
| **Aider** | `aider --openai-api-base http://127.0.0.1:4000/v1 --openai-api-key <token>` |
| **Hermes** | `dciso plug` (still the turnkey path; also installs the optional Layer 2 hook with `--exec-pep`) |

Start the stack so it governs everything, not just Hermes:

```bash
./bin/dciso up-ollama gpt-oss:120b --agent generic
#   agent scope : any OpenAI-compatible client
#   CISO advisor : hermes (default)   ← add --ciso rule for an instant CISO
```

`--agent generic` clears `GATEWAY_DEFAULT_HARNESS`, so the generic adapter
handles any client and a per-request `metadata.harness_type` (if the client
sends one) is recorded in the audit as-is.

## Unplug

Point the agent's `base_url` / `api_key` back at its real provider. That's it —
nothing was installed in the agent.

## Optional: tell the gateway who's calling

If your client can send `metadata` on the request, add:

```json
{"metadata": {
  "harness_type": "langchain",
  "dciso": {
    "session_id": "…",
    "task": {"data_classification": ["PII"]},
    "governance": {"capability_level": "C1"}
  }
}}
```

All of it is optional and is only *input* to the policy — the gateway still
decides. Forged fields (`risk_score`, `policy_version`, `approval_id`, …) are
ignored.

## Sub-agent spawns

A tool call named like a delegation primitive — `delegate_task`, `spawn_agent`,
`create_subagent`, `Task`, `handoff`, `transfer_to_agent`, … — is treated as
`agent.spawn`, so the autonomy-ceiling and parent-grant rules apply. Add your
framework's name with `DCISO_DELEGATION_TOOLS=my_spawner,other_spawner` or a
`DCISO_MAPPING_PATH` JSON (`{"my_spawner": "agent.spawn"}`).

## Knobs

| var | default | meaning |
|---|---|---|
| `GATEWAY_DEFAULT_HARNESS` | `hermes` | assumed harness when a request carries none; **empty** = generic adapter + per-request value |
| `DCISO_GENERIC_ADAPTER` | `1` | `0` disables the catch-all → non-Hermes traffic fails closed as `UNKNOWN_HARNESS` |
| `DCISO_DELEGATION_TOOLS` | — | extra comma-separated tool names that mean "spawn a sub-agent" |
| `DCISO_MAPPING_PATH` | — | JSON file of `{native_name: canonical_name}` overrides |

## What still needs the agent's cooperation

Layer 1 governs what the **model proposes**. It cannot see a tool the agent
runs on its own without asking the model (e.g. a deterministic post-step, a
skill's own shell-out). For that you need Layer 2 — an execution-time check the
agent calls before dispatch. Hermes has a `pre_tool_call` hook for this
(`dciso plug --exec-pep`); other agents need an equivalent. If you want Layer 1
only, that's a deliberate, smaller surface: every LLM-driven action is still
gated.
