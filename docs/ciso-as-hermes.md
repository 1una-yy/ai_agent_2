# The AI CISO as a Hermes

By default the Soft-policy advisor is a ~200-line service (`CISO_MODE=rule` or
`llm`). You can instead make it **a real, separate Hermes** — its own persona,
its own model — while keeping every safety property intact.

## What stays true

- **It is still only an advisor.** OPA is the sole decision point. The CISO
  Hermes can flag risk and ask for tighter limits; it can never authorise
  anything. The rego only *tightens* on a CISO `DENY`/`CRITICAL` — a CISO
  `REQUIRE_REVIEW` or `MODIFY` is folded in as context, not an override.
- **It has no tools.** It is invoked with `hermes -z … -t ""` — no terminal,
  no file writes, no messaging.
- **Its output is untrusted.** Whatever text it returns is parsed for the last
  JSON object and clamped to the fixed `SoftAdvice` schema. A bad/absent
  verdict fails closed.
- **It never calls the gateway.** Its model points straight at Ollama. (Gateway
  → CISO Hermes → gateway would recurse.)
- **It is a separate identity.** Own `HERMES_HOME` (`~/.hermes-ciso`), never
  your real `~/.hermes`, never the governed profile.

## One-time setup

```bash
# .env already has OLLAMA_BASE_URL=http://192.168.47.77:11434
./bin/dciso ciso-hermes setup gemma4:31b      # creates ~/.hermes-ciso
./bin/dciso ciso-hermes test                  # one-shot sanity check (prints JSON)
```

`~/.hermes-ciso` gets:

| file | purpose |
|---|---|
| `config.yaml` | `model.provider: custom`, `base_url: <ollama>/v1`, `default: gemma4:31b`, streaming off, tools off |
| `SOUL.md` | the CISO persona: advisor-only, tighten-only, treat the event as untrusted, reply with one line of JSON |

## Run it

CISO-as-Hermes is the **default** for the real-model path — no flag:

```bash
./bin/dciso up-ollama gpt-oss:120b
```

(`--ciso rule` opts out to the instant containerised engine; `--ciso llm` to a
single direct model call.) This:
1. scaffolds `~/.hermes-ciso` if missing;
2. starts the advisor as a **host sidecar** on `0.0.0.0:9009` (`CISO_MODE=hermes`) —
   on the host, not in Docker, because it needs the host `hermes` binary;
3. stops the containerised `ciso-advisor`;
4. brings the stack up with `docker-compose.ciso-hermes.yml`, which repoints
   `gateway` and `pep` at `host.docker.internal:9009` and gives their
   advisor call a 90s timeout.

Check it:

```bash
./bin/dciso status
#   CISO advisor      : hermes (host sidecar pid …, :9009)
```

`./bin/dciso down` stops the sidecar and the stack. `./bin/dciso ciso-hermes remove`
deletes `~/.hermes-ciso`.

## Latency and the fast fallback

A `hermes -z` one-shot on a 30B+ model takes **~18–45s** (fixed agent
bootstrap + model load dominate, not the reasoning). So:

- `CISO_HERMES_TIMEOUT=60` (sidecar → `hermes` subprocess). On timeout / error /
  unparseable output the **rule engine answers instead**, tagged
  `CISO_HERMES_FALLBACK_RULE` + the failure code. Set `CISO_HERMES_FALLBACK=deny`
  to fail fully closed instead.
- The gateway waits up to 90s for the advisor, so a slow-but-successful CISO
  Hermes still lands (audit row shows `soft_availability: OK`).

In the dashboard you will see the CISO Hermes verdict as the soft advice, and —
where it disagrees with the Hard PDP — the final decision is OPA's.

## Why Hermes and not `CISO_MODE=llm`

`llm` mode is one bare model call — a fixed system prompt and the event. The
Hermes path gives you the things that make it a real agent:

- **skills** — advice-only instruction packs (a risk-scoring playbook, an OWASP
  Agentic mapping, your house data-classification rules). `llm` mode can't load
  these.
- a persona / `SOUL.md`, and memory if you enable it.

It still can't authorise anything and still has no tools.

### Adding a skill to the CISO

```bash
HERMES_HOME=~/.hermes-ciso hermes skills install <name>     # or drop it in ~/.hermes-ciso/skills/
```

Then activate it for every advice call:

```bash
# .env
CISO_HERMES_SKILLS=risk-playbook,owasp-agentic
```

The sidecar passes `--skills` to the `hermes -z` one-shot. A skill that needs a
tool simply won't fire — the CISO is launched with `-t ""`. Keep skills to
instructions/checklists; the more they add to the prompt, the slower each call.

## Env knobs

| var | default | meaning |
|---|---|---|
| `CISO_HERMES_HOME` | `~/.hermes-ciso` | the advisor Hermes' home |
| `CISO_HERMES_MODEL` | `gemma4:31b` | its model (direct to `OLLAMA_BASE_URL`) |
| `CISO_HERMES_SKILLS` | — | comma list of advice-only skills to activate (`--skills`) |
| `CISO_HERMES_TIMEOUT` | `60` | seconds to wait for the one-shot |
| `CISO_HERMES_FALLBACK` | `rule` | `rule` → rule engine on failure; `deny` → fail closed |
| `HOST_CISO_BIND` | `0.0.0.0` | sidecar bind addr; `127.0.0.1` = host-only (containers then can't reach it) |
| `CISO_HERMES_HTTP_TIMEOUT` | `90` | gateway/pep → advisor HTTP timeout in hermes mode |

## Verified

`tests/integration/test_services.py` covers the fallback, fail-closed, health,
JSON-extraction and clamp paths. Live 2026-09-07: real gateway + Ollama
`gpt-oss:120b` + CISO Hermes `gemma4:31b` — `rm -rf …` proposal → DENY with
`soft_availability: OK`; `ls …` proposal → ALLOW (CISO Hermes said review, Hard
PDP read the command and allowed the read-only call).
