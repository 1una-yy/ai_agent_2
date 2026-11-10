# User guide — run the AI CISO, plug it in, pull it out

This is for someone who just wants to **use** the product: put an AI security
officer (the "CISO") in front of their Hermes agent so every action the model
proposes is checked first, and remove it again in one command when they don't
want it.

You need: a Linux / macOS / WSL2 machine with **Docker** (Desktop or Engine +
Compose v2). That's it — no API key needed for the offline trial.

---

## 1. Download it

```bash
git clone https://github.com/<owner>/dciso-governance-gateway.git
cd dciso-governance-gateway
```

## 2. Run it

```bash
./install.sh
```

This checks Docker, creates a `.env` with fresh random secrets, and starts five
small containers (the gateway, the CISO advisor, the policy engine, a local test
model, and a dashboard). First run builds images — a few minutes.

When it finishes you have:

- **Dashboard**: <http://127.0.0.1:8900> — every governance decision, click any
  row to see the whole chain.
- The `dciso` command (in `./bin/dciso`, and on your `PATH` if `~/.local/bin` is
  there).

Check it any time:

```bash
./bin/dciso status
./bin/dciso doctor
```

---

## 3. Plug the CISO in front of Hermes

> `plug` edits **only** your Hermes profile (`~/.hermes/.env` and
> `config.yaml`), and backs up what was there. It never touches Hermes' code.

```bash
./bin/dciso plug
```

That points Hermes at the gateway as its model endpoint and removes any real
provider key from the Hermes profile (so Hermes can *only* reach the gateway).

Try it:

```bash
hermes chat -q "say GOVERNED_OK"
```

You'll see the reply come back as normal — but it went through the CISO, and a
row appeared on the dashboard.

Now ask Hermes to do something risky:

```bash
hermes chat -q "run the shell command: rm -rf /tmp/demo"
```

Hermes shows a refusal in plain language ("已阻止一項高風險操作…") plus a small
`dciso_governance` block, and **the command never runs**. The chat session
keeps going — you can ask for something safe next. The dashboard shows a
`DENY` row; click it to see the CISO's risk assessment and the policy decision.

**In the live Hermes chat, use ALLOW / DENY / REQUIRE_REVIEW examples** (plain
chat, `run a shell command`, `send an email to ops`). The MODIFY (sub-agent
downgrade) and one-time approval-token flows are best shown with the narrated
`./bin/dciso guided` walk-through — running delegation against the offline test
model loops because it can't actually do the delegated work. With a real model
(`dciso demo`) all outcomes work live.

Tip: `./bin/dciso reset` clears the auto-replan counters between demo runs (add
`--audit` to also clear the dashboard history for a clean start).

### Which profile to govern

| flag | what it does |
|---|---|
| *(none)* | your real `~/.hermes` — backed up, restored byte-for-byte on `unplug` |
| `--clone` | a **config-only copy** at `~/.hermes-governed` (all your skills/tools/auth, ~8 MB, not the 1 GB install). Your daily driver is never touched. **Recommended for demos.** |
| `--isolated` | a tiny throwaway profile at `.hermes-governed-test` (few tools; forces the full toolset visible) |

```bash
./bin/dciso plug --clone
HERMES_HOME=~/.hermes-governed hermes           # full skill set, governed
./bin/dciso unplug --clone
```

> **While plugged, Hermes uses the *gateway's* upstream model, not its own.**
> If your Hermes logs in via `openai-codex` (ChatGPT subscription), the gateway
> can't front that — pick an upstream with `./bin/dciso demo` (OpenAI key) or
> `./bin/dciso up-proxy` (a Nous / xAI login; free model ids work on any
> balance, strong ids need Portal credits). `unplug` puts your own model back.

---

## 4. Pull it out

```bash
./bin/dciso unplug
```

Restores your Hermes profile from the backup `plug` made. Hermes is back to
exactly how it was — no governance, no leftovers. (If you want Hermes to work
on its own again, put your normal provider API key back in `~/.hermes/.env`.)

Stop the containers when you're done:

```bash
./bin/dciso down          # keep the audit history
./bin/dciso destroy       # also delete audit history + built images
```

---

## 5. Use a real model

The offline setup routes to a built-in fake model. To govern real work:

**With an API key:**
1. Put it in `.env`: `OPENAI_API_KEY=sk-...`
2. `./bin/dciso demo` (real OpenAI + LLM CISO), then `./bin/dciso plug`.

**With a login instead of a key** (Nous Portal / xAI):
```bash
./bin/dciso login          # OAuth in your browser
./bin/dciso up-proxy        # gateway routes through `hermes proxy` (your login)
./bin/dciso plug
```
See **[`docs/real-model-with-login.md`](real-model-with-login.md)** for model
choice and details.

Either way the real credential lives **only** on your side (gateway `.env` or
`hermes proxy`). Hermes never gets it.

---

## Command reference

| Command | What it does |
|---|---|
| `dciso setup` | create `.env`, generate secrets (first run) |
| `dciso up` / `dciso demo` | start the stack (offline / real-model) |
| `dciso down` / `dciso destroy` | stop / stop + wipe |
| `dciso plug [--isolated]` | route Hermes through the CISO |
| `dciso unplug [--isolated]` | restore Hermes, remove the CISO |
| `dciso verify` | prove Hermes can't reach a model without the gateway |
| `dciso status` / `dciso doctor` | health + routing state / diagnose problems |
| `dciso dashboard` | print / open the dashboard URL |
| `dciso logs [service]` | follow container logs |

---

## Troubleshooting

- **`install.sh` says Docker missing** — install Docker Desktop (Mac/Windows) or
  Docker Engine + the compose plugin (Linux), then re-run.
- **`dciso up` fails with `failed to prepare extraction snapshot`** — a Docker
  build-cache glitch. `docker builder prune -af` then `dciso up`.
- **Hermes says "API call failed" after `plug`** — make sure the stack is up
  (`dciso status`) and that `~/.hermes/config.yaml` has
  `model: { provider: custom, base_url: http://127.0.0.1:4000/v1 }`. `dciso unplug`
  then `dciso plug` rewrites it.
- **Everything gets denied as "UNRECOGNIZED_ACTION / unknown harness"** — the
  gateway assumes it fronts Hermes via `GATEWAY_DEFAULT_HARNESS=hermes` (already
  set in `docker-compose.yml`). If you changed it, set it back.
- **A tool call is denied as `UNKNOWN_TOOL` that shouldn't be** — your Hermes
  build names a tool differently than the built-in map. Open the dashboard event,
  note `proposed_action.native_name`, and see `docs/live-demo-runbook.md` §5c.
