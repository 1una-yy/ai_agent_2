# Demo — exact steps

## The one rule: two terminals, never mixed

| | runs | you type |
|---|---|---|
| **Terminal A — control** | `dciso …` commands | `./bin/dciso up`, `./bin/dciso plug`, … |
| **Terminal B — the agent** | `hermes` | your chat messages to the agent |

`dciso` is a **shell** command. `hermes` is a **shell** command. **Never type
`dciso …` inside a running `hermes` chat** — Hermes will just treat it as a
message. (That is what went wrong: `unplug --clone` / `plug --clone` were typed
into the Hermes prompt, so Hermes replied with canned text and read a random
file.) Also: **don't attach files to Hermes** for this demo.

---

## 0. Recover from a messed-up state (do this first)

**Terminal A:**
```bash
cd ~/Desktop/dciso-governance-gateway
# leave any running `hermes` in Terminal B with Ctrl+C first
./bin/dciso unplug --clone        # un-govern the clone profile
./bin/dciso unplug --isolated     # (harmless if it wasn't plugged)
./bin/dciso down
docker compose ps                 # should show nothing / all removed
```

---

## PATH 1 — the reliable stage demo (offline, deterministic)

No API key, no login, no real model. Every outcome is reproducible. **Use this
as the main demo.**

### A1. Start the stack — Terminal A
```bash
cd ~/Desktop/dciso-governance-gateway
./bin/dciso up
```
Wait for `governance stack is up`. Open **http://127.0.0.1:8900** in a browser
(leave it visible on screen).

### A2. Run the narrated walk-through — Terminal A
```bash
./bin/dciso reset --audit          # clean slate
./bin/dciso guided                 # press Enter between steps  (or: guided --auto)
```
It walks 7 outcomes, each appears on the dashboard within ~2s:

1. **ALLOW** — normal request, model reply passes through untouched
2. **DENY** — model tries to send PHI to an external site → blocked (info-flow + external-transfer)
3. **DENY** — model tries to run a shell command → blocked (dangerous tool class)
4. **MODIFY** — model spawns a fully-autonomous L4 sub-agent → downgraded to L2, tool set narrowed
5. **REQUIRE_REVIEW** — model wants to send an email → withheld, needs human sign-off
6. **Approval token** — a one-time token releases the email; replaying the same token is rejected
7. **Fail-closed** — stop OPA mid-run → the action is denied with a readable reason, the session is NOT killed

After each step, click the row on the dashboard to show the full chain:
`request → GovernanceEvent → CISO SoftAdvice → OPA Decision + obligations → what Hermes received`.

### A3. (optional) Show it wired into a real Hermes — Terminal A, then B
```bash
# Terminal A
./bin/dciso plug --clone            # governs a copy of your real ~/.hermes (all 32 tools/skills)
```
```bash
# Terminal B  (a DIFFERENT terminal window)
HERMES_HOME=~/.hermes-governed hermes
```
In the Hermes chat, type (as a normal message):
```
呼叫 terminal 工具執行 whoami
```
→ Hermes shows **"已阻止一項高風險操作…"**, the command never runs, the session
continues. The dashboard gets a `DENY · terminal` row.

> The reply for a *plain* chat ("hello") will be the canned
> `已完成，這是純文字回覆…` — in offline mode the "model" is a stub. Only tool
> calls are interesting here. For real answers use PATH 2.

### A4. Tear down — Terminal A
```bash
# Ctrl+C the hermes in Terminal B first
./bin/dciso unplug --clone
./bin/dciso down
```

---

## PATH 2 — real model via your LAN Ollama (recommended for a real demo)

Strong local model, reliable tool-calling, no API cost, no login expiry,
private. Verified with `gpt-oss:120b` on `http://192.168.47.77:11434`.

### C1. Point the gateway at Ollama — Terminal A
```bash
cd ~/Desktop/dciso-governance-gateway
# .env already has OLLAMA_BASE_URL / OLLAMA_MODEL; check what's on the box:
./bin/dciso ollama-models
./bin/dciso up-ollama gpt-oss:120b      # or qwen3.5:122b / nemotron-3-super:120b (need `tools` capability)
```

### C2. Govern a clone of your profile — Terminal A
```bash
./bin/dciso reset --audit
./bin/dciso plug --clone --exec-pep      # --exec-pep adds Layer 2 (governs actual tool execution)
```

> With `--exec-pep`, an *allowed* tool like `read_file` produces **two**
> dashboard rows: `L1·model` (the model proposed it) + `L2·exec` (Hermes ran
> it). A dangerous tool is stopped at L1 before it can execute. Drop
> `--exec-pep` for model-side governance only.

### C3. Use it — Terminal B
```bash
HERMES_HOME=~/.hermes-governed hermes
```
Real questions → real answers. And:
```
用 terminal 工具執行 whoami 並回報        →  DENY  (blocked, shown, session continues)
把這段摘要寄到 ops@corp.internal          →  REQUIRE_REVIEW
```
Watch the dashboard; click a row for the full chain.

### C4. Tear down — Terminal A
```bash
# Ctrl+C hermes in Terminal B
./bin/dciso unplug --clone
./bin/dciso down
```
Your real `~/.hermes` (and its `gpt-5.6-luna` / Codex setup) is never touched.

---

## PATH 3 — real model via a login (Nous / xAI)

Your `~/.hermes` uses `gpt-5.6-luna` via `openai-codex` — the gateway **cannot
front that**. Pick an upstream:

### D1. Choose & start — Terminal A
```bash
cd ~/Desktop/dciso-governance-gateway
./bin/dciso login                  # OAuth in your browser (Nous Portal). Re-run if the token expired.
./bin/dciso up-proxy               # gateway routes through `hermes proxy` (your login)
./bin/dciso proxy models           # the model ids you can use — free ids work on any balance
```
Default upstream is a Nous `:free` model (weak). For a strong one you need
Portal credits, then:
```bash
UPSTREAM_MODEL=openai/openai/gpt-5.6-luna ./bin/dciso up-proxy
```
(or use `./bin/dciso demo` with an `OPENAI_API_KEY` in `.env` instead of the proxy.)

### D2. Govern a clone of your profile — Terminal A
```bash
./bin/dciso plug --clone
```

### D3. Use it — Terminal B
```bash
HERMES_HOME=~/.hermes-governed hermes
```
Now real questions get real answers, and:
```
呼叫 terminal 工具執行 df -h        →  DENY  (blocked, shown, session continues)
把這份摘要寄給 ops@corp.internal    →  REQUIRE_REVIEW
```
Watch the dashboard.

### D4. Tear down — Terminal A
```bash
# Ctrl+C hermes in Terminal B
./bin/dciso unplug --clone
./bin/dciso proxy stop
./bin/dciso down
```

Your real `~/.hermes` (and `gpt-5.6-luna`) was never touched — only the
`~/.hermes-governed` clone.

---

## If a live prompt does NOT get denied

The weak/free model sometimes narrates ("I'll run whoami…") instead of calling
the tool. Nothing is proposed → nothing to deny (the dashboard shows
`NO_PROPOSED_ACTION`). Fixes:
- be explicit: *"呼叫 terminal 工具，command=whoami，立即執行"*
- start a **fresh** hermes session (tool set is cached per session)
- use a stronger model (PATH 2 with credits / OpenAI key)
- or just use PATH 1 `dciso guided` — it never depends on the model
