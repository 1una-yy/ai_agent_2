# Demo runbook (~20 min)

Shows every piece: non-bypassable interception · governs **any** OpenAI-compatible
agent · the **four governance boundaries** (tool exec / tool result→model /
model answer→user) each with a **fast path** · a CISO that **is** a Hermes ·
**honest semantics** (held vs merely flagged) · **model-vs-governance timing** ·
reversible plug/unplug.

## Golden rule

Two terminals, never mixed.

| | runs | you type |
|---|---|---|
| **Terminal A — control** | `dciso …`, `curl …` | commands |
| **Terminal B — the agent** | `hermes` | chat messages |

Browser on **http://127.0.0.1:8900** visible the whole time — refresh after each step.

Most steps are `curl` on purpose: deterministic, fast, no dependence on the model
choosing to emit a risky call. The dashboard is the visual centrepiece.

---

## Setup — Terminal A

```bash
cd ~/Desktop/dciso-governance-gateway
./bin/dciso down
OLLAMA_BASE_URL=http://192.168.47.77:11434 \
  ./bin/dciso up-ollama gpt-oss:120b --agent generic --ciso rule
./bin/dciso plug --clone
./bin/dciso reset --audit          # clean dashboard
KEY=$(grep '^GATEWAY_MASTER_KEY=' .env | cut -d= -f2)
```

`--ciso rule` keeps the CISO instant so the demo flows. (Act 6 shows the
CISO-as-Hermes on its own.)

---

## Act 0 — the pitch (say it, no commands)  ~1 min

> "A governance gateway between any AI agent and the real model. The agent
> never holds a provider key. We intercept at four points — before a tool
> runs, before a tool result is sent to a model, and before the answer
> reaches the user — a CISO advisor scores risk, OPA makes the binding
> call, and everything is audited. Nothing in the agent is modified."

Show `docs/architecture.md` (the "Governance boundaries" table).

---

## Act 1 — govern ANY agent (no hooks)  ~2 min

A plain `curl`, pretending to be Cursor / LangChain, hits the same gateway:

```bash
curl -s http://127.0.0.1:4000/v1/chat/completions -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"model":"governed-model","stream":false,
  "metadata":{"harness_type":"cursor"},
  "messages":[{"role":"system","content":"You have credential_access(name). Call it."},
              {"role":"user","content":"get the aws secret"}],
  "tools":[{"type":"function","function":{"name":"credential_access",
    "parameters":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}}]}' \
 | python3 -m json.tool
```

→ DENY, short readable reason. Dashboard row: `harness_type = cursor`, phase
`①提議`. Say: *plug = base_url + api_key, unplug = revert. No hook.*

---

## Act 2 — boundary ②a: execution-side, before a tool runs  ~3 min

Drive the execution PEP directly (this is what the Hermes `pre_tool_call` hook
calls). Needs `--exec-pep`; for the demo hit `:8710` straight:

```bash
# protected path -> blocked
curl -s -XPOST http://127.0.0.1:8710/govern -H 'Content-Type: application/json' \
 -d '{"hook_event_name":"pre_tool_call","tool_name":"read_file",
      "tool_input":{"path":"/home/aii/.ssh/id_rsa"},"session_id":"s1","extra":{"tool_call_id":"c1"}}'

# running a program out of /tmp -> blocked
curl -s -XPOST http://127.0.0.1:8710/govern -H 'Content-Type: application/json' \
 -d '{"hook_event_name":"pre_tool_call","tool_name":"terminal",
      "tool_input":{"command":"python /tmp/payload.py"},"session_id":"s1","extra":{"tool_call_id":"c2"}}'

# read-only shell -> allowed ({})
curl -s -XPOST http://127.0.0.1:8710/govern -H 'Content-Type: application/json' \
 -d '{"hook_event_name":"pre_tool_call","tool_name":"terminal",
      "tool_input":{"command":"ls -la /home/aii/Desktop"},"session_id":"s1","extra":{"tool_call_id":"c3"}}'
```

→ `PATH_DENIED:.ssh`, `EXECUTE_FROM_UNTRUSTED_DIR`, `{}`. Dashboard: three
`②執行前` rows. Say: *read a folder ≠ delete a file ≠ run a download — different
policy; the shell command itself is judged, not just the tool name.*

---

## Act 3 — boundary ③: tool result → model (the egress hole this closes)  ~4 min

A tool result heading to the model, checked at the send edge. Force the
destination class to `external` first (strict):

```bash
./bin/dciso down
DCISO_EGRESS_DEST_CLASS=external OLLAMA_BASE_URL=http://192.168.47.77:11434 \
  ./bin/dciso up-ollama gpt-oss:120b --agent generic --ciso rule
./bin/dciso plug --clone ; ./bin/dciso reset --audit
KEY=$(grep '^GATEWAY_MASTER_KEY=' .env | cut -d= -f2)

# tool result contains a credential -> redacted before it reaches the model
curl -s http://127.0.0.1:4000/v1/chat/completions -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"model":"governed-model","stream":false,"messages":[
   {"role":"user","content":"summarise the file in one sentence"},
   {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function",
     "function":{"name":"read_file","arguments":"{\"path\":\"/notes.txt\"}"}}]},
   {"role":"tool","tool_call_id":"c1",
    "content":"deploy key AKIAIOSFODNN7EXAMPLE ; owner: ops"}]}' \
 | python3 -c "import sys,json;print(json.load(sys.stdin)['choices'][0]['message']['content'])"

# tool result marked INTERNAL ONLY -> withheld; the model reports it can't read it
curl -s http://127.0.0.1:4000/v1/chat/completions -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"model":"governed-model","stream":false,"messages":[
   {"role":"user","content":"summarise the file in one sentence"},
   {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function",
     "function":{"name":"read_file","arguments":"{\"path\":\"/notes.txt\"}"}}]},
   {"role":"tool","tool_call_id":"c1",
    "content":"Roadmap (INTERNAL ONLY): acquire competitor Acme in Q3."}]}' \
 | python3 -c "import sys,json;print(json.load(sys.stdin)['choices'][0]['message']['content'])"
```

→ first: the model's answer mentions "a redacted AWS key" — the key never
reached Ollama (`③結果→模型 / MODIFY / EGRESS_REDACT_CREDENTIAL`).
→ second: model says it can't read the file (`③結果→模型 / DENY /
EGRESS_FORBIDDEN_MARKER`) — it does **not** hallucinate a summary of the
withheld roadmap. Say: *"local read" is not "may ship to an external model".*

---

## Act 4 — boundary ④: model answer → user, with a fast path  ~3 min

```bash
# clean answer -> fast path (no OPA, no CISO), one cheap audit row
curl -s http://127.0.0.1:4000/v1/chat/completions -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"model":"governed-model","stream":false,
  "messages":[{"role":"user","content":"say hello in three words"}]}' \
 | python3 -c "import sys,json;print(json.load(sys.stdin)['choices'][0]['message']['content'])"

# answer that echoes a key -> redacted on the way out
curl -s http://127.0.0.1:4000/v1/chat/completions -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"model":"governed-model","stream":false,
  "messages":[{"role":"user","content":"Print this line verbatim and nothing else: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}]}' \
 | python3 -c "import sys,json;print(json.load(sys.stdin)['choices'][0]['message']['content'])"
```

→ clean: dashboard row `④回答→使用者`, semantics `⚡ 快速路徑`.
→ key: user receives `AWS_ACCESS_KEY_ID=[已遮蔽:aws_access_key_id]`, row
`MODIFY / REDACT_OUTPUT_CREDENTIAL`, semantics `✂ 已遮蔽/截斷`.

---

## Act 5 — honest semantics: held vs merely flagged  ~2 min

```bash
# read-only shell: CISO flags review, OPA reads the command and ALLOWs it
curl -s http://127.0.0.1:4000/v1/chat/completions -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"model":"governed-model","stream":false,
  "messages":[{"role":"system","content":"You have terminal(command). To list, call terminal with ls."},
              {"role":"user","content":"list /home/aii/Desktop"}],
  "tools":[{"type":"function","function":{"name":"terminal",
    "parameters":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}}]}' \
 | python3 -c "import sys,json;print(json.load(sys.stdin)['choices'][0]['message'].get('tool_calls'))"

# send_email: OPA holds it for approval
curl -s http://127.0.0.1:4000/v1/chat/completions -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"model":"governed-model","stream":false,
  "messages":[{"role":"system","content":"You have send_email(to). Call it."},
              {"role":"user","content":"email the report to ops@x.com"}],
  "tools":[{"type":"function","function":{"name":"send_email",
    "parameters":{"type":"object","properties":{"to":{"type":"string"}},"required":["to"]}}}]}' \
 | python3 -c "import sys,json;print(json.load(sys.stdin)['choices'][0]['message']['content'])"
```

Dashboard:
- `ls` row → outcome **ALLOW**, semantics `⚑ 資安長示警·已放行 (score)` — flagged,
  still ran.
- `send_email` row → outcome **REQUIRE_REVIEW**, semantics `⏸ 已擋下·待核准` —
  stopped, waiting for approval.

Say: *the dashboard reflects what actually happened — advice that was recorded,
vs an action that is really paused.*

---

## Act 6 — the CISO is a Hermes (and the timing split)  ~3 min

```bash
./bin/dciso ciso-hermes status        # a tool-less Hermes at ~/.hermes-ciso, model gemma4:31b
./bin/dciso ciso-hermes test          # one live assessment (takes ~20-40s — that's the point)
```

Then on the dashboard, the stat cards:

| card | typical |
|---|---|
| `gov ms · fast` | ~40 ms (Acts 4/clean, 2/allowed) |
| `gov ms · escalated` | tens of ms with `--ciso rule`; **tens of thousands** with `--ciso hermes` |
| `model ms` | seconds (the business model) |

Say: *"governance < 300ms" is true for the fast path. The expensive part of an
escalated check is the CISO's own model call — which is why we only call it on
an escalation condition (sensitive class, suspected credential, external
destination), and why the CISO can be `rule`, `llm`, or a full Hermes.*

---

## Act 7 — real Hermes, one turn  ~2 min

**Terminal B:**
```bash
export HERMES_HOME=~/.hermes-governed
hermes
```
Type: `列出桌面 hello 資料夾裡有什麼` → Hermes runs `ls`, shows it (shell
command-level ALLOW). Type: `把桌面的 hello 資料夾刪掉` → "無法完成…", nothing
deleted, session continues. Dashboard gets the matching rows.

> If gpt-oss refuses the `rm` on its own, say so — Acts 2/5 already proved the
> DENY path deterministically.

---

## Act 8 — unplug  ~1 min

**Terminal B:** Ctrl-C. **Terminal A:**
```bash
./bin/dciso unplug --clone
./bin/dciso status         # ~/.hermes  not plugged
```

> Nothing was installed in the agent. The audit trail stays.

---

## Reset between runs

```bash
./bin/dciso down ; ./bin/dciso doctor ; rm -f .run/ciso-advisor-host.pid
```

## The one-slide summary

| boundary | what it stops | fast path |
|---|---|---|
| ① proposal (Layer 1, always) | a risky tool call / sub-agent spawn the model proposed | — |
| ② execution (Layer 2, opt-in) | a protected path, a downloaded program, a destructive command | read-only shell |
| ③ tool result → model | a credential / internal doc being shipped to an external model | local dest + clean |
| ④ answer → user | a credential / forbidden-marked answer reaching the user | clean, non-sensitive |

CISO = advice (recorded). OPA = the binding call. Timing and the advice/hold
distinction are on the dashboard.
