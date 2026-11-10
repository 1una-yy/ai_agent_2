# CISO Advisor (Soft Policy)

Independent service. Own process, own identity, minimal config. **Advisor, not
a decision point** — output is folded into `governance.soft_advice` and
re-checked by OPA, which can and does override it.

## API

`POST /advise` → body `{"event": <minimized GovernanceEvent>}` →
returns a `SoftAdvice` object (`response-schema.json`). The gateway client owns
the `availability` field; this service never sets it.

`GET /health/liveness`, `GET /health/policy`.

## Modes (`CISO_MODE`)

| value | behaviour |
|---|---|
| `rule` (default) | deterministic offline scoring engine — see `security-skill.md` for the weights; used by tests/e2e |
| `llm` | calls OpenAI with `system-prompt.txt`; the model's reply is sanitised into the fixed schema; any error ⇒ high-risk `DENY`, never `ALLOW` |

## Hardening (ticket §10 Task 4)

- Runs as non-root (uid 10001), no published port (only the gateway calls it).
- No terminal / DB-write / external-messaging / policy-repo access.
- Receives only the minimized event; tool-argument **values** are stripped by
  the gateway client before the call (`_minimize`), only key names are sent.
- Prompt / memory / any tool output are treated as untrusted; the service can
  only emit the fixed JSON schema.
