# Threat model (ticket §12 deliverable 10)

Scope: the MVP model-side PEP. Assets: the upstream provider credential, the
Hard Policy bundle, the audit evidence chain, and the guarantee that a
`proposed` dangerous action cannot reach Hermes un-governed.

| # | Threat | Vector | Mitigation in this repo | Residual risk / next phase |
|---|---|---|---|---|
| 1 | **Gateway bypass** | Hermes (or a compromised skill) calls OpenAI/Anthropic/Ollama directly instead of the Gateway | Hermes profile holds only `GATEWAY_MASTER_KEY`; `enable-routing.sh` scrubs provider keys; `verify-routing.sh` check 1 & 4 prove no key + no fallback; compose publishes provider access to the Gateway only | Network-level egress lockdown (firewall/proxy) is deployment responsibility; documented in operating-sop |
| 2 | **Prompt injection into the CISO advisor** | Malicious text in task purpose / tool args / advisor memory tells the advisor to return `ALLOW` | Advisor output is schema-validated; a parse failure or missing field ⇒ `UNAVAILABLE`/`UNPARSEABLE`, never ALLOW; OPA re-decides and rule 7 forbids soft-advice widening; OPA test `test_soft_allow_does_not_loosen_terminal` + `test_phi_external_denied_despite_soft_allow` | Advisor could still under-state risk within valid bounds; Hard Policy is the backstop by design |
| 3 | **Policy tampering** | Business Hermes / CISO Agent tries to edit the Rego bundle or `data.json` | Policy lives in git with `opa check --strict` + 18 unit tests + review; OPA loads a read-only mount; neither Hermes nor the advisor has write access or a path to OPA's bundle | Signed bundles / OPA bundle API with auth = next phase |
| 4 | **Credential leakage** | Real provider key ends up in Hermes env, logs, or audit rows | Key only in Gateway `.env`; `audit.scrub()` drops `api_key/authorization/token/...`; audit stores hashes not raw bodies; `_redactable_request()` sends only counts + metadata | Secret-scanning in CI recommended; rotate `GATEWAY_MASTER_KEY` per deployment |
| 5 | **Fail-open** | OPA down / CISO down / audit write fails / callback throws | Every path maps to `Decision.fail_closed()` → DENY current action; `GovernanceReject` wraps any callback exception into an HTTP 4xx with a zh-Hant reason; audit write failure raises `AUDIT_WRITE_FAILED`; tests: `test_opa_*_fails_closed`, `test_ciso_*`, `test_audit_write_failure_fails_closed` | Per-process replan tracker state is lost on restart (accepted for MVP) |
| 6 | **Schema confusion** | Attacker sends `schema_version` / `event_type` / `harness_type` the policy doesn't expect, hoping for a default-allow | Pydantic models use `extra="forbid"`; Rego rule 6 denies unknown harness/event/tool/schema; `test_bad_schema_version_denied`, `test_unknown_harness_denied`, `test_unknown_tool_fail_closed` | Keep `data.json` allow-lists current as harnesses/tools are added |
| 7 | **Replay** | Re-submitting a previously-approved response / event, or an old approval token, to get a stale ALLOW | Every request is re-evaluated from scratch; approval tokens are short-TTL (`expired` check) and bound to a fingerprint of the exact action, so a token from action A cannot release action B (`test_fingerprint_mismatch_rejected`); `correlation_id` + per-row hashes make replays visible in audit | Add a one-time nonce / used-token ledger so a valid token cannot be used twice within its TTL |
| 8 | **Forged approval** | Request carries a fake `approval_id` / `approval_token` / `policy_version` / low `risk_score` in metadata | Adapter copies **no** trust fields from client metadata into the event (`test_forged_governance_fields_in_metadata_are_ignored`); `policy_version` set only from OPA; approval tokens are HMAC-signed with a server-only secret and verified (`approvals.verify`) — a forged/tampered token yields `bad_signature`/`malformed` and stays blocked (`test_tampered_signature_rejected`); with no secret configured, **no** token is ever accepted; a token never rescues a hard DENY | Rotate `GOVERNANCE_APPROVAL_SECRET`; move minting behind a real review service with its own authn |

## Additional notes

- **Batch confusion (ticket §10 test 9):** if any tool call in a multi-call
  response is DENY/REVIEW, the whole assistant turn is withheld — see
  `Enforcer` (`worst = max(... severity ...)`) and `test_batch_one_deny_blocks_whole_turn`.
- **Silent re-plan abuse (ticket §13):** every DENY is fully audited with the
  user-facing message and `replan_attempt`; the auto loop stops after
  `REPLAN_MAX_ATTEMPTS` or a repeated coarse reason code.
- **Streaming bypass:** `stream:true` responses are buffered in
  `async_post_call_streaming_iterator_hook` and run through the same pipeline
  before any chunk reaches the client; a DENY replaces the raw tool-call stream
  with a synthetic assistant stream. `ALLOW_UNGOVERNED_STREAMING=1` disables
  this and is off by default.
- **Default-harness assumption:** `GATEWAY_DEFAULT_HARNESS` lets an unmodified
  harness that sends no `metadata.harness_type` still be governed as the one
  harness this gateway fronts (operator declaration, network-isolated to that
  harness). An explicit but wrong `harness_type` is still DENied as
  `UNKNOWN_HARNESS` (`test_unknown_harness_tool_call_denied`).
- **Dashboard exposure:** read-only, localhost-bound, shows only already-redacted
  audit columns (PLAN §E).
- **Supply chain:** LiteLLM pinned to `v1.89.3` (post the compromised
  1.82.7/1.82.8 range); all images pinned; see `docs/versions.md`.
