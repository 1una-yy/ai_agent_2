# Operating SOP

## Roles

| Role | May do | May NOT do |
|---|---|---|
| Policy maintainer | edit `policy/`, run `opa test`, review + merge, bump `policy_version` | — |
| Gateway operator | run compose, rotate `GATEWAY_MASTER_KEY`, read audit / dashboard | edit policy bundle |
| Business Hermes | call `governed-model` via the Gateway | reach a provider directly; write policy; read audit |
| CISO Advisor | return `SoftAdvice` JSON | allow/deny; write policy; terminal / DB / external messaging |

## Bring-up (test mode, offline)

```bash
cp .env.example .env            # edit GATEWAY_MASTER_KEY at least
make up                         # builds + starts opa, ciso-advisor, mock-llm, gateway, viewer
make smoke                      # curl a plain completion through the gateway
open http://127.0.0.1:8900      # dashboard
```

## Bring-up (demo mode, real OpenAI + LLM CISO)

```bash
# .env must contain a real OPENAI_API_KEY (used ONLY by the gateway + advisor)
make demo-up
```

## Plug Hermes in / pull it out

```bash
export HERMES_HOME="$PWD/.hermes-governed-test"
./hermes/enable-routing.sh                 # plug in  (writes gateway base_url + token only)
HERMES_HOME=$HERMES_HOME hermes chat -q "say HERMES_GATEWAY_OK"
./hermes/verify-routing.sh                 # prove no bypass, source unmodified
# ... run the workload ...
./hermes/disable-routing.sh                # pull out  (restores the profile)
```

## Health semantics

| Endpoint | Means |
|---|---|
| `GET :4000/health/liveliness` | gateway process is up |
| `GET :4000/health/readiness` | gateway can route |
| `GET ciso-advisor:9000/health/policy` | advisor mode is usable (rule always; llm needs a key) |
| `opa:8181` POST `/v1/data/dciso/governance` returns `result` | **the decision path is actually loaded** |
| `GET viewer:8900/health/policy` | audit DB is present |

Compose `depends_on` waits on the *policy-loaded* checks, not just liveness.

## Incident: a legitimate action is being denied

1. Open the dashboard → find the event → read `reason_codes` (raw) and the OPA
   `Decision`.
2. If policy is wrong: fix `policy/agent_governance.rego` / `data.json`, add a
   test, `make test-opa`, review, merge, redeploy OPA. Bump `policy_version`.
3. If it is a governance-service outage: `reason_codes` will contain
   `HARD_PDP_*` / `SOFT_ADVICE_UNAVAILABLE_*`. Restore the service; the user can
   retry. The session was never killed.

## Releasing a REQUIRE_REVIEW action

1. Dashboard → find the 409'd event → note `session_id`, the action
   (`canonical_name`) and its arguments (from `event_json.proposed_action`).
2. Confirm the human decision out of band.
3. Mint a token (same `GOVERNANCE_APPROVAL_SECRET` as the gateway):
   ```bash
   python demo/mint-approval.py --session <sid> --tool <canonical> \
       --args '<exact args json>' --ttl 900 --approver <you>
   ```
4. Ask the caller to resubmit the **same** request with
   `metadata.dciso.approval_token`. The release is audited as `ALLOW` +
   `HUMAN_APPROVED:approved_by:<you>`.
5. Tokens expire (default 15 min) and only match that one action.

## Rotating the Gateway token

Change `GATEWAY_MASTER_KEY` in `.env`, `make restart`, then re-run
`./hermes/enable-routing.sh` so the Hermes profile picks up the new token.

## Audit / evidence

- Store: SQLite at the `audit-data` volume (`/data/audit.sqlite`), INSERT-only
  in code. Columns: see `gateway/governance/audit.py` `_SCHEMA`.
- Export a decision: `GET http://127.0.0.1:8900/api/event/<event_id_or_row_id>`.
- Each row has `request_hash` + `response_hash` (sha-256 of the redacted bodies),
  `policy_version`, `reason_codes`, `soft_availability`, `latency_ms`,
  `error_class`, `replan_attempt`.
