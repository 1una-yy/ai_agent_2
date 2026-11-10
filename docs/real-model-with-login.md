# Use a real model via your login (no API key)

If you sign in to a provider (Nous Portal, xAI) instead of holding a static API
key, route the gateway through **`hermes proxy`** — a local OpenAI-compatible
server that attaches your real OAuth credential upstream.

```
Business Hermes ──► Gateway (:4000) ──► hermes proxy (:8645, your login) ──► real model
CISO advisor    ──► Gateway ─────────────► (same proxy, if --ciso-llm)
```

The real credential lives only in `hermes proxy` on your machine. The Business
Hermes still holds nothing but the gateway token.

## Steps

```bash
cd dciso-governance-gateway
./install.sh                      # once: docker check, .env, secrets

./bin/dciso login                 # opens Nous Portal OAuth (or: dciso login xai)
./bin/dciso proxy status          # should show "ready"

./bin/dciso up-proxy              # starts the proxy + the stack, routed through it
./bin/dciso proxy models          # the model ids your account can use (look for :free)

./bin/dciso plug                  # point your Hermes at the gateway
hermes chat -q "explain least privilege in one line"     # real answer, governed
hermes chat -q "run the shell command: whoami"           # denied, command withheld
```

Dashboard: <http://127.0.0.1:8900>. Stop: `./bin/dciso proxy stop && ./bin/dciso down`.

## Choosing models

`dciso proxy models` lists the ids. The value the gateway needs is
**double-prefixed** — `openai/` (so LiteLLM uses its OpenAI-compatible handler)
plus the proxy's own id:

```
UPSTREAM_MODEL=openai/upstage/solar-pro4:free        # in .env, or:
GATEWAY_ROUTE_MODE=proxy UPSTREAM_MODEL=openai/<id> ./bin/dciso up-proxy
```

- **Business model**: pick a capable one that does tool-calling. Paid ids need
  Portal credits; `:free` ids work on any account (they are weaker/slower).
- **CISO advisor**: defaults to the deterministic **rule engine** (`CISO_MODE=rule`)
  even in proxy mode — it is fast and reliable. Add `--ciso-llm` to
  `up-proxy` to make the CISO a real LLM too (needs a decent model; weak free
  models over-block).

## Notes

- `hermes proxy` binds `0.0.0.0:8645` so the gateway container can reach it via
  `host.docker.internal` (compose adds the `extra_hosts` mapping).
- If a request fails with *"requires available credits"*, your Portal balance is
  zero for that model — switch to a `:free` id.
- If it fails with *"not logged in"* / *"credentials need attention"*, re-run
  `./bin/dciso login`.
- A tool name the policy doesn't recognise is denied as `UNKNOWN_TOOL`
  (fail-closed). Common shell/write/db/secret/egress names are already mapped in
  `policy/data.json`; add more there (OPA hot-reloads with `--watch`).
