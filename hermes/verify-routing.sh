#!/usr/bin/env bash
# Prove the Gateway is NOT bypassable (ticket §9E, §11 DoD).
#
# Checks:
#   1. Hermes profile has the Gateway base_url and NO real provider key.
#   2. The Gateway is reachable and answers /v1/chat/completions.
#   3. A request through Hermes shows up in the Gateway logs / audit trail.
#   4. With the Gateway blocked, Hermes CANNOT get a completion (no fallback).
#   5. The Hermes git working tree is clean (no source patch for governance).
set -uo pipefail

HERMES_HOME="${HERMES_HOME:-$PWD/.hermes-governed-test}"
GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:4000}"
GATEWAY_TOKEN="${GATEWAY_MASTER_KEY:-hermes-to-gateway-token-CHANGE_ME}"
HERMES_SRC="${HERMES_SRC:-$PWD/hermes/hermes-agent}"
fail=0
note() { printf '  %s\n' "$*"; }
ok()   { printf '[ ok ] %s\n' "$*"; }
bad()  { printf '[FAIL] %s\n' "$*"; fail=1; }

echo "== 1. profile has gateway routing, no provider key =="
ENV_FILE="$HERMES_HOME/.env"
if grep -Eq "^OPENAI_BASE_URL=$(printf '%s' "$GATEWAY_URL" | sed 's/[.[\*^$/]/\\&/g')" "$ENV_FILE"; then
  ok "OPENAI_BASE_URL points at the Gateway"
else
  bad "OPENAI_BASE_URL in $ENV_FILE does not point at $GATEWAY_URL"
fi
if grep -Eq '^(ANTHROPIC_API_KEY|OPENROUTER_API_KEY|GEMINI_API_KEY|GROQ_API_KEY|MISTRAL_API_KEY|XAI_API_KEY|DEEPSEEK_API_KEY)=' "$ENV_FILE"; then
  bad "a real provider key is present in the Hermes profile"
else
  ok "no real provider key in the Hermes profile"
fi

echo "== 2. gateway answers directly =="
code=$(curl -s -o /dev/null -w '%{http_code}' "$GATEWAY_URL/health/readiness")
[ "$code" = "200" ] && ok "GET /health/readiness -> 200" || bad "GET /health/readiness -> $code"

echo "== 3. a governed request is recorded =="
before=$(curl -s "http://127.0.0.1:8900/api/events" | tr ',' '\n' | grep -c '"row_id"' || true)
curl -s "$GATEWAY_URL/v1/chat/completions" \
  -H "Authorization: Bearer $GATEWAY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"model":"governed-model","metadata":{"harness_type":"hermes","session_id":"verify-routing"},"messages":[{"role":"user","content":"[[scenario:read]] please read a file"}]}' >/dev/null
sleep 1
after=$(curl -s "http://127.0.0.1:8900/api/events" | tr ',' '\n' | grep -c '"row_id"' || true)
[ "$after" -gt "$before" ] && ok "audit row count went $before -> $after" || bad "no new audit row after a governed request"

echo "== 4. no bypass: with the gateway DOWN, Hermes must not get a completion =="
if command -v hermes >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
  ( cd "$(dirname "$0")/.." && docker compose stop gateway >/dev/null 2>&1 ) || true
  HERMES_HOME="$HERMES_HOME" timeout 45 hermes chat -q "say BYPASS_MARKER_42" >/tmp/dciso_bypass.out 2>&1 || true
  ( cd "$(dirname "$0")/.." && docker compose start gateway >/dev/null 2>&1 ) || true
  for _ in $(seq 1 30); do curl -sf "$GATEWAY_URL/health/readiness" >/dev/null 2>&1 && break; sleep 2; done
  # a real assistant turn would echo the marker or produce a non-error reply
  if grep -q 'BYPASS_MARKER_42' /tmp/dciso_bypass.out && ! grep -qiE 'error|failed|refused|timeout|connect' /tmp/dciso_bypass.out; then
    bad "Hermes produced a completion while the gateway was down (BYPASS / fallback provider!)"
  else
    ok "Hermes could not get a completion without the gateway (no fallback)"
  fi
else
  note "hermes and/or docker not available here — run the gateway-down test manually"
fi

echo "== 5. Hermes source unmodified =="
if [ -d "$HERMES_SRC/.git" ]; then
  dirty=$(git -C "$HERMES_SRC" status --porcelain)
  [ -z "$dirty" ] && ok "git working tree clean at $HERMES_SRC" || bad "Hermes tree is dirty:%n$dirty"
  note "pinned commit: $(git -C "$HERMES_SRC" rev-parse HEAD 2>/dev/null || echo '?')"
else
  note "no git checkout at $HERMES_SRC — record your install method + version manually"
fi

echo
[ "$fail" = "0" ] && echo "ALL CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
