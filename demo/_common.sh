# shared helpers for demo scripts
GATEWAY="${GATEWAY_URL:-http://127.0.0.1:4000}"
TOKEN="${GATEWAY_MASTER_KEY:-hermes-to-gateway-token-CHANGE_ME}"
DASH="${DASHBOARD_URL:-http://127.0.0.1:8900}"

# call SESSION USER_CONTENT [EXTRA_DCISO_JSON]
#   EXTRA_DCISO_JSON is merged into metadata.dciso, e.g.
#   '{"task":{"data_classification":["PHI"]},"governance":{"capability_level":"C2"}}'
call() {
  local extra="${3:-}"; [ -z "$extra" ] && extra='{}'
  curl -s "$GATEWAY/v1/chat/completions" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "$(cat <<JSON
{
  "model": "governed-model",
  "metadata": {
    "harness_type": "hermes",
    "harness_instance_id": "hermes-demo-01",
    "session_id": "$1",
    "dciso": $extra
  },
  "messages": [{"role": "user", "content": "$2"}]
}
JSON
)"
}

show_last_event() {
  echo
  echo "--- latest audited decisions (newest first) ---"
  curl -s "$DASH/api/events" | python3 -c "import sys,json;[print(f\"{e['ts_rfc3339']}  {e['outcome']:15s} {e['canonical_name']:14s} {e['reason_codes']}\") for e in json.load(sys.stdin)['events'][:6]]" 2>/dev/null \
    || curl -s "$DASH/api/events" | head -c 800
  echo
  echo "Dashboard: $DASH"
}
