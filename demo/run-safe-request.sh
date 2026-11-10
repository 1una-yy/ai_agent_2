#!/usr/bin/env bash
# DEMO 1 — plain conversation, no tool call -> ALLOW, response passes through.
set -euo pipefail
cd "$(dirname "$0")/.."
. demo/_common.sh

echo "== DEMO: safe request (expect ALLOW) =="
resp="$(call "demo-safe-$(date +%s)" "[[scenario:safe]] Summarise our meeting in one line, no tools please.")"
echo "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"

echo
if echo "$resp" | grep -Eq '"role": *"assistant"' \
   && ! echo "$resp" | grep -Eq '"finish_reason": *"tool_calls"|DENIED'; then
  echo "PASS: plain assistant content returned unchanged (ALLOW passthrough)"
else
  echo "CHECK: inspect the response above"
fi
show_last_event
