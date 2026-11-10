#!/usr/bin/env bash
# DCISO execution-side PEP — Hermes `pre_tool_call` shell hook.
#
# stdin  : Hermes pre_tool_call JSON  {hook_event_name, tool_name, tool_input,
#          session_id, cwd, extra}
# stdout : decision JSON  —  {} = allow | {"action":"block","message":…}
#          | {"action":"modify","args":{…}}
# exit 2 : also signals block (honoured even if stdout is ignored)
#
# Configured with `fail_closed: true`, so if THIS script errors Hermes blocks
# the tool anyway. We still block explicitly on transport failure for a clean
# message.
set -uo pipefail

PEP_URL="${DCISO_PEP_URL:-http://127.0.0.1:8710/govern}"
payload="$(cat -)"

resp="$(curl -s --max-time 8 -H 'Content-Type: application/json' \
        --data-binary "$payload" "$PEP_URL" 2>/dev/null)"
if [ $? -ne 0 ] || [ -z "$resp" ]; then
  # transport failure -> fail closed with a readable reason
  printf '{"action":"block","message":"治理服務不可達，工具執行前攔截失敗（fail closed）"}\n'
  exit 2
fi

printf '%s\n' "$resp"

# make the block authoritative regardless of how the host reads stdout
case "$resp" in
  *'"action"'*'"block"'*|*'"action": "block"'*) exit 2 ;;
  *) exit 0 ;;
esac
