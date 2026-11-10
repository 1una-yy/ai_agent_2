#!/usr/bin/env bash
# "PULL OUT" the governance layer (ticket §9E). Restore the Hermes profile to
# exactly what it was before the first `enable-routing.sh` — both .env and
# config.yaml. Hermes source is never touched, so removing governance is just
# this.
#
# Env in:  HERMES_HOME (default ~/.hermes)
set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
ENV_FILE="$HERMES_HOME/.env"
CFG_FILE="$HERMES_HOME/config.yaml"
ENV_BAK="$HERMES_HOME/.env.pre-dciso-backup"
CFG_BAK="$HERMES_HOME/config.yaml.pre-dciso-backup"
STAMP="$(date +%s)"
restored=0

if [ -f "$ENV_BAK" ]; then
  cp "$ENV_FILE" "$ENV_FILE.dciso-removed-$STAMP" 2>/dev/null || true
  mv "$ENV_BAK" "$ENV_FILE"
  echo "[disable] restored $ENV_FILE"
  restored=1
else
  # no backup: just strip the injected lines
  if [ -f "$ENV_FILE" ]; then
    TMP="$(mktemp)"
    grep -Ev '^(OPENAI_BASE_URL|OPENAI_API_KEY)=|^# --- injected by dciso' "$ENV_FILE" > "$TMP" || true
    mv "$TMP" "$ENV_FILE"
    echo "[disable] stripped gateway lines from $ENV_FILE (no backup found)"
  fi
fi

if [ -f "$CFG_BAK" ]; then
  cp "$CFG_FILE" "$CFG_FILE.dciso-removed-$STAMP" 2>/dev/null || true
  mv "$CFG_BAK" "$CFG_FILE"
  echo "[disable] restored $CFG_FILE"
  restored=1
elif [ -f "$HERMES_HOME/.dciso-no-config-before" ]; then
  # there was no config.yaml before we plugged in — remove the one we made
  [ -f "$CFG_FILE" ] && mv "$CFG_FILE" "$CFG_FILE.dciso-removed-$STAMP"
  rm -f "$HERMES_HOME/.dciso-no-config-before"
  echo "[disable] removed the config.yaml that plug created (there was none before)"
  restored=1
elif command -v hermes >/dev/null 2>&1 && [ -f "$CFG_FILE" ]; then
  # last resort: clear just the model routing keys we set
  for k in model.base_url model.api_key; do
    HERMES_HOME="$HERMES_HOME" hermes config unset "$k" >/dev/null 2>&1 || true
  done
  HERMES_HOME="$HERMES_HOME" hermes config set model.provider auto >/dev/null 2>&1 || true
  echo "[disable] cleared gateway model keys via 'hermes config'"
fi

if grep -Eq '^OPENAI_BASE_URL=.*127\.0\.0\.1:4000' "$ENV_FILE" 2>/dev/null \
   || grep -Eq '127\.0\.0\.1:4000' "$CFG_FILE" 2>/dev/null; then
  echo "[disable] !! gateway routing still present — check $ENV_FILE / $CFG_FILE by hand"; exit 1
fi
# remove the Layer-2 execution hook script (config.yaml restore already drops
# the hooks: entry; also strip it if the restore path didn't run)
rm -f "$HERMES_HOME/agent-hooks/dciso-precall-hook.sh" 2>/dev/null || true
if [ -f "$CFG_FILE" ] && grep -q 'dciso-precall-hook.sh' "$CFG_FILE" 2>/dev/null && command -v python3 >/dev/null 2>&1; then
  python3 - "$CFG_FILE" <<'PY' 2>/dev/null || true
import sys
try:
    import yaml
    p = sys.argv[1]; d = yaml.safe_load(open(p)) or {}
    h = d.get("hooks", {})
    if isinstance(h.get("pre_tool_call"), list):
        h["pre_tool_call"] = [e for e in h["pre_tool_call"]
                              if not str((e or {}).get("command", "")).endswith("dciso-precall-hook.sh")]
        if not h["pre_tool_call"]:
            h.pop("pre_tool_call", None)
        if not h:
            d.pop("hooks", None)
    yaml.safe_dump(d, open(p, "w"), sort_keys=False, default_flow_style=False)
except Exception:
    pass
PY
  echo "[disable] removed the Layer-2 execution hook"
fi

[ "$restored" = 1 ] || echo "[disable] nothing to restore (was it ever plugged?)"
echo "[disable] Hermes profile is back to its un-governed state."
echo "[disable] (put a real provider key back if you want Hermes to work standalone)"
