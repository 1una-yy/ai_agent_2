#!/usr/bin/env bash
# "PLUG IN" the governance layer (ticket §9E). Point a Hermes profile at the
# Governance Gateway as a custom OpenAI-compatible endpoint — WITHOUT touching
# Hermes source. Everything it changes lives in $HERMES_HOME and is backed up so
# disable-routing.sh restores it exactly.
#
# Env in:  HERMES_HOME (default ~/.hermes)
#          GATEWAY_URL  (default http://127.0.0.1:4000/v1)
#          GATEWAY_MASTER_KEY  (the token Hermes uses to reach the gateway)
set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:4000/v1}"
GATEWAY_TOKEN="${GATEWAY_MASTER_KEY:-hermes-to-gateway-token-CHANGE_ME}"
MODEL_ALIAS="${GATEWAY_MODEL_ALIAS:-governed-model}"

ENV_FILE="$HERMES_HOME/.env"
CFG_FILE="$HERMES_HOME/config.yaml"
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$HERMES_HOME"
touch "$ENV_FILE"

# --- back up once (first plug), keep the pristine copy -----------------------
[ -f "$HERMES_HOME/.env.pre-dciso-backup" ]      || cp "$ENV_FILE" "$HERMES_HOME/.env.pre-dciso-backup"
if [ -f "$CFG_FILE" ]; then
  [ -f "$HERMES_HOME/config.yaml.pre-dciso-backup" ] || cp "$CFG_FILE" "$HERMES_HOME/config.yaml.pre-dciso-backup"
else
  # remember that there was no config so unplug can delete ours
  [ -f "$HERMES_HOME/.dciso-no-config-before" ] || : > "$HERMES_HOME/.dciso-no-config-before"
fi

# --- .env: only the gateway token, and scrub any real provider keys ---------
TMP="$(mktemp)"
grep -Ev '^(OPENAI_BASE_URL|OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|GROQ_API_KEY|MISTRAL_API_KEY|XAI_API_KEY|DEEPSEEK_API_KEY|NOUS_API_KEY|GLM_API_KEY|KIMI_API_KEY)=' "$ENV_FILE" > "$TMP" || true
{
  echo "# --- injected by dciso enable-routing.sh ($STAMP) ---"
  echo "OPENAI_BASE_URL=$GATEWAY_URL"
  echo "OPENAI_API_KEY=$GATEWAY_TOKEN"
} >> "$TMP"
mv "$TMP" "$ENV_FILE"

# --- model config: custom OpenAI-compatible endpoint = the gateway ----------
# (Hermes: `provider: custom` + `base_url` makes it call the endpoint directly,
#  using `api_key` / OPENAI_API_KEY for auth. Confirmed against Hermes v0.21.)
if command -v hermes >/dev/null 2>&1; then
  HERMES_HOME="$HERMES_HOME" hermes config set model.provider custom      >/dev/null
  HERMES_HOME="$HERMES_HOME" hermes config set model.default  "$MODEL_ALIAS" >/dev/null
  HERMES_HOME="$HERMES_HOME" hermes config set model.base_url "$GATEWAY_URL"  >/dev/null
  HERMES_HOME="$HERMES_HOME" hermes config set model.api_key  "$GATEWAY_TOKEN" >/dev/null
  # Optionally expose the full toolset to the model (DCISO_FORCE_FULL_TOOLSET=1,
  # set by `dciso plug --isolated`). Useful with a weak model + few tools so it
  # actually proposes the tool you want denied. NOT done on a big real profile
  # (would push dozens of tools/skills into every prompt).
  if [ "${DCISO_FORCE_FULL_TOOLSET:-0}" = "1" ]; then
    HERMES_HOME="$HERMES_HOME" hermes config set tools.tool_search.enabled off >/dev/null 2>&1 || true
    echo "[enable] model routed (tool_search disabled — full toolset visible)"
  else
    echo "[enable] model routed via 'hermes config set' (tool_search left as-is)"
  fi
else
  # no hermes binary: write the model block into config.yaml directly.
  cp "$CFG_FILE" "$CFG_FILE.dciso-prev-$STAMP" 2>/dev/null || true
  python3 - "$CFG_FILE" "$MODEL_ALIAS" "$GATEWAY_URL" "$GATEWAY_TOKEN" <<'PY'
import sys, io
path, alias, url, key = sys.argv[1:5]
try:
    import yaml
except ImportError:
    yaml = None
data = {}
try:
    with open(path) as fh:
        text = fh.read()
    data = (yaml.safe_load(text) if yaml else {}) or {}
except FileNotFoundError:
    text = ""
if yaml is None and text.strip():
    print("[enable] PyYAML missing and config.yaml non-empty — edit model: block by hand", file=sys.stderr)
    sys.exit(1)
data.setdefault("model", {})
if not isinstance(data["model"], dict):
    data["model"] = {}
data["model"].update({"provider": "custom", "default": alias, "base_url": url, "api_key": key})
with open(path, "w") as fh:
    if yaml:
        yaml.safe_dump(data, fh, sort_keys=False, default_flow_style=False)
    else:
        fh.write("model:\n  provider: custom\n  default: %s\n  base_url: %s\n  api_key: %s\n" % (alias, url, key))
PY
  echo "[enable] model routed by writing $CFG_FILE"
fi

# --- optional Layer-2 hook: govern the ACTUAL tool execution ----------------
# DCISO_INSTALL_EXEC_HOOK=1 (dciso plug --exec-pep). Adds a `pre_tool_call`
# shell hook that calls the execution PEP before Hermes runs any tool.
if [ "${DCISO_INSTALL_EXEC_HOOK:-0}" = "1" ]; then
  HOOK_SRC="$(cd "$(dirname "$0")/.." && pwd)/hermes-hook/dciso-precall-hook.sh"
  mkdir -p "$HERMES_HOME/agent-hooks"
  cp "$HOOK_SRC" "$HERMES_HOME/agent-hooks/dciso-precall-hook.sh"
  chmod +x "$HERMES_HOME/agent-hooks/dciso-precall-hook.sh"
  python3 - "$CFG_FILE" "$HERMES_HOME/agent-hooks/dciso-precall-hook.sh" <<'PY'
import sys
path, hook = sys.argv[1:3]
try:
    import yaml
except ImportError:
    print("[enable] PyYAML missing — add the hooks: block to config.yaml by hand", file=sys.stderr); sys.exit(1)
try:
    data = (yaml.safe_load(open(path)) if __import__("os").path.exists(path) else {}) or {}
except Exception:
    data = {}
data["hooks_auto_accept"] = True   # no interactive consent prompt for our hook
hooks = data.setdefault("hooks", {})
entry = {"matcher": ".*", "command": hook, "timeout": 10, "fail_closed": True}
lst = hooks.get("pre_tool_call")
if not isinstance(lst, list):
    lst = []
lst = [e for e in lst if not (isinstance(e, dict) and str(e.get("command", "")).endswith("dciso-precall-hook.sh"))]
lst.append(entry)
hooks["pre_tool_call"] = lst
yaml.safe_dump(data, open(path, "w"), sort_keys=False, default_flow_style=False)
PY
  echo "[enable] Layer-2 execution hook installed (pre_tool_call -> execution PEP, fail-closed)"
fi

echo "[enable] HERMES_HOME = $HERMES_HOME"
echo "[enable] routed to    = $GATEWAY_URL   (model: $MODEL_ALIAS, provider: custom)"
if grep -Eq '^(ANTHROPIC_API_KEY|OPENROUTER_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|GROQ_API_KEY|NOUS_API_KEY)=' "$ENV_FILE"; then
  echo "[enable] !! a real provider key is still in $ENV_FILE — remove it (Hermes could bypass the gateway)"; exit 1
fi
echo "[enable] no real provider key in the profile — Hermes can only reach the gateway."
echo "[enable] test:  HERMES_HOME=$HERMES_HOME hermes chat -q 'say GOVERNED_OK'"
echo "[enable] undo:  ./hermes/disable-routing.sh   (or: dciso unplug)"
