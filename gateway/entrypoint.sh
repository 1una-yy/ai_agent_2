#!/bin/sh
# Resolve the upstream the Gateway routes `governed-model` to.
#   GATEWAY_ROUTE_MODE=test   -> local mock-llm (offline, deterministic)
#   GATEWAY_ROUTE_MODE=demo   -> real OpenAI (needs OPENAI_API_KEY)
#   GATEWAY_ROUTE_MODE=gemini -> real Google Gemini (needs GEMINI_API_KEY)
#   GATEWAY_ROUTE_MODE=proxy  -> a real model via a `hermes proxy` login
#                               (OAuth; no static API key). See docs/real-model-with-login.md
set -eu

MODE="${GATEWAY_ROUTE_MODE:-test}"

if [ "$MODE" = "demo" ]; then
  : "${OPENAI_API_KEY:?demo mode requires OPENAI_API_KEY in the Gateway env}"
  export GATEWAY_UPSTREAM_MODEL="${GATEWAY_UPSTREAM_MODEL:-openai/gpt-4o}"
  export GATEWAY_UPSTREAM_API_BASE="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
  export GATEWAY_UPSTREAM_API_KEY="$OPENAI_API_KEY"
  echo "[gateway] route mode=demo upstream=$GATEWAY_UPSTREAM_MODEL base=$GATEWAY_UPSTREAM_API_BASE"
elif [ "$MODE" = "gemini" ]; then
  # LiteLLM's native `gemini/` provider talks to Google's API directly (not an
  # OpenAI-compatible /v1 endpoint) — it resolves its own endpoint from the
  # model prefix, so NO api_base override is set here (an inherited empty
  # GATEWAY_UPSTREAM_API_BASE would otherwise get passed straight through
  # config.yaml's litellm_params and could misroute the request).
  : "${GEMINI_API_KEY:?gemini mode requires GEMINI_API_KEY in the Gateway env}"
  export GATEWAY_UPSTREAM_MODEL="${GATEWAY_UPSTREAM_MODEL:-gemini/gemini-3.8-flash}"
  export GATEWAY_UPSTREAM_API_BASE=""
  export GATEWAY_UPSTREAM_API_KEY="$GEMINI_API_KEY"
  echo "[gateway] route mode=gemini upstream=$GATEWAY_UPSTREAM_MODEL"
elif [ "$MODE" = "proxy" ]; then
  # `hermes proxy` runs on the host and attaches the real OAuth credential
  # upstream; it ignores the bearer we send.
  export GATEWAY_UPSTREAM_MODEL="${UPSTREAM_MODEL:-openai/Hermes-4-70B}"
  export GATEWAY_UPSTREAM_API_BASE="${HERMES_PROXY_URL:-http://host.docker.internal:8645/v1}"
  export GATEWAY_UPSTREAM_API_KEY="sk-unused-proxy-attaches-real"
  echo "[gateway] route mode=proxy upstream=$GATEWAY_UPSTREAM_MODEL via $GATEWAY_UPSTREAM_API_BASE"
elif [ "$MODE" = "ollama" ]; then
  # A LAN / local Ollama server. LiteLLM's ollama_chat/ provider speaks Ollama's
  # /api/chat and translates tool calls. api_base has NO /v1 suffix.
  : "${OLLAMA_BASE_URL:?ollama mode requires OLLAMA_BASE_URL (e.g. http://192.168.1.10:11434)}"
  _m="${OLLAMA_MODEL:-gpt-oss:120b}"
  case "$_m" in ollama_chat/*|ollama/*) : ;; *) _m="ollama_chat/$_m" ;; esac
  export GATEWAY_UPSTREAM_MODEL="$_m"
  export GATEWAY_UPSTREAM_API_BASE="${OLLAMA_BASE_URL%/}"
  export GATEWAY_UPSTREAM_API_KEY="ollama-unused"
  echo "[gateway] route mode=ollama upstream=$GATEWAY_UPSTREAM_MODEL via $GATEWAY_UPSTREAM_API_BASE"

  # Let the GOVERNED client pick among any tool-capable model on this SAME
  # on-prem Ollama server, not just $OLLAMA_MODEL — every generated entry is
  # still pinned to this one api_base/api_key, so this only widens model
  # CHOICE, never the set of reachable endpoints; every request is still
  # intercepted by governance_callback regardless of which entry matched.
  # Set OLLAMA_EXPOSE_ALL_MODELS=0 to keep only the single fixed model.
  # NB: the generated file MUST live next to config.yaml (i.e. in /app) —
  # LiteLLM resolves `callbacks:` relative to the config file's own
  # directory, so writing this to /tmp would break the
  # gateway.callbacks.governance_callback import and silently run ungoverned.
  if [ "${OLLAMA_EXPOSE_ALL_MODELS:-1}" != "0" ]; then
    if python3 /app/gateway/gen_ollama_model_list.py \
         --base "$GATEWAY_UPSTREAM_API_BASE" \
         --template /app/config.yaml \
         --out /app/config.generated.yaml \
         --default-model "$GATEWAY_UPSTREAM_MODEL"; then
      CONFIG_FILE=/app/config.generated.yaml
    else
      echo "[gateway] model-list generation failed — continuing with only the fixed default model" >&2
    fi
  fi
else
  export GATEWAY_UPSTREAM_MODEL="openai/mock-governed-model"
  export GATEWAY_UPSTREAM_API_BASE="${MOCK_LLM_BASE:-http://mock-llm:8080/v1}"
  export GATEWAY_UPSTREAM_API_KEY="sk-mock-not-a-secret"
  echo "[gateway] route mode=test upstream=mock-llm ($GATEWAY_UPSTREAM_API_BASE)"
fi

exec litellm --config "${CONFIG_FILE:-/app/config.yaml}" --host 0.0.0.0 --port 4000
