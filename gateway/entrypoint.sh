#!/bin/sh
# Resolve the upstream the Gateway routes `governed-model` to.
#   GATEWAY_ROUTE_MODE=test  -> local mock-llm (offline, deterministic)
#   GATEWAY_ROUTE_MODE=demo  -> real OpenAI (needs OPENAI_API_KEY)
#   GATEWAY_ROUTE_MODE=proxy -> a real model via a `hermes proxy` login
#                               (OAuth; no static API key). See docs/real-model-with-login.md
set -eu

MODE="${GATEWAY_ROUTE_MODE:-test}"

if [ "$MODE" = "demo" ]; then
  : "${OPENAI_API_KEY:?demo mode requires OPENAI_API_KEY in the Gateway env}"
  export GATEWAY_UPSTREAM_MODEL="${GATEWAY_UPSTREAM_MODEL:-openai/gpt-4o}"
  export GATEWAY_UPSTREAM_API_BASE="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
  export GATEWAY_UPSTREAM_API_KEY="$OPENAI_API_KEY"
  echo "[gateway] route mode=demo upstream=$GATEWAY_UPSTREAM_MODEL base=$GATEWAY_UPSTREAM_API_BASE"
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
else
  export GATEWAY_UPSTREAM_MODEL="openai/mock-governed-model"
  export GATEWAY_UPSTREAM_API_BASE="${MOCK_LLM_BASE:-http://mock-llm:8080/v1}"
  export GATEWAY_UPSTREAM_API_KEY="sk-mock-not-a-secret"
  echo "[gateway] route mode=test upstream=mock-llm ($GATEWAY_UPSTREAM_API_BASE)"
fi

exec litellm --config /app/config.yaml --host 0.0.0.0 --port 4000
