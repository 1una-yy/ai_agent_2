# Governance Gateway = LiteLLM proxy + our interception callback.
# Pin the LiteLLM image (verified 2026-09-01: v1.89.3 == main-stable; avoids the
# compromised 1.82.7/1.82.8 range). Pin by digest at build for full repro.
FROM ghcr.io/berriai/litellm:v1.89.3@sha256:8f3517476b8293ccc1c3b0da7940d8dabbfe64b013454113f5a3cb68265c439b

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AUDIT_DB_PATH=/data/audit.sqlite

WORKDIR /app

# Governance core + callback. LiteLLM's image already ships pydantic v2 + httpx;
# we do not reinstall them to avoid version skew inside the proxy.
COPY gateway/ /app/gateway/

# LiteLLM resolves `callbacks:` in the config as a path RELATIVE TO THE CONFIG
# FILE'S DIRECTORY. Keep the config at /app so `gateway.callbacks.governance_callback`
# resolves to /app/gateway/callbacks/governance_callback.py (not /app/gateway/gateway/...).
COPY gateway/config.yaml /app/config.yaml

# Writable audit volume mount point.
RUN mkdir -p /data && chmod +x /app/gateway/entrypoint.sh

EXPOSE 4000
HEALTHCHECK --interval=10s --timeout=4s --retries=6 --start-period=45s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness').status==200 else 1)" || exit 1

ENTRYPOINT ["/app/gateway/entrypoint.sh"]
