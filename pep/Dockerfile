# Execution-side PEP. Reuses the gateway governance core.
FROM python:3.12-slim@sha256:e5c9fa26ffb76e11e0f054f30dc2523a2f9693f0c36c0cf1e39b27e152d899fc
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app AUDIT_DB_PATH=/data/audit.sqlite
WORKDIR /app
COPY pep/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gateway/ /app/gateway/
COPY pep/ /app/pep/
RUN mkdir -p /data
# Runs as root to share the append-only audit volume with the gateway (same as
# the LiteLLM proxy container). Internal, localhost-published only.
EXPOSE 8710
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8710/health/liveness').status==200 else 1)"
CMD ["uvicorn", "pep.app:app", "--host", "0.0.0.0", "--port", "8710"]
