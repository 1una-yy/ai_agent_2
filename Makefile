# DCISO Governance Gateway — task runner.
# `make help` for the list. Requires: docker (compose v2). Tests also need
# `opa` on PATH and a Python env with tests/requirements.txt.

SHELL := /bin/sh
COMPOSE := docker compose

# Auto-detect a local venv / vendored opa (from `make bootstrap`); override with
#   make test PY=python3 OPA=opa
PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
OPA ?= $(if $(wildcard .tools/opa),./.tools/opa,opa)
GW_KEY = $(shell sed -n 's/^GATEWAY_MASTER_KEY=//p' .env 2>/dev/null)
export OPA_BIN = $(OPA)
export GATEWAY_MASTER_KEY ?= $(GW_KEY)

.DEFAULT_GOAL := help

.PHONY: help
help: ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
	 awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- run (test mode)
.PHONY: build up down restart logs ps
build: ## build all images
	$(COMPOSE) build

up: ## start the stack in TEST mode (offline mock-llm)
	GATEWAY_ROUTE_MODE=test $(COMPOSE) up -d --build
	@echo "gateway  : http://127.0.0.1:4000  (key: $${GATEWAY_MASTER_KEY:-hermes-to-gateway-token-CHANGE_ME})"
	@echo "dashboard: http://127.0.0.1:8900"

down: ## stop the stack (keep audit volume)
	$(COMPOSE) down

restart: down up ## restart

logs: ## follow logs
	$(COMPOSE) logs -f --tail=100

ps: ## container status
	$(COMPOSE) ps

# ---------------------------------------------------------------- run (demo mode)
.PHONY: demo-up demo-down
demo-up: ## start the stack in DEMO mode (real OpenAI + LLM CISO; needs OPENAI_API_KEY in .env)
	GATEWAY_ROUTE_MODE=demo CISO_MODE=llm $(COMPOSE) up -d --build
	@echo "DEMO mode: gateway routes to real OpenAI. dashboard: http://127.0.0.1:8900"

demo-down: down ## stop demo stack

# ---------------------------------------------------------------- dashboard
.PHONY: dashboard
dashboard: ## print the dashboard URL (open it in a browser)
	@echo "http://127.0.0.1:8900"

# ---------------------------------------------------------------- tests
.PHONY: bootstrap test test-opa test-py
bootstrap: ## one-time host setup for tests: .venv + vendored opa (no docker needed)
	python3 -m venv .venv
	./.venv/bin/pip -q install -r tests/requirements.txt
	@mkdir -p .tools
	@test -x .tools/opa || (echo "downloading opa 1.19.0..." && \
	  curl -fsSL -o .tools/opa https://openpolicyagent.org/downloads/v1.19.0/opa_linux_amd64_static && \
	  chmod +x .tools/opa)
	@echo "bootstrap done — now: make test"

test: test-opa test-py ## run all tests (OPA + Python)

test-opa: ## run the Rego unit tests
	$(OPA) fmt --list policy/ | (grep . && (echo "rego not formatted; run: opa fmt -w policy/" && exit 1) || true)
	$(OPA) check --strict policy/
	$(OPA) test policy/ -v

test-py: ## run the Python unit + integration tests (real-OPA tests need `opa` on PATH or $OPA_BIN)
	$(PY) -m pytest -q

.PHONY: e2e sample-evidence
e2e: ## live end-to-end checks (stack must be up: `make up`)
	tests/e2e/run-e2e.sh

sample-evidence: ## regenerate docs/sample-evidence.jsonl from the real pipeline
	$(PY) demo/gen-sample-evidence.py

# ---------------------------------------------------------------- demos
.PHONY: demo-safe demo-deny demo-delegate
demo-safe: ## scenario: plain chat, no tool call -> ALLOW
	./demo/run-safe-request.sh

demo-deny: ## scenario: model proposes external PHI transfer -> DENY
	./demo/run-denied-tool-call.sh

demo-delegate: ## scenario: over-ceiling delegation -> MODIFY / REQUIRE_REVIEW
	./demo/run-delegation-review.sh

# ---------------------------------------------------------------- smoke / clean
.PHONY: smoke clean
smoke: ## quick end-to-end curl through the gateway (test mode)
	@curl -s http://127.0.0.1:4000/health/readiness | head -c 400; echo
	@curl -s http://127.0.0.1:4000/v1/chat/completions \
	  -H "Authorization: Bearer $${GATEWAY_MASTER_KEY:-hermes-to-gateway-token-CHANGE_ME}" \
	  -H "Content-Type: application/json" \
	  -d '{"model":"governed-model","messages":[{"role":"user","content":"just say hi, no tools"}]}' | head -c 800; echo

clean: ## stop and DELETE the audit volume
	$(COMPOSE) down -v
