"""gateway/gen_ollama_model_list.py — lets the GOVERNED client pick among
several on-prem Ollama models (not just the one fixed GATEWAY_UPSTREAM_MODEL),
without reopening "side-steppable by model name": every generated entry is
still pinned to the SAME api_base/api_key the operator configured, so only
the model id becomes client-choosable, never the endpoint/credentials.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPT = os.path.join(ROOT, "gateway", "gen_ollama_model_list.py")
TEMPLATE = os.path.join(ROOT, "gateway", "config.yaml")

_MOCK_MODELS = {
    "models": [
        {"name": "gpt-oss:120b", "capabilities": ["completion", "tools", "thinking"]},
        {"name": "qwen3.5:122b", "capabilities": ["vision", "completion", "tools", "thinking"]},
        {"name": "nomic-embed-text:latest", "capabilities": ["embedding"]},
        {"name": "gemma4:31b", "capabilities": ["completion", "tools", "thinking"]},
    ]
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib handler naming
        body = json.dumps(_MOCK_MODELS).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence stdlib access logs in test output
        pass


def _run(out_path: str, base: str, default_model: str = "ollama_chat/gpt-oss:120b") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, SCRIPT, "--base", base, "--template", TEMPLATE,
         "--out", out_path, "--default-model", default_model, "--timeout", "3"],
        capture_output=True, text=True, timeout=15,
    )


def test_adds_one_entry_per_tool_capable_model_skipping_the_default(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = str(tmp_path / "config.generated.yaml")
        r = _run(out, f"http://127.0.0.1:{port}")
        assert r.returncode == 0, r.stderr
        with open(out) as fh:
            cfg = yaml.safe_load(fh)
        names = {e["model_name"] for e in cfg["model_list"]}
        assert "qwen3.5:122b" in names
        assert "gemma4:31b" in names
        # non-tool-capable models are excluded
        assert "nomic-embed-text:latest" not in names
        # the default model is already covered by the `governed-model` alias
        # -> must not be duplicated as its own bare-name entry
        assert "gpt-oss:120b" not in names
    finally:
        srv.shutdown()


def test_generated_entries_are_pinned_to_the_operator_api_base_and_key(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = str(tmp_path / "config.generated.yaml")
        base = f"http://127.0.0.1:{port}"
        r = _run(out, base)
        assert r.returncode == 0, r.stderr
        with open(out) as fh:
            cfg = yaml.safe_load(fh)
        new_entries = [e for e in cfg["model_list"] if e["model_name"] in ("qwen3.5:122b", "gemma4:31b")]
        assert len(new_entries) == 2
        for e in new_entries:
            # only the model id varies — the endpoint/credentials never do
            assert e["litellm_params"]["api_base"] == base
            assert e["litellm_params"]["api_key"] == "ollama-unused"
            assert e["litellm_params"]["model"].startswith("ollama_chat/")
    finally:
        srv.shutdown()


def test_preserves_the_fixed_default_and_wildcard_entries(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = str(tmp_path / "config.generated.yaml")
        r = _run(out, f"http://127.0.0.1:{port}")
        assert r.returncode == 0, r.stderr
        with open(out) as fh:
            cfg = yaml.safe_load(fh)
        names = [e["model_name"] for e in cfg["model_list"]]
        assert "governed-model" in names
        assert "*" in names
        # the governance callback wiring must be untouched
        assert cfg["litellm_settings"]["callbacks"] == \
            "gateway.callbacks.governance_callback.governance_handler_instance"
    finally:
        srv.shutdown()


def test_unreachable_ollama_fails_safe_to_just_the_template(tmp_path):
    out = str(tmp_path / "config.generated.yaml")
    r = _run(out, "http://127.0.0.1:1", default_model="ollama_chat/gpt-oss:120b")
    assert r.returncode == 0, r.stderr  # never fatal — must not block gateway startup
    with open(out) as fh:
        cfg = yaml.safe_load(fh)
    names = {e["model_name"] for e in cfg["model_list"]}
    assert names == {"governed-model", "*"}


def test_output_file_is_valid_yaml_with_the_original_sections_intact(tmp_path):
    out = str(tmp_path / "config.generated.yaml")
    r = _run(out, "http://127.0.0.1:1")
    assert r.returncode == 0, r.stderr
    with open(out) as fh:
        cfg = yaml.safe_load(fh)
    assert "general_settings" in cfg
    assert cfg["general_settings"]["master_key"] == "os.environ/GATEWAY_MASTER_KEY"
