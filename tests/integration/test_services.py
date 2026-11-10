"""TestClient checks for the sidecar services: mock-llm, ciso-advisor, viewer."""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _load(mod_name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(mod_name, os.path.join(ROOT, rel_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# mock-llm
# --------------------------------------------------------------------------- #
@pytest.fixture()
def mock_client():
    return TestClient(_load("dciso_mock_llm", "mock-llm/app.py").app)


def test_mock_scenarios(mock_client):
    def call(content):
        r = mock_client.post("/v1/chat/completions", json={
            "model": "governed-model", "messages": [{"role": "user", "content": content}]})
        assert r.status_code == 200
        return r.json()["choices"][0]["message"]

    assert call("[[scenario:safe]] hi")["tool_calls"] is None
    assert call("[[scenario:read]] x")["tool_calls"][0]["function"]["name"] == "read_file"
    assert call("[[scenario:delegate]] x")["tool_calls"][0]["function"]["name"] == "delegate_task"
    multi = call("[[scenario:multi]] x")["tool_calls"]
    assert {c["function"]["name"] for c in multi} == {"read_file", "terminal"}


def test_mock_streams_sse(mock_client):
    with mock_client.stream("POST", "/v1/chat/completions", json={
        "model": "m", "stream": True,
        "messages": [{"role": "user", "content": "[[scenario:read]] x"}]}) as r:
        assert r.status_code == 200
        assert "text/event-stream" in r.headers["content-type"]
        body = "".join(r.iter_text())
    assert body.startswith("data: ") and "[DONE]" in body
    assert "read_file" in body and '"delta"' in body


def test_mock_stops_proposing_after_a_tool_result(mock_client):
    # keyword would pick "terminal", but the last message is a tool result
    r = mock_client.post("/v1/chat/completions", json={"model": "m", "messages": [
        {"role": "user", "content": "請執行 shell 指令"},
        {"role": "assistant", "tool_calls": [{"id": "c1", "type": "function",
                                              "function": {"name": "terminal", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "denied"},
    ]})
    assert r.json()["choices"][0]["message"]["tool_calls"] is None
    # an explicit marker still wins even after a tool result
    r2 = mock_client.post("/v1/chat/completions", json={"model": "m", "messages": [
        {"role": "user", "content": "[[scenario:read]] x"},
        {"role": "tool", "tool_call_id": "c1", "content": "ok"},
    ]})
    assert r2.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "read_file"


def test_mock_metadata_scenario_beats_keywords(mock_client):
    r = mock_client.post("/v1/chat/completions", json={
        "model": "m", "metadata": {"dciso": {"mock_scenario": "exfil"}},
        "messages": [{"role": "user", "content": "just read a file please"}]})
    assert r.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "http_request"


# --------------------------------------------------------------------------- #
# ciso-advisor (rule mode)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def ciso_client(monkeypatch):
    monkeypatch.setenv("CISO_MODE", "rule")
    mod = _load("dciso_ciso_advisor", "ciso-advisor/app.py")
    return TestClient(mod.app)


def _advise(client, event):
    r = client.post("/advise", json={"event": event})
    assert r.status_code == 200
    return r.json()


def test_ciso_rule_read_only_allows(ciso_client):
    a = _advise(ciso_client, {
        "event_type": "tool.execute.proposed",
        "proposed_action": {"canonical_name": "read_file", "argument_keys": ["path"]},
        "task": {"data_classification": ["internal"]},
        "governance": {"requested_autonomy": "L1"}})
    assert a["advice"] == "ALLOW"
    assert "availability" not in a  # the gateway client owns that field


def test_ciso_rule_phi_external_not_allow(ciso_client):
    a = _advise(ciso_client, {
        "event_type": "tool.execute.proposed",
        "proposed_action": {"canonical_name": "http_request",
                            "destination": "https://evil.example.com", "argument_keys": ["body"]},
        "task": {"data_classification": ["PHI"]},
        "governance": {"requested_autonomy": "L1"}})
    assert a["advice"] in ("DENY", "REQUIRE_REVIEW")
    assert a["risk_level"] in ("HIGH", "CRITICAL")


def test_ciso_rule_terminal_is_high_risk(ciso_client):
    a = _advise(ciso_client, {
        "event_type": "tool.execute.proposed",
        "proposed_action": {"canonical_name": "terminal", "argument_keys": ["cmd"]},
        "task": {"data_classification": ["internal"]},
        "governance": {"requested_autonomy": "L1"}})
    assert a["advice"] in ("DENY", "REQUIRE_REVIEW")
    assert a["suggested_obligations"]["read_only"] is True


def test_ciso_health(ciso_client):
    assert ciso_client.get("/health/liveness").json()["mode"] == "rule"
    assert ciso_client.get("/health/policy").json()["ready"] is True


# --------------------------------------------------------------------------- #
# ciso-advisor (hermes mode) — the advisor IS a separate tool-less Hermes
# --------------------------------------------------------------------------- #
@pytest.fixture()
def ciso_hermes_client(monkeypatch, tmp_path):
    monkeypatch.setenv("CISO_MODE", "hermes")
    monkeypatch.setenv("CISO_HERMES_HOME", str(tmp_path))  # dir exists, no hermes inside
    monkeypatch.setenv("CISO_HERMES_BIN", "/nonexistent/hermes-xyz")
    monkeypatch.setenv("CISO_HERMES_TIMEOUT", "3")
    mod = _load("dciso_ciso_advisor_hermes", "ciso-advisor/app.py")
    return TestClient(mod.app)


_TERMINAL_EVENT = {
    "event_type": "tool.execute.proposed",
    "proposed_action": {"canonical_name": "terminal", "argument_keys": ["command"]},
    "task": {"data_classification": ["internal"]},
    "governance": {"requested_autonomy": "L1"},
}


def test_ciso_hermes_missing_binary_falls_back_to_rule(ciso_hermes_client, monkeypatch):
    monkeypatch.setenv("CISO_HERMES_FALLBACK", "rule")
    a = _advise(ciso_hermes_client, _TERMINAL_EVENT)
    # rule engine still ran -> a real judgement, not a blind DENY
    assert a["advice"] in ("DENY", "REQUIRE_REVIEW")
    assert a["reason_codes"][0] == "CISO_HERMES_FALLBACK_RULE"
    assert any(rc.startswith("CISO_HERMES_ERROR") for rc in a["reason_codes"])


def test_ciso_hermes_fail_closed_when_no_fallback(ciso_hermes_client, monkeypatch):
    monkeypatch.setenv("CISO_HERMES_FALLBACK", "deny")
    a = _advise(ciso_hermes_client, _TERMINAL_EVENT)
    assert a["advice"] == "DENY"
    assert a["risk_level"] == "CRITICAL"


def test_ciso_hermes_health_reports_home(ciso_hermes_client):
    h = ciso_hermes_client.get("/health/policy").json()
    assert h["mode"] == "hermes"
    assert h["ready"] is True  # rule fallback keeps us able to advise
    assert h["hermes_home_present"] is True


def test_ciso_extract_json_tolerates_prose():
    mod = sys.modules["dciso_ciso_advisor_hermes"]
    assert mod._extract_json('ok\n{"advice":"DENY","risk_score":80}\nthanks')["advice"] == "DENY"
    assert mod._extract_json('{"a":1} {"advice":"MODIFY","risk_score":40}')["advice"] == "MODIFY"
    with pytest.raises(ValueError):
        mod._extract_json("no json at all")


def test_ciso_sanitize_clamps_untrusted_output():
    mod = sys.modules["dciso_ciso_advisor_hermes"]
    bad = mod._sanitize({"advice": "yolo"}, bad_code="X", default_reason="Y")
    assert bad["advice"] == "DENY" and bad["risk_score"] == 100
    ok = mod._sanitize({"advice": "ALLOW", "risk_score": "5", "risk_level": "nonsense"},
                       bad_code="X", default_reason="Y")
    assert ok["advice"] == "ALLOW" and ok["risk_score"] == 5 and ok["risk_level"] == "HIGH"


def test_ciso_hermes_passes_skills_flag_and_stays_toolless(monkeypatch, tmp_path):
    """CISO_HERMES_SKILLS -> `--skills` on the one-shot; `-t ""` always present."""
    import asyncio as _aio
    mod = sys.modules["dciso_ciso_advisor_hermes"]
    monkeypatch.setenv("CISO_HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("CISO_HERMES_BIN", "hermes")
    monkeypatch.setenv("CISO_HERMES_SKILLS", "risk-playbook, owasp-agentic")
    monkeypatch.setenv("CISO_HERMES_FALLBACK", "deny")
    captured = {}

    class _FakeProc:
        returncode = 0
        async def communicate(self):
            return (b'{"advice":"REQUIRE_REVIEW","risk_score":50,"risk_level":"MEDIUM"}', b"")

    async def _fake_exec(*cmd, **kw):
        captured["cmd"] = list(cmd)
        return _FakeProc()

    monkeypatch.setattr(_aio, "create_subprocess_exec", _fake_exec)
    out = _aio.get_event_loop().run_until_complete(
        mod._hermes_engine({"proposed_action": {"canonical_name": "terminal", "argument_keys": ["command"]},
                            "task": {"data_classification": ["internal"]},
                            "governance": {"requested_autonomy": "L1"}})
    )
    cmd = captured["cmd"]
    assert "--skills" in cmd and cmd[cmd.index("--skills") + 1] == "risk-playbook, owasp-agentic"
    assert cmd[cmd.index("-t") + 1] == ""            # still tool-less
    assert out["advice"] == "REQUIRE_REVIEW" and out["reason_codes"][0] == "CISO_HERMES"


# --------------------------------------------------------------------------- #
# viewer (read-only dashboard)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def viewer_client(tmp_path, monkeypatch):
    db = tmp_path / "audit.sqlite"
    monkeypatch.setenv("AUDIT_DB_PATH", str(db))
    # seed one row via the real audit writer
    from gateway.governance.audit import AuditWriter
    from gateway.governance.schemas import (
        SCHEMA_VERSION, Decision, EnforcementPhase, EnforcementResult, EventType,
        GovernanceBlock, GovernanceEvent, ProposedAction, SoftAdvice, Source, Task, Verdict,
    )
    ev = GovernanceEvent(
        schema_version=SCHEMA_VERSION, event_id="evt-seed", timestamp="2026-09-01T00:00:00Z",
        event_type=EventType.TOOL_EXECUTE_PROPOSED,
        enforcement_phase=EnforcementPhase.MODEL_RESPONSE_PRE_EXECUTION,
        source=Source(harness_type="hermes", harness_instance_id="h1", agent_id="a1", session_id="sess-seed"),
        task=Task(task_id="t1"), proposed_action=ProposedAction(native_name="terminal", canonical_name="terminal"),
        governance=GovernanceBlock())
    AuditWriter(str(db)).write(
        event=ev, soft_advice=SoftAdvice(advice="ALLOW", risk_score=1, risk_level="LOW"),
        decision=Decision(decision=Verdict.DENY, reason_codes=["DANGEROUS_TOOL_DENIED:terminal"],
                          policy_version="v0.1.0"),
        enforcement=EnforcementResult(outcome="DENY", event_id="evt-seed",
                                      reason_codes=["DANGEROUS_TOOL_DENIED:terminal"],
                                      user_message="無法完成"),
        raw_request={"model": "governed-model"}, raw_response={"choices": []}, latency_ms=12.0)
    mod = _load("dciso_viewer", "viewer/app.py")
    return TestClient(mod.app)


def test_viewer_index_lists_the_seeded_decision(viewer_client):
    r = viewer_client.get("/")
    assert r.status_code == 200
    assert "evt-seed" in r.text and "DENY" in r.text


def test_viewer_event_detail_shows_pipeline(viewer_client):
    r = viewer_client.get("/event/evt-seed")
    assert r.status_code == 200
    assert "OPA Decision" in r.text and "v0.1.0" in r.text


def test_viewer_api_event_json(viewer_client):
    r = viewer_client.get("/api/event/evt-seed")
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "DENY"
    assert body["hard_decision_json"]["policy_version"] == "v0.1.0"


def test_viewer_has_no_write_endpoints(viewer_client):
    # only GETs exist; a POST anywhere should 404/405, never mutate
    assert viewer_client.post("/api/event/evt-seed").status_code in (404, 405)
    assert viewer_client.post("/").status_code in (404, 405)
