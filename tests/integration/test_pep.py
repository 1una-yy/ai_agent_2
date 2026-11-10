"""Execution-side PEP (Layer 2) — /govern endpoint."""

import importlib
import os
import sqlite3

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

CISO = "http://ciso-advisor:9000/advise"
OPA = r".*/v1/data/.*"


@pytest.fixture()
def pep(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.sqlite"))
    monkeypatch.setenv("OPA_URL", "http://opa:8181")
    monkeypatch.setenv("CISO_ADVISOR_URL", "http://ciso-advisor:9000")
    import pep.app as mod

    importlib.reload(mod)
    return TestClient(mod.app)


def _ciso_allow():
    return httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"})


def _opa(decision, reason_codes=None, obligations=None):
    return httpx.Response(200, json={"result": {
        "decision": decision, "reason_codes": reason_codes or [],
        "obligations": obligations or {}, "policy_version": "v0.1.0"}})


def _rows(db):
    c = sqlite3.connect(db)
    try:
        return c.execute("SELECT outcome, canonical_name, enforcement_phase FROM audit_log").fetchall()
    finally:
        c.close()


def test_non_tool_event_is_noop(pep):
    r = pep.post("/govern", json={"hook_event_name": "pre_llm_call", "tool_name": None})
    assert r.status_code == 200 and r.json() == {}


@respx.mock
def test_read_file_allowed_returns_empty(pep):
    respx.post(CISO).mock(return_value=_ciso_allow())
    respx.post(url__regex=OPA).mock(return_value=_opa("ALLOW", ["POLICY_ALLOW"]))
    r = pep.post("/govern", json={
        "hook_event_name": "pre_tool_call", "tool_name": "read_file",
        "tool_input": {"path": "/x"}, "session_id": "s1", "cwd": "/home/u",
        "extra": {"tool_call_id": "c1"}})
    assert r.json() == {}
    row = _rows(os.environ["AUDIT_DB_PATH"])[0]
    assert row[0] == "ALLOW" and row[2] == "tool_execution_pre_dispatch"


@respx.mock
def test_terminal_execution_blocked(pep):
    respx.post(CISO).mock(return_value=_ciso_allow())
    respx.post(url__regex=OPA).mock(return_value=_opa("DENY", ["DANGEROUS_TOOL_DENIED:terminal"]))
    r = pep.post("/govern", json={
        "hook_event_name": "pre_tool_call", "tool_name": "terminal",
        "tool_input": {"command": "rm -rf /"}, "session_id": "s2"})
    body = r.json()
    assert body["action"] == "block"
    assert "風險太高" in body["message"] and "無法執行" in body["message"]
    assert body["dciso"]["reason_code"] == "DANGEROUS_TOOL_DENIED"
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][0] == "DENY"


@respx.mock
def test_modify_rewrites_args(pep):
    respx.post(CISO).mock(return_value=_ciso_allow())
    respx.post(url__regex=OPA).mock(return_value=_opa(
        "MODIFY", ["AUTONOMY_DOWNGRADED_TO_CEILING"],
        {"argument_overrides": {"autonomy": "L1"}, "max_autonomy": "L1"}))
    r = pep.post("/govern", json={
        "hook_event_name": "pre_tool_call", "tool_name": "delegate_task",
        "tool_input": {"autonomy": "L4", "goal": "x"}, "session_id": "s3"})
    body = r.json()
    assert body["action"] == "modify"
    assert body["args"]["autonomy"] == "L1" and body["args"]["goal"] == "x"


@respx.mock
def test_opa_down_fails_closed_block(pep):
    respx.post(CISO).mock(return_value=_ciso_allow())
    respx.post(url__regex=OPA).mock(side_effect=httpx.ConnectError("down"))
    r = pep.post("/govern", json={
        "hook_event_name": "pre_tool_call", "tool_name": "read_file",
        "tool_input": {"path": "/x"}, "session_id": "s4"})
    assert r.json()["action"] == "block"
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][0] == "DENY"


@respx.mock
def test_audit_failure_fails_closed(pep, monkeypatch):
    respx.post(CISO).mock(return_value=_ciso_allow())
    respx.post(url__regex=OPA).mock(return_value=_opa("ALLOW", ["POLICY_ALLOW"]))
    import pep.app as mod

    def boom(**kw):
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(mod._audit, "write", boom)
    r = pep.post("/govern", json={
        "hook_event_name": "pre_tool_call", "tool_name": "read_file",
        "tool_input": {"path": "/x"}, "session_id": "s5"})
    assert r.json()["action"] == "block"
