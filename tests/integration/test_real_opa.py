"""Integration tests against a REAL OPA server loading the real Rego bundle.

Proves rego + OPAClient + DecisionOrchestrator + Enforcer work together
without Docker. Skipped automatically if an `opa` binary is not available
(set OPA_BIN to override the lookup).
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time

import httpx
import pytest

from gateway.governance.adapters.hermes import HermesAdapter
from gateway.governance.clients.opa import OPAClient
from gateway.governance.decision_orchestrator import DecisionOrchestrator
from gateway.governance.enforcer import Enforcer, ReplanTracker
from gateway.governance.schemas import SoftAdvice, Verdict

OPA_BIN = os.environ.get("OPA_BIN") or shutil.which("opa")
POLICY_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "policy")

pytestmark = pytest.mark.skipif(not OPA_BIN, reason="opa binary not found (set OPA_BIN)")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StubCiso:
    def __init__(self, advice: SoftAdvice) -> None:
        self._advice = advice

    async def advise(self, event) -> SoftAdvice:
        return self._advice


SOFT_ALLOW = SoftAdvice(advice="ALLOW", risk_score=2, risk_level="LOW")


@pytest.fixture(scope="module")
def opa_server():
    port = _free_port()
    proc = subprocess.Popen(
        [OPA_BIN, "run", "--server", f"--addr=127.0.0.1:{port}",
         "--ignore=tests", "--log-level=error", POLICY_DIR],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if httpx.get(f"{base}/health", timeout=0.5).status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.05)
        else:
            raise RuntimeError("OPA did not become ready")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _client(base: str) -> OPAClient:
    return OPAClient(base_url=base, decision_path="dciso/governance/decision", timeout=3)


async def _resp(adapter, req, tool_calls):
    return {"choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                                                 "tool_calls": tool_calls}}]}


def _req(md=None):
    return {"model": "governed-model", "messages": [{"role": "user", "content": "x"}],
            "metadata": md or {"harness_type": "hermes", "session_id": "s-real"}}


def _tc(name, args):
    import json
    return {"id": "c1", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


# --------------------------------------------------------------------------- #
async def test_real_read_file_allow(opa_server):
    adapter = HermesAdapter()
    events = adapter.normalize_response(_req(), await _resp(adapter, _req(), [_tc("read_file", {"path": "/a"})]))
    orch = DecisionOrchestrator(ciso=_StubCiso(SOFT_ALLOW), opa=_client(opa_server))
    out = await orch.evaluate(events[0])
    assert out.decision.decision == Verdict.ALLOW
    assert out.decision.policy_version == "v0.1.0"


async def test_real_terminal_denied(opa_server):
    adapter = HermesAdapter()
    orch = DecisionOrchestrator(ciso=_StubCiso(SOFT_ALLOW), opa=_client(opa_server))

    # destructive shell command -> DENY
    ev = adapter.normalize_response(_req(), await _resp(adapter, _req(), [_tc("terminal", {"command": "rm -rf /data"})]))
    out = await orch.evaluate(ev[0])
    assert out.decision.decision == Verdict.DENY

    # read-only shell command -> ALLOW (command-level policy)
    ev = adapter.normalize_response(_req(), await _resp(adapter, _req(), [_tc("terminal", {"command": "ls -la /tmp"})]))
    out = await orch.evaluate(ev[0])
    assert out.decision.decision == Verdict.ALLOW

    # bare terminal, no command -> DENY (can't assess)
    ev = adapter.normalize_response(_req(), await _resp(adapter, _req(), [_tc("terminal", {})]))
    out = await orch.evaluate(ev[0])
    assert out.decision.decision == Verdict.DENY


async def test_real_soft_review_does_not_overblock_readonly_shell(opa_server):
    """The real CISO rule engine flags every shell tool as REQUIRE_REVIEW
    (score 60) because it never sees the command string. OPA, which does see
    it, must still ALLOW a read-only command — soft advice only tightens on a
    CISO *DENY*, not on REVIEW."""
    adapter = HermesAdapter()
    soft_review = SoftAdvice(advice="REQUIRE_REVIEW", risk_score=60, risk_level="HIGH")
    orch = DecisionOrchestrator(ciso=_StubCiso(soft_review), opa=_client(opa_server))
    ev = adapter.normalize_response(_req(), await _resp(adapter, _req(), [_tc("terminal", {"command": "ls -la /tmp"})]))
    out = await orch.evaluate(ev[0])
    assert out.soft_advice.advice == "REQUIRE_REVIEW"
    assert out.decision.decision == Verdict.ALLOW


async def test_real_ciso_allow_but_phi_external_still_denied(opa_server):
    """The headline §7 property, end to end through the real rego."""
    adapter = HermesAdapter()
    md = {"harness_type": "hermes", "session_id": "s-real",
          "dciso": {"task": {"data_classification": ["PHI"]}}}
    tc = _tc("http_request", {"url": "https://external.example.com", "destination": "https://external.example.com"})
    events = adapter.normalize_response(_req(md), await _resp(adapter, _req(md), [tc]))
    orch = DecisionOrchestrator(ciso=_StubCiso(SOFT_ALLOW), opa=_client(opa_server))
    out = await orch.evaluate(events[0])
    assert out.soft_advice.advice == Verdict.ALLOW
    assert out.decision.decision == Verdict.DENY
    assert "EXTERNAL_SENSITIVE_TRANSFER_DENIED" in out.decision.reason_codes

    disp = Enforcer(adapter, ReplanTracker()).enforce(
        raw_response=await _resp(adapter, _req(md), [tc]), outcomes=[out]
    )
    assert disp.result.outcome == "DENY"
    assert disp.response["choices"][0]["message"]["tool_calls"] is None
    assert "無法完成" in disp.response["choices"][0]["message"]["content"]


async def test_real_over_ceiling_delegation_modifies(opa_server):
    adapter = HermesAdapter()
    md = {"harness_type": "hermes", "session_id": "s-real",
          "dciso": {"governance": {"capability_level": "C2"}}}
    tc = _tc("delegate_task", {"autonomy": "L4", "allowed_tools": ["read_file"]})
    events = adapter.normalize_response(_req(md), await _resp(adapter, _req(md), [tc]))
    orch = DecisionOrchestrator(ciso=_StubCiso(SOFT_ALLOW), opa=_client(opa_server))
    out = await orch.evaluate(events[0])
    assert out.decision.decision == Verdict.MODIFY
    assert out.decision.obligations.max_autonomy == "L2"


async def test_real_unknown_tool_fail_closed(opa_server):
    adapter = HermesAdapter()
    tc = _tc("quantum_teleport", {"x": 1})
    events = adapter.normalize_response(_req(), await _resp(adapter, _req(), [tc]))
    orch = DecisionOrchestrator(ciso=_StubCiso(SOFT_ALLOW), opa=_client(opa_server))
    out = await orch.evaluate(events[0])
    assert out.decision.decision == Verdict.DENY
    assert "UNKNOWN_TOOL" in out.decision.reason_codes


async def test_real_opa_unreachable_fails_closed():
    """No server on this port -> DENY with a fail-closed reason code."""
    orch = DecisionOrchestrator(
        ciso=_StubCiso(SOFT_ALLOW),
        opa=OPAClient(base_url="http://127.0.0.1:1", timeout=0.3),
    )
    adapter = HermesAdapter()
    events = adapter.normalize_response(_req(), await _resp(adapter, _req(), [_tc("read_file", {"path": "/a"})]))
    out = await orch.evaluate(events[0])
    assert out.decision.decision == Verdict.DENY
    assert any(rc.startswith("HARD_PDP_") for rc in out.decision.reason_codes)


async def test_real_protected_path_denied_layer1(opa_server):
    """A read_file at a protected path is denied by the real rego (Phase C)."""
    adapter = HermesAdapter()
    orch = DecisionOrchestrator(ciso=_StubCiso(SOFT_ALLOW), opa=_client(opa_server))
    ev = adapter.normalize_response(_req(), await _resp(adapter, _req(),
        [_tc("read_file", {"path": "/home/u/.ssh/id_rsa"})]))
    out = await orch.evaluate(ev[0])
    assert out.decision.decision == Verdict.DENY
    assert any(rc.startswith("PATH_DENIED:") for rc in out.decision.reason_codes)


async def test_real_execute_from_tmp_denied_at_exec_phase(opa_server):
    """The Layer 2 hook payload for `python /tmp/x.py` is denied through the
    real rego (same event_type, enforcement_phase=tool_execution_pre_dispatch)."""
    adapter = HermesAdapter()
    orch = DecisionOrchestrator(ciso=_StubCiso(SOFT_ALLOW), opa=_client(opa_server))
    ev = adapter.normalize_tool_execution({
        "tool_name": "terminal", "tool_input": {"command": "python /tmp/payload.py"},
        "session_id": "s-real", "extra": {"tool_call_id": "c1"}})
    out = await orch.evaluate(ev)
    assert out.decision.decision == Verdict.DENY
    assert "EXECUTE_FROM_UNTRUSTED_DIR" in out.decision.reason_codes
