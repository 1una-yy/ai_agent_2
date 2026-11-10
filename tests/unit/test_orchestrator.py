import httpx
import respx

from gateway.governance.clients.ciso_advisor import CISOAdvisorClient
from gateway.governance.clients.opa import OPAClient
from gateway.governance.decision_orchestrator import DecisionOrchestrator
from gateway.governance.schemas import (
    SCHEMA_VERSION,
    AdviceAvailability,
    EnforcementPhase,
    EventType,
    GovernanceBlock,
    GovernanceEvent,
    ProposedAction,
    Source,
    Task,
    Verdict,
)


def _event():
    return GovernanceEvent(
        schema_version=SCHEMA_VERSION,
        event_id="evt-1",
        timestamp="2026-09-01T00:00:00Z",
        event_type=EventType.TOOL_EXECUTE_PROPOSED,
        enforcement_phase=EnforcementPhase.MODEL_RESPONSE_PRE_EXECUTION,
        source=Source(harness_type="hermes", harness_instance_id="h1", agent_id="a1", session_id="s1"),
        task=Task(task_id="t1", data_classification=["PHI"]),
        proposed_action=ProposedAction(native_name="read_file", canonical_name="read_file"),
        governance=GovernanceBlock(),
    )


def _orch():
    return DecisionOrchestrator(
        ciso=CISOAdvisorClient(url="http://ciso-advisor:9000", timeout=0.5),
        opa=OPAClient(base_url="http://opa:8181", timeout=0.5),
    )


@respx.mock
async def test_ciso_down_still_queries_opa_with_unavailable_advice():
    respx.post("http://ciso-advisor:9000/advise").mock(side_effect=httpx.ConnectError("down"))
    route = respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "DENY", "reason_codes": ["SOFT_ADVICE_UNAVAILABLE_SENSITIVE"],
                   "obligations": {}, "policy_version": "v0.1.0"}
    }))
    out = await _orch().evaluate(_event())
    assert route.called
    sent = route.calls.last.request
    assert b'"availability":"UNAVAILABLE"' in sent.content.replace(b" ", b"")
    assert out.soft_advice.availability == AdviceAvailability.UNAVAILABLE
    assert out.decision.decision == Verdict.DENY


@respx.mock
async def test_opa_down_fails_closed_regardless_of_soft_allow():
    respx.post("http://ciso-advisor:9000/advise").mock(return_value=httpx.Response(200, json={
        "advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/.*").mock(side_effect=httpx.ConnectError("opa down"))
    out = await _orch().evaluate(_event())
    assert out.soft_advice.advice == Verdict.ALLOW
    assert out.decision.decision == Verdict.DENY
    assert "HARD_PDP_UNREACHABLE" in out.decision.reason_codes


@respx.mock
async def test_advice_is_folded_into_event_and_never_bypasses_opa():
    respx.post("http://ciso-advisor:9000/advise").mock(return_value=httpx.Response(200, json={
        "advice": "DENY", "risk_score": 90, "risk_level": "HIGH", "reason_codes": ["X"]}))
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {}, "policy_version": "v0.1.0"}
    }))
    out = await _orch().evaluate(_event())
    # OPA is the final authority: it said ALLOW even though soft said DENY
    assert out.decision.decision == Verdict.ALLOW
    assert out.event.governance.soft_advice.advice == Verdict.DENY


@respx.mock
async def test_phase_e_timings_split_ciso_and_opa():
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {},
                   "policy_version": "v0.1.0"}}))
    out = await _orch().evaluate(_event())
    assert out.ciso_ms >= 0 and out.opa_ms >= 0
    assert out.ciso_ms + out.opa_ms <= out.latency_ms + 5  # split fits inside the total


@respx.mock
async def test_phase_e_fastpath_records_zero_ciso_ms():
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {},
                   "policy_version": "v0.1.0"}}))
    out = await _orch().evaluate(_event(), consult_ciso=False)
    assert out.ciso_ms == 0.0
    assert "CISO_NOT_CONSULTED_FASTPATH" in out.soft_advice.reason_codes


@respx.mock
async def test_hard_precheck_deny_skips_ciso_entirely():
    ciso_route = respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/hard_precheck.*").mock(return_value=httpx.Response(200, json={
        "result": {"reasons": ["DANGEROUS_TOOL_DENIED:credential_access"], "policy_version": "v0.1.0"}}))
    decide_route = respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={
            "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {},
                       "policy_version": "v0.1.0"}}))
    out = await _orch().evaluate(_event())
    assert not ciso_route.called, "CISO must not be consulted when the hard pre-check already denies"
    assert not decide_route.called, "the full decision call is unnecessary once the pre-check denies"
    assert out.decision.decision == Verdict.DENY
    assert "DANGEROUS_TOOL_DENIED:credential_access" in out.decision.reason_codes
    assert "CISO_SKIPPED_HARD_PRECHECK_DENY" in out.soft_advice.reason_codes
    assert out.ciso_ms == 0.0


@respx.mock
async def test_hard_precheck_clean_still_consults_ciso():
    ciso_route = respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/hard_precheck.*").mock(return_value=httpx.Response(200, json={
        "result": {"reasons": [], "policy_version": "v0.1.0"}}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {},
                   "policy_version": "v0.1.0"}}))
    out = await _orch().evaluate(_event())
    assert ciso_route.called, "a clean pre-check must not skip the real CISO consultation"
    assert out.decision.decision == Verdict.ALLOW


@respx.mock
async def test_hard_precheck_unreachable_falls_through_safely():
    # precheck endpoint errors; CISO + the real decision endpoint must still run normally
    ciso_route = respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/hard_precheck.*").mock(
        side_effect=httpx.ConnectError("precheck down"))
    decide_route = respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={
            "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {},
                       "policy_version": "v0.1.0"}}))
    out = await _orch().evaluate(_event())
    assert ciso_route.called
    assert decide_route.called
    assert out.decision.decision == Verdict.ALLOW
