import httpx
import pytest
import respx

from gateway.governance.clients.ciso_advisor import CISOAdvisorClient
from gateway.governance.clients.opa import OPAClient
from gateway.governance.schemas import (
    SCHEMA_VERSION,
    AdviceAvailability,
    EnforcementPhase,
    EventType,
    GovernanceBlock,
    GovernanceEvent,
    ProposedAction,
    SoftAdvice,
    Source,
    Task,
    Verdict,
)


def _event(canonical="read_file", data_classification=None):
    return GovernanceEvent(
        schema_version=SCHEMA_VERSION,
        event_id="evt-1",
        timestamp="2026-09-01T00:00:00Z",
        event_type=EventType.TOOL_EXECUTE_PROPOSED,
        enforcement_phase=EnforcementPhase.MODEL_RESPONSE_PRE_EXECUTION,
        source=Source(harness_type="hermes", harness_instance_id="h1", agent_id="a1", session_id="s1"),
        task=Task(task_id="t1", data_classification=data_classification or ["internal"]),
        proposed_action=ProposedAction(native_name=canonical, canonical_name=canonical),
        governance=GovernanceBlock(),
    )


OK_ADVICE = SoftAdvice(advice="ALLOW", risk_score=3, risk_level="LOW")


# --------------------------- OPA client ------------------------------------ #
@respx.mock
async def test_opa_missing_result_fails_closed():
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={}))
    d = await OPAClient(base_url="http://opa:8181").decide(_event(), OK_ADVICE)
    assert d.decision == Verdict.DENY
    assert "HARD_PDP_UNDEFINED_DECISION" in d.reason_codes


@respx.mock
async def test_opa_http_500_fails_closed():
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(500, text="boom"))
    d = await OPAClient(base_url="http://opa:8181").decide(_event(), OK_ADVICE)
    assert d.decision == Verdict.DENY
    assert "HARD_PDP_HTTP_ERROR" in d.reason_codes


@respx.mock
async def test_opa_timeout_fails_closed():
    respx.post(url__regex=r".*/v1/data/.*").mock(side_effect=httpx.ConnectTimeout("t"))
    d = await OPAClient(base_url="http://opa:8181", timeout=0.5).decide(_event(), OK_ADVICE)
    assert d.decision == Verdict.DENY
    assert "HARD_PDP_UNREACHABLE" in d.reason_codes


@respx.mock
async def test_opa_valid_decision_parsed():
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"],
                   "obligations": {"read_only": True, "max_autonomy": "L1", "max_subagent_depth": 0,
                                   "allowed_tools": ["read_file"], "denied_tools": []},
                   "policy_version": "v0.1.0"}
    }))
    d = await OPAClient(base_url="http://opa:8181").decide(_event(), OK_ADVICE)
    assert d.decision == Verdict.ALLOW
    assert d.policy_version == "v0.1.0"


@respx.mock
async def test_opa_result_without_decision_field_fails_closed():
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={"result": {"foo": 1}}))
    d = await OPAClient(base_url="http://opa:8181").decide(_event(), OK_ADVICE)
    assert d.decision == Verdict.DENY


# --------------------------- CISO advisor client -------------------------- #
@respx.mock
async def test_ciso_timeout_is_unavailable_not_allow():
    respx.post("http://ciso-advisor:9000/advise").mock(side_effect=httpx.ReadTimeout("t"))
    a = await CISOAdvisorClient(url="http://ciso-advisor:9000", timeout=0.5).advise(_event())
    assert a.availability == AdviceAvailability.UNAVAILABLE
    assert a.advice == Verdict.DENY


@respx.mock
async def test_ciso_bad_json_is_unparseable():
    respx.post("http://ciso-advisor:9000/advise").mock(return_value=httpx.Response(200, text="not json"))
    a = await CISOAdvisorClient(url="http://ciso-advisor:9000").advise(_event())
    assert a.availability == AdviceAvailability.UNPARSEABLE
    assert a.advice == Verdict.DENY


@respx.mock
async def test_ciso_schema_mismatch_is_unparseable():
    respx.post("http://ciso-advisor:9000/advise").mock(return_value=httpx.Response(200, json={"advice": "SURE"}))
    a = await CISOAdvisorClient(url="http://ciso-advisor:9000").advise(_event())
    assert a.availability == AdviceAvailability.UNPARSEABLE


@respx.mock
async def test_ciso_valid_advice_ok_and_availability_owned_by_client():
    respx.post("http://ciso-advisor:9000/advise").mock(return_value=httpx.Response(200, json={
        "advice": "MODIFY", "risk_score": 40, "risk_level": "MEDIUM",
        "reason_codes": ["BROAD_SCOPE"], "explanation": "narrow it",
        "suggested_obligations": {"read_only": True},
        "availability": "UNAVAILABLE",  # service lies; client must overwrite
    }))
    a = await CISOAdvisorClient(url="http://ciso-advisor:9000").advise(_event())
    assert a.advice == Verdict.MODIFY
    assert a.availability == AdviceAvailability.OK


@respx.mock
async def test_ciso_minimization_strips_argument_values():
    captured = {}

    def _capture(request):
        import json as _j
        captured.update(_j.loads(request.content))
        return httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"})

    respx.post("http://ciso-advisor:9000/advise").mock(side_effect=_capture)
    ev = _event()
    ev.proposed_action.arguments = {"password": "hunter2", "path": "/etc/shadow"}
    await CISOAdvisorClient(url="http://ciso-advisor:9000").advise(ev)
    sent_pa = captured["event"]["proposed_action"]
    assert sent_pa["arguments"] == {}
    assert set(sent_pa["argument_keys"]) == {"password", "path"}
