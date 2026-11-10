import json

from gateway.governance.decision_orchestrator import OrchestrationOutcome
from gateway.governance.enforcer import Enforcer, ReplanTracker, public_code
from gateway.governance.adapters.hermes import HermesAdapter
from gateway.governance.schemas import (
    SCHEMA_VERSION,
    Decision,
    EnforcementPhase,
    EventType,
    GovernanceBlock,
    Obligations,
    ProposedAction,
    SoftAdvice,
    Source,
    Task,
    Verdict,
    GovernanceEvent,
    AdviceAvailability,
)


def _event(canonical="read_file", session="s1", etype=EventType.TOOL_EXECUTE_PROPOSED):
    return GovernanceEvent(
        schema_version=SCHEMA_VERSION,
        event_id=f"evt-{canonical}",
        timestamp="2026-09-01T00:00:00Z",
        event_type=etype,
        enforcement_phase=EnforcementPhase.MODEL_RESPONSE_PRE_EXECUTION,
        source=Source(harness_type="hermes", harness_instance_id="h1", agent_id="a1", session_id=session),
        task=Task(task_id="t1"),
        proposed_action=ProposedAction(native_name=canonical, canonical_name=canonical),
        governance=GovernanceBlock(),
    )


def _outcome(decision: Decision, **ev_kw):
    ev = _event(**ev_kw)
    return OrchestrationOutcome(
        event=ev,
        soft_advice=SoftAdvice(advice="ALLOW", risk_score=1, risk_level="LOW"),
        decision=decision,
        latency_ms=1.0,
    )


def _resp_with_calls(names):
    return {
        "id": "c1",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": f"c{i}", "type": "function",
                     "function": {"name": n, "arguments": "{}"}}
                    for i, n in enumerate(names)
                ],
            },
        }],
    }


def _enforcer():
    return Enforcer(HermesAdapter(), ReplanTracker(max_attempts=2))


def test_public_code_mapping():
    assert public_code(["DANGEROUS_TOOL_DENIED:terminal"]) == "DANGEROUS_TOOL_DENIED"
    assert public_code(["HARD_PDP_UNREACHABLE"]) == "GOVERNANCE_SERVICE_UNAVAILABLE"
    assert public_code(["something_unmapped"]) == "POLICY_DENIED"


def test_batch_one_deny_blocks_whole_turn():
    e = _enforcer()
    outcomes = [
        _outcome(Decision(decision=Verdict.ALLOW), canonical="read_file"),
        _outcome(Decision(decision=Verdict.DENY, reason_codes=["DANGEROUS_TOOL_DENIED:terminal"]), canonical="terminal"),
    ]
    d = e.enforce(raw_response=_resp_with_calls(["read_file", "terminal"]), outcomes=outcomes)
    assert d.result.outcome == "DENY"
    # no tool call survives
    assert d.response["choices"][0]["message"]["tool_calls"] is None
    assert d.response["choices"][0]["message"]["content"]  # user-facing reason present
    assert d.result.session_continues is True


def test_deny_user_message_is_traditional_chinese_and_has_alternatives():
    e = _enforcer()
    outcomes = [_outcome(Decision(decision=Verdict.DENY,
                                  reason_codes=["EXTERNAL_SENSITIVE_TRANSFER_DENIED"]), canonical="http_request")]
    d = e.enforce(raw_response=_resp_with_calls(["http_request"]), outcomes=outcomes)
    assert "無法完成" in d.result.user_message
    assert d.result.agent_feedback.reason_code == "EXTERNAL_SENSITIVE_TRANSFER_DENIED"
    assert "redact_sensitive_fields" in d.result.agent_feedback.allowed_alternatives


def test_replan_loop_stops_on_repeated_reason_code():
    e = _enforcer()
    dec = Decision(decision=Verdict.DENY, reason_codes=["DANGEROUS_TOOL_DENIED:terminal"])
    first = e.enforce(raw_response=_resp_with_calls(["terminal"]),
                      outcomes=[_outcome(dec, canonical="terminal", session="loop")])
    assert first.result.agent_feedback.action == "REPLAN"
    second = e.enforce(raw_response=_resp_with_calls(["terminal"]),
                       outcomes=[_outcome(dec, canonical="terminal", session="loop")])
    assert second.result.agent_feedback.action == "STOP_AUTO_REPLAN"
    assert "已多次被同一原因擋下" in second.result.user_message


def test_require_review_is_inband_by_default():
    e = _enforcer()
    outcomes = [_outcome(Decision(decision=Verdict.REQUIRE_REVIEW,
                                  reason_codes=["TOOL_REVIEW_REQUIRED:send_email"]), canonical="send_email")]
    d = e.enforce(raw_response=_resp_with_calls(["send_email"]), outcomes=outcomes)
    assert d.transport == "inband"
    assert d.result.outcome == "REQUIRE_REVIEW"
    assert d.response["choices"][0]["message"]["tool_calls"] is None
    assert "人工審核" in d.response["choices"][0]["message"]["content"]


def test_require_review_can_opt_into_http_409(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_REVIEW_AS_HTTP_ERROR", "1")
    e = _enforcer()
    outcomes = [_outcome(Decision(decision=Verdict.REQUIRE_REVIEW,
                                  reason_codes=["TOOL_REVIEW_REQUIRED:send_email"]), canonical="send_email")]
    d = e.enforce(raw_response=_resp_with_calls(["send_email"]), outcomes=outcomes)
    assert d.transport == "http_error" and d.http_status == 409
    assert d.response["error"]["code"] == "GOVERNANCE_REVIEW_REQUIRED"


def test_modify_records_before_after_snapshot():
    e = _enforcer()
    r = {
        "id": "c1",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c0", "type": "function",
             "function": {"name": "delegate_task", "arguments": json.dumps({"allowed_tools": ["read_file", "terminal"], "autonomy": "L4"})}}
        ]}}],
    }
    dec = Decision(decision=Verdict.MODIFY,
                   obligations=Obligations(allowed_tools=["read_file"], denied_tools=["terminal"],
                                           argument_overrides={"autonomy": "L1"}))
    d = e.enforce(raw_response=r, outcomes=[_outcome(dec, canonical="agent.spawn", etype=EventType.AGENT_SPAWN)])
    assert d.result.outcome == "MODIFY"
    assert d.result.modification["before"] != d.result.modification["after"]
    args = json.loads(d.response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])
    assert args["autonomy"] == "L1" and args["allowed_tools"] == ["read_file"]


def test_replan_tracker_persists_across_instances(tmp_path):
    db = str(tmp_path / "audit.sqlite")
    t1 = ReplanTracker(max_attempts=2, db_path=db)
    n, stop = t1.register_deny("sess-persist", "DANGEROUS_TOOL_DENIED")
    assert (n, stop) == (1, False)
    # simulate a gateway restart: brand-new tracker, same db
    t2 = ReplanTracker(max_attempts=2, db_path=db)
    n, stop = t2.register_deny("sess-persist", "DANGEROUS_TOOL_DENIED")
    assert stop is True  # same reason code seen again -> stop the auto loop
    t2.reset("sess-persist")
    _, stop = ReplanTracker(max_attempts=2, db_path=db).register_deny("sess-persist", "DANGEROUS_TOOL_DENIED")
    assert stop is False  # reset cleared it


def test_replan_tracker_falls_back_to_memory_on_bad_db(tmp_path):
    t = ReplanTracker(max_attempts=2, db_path=str(tmp_path / "nope" / "x" / "\0bad"))
    # unwritable path -> in-memory, still functions
    n, stop = t.register_deny("s", "CODE")
    assert (n, stop) == (1, False)


def test_no_proposed_action_passes_through():
    e = _enforcer()
    raw = {"id": "c1", "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}}]}
    d = e.enforce(raw_response=raw, outcomes=[])
    assert d.result.outcome == "ALLOW"
    assert d.response is raw


# --------------------------------------------------------------------------- #
# Phase D — honest outcome semantics (advisory vs real hold)
# --------------------------------------------------------------------------- #
def _outcome_soft(decision, soft, **ev_kw):
    return OrchestrationOutcome(event=_event(**ev_kw), soft_advice=soft,
                                decision=decision, latency_ms=1.0)


def test_allow_with_ciso_review_flag_is_advisory_not_hold():
    soft = SoftAdvice(advice="REQUIRE_REVIEW", risk_score=60, risk_level="HIGH",
                      reason_codes=["HIGH_RISK_TOOL"], explanation="shell tool")
    d = Decision(decision=Verdict.ALLOW, reason_codes=["POLICY_ALLOW"])
    disp = _enforcer().enforce(raw_response=_resp_with_calls(["terminal"]),
                               outcomes=[_outcome_soft(d, soft)])
    r = disp.result
    assert r.outcome == "ALLOW"          # action proceeds
    assert r.hold == "ADVISORY"          # but it is honestly flagged
    assert r.advisory and r.advisory["advice"] == "REQUIRE_REVIEW" and r.advisory["binding"] is False


def test_allow_with_clean_ciso_has_no_advisory():
    soft = SoftAdvice(advice="ALLOW", risk_score=5, risk_level="LOW")
    d = Decision(decision=Verdict.ALLOW, reason_codes=["POLICY_ALLOW"])
    r = _enforcer().enforce(raw_response=_resp_with_calls(["read_file"]),
                            outcomes=[_outcome_soft(d, soft)]).result
    assert r.hold == "NONE" and r.advisory is None and r.escalated is True


def test_fastpath_skipped_ciso_marks_not_escalated():
    soft = SoftAdvice(advice="ALLOW", risk_score=0, risk_level="LOW",
                      reason_codes=["CISO_NOT_CONSULTED_FASTPATH"])
    d = Decision(decision=Verdict.ALLOW, reason_codes=["POLICY_ALLOW"])
    r = _enforcer().enforce(raw_response=_resp_with_calls(["read_file"]),
                            outcomes=[_outcome_soft(d, soft)]).result
    assert r.escalated is False and r.escalate_reason == "fastpath_no_escalation"
    assert r.hold == "NONE"


def test_require_review_verdict_is_a_real_hold():
    soft = SoftAdvice(advice="ALLOW", risk_score=5, risk_level="LOW")
    d = Decision(decision=Verdict.REQUIRE_REVIEW, reason_codes=["TOOL_REVIEW_REQUIRED:send_email"])
    r = _enforcer().enforce(raw_response=_resp_with_calls(["send_email"]),
                            outcomes=[_outcome_soft(d, soft)]).result
    assert r.outcome == "REQUIRE_REVIEW"
    assert r.hold == "REVIEW_HOLD"       # stopped, waiting for approval
