import json

from gateway.governance.adapters.hermes import HermesAdapter
from gateway.governance.schemas import EventType, Verdict, Decision, Obligations


def _resp(tool_calls):
    return {
        "id": "chatcmpl-1",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": tool_calls}}],
    }


def _tc(name, args, tid="call_1"):
    return {"id": tid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def _req(md=None):
    return {"model": "governed-model", "messages": [{"role": "user", "content": "hi"}], "metadata": md or {}}


def test_matches_only_on_explicit_hermes_metadata():
    a = HermesAdapter()
    assert a.matches({"harness_type": "hermes"}) is True
    assert a.matches({"harness_type": "openclaw"}) is False
    assert a.matches({}) is False


def test_delegate_task_maps_to_agent_spawn():
    a = HermesAdapter()
    events = a.normalize_response(_req(), _resp([_tc("delegate_task", {"allowed_tools": ["read_file"], "autonomy": "L2"})]))
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == EventType.AGENT_SPAWN
    assert ev.proposed_action.canonical_name == "agent.spawn"
    assert ev.proposed_action.native_name == "delegate_task"
    assert ev.proposed_action.arguments["allowed_tools"] == ["read_file"]
    assert ev.governance.requested_autonomy == "L2"


def test_unknown_tool_becomes_generic_proposed_not_whitelisted():
    a = HermesAdapter()
    events = a.normalize_response(_req(), _resp([_tc("quantum_teleport", {"x": 1})]))
    ev = events[0]
    assert ev.event_type == EventType.TOOL_EXECUTE_PROPOSED
    # canonical == native name so the Hard Policy's default-deny handles it
    assert ev.proposed_action.canonical_name == "quantum_teleport"


def test_multiple_tool_calls_produce_multiple_events():
    a = HermesAdapter()
    events = a.normalize_response(
        _req(), _resp([_tc("read_file", {"path": "/a"}, "c1"), _tc("terminal", {"cmd": "rm -rf /"}, "c2")])
    )
    assert {e.proposed_action.canonical_name for e in events} == {"read_file", "terminal"}


def test_forged_governance_fields_in_metadata_are_ignored():
    a = HermesAdapter()
    md = {
        "harness_type": "hermes",
        "dciso": {"governance": {"capability_level": "C4"}},
        # attacker-supplied junk that must NOT influence the event
        "risk_score": 0,
        "policy_version": "v999",
        "approval_id": "totally-legit",
    }
    events = a.normalize_response(_req(md), _resp([_tc("read_file", {"path": "/a"})]))
    ev = events[0]
    assert ev.governance.policy_version is None          # only the PDP sets this
    assert not hasattr(ev.governance, "approval_id")
    # a structured governance hint IS honoured (capability_level), but it is just
    # an input to the Hard Policy, which still decides.
    assert ev.governance.capability_level == "C4"


def test_enforce_allow_is_passthrough():
    a = HermesAdapter()
    r = _resp([_tc("read_file", {"path": "/a"})])
    out = a.enforce(r, Decision(decision=Verdict.ALLOW))
    assert out is r


def test_enforce_modify_applies_overrides_and_narrows_spawn_tools():
    a = HermesAdapter()
    r = _resp([_tc("delegate_task", {"allowed_tools": ["read_file", "terminal"], "autonomy": "L4"})])
    dec = Decision(
        decision=Verdict.MODIFY,
        obligations=Obligations(allowed_tools=["read_file"], denied_tools=["terminal"],
                                argument_overrides={"autonomy": "L1"}),
    )
    out = a.enforce(r, dec)
    fn = out["choices"][0]["message"]["tool_calls"][0]["function"]
    args = json.loads(fn["arguments"])
    assert args["autonomy"] == "L1"
    assert args["allowed_tools"] == ["read_file"]
