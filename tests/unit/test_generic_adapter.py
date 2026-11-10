"""GenericOpenAIAdapter — Layer 1 governance for ANY OpenAI-compatible agent."""

import json

import pytest

from gateway.governance.adapters.generic import GenericOpenAIAdapter
from gateway.governance.adapters.hermes import HermesAdapter
from gateway.governance.normalizer import select_adapter
from gateway.governance.schemas import Decision, EventType, Obligations, Verdict


def _resp(tool_calls):
    return {"id": "chatcmpl-x",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                                                 "tool_calls": tool_calls}}]}


def _tc(name, args, tid="call_1"):
    return {"id": tid, "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}


def _req(md=None):
    return {"model": "m", "messages": [{"role": "user", "content": "hi"}], "metadata": md or {}}


# --------------------------------------------------------------------------- #
# selection
# --------------------------------------------------------------------------- #
def test_generic_is_the_catch_all():
    a = GenericOpenAIAdapter()
    assert a.matches({}) is True
    assert a.matches({"harness_type": "anything-at-all"}) is True


def test_registry_prefers_specific_then_falls_back_to_generic():
    assert select_adapter({"harness_type": "hermes"}).name == "hermes"
    assert select_adapter({"harness_type": "cursor"}).name == "openai-compatible"
    assert select_adapter({}).name == "openai-compatible"


def test_catch_all_can_be_disabled(monkeypatch):
    monkeypatch.setenv("DCISO_GENERIC_ADAPTER", "0")
    assert GenericOpenAIAdapter().matches({}) is False
    assert select_adapter({"harness_type": "cursor"}) is None  # -> fail closed upstream


# --------------------------------------------------------------------------- #
# harness_type stamping
# --------------------------------------------------------------------------- #
def test_known_harness_type_passes_through():
    a = GenericOpenAIAdapter()
    ev = a.normalize_response(_req({"harness_type": "claude-code"}), _resp([_tc("read_file", {"path": "/a"})]))[0]
    assert ev.source.harness_type == "claude-code"


def test_unknown_harness_type_normalised_to_generic():
    a = GenericOpenAIAdapter()
    ev = a.normalize_response(_req({"harness_type": "some-bespoke-runner"}), _resp([_tc("read_file", {"path": "/a"})]))[0]
    assert ev.source.harness_type == "openai-compatible"


# --------------------------------------------------------------------------- #
# normalization parity with the standard OpenAI schema
# --------------------------------------------------------------------------- #
def test_plain_tool_call_keeps_native_name_for_default_deny():
    a = GenericOpenAIAdapter()
    ev = a.normalize_response(_req(), _resp([_tc("terminal", {"command": "rm -rf /"})]))[0]
    assert ev.event_type == EventType.TOOL_EXECUTE_PROPOSED
    assert ev.proposed_action.canonical_name == "terminal"
    assert ev.proposed_action.arguments["command"] == "rm -rf /"


def test_multiple_tool_calls_multiple_events():
    a = GenericOpenAIAdapter()
    evs = a.normalize_response(_req(), _resp([_tc("read_file", {"path": "/a"}, "c1"),
                                             _tc("http_request", {"url": "https://x"}, "c2")]))
    assert {e.proposed_action.canonical_name for e in evs} == {"read_file", "http_request"}


@pytest.mark.parametrize("spawn_name", ["spawn_agent", "create_subagent", "Task", "handoff", "transfer_to_agent"])
def test_framework_delegation_names_map_to_agent_spawn(spawn_name):
    a = GenericOpenAIAdapter()
    ev = a.normalize_response(_req(), _resp([_tc(spawn_name, {"allowed_tools": ["read_file"], "autonomy": "L3"})]))[0]
    assert ev.event_type == EventType.AGENT_SPAWN
    assert ev.proposed_action.canonical_name == "agent.spawn"
    assert ev.governance.requested_autonomy == "L3"
    assert ev.proposed_action.arguments["allowed_tools"] == ["read_file"]


def test_extra_delegation_names_from_env(monkeypatch):
    monkeypatch.setenv("DCISO_DELEGATION_TOOLS", "my_custom_spawner, another_one")
    a = GenericOpenAIAdapter()
    ev = a.normalize_response(_req(), _resp([_tc("my_custom_spawner", {})]))[0]
    assert ev.event_type == EventType.AGENT_SPAWN


def test_forged_governance_metadata_ignored_but_hint_honoured():
    a = GenericOpenAIAdapter()
    md = {"harness_type": "langchain",
          "dciso": {"governance": {"capability_level": "C4"}},
          "risk_score": 0, "policy_version": "v999"}
    ev = a.normalize_response(_req(md), _resp([_tc("read_file", {"path": "/a"})]))[0]
    assert ev.governance.policy_version is None
    assert ev.governance.capability_level == "C4"


# --------------------------------------------------------------------------- #
# enforcement
# --------------------------------------------------------------------------- #
def test_enforce_allow_passthrough_identity():
    a = GenericOpenAIAdapter()
    r = _resp([_tc("read_file", {"path": "/a"})])
    assert a.enforce(r, Decision(decision=Verdict.ALLOW)) is r


def test_enforce_modify_narrows_spawn():
    a = GenericOpenAIAdapter()
    r = _resp([_tc("spawn_agent", {"allowed_tools": ["read_file", "terminal"], "autonomy": "L4"})])
    dec = Decision(decision=Verdict.MODIFY,
                   obligations=Obligations(allowed_tools=["read_file"], denied_tools=["terminal"],
                                           argument_overrides={"autonomy": "L1"}))
    out = a.enforce(r, dec)
    args = json.loads(out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])
    assert args["autonomy"] == "L1"
    assert args["allowed_tools"] == ["read_file"]


def test_hermes_delegation_stays_narrow():
    """Hermes must NOT inherit the generic broad delegation-name heuristic."""
    a = HermesAdapter()
    ev = a.normalize_response(_req({"harness_type": "hermes"}), _resp([_tc("handoff", {})]))[0]
    assert ev.event_type == EventType.TOOL_EXECUTE_PROPOSED  # not agent.spawn
    assert ev.proposed_action.canonical_name == "handoff"
