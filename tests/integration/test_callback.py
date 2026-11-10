"""Wiring tests for the LiteLLM governance callback.

OPA and the CISO advisor are mocked with respx; the callback, adapter,
orchestrator, enforcer and audit writer are exercised for real.
"""

import json
import os
import sqlite3
import types

import httpx
import pytest
import respx


@pytest.fixture()
def cb(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.sqlite"))
    monkeypatch.setenv("OPA_URL", "http://opa:8181")
    monkeypatch.setenv("CISO_ADVISOR_URL", "http://ciso-advisor:9000")
    monkeypatch.setenv("REPLAN_MAX_ATTEMPTS", "2")
    import importlib

    from gateway.callbacks import governance_callback as mod

    importlib.reload(mod)
    return mod


def _mk_response(tool_calls=None, content=None):
    """A minimal stand-in for litellm.ModelResponse with attribute access."""
    msg = types.SimpleNamespace(role="assistant", content=content, tool_calls=tool_calls)
    choice = types.SimpleNamespace(index=0, finish_reason="tool_calls" if tool_calls else "stop", message=msg)

    def model_dump():
        return {
            "id": "chatcmpl-x",
            "choices": [{
                "index": 0,
                "finish_reason": choice.finish_reason,
                "message": {
                    "role": "assistant",
                    "content": msg.content,
                    "tool_calls": [
                        {"id": tc["id"], "type": "function",
                         "function": {"name": tc["function"]["name"],
                                      "arguments": tc["function"]["arguments"]}}
                        for tc in (tool_calls or [])
                    ] or None,
                },
            }],
        }

    return types.SimpleNamespace(id="chatcmpl-x", choices=[choice], model_dump=model_dump)


def _tc(name, args):
    return {"id": "call_1", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def _data(tool_name=None, args=None, harness="hermes"):
    d = {
        "model": "governed-model",
        "messages": [{"role": "user", "content": "do the thing"}],
        "metadata": {"harness_type": harness, "session_id": "sess-1", "harness_instance_id": "hermes-01"},
        "litellm_call_id": "lc-1",
    }
    return d


def _rows(db_path):
    con = sqlite3.connect(db_path)
    try:
        return con.execute("SELECT outcome, event_type, canonical_name, reason_codes FROM audit_log").fetchall()
    finally:
        con.close()


@respx.mock
async def test_plain_response_passes_through_and_is_audited(cb):
    resp = _mk_response(content="hello, no tools here")
    out = await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    assert out is resp
    rows = _rows(os.environ["AUDIT_DB_PATH"])
    assert rows and rows[0][0] == "ALLOW"


@respx.mock
async def test_allow_tool_call_is_unchanged(cb):
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 2, "risk_level": "LOW"})
    )
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {},
                   "policy_version": "v0.1.0"}
    }))
    resp = _mk_response(tool_calls=[_tc("read_file", {"path": "/a"})])
    out = await cb.governance_handler_instance.async_post_call_success_hook(
        _data(), None, resp
    )
    assert out.choices[0].message.tool_calls is not None
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][0] == "ALLOW"


@respx.mock
async def test_deny_strips_tool_calls_and_shows_reason(cb):
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 2, "risk_level": "LOW"})
    )
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "DENY", "reason_codes": ["DANGEROUS_TOOL_DENIED:terminal"],
                   "obligations": {}, "policy_version": "v0.1.0"}
    }))
    resp = _mk_response(tool_calls=[_tc("terminal", {"cmd": "rm -rf /"})])
    out = await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    assert out.choices[0].message.tool_calls is None
    # end-user content is a short plain sentence: no JSON block, no internals
    assert "無法完成" in out.choices[0].message.content
    assert "dciso_governance" not in out.choices[0].message.content
    assert "rule-engine" not in out.choices[0].message.content
    outcome, etype, canon, reasons = _rows(os.environ["AUDIT_DB_PATH"])[0]
    assert outcome == "DENY" and canon == "terminal"


@respx.mock
async def test_deny_verbose_block_opt_in(cb, monkeypatch):
    monkeypatch.setenv("DCISO_VERBOSE_DENY", "1")
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 2, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "DENY", "reason_codes": ["DANGEROUS_TOOL_DENIED:terminal"],
                   "obligations": {}, "policy_version": "v0.1.0"}}))
    resp = _mk_response(tool_calls=[_tc("terminal", {"cmd": "x"})])
    out = await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    assert "dciso_governance" in out.choices[0].message.content


@respx.mock
async def test_require_review_inband_strips_tool_call(cb):
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 2, "risk_level": "LOW"})
    )
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "REQUIRE_REVIEW", "reason_codes": ["TOOL_REVIEW_REQUIRED:send_email"],
                   "obligations": {}, "policy_version": "v0.1.0"}
    }))
    resp = _mk_response(tool_calls=[_tc("send_email", {"to": "x@y.z"})])
    out = await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    assert out.choices[0].message.tool_calls is None
    assert "人工審核" in out.choices[0].message.content
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][0] == "REQUIRE_REVIEW"


@respx.mock
async def test_unknown_harness_tool_call_denied(cb):
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"})
    )
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "DENY", "reason_codes": ["UNKNOWN_HARNESS", "UNKNOWN_EVENT_TYPE"],
                   "obligations": {}, "policy_version": "v0.1.0"}
    }))
    resp = _mk_response(tool_calls=[_tc("read_file", {"path": "/a"})])
    out = await cb.governance_handler_instance.async_post_call_success_hook(
        _data(harness="openclaw"), None, resp
    )
    assert out.choices[0].message.tool_calls is None


async def test_pre_hook_does_not_refuse_streaming(cb):
    out = await cb.governance_handler_instance.async_pre_call_hook(
        None, None, {"model": "governed-model", "stream": True,
                     "messages": [{"role": "user", "content": "hi"}]}, "completion",
    )
    assert out["metadata"]["dciso_runtime"]["t_start"] > 0


async def _aiter(items):
    for it in items:
        yield it


def _stream_chunk(content=None, tool_calls=None, finish=None):
    return {"id": "chatcmpl-s", "object": "chat.completion.chunk", "model": "governed-model",
            "choices": [{"index": 0, "finish_reason": finish,
                         "delta": {"content": content, "tool_calls": tool_calls}}]}


@respx.mock
async def test_streaming_allow_replays_chunks_unchanged(cb):
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {},
                   "policy_version": "v0.1.0"}}))
    src = [_stream_chunk(content="hel"), _stream_chunk(content="lo"), _stream_chunk(finish="stop")]
    out = [c async for c in cb.governance_handler_instance.async_post_call_streaming_iterator_hook(
        None, _aiter(src), _data())]
    assert out == src


@respx.mock
async def test_streaming_deny_replaces_tool_call_stream_with_reason(cb):
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "DENY", "reason_codes": ["DANGEROUS_TOOL_DENIED:terminal"],
                   "obligations": {}, "policy_version": "v0.1.0"}}))
    # streamed tool call assembled from deltas
    src = [
        _stream_chunk(tool_calls=[{"index": 0, "id": "call_1", "type": "function",
                                   "function": {"name": "terminal", "arguments": ""}}]),
        _stream_chunk(tool_calls=[{"index": 0, "function": {"arguments": "{\"cmd\":\"rm -rf /\"}"}}]),
        _stream_chunk(finish="tool_calls"),
    ]
    out = [c async for c in cb.governance_handler_instance.async_post_call_streaming_iterator_hook(
        None, _aiter(src), _data())]
    text = "".join((c["choices"][0]["delta"].get("content") or "") for c in out)
    assert "無法完成" in text and "dciso_governance" not in text
    # the raw terminal tool call never reaches the client
    assert all(not c["choices"][0]["delta"].get("tool_calls") for c in out)
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][0] == "DENY"


@respx.mock
async def test_audit_write_failure_fails_closed(cb, monkeypatch):
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"})
    )
    respx.post(url__regex=r".*/v1/data/.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {},
                   "policy_version": "v0.1.0"}
    }))

    def boom(**kw):
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(cb.governance_handler_instance._audit, "write", boom)
    resp = _mk_response(tool_calls=[_tc("read_file", {"path": "/a"})])
    with pytest.raises(cb.GovernanceReject) as ei:
        await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    assert ei.value.body["error"]["code"] in ("AUDIT_WRITE_FAILED", "GOVERNANCE_FAIL_CLOSED")


# --------------------------------------------------------------------------- #
# Phase A — output-side governance (model answer before delivery)
# --------------------------------------------------------------------------- #
@respx.mock
async def test_output_fastpath_clean_answer_skips_opa_and_ciso(cb):
    opa = respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={"result": {"decision": "ALLOW"}}))
    ciso = respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    resp = _mk_response(content="the hello folder has a.txt and b.txt")
    out = await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    assert out is resp
    assert not opa.called and not ciso.called          # fast path — no expensive calls
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][:1] == ("ALLOW",)
    assert "OUTPUT_FASTPATH_ALLOW" in _rows(os.environ["AUDIT_DB_PATH"])[0][3]


@respx.mock
async def test_output_credential_is_redacted(cb):
    respx.post(url__regex=r".*/v1/data/dciso/output_policy.*").mock(
        return_value=httpx.Response(200, json={"result": {"enabled": True, "forbidden_markers": []}}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "decision": "MODIFY", "reason_codes": ["REDACT_OUTPUT_CREDENTIAL"],
            "obligations": {}, "policy_version": "v0.1.0"}}))
    respx.get(url__regex=r".*/v1/data/dciso/output_policy.*").mock(
        return_value=httpx.Response(200, json={"result": {"enabled": True, "forbidden_markers": []}}))
    resp = _mk_response(content="your key is AKIAIOSFODNN7EXAMPLE, keep it safe")
    out = await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    assert "AKIAIOSFODNN7EXAMPLE" not in out.choices[0].message.content
    assert "已遮蔽" in out.choices[0].message.content
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][0] == "MODIFY"


@respx.mock
async def test_output_forbidden_marker_is_blocked(cb):
    respx.get(url__regex=r".*/v1/data/dciso/output_policy.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "enabled": True, "forbidden_markers": ["INTERNAL ONLY"]}}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "decision": "DENY", "reason_codes": ["FORBIDDEN_DISCLOSURE"],
            "obligations": {}, "policy_version": "v0.1.0"}}))
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    resp = _mk_response(content="Roadmap (INTERNAL ONLY): we will acquire X in Q3.")
    out = await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    assert "acquire X" not in (out.choices[0].message.content or "")
    assert "輸出政策" in out.choices[0].message.content
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][0] == "DENY"


# --------------------------------------------------------------------------- #
# Phase B — egress governance (tool result before it reaches a model)
# --------------------------------------------------------------------------- #
def _data_with_tool_result(content):
    return {
        "model": "governed-model",
        "messages": [
            {"role": "user", "content": "list the folder"},
            {"role": "assistant", "content": None,
             "tool_calls": [_tc("terminal", {"command": "ls"})]},
            {"role": "tool", "tool_call_id": "call_1", "content": content},
        ],
        "metadata": {"harness_type": "hermes", "session_id": "sess-1"},
        "litellm_call_id": "lc-b",
    }


@respx.mock
async def test_egress_local_clean_is_fastpath(cb, monkeypatch):
    monkeypatch.setenv("DCISO_EGRESS_DEST_CLASS", "local")
    dec = respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={"result": {"decision": "ALLOW"}}))
    d = _data_with_tool_result("total 0\n-rw-r--r-- 1 u u 0 a.txt\n-rw-r--r-- 1 u u 0 b.txt")
    out = await cb.governance_handler_instance.async_pre_call_hook(None, None, d, "completion")
    assert out["messages"][2]["content"].startswith("total 0")   # untouched
    assert not dec.called
    assert "EGRESS_FASTPATH_ALLOW" in _rows(os.environ["AUDIT_DB_PATH"])[0][3]


@respx.mock
async def test_egress_credential_redacted_before_send(cb, monkeypatch):
    monkeypatch.setenv("DCISO_EGRESS_DEST_CLASS", "external")
    respx.get(url__regex=r".*/v1/data/dciso/egress_policy.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "enabled": True, "forbidden_markers": [], "sensitive_field_markers": [],
            "class_rules": {"external": {"max_result_kb": 256, "redact_credentials": True,
                                        "block_forbidden": True, "block_if_sensitive_task": True,
                                        "block_sensitive_fields": True}},
            "withheld_notice": "[治理] withheld"}}))
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "decision": "MODIFY", "reason_codes": ["EGRESS_REDACT_CREDENTIAL"],
            "obligations": {}, "policy_version": "v0.1.0"}}))
    d = _data_with_tool_result("config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE ok")
    out = await cb.governance_handler_instance.async_pre_call_hook(None, None, d, "completion")
    assert "AKIAIOSFODNN7EXAMPLE" not in out["messages"][2]["content"]
    assert "已遮蔽" in out["messages"][2]["content"]
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][0] == "MODIFY"


@respx.mock
async def test_egress_forbidden_marker_withheld(cb, monkeypatch):
    monkeypatch.setenv("DCISO_EGRESS_DEST_CLASS", "external")
    respx.get(url__regex=r".*/v1/data/dciso/egress_policy.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "enabled": True, "forbidden_markers": ["INTERNAL ONLY"], "sensitive_field_markers": [],
            "class_rules": {"external": {"max_result_kb": 256, "redact_credentials": True,
                                        "block_forbidden": True, "block_if_sensitive_task": True,
                                        "block_sensitive_fields": True}},
            "withheld_notice": "[治理] 這段工具結果未送往模型。"}}))
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "decision": "DENY", "reason_codes": ["EGRESS_FORBIDDEN_MARKER"],
            "obligations": {}, "policy_version": "v0.1.0"}}))
    d = _data_with_tool_result("Q3 roadmap — INTERNAL ONLY — acquire competitor X")
    out = await cb.governance_handler_instance.async_pre_call_hook(None, None, d, "completion")
    assert "acquire competitor X" not in out["messages"][2]["content"]
    assert "未送往模型" in out["messages"][2]["content"]
    assert _rows(os.environ["AUDIT_DB_PATH"])[0][0] == "DENY"


@respx.mock
async def test_phase_e_timings_written_to_audit(cb):
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 2, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {},
            "policy_version": "v0.1.0"}}))
    d = _data()
    await cb.governance_handler_instance.async_pre_call_hook(None, None, d, "completion")
    resp = _mk_response(tool_calls=[_tc("read_file", {"path": "/a"})])
    await cb.governance_handler_instance.async_post_call_success_hook(d, None, resp)
    con = sqlite3.connect(os.environ["AUDIT_DB_PATH"])
    try:
        tj, hold = con.execute(
            "SELECT timings, hold FROM audit_log ORDER BY ts_epoch DESC LIMIT 1").fetchone()
    finally:
        con.close()
    t = json.loads(tj)
    assert "governance_ms" in t and "model_ms" in t and "opa_ms" in t
    assert hold == "NONE"
