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
# ticket remediation §3 — a reply's free text must be checked by the output
# policy even when it ALSO carries tool calls (previously the output gate was
# only reached when there were NO proposed tool-call events at all).
# --------------------------------------------------------------------------- #
def _decision_by_event_type(tool_result, output_result):
    """respx side_effect: the SAME /decision endpoint is hit once for the
    tool-call event and once for the output(text) event in a mixed reply —
    answer each differently based on input.event_type."""
    def _side_effect(request):
        body = json.loads(request.content)
        event_type = (body.get("input") or {}).get("event_type")
        payload = output_result if event_type == "model.output.proposed" else tool_result
        return httpx.Response(200, json={"result": payload})
    return _side_effect


@respx.mock
async def test_mixed_reply_text_pii_still_redacted_alongside_allowed_tool_call(cb):
    respx.get(url__regex=r".*/v1/data/dciso/output_policy.*").mock(
        return_value=httpx.Response(200, json={"result": {"enabled": True, "forbidden_markers": []}}))
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(side_effect=_decision_by_event_type(
        tool_result={"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {}, "policy_version": "v0.1.0"},
        output_result={"decision": "MODIFY", "reason_codes": ["REDACT_OUTPUT_PII"], "obligations": {}, "policy_version": "v0.1.0"},
    ))
    resp = _mk_response(
        content="his number is A199456780, let me check the file",
        tool_calls=[_tc("read_file", {"path": "/a"})])
    out = await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    # text was redacted even though the tool call itself was ALLOW
    assert "A199456780" not in out.choices[0].message.content
    assert "已遮蔽" in out.choices[0].message.content
    # the allowed tool call is still intact — the text verdict didn't erase it
    assert out.choices[0].message.tool_calls is not None


@respx.mock
async def test_output_text_exceeding_scan_limit_tail_is_truncated_not_delivered(cb, monkeypatch):
    monkeypatch.setattr(cb.governance_handler_instance, "_output_max_scan", 20)
    respx.get(url__regex=r".*/v1/data/dciso/output_policy.*").mock(
        return_value=httpx.Response(200, json={"result": {"enabled": True, "forbidden_markers": []}}))
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(return_value=httpx.Response(200, json={
        "result": {"decision": "MODIFY", "reason_codes": ["OUTPUT_TRUNCATE_UNSCANNED"],
                   "obligations": {}, "policy_version": "v0.1.0"}}))
    text = ("A" * 20) + "RAW-SECRET-TAIL-MUST-NOT-SHIP"
    resp = _mk_response(content=text)
    out = await cb.governance_handler_instance.async_post_call_success_hook(_data(), None, resp)
    assert "RAW-SECRET-TAIL-MUST-NOT-SHIP" not in out.choices[0].message.content
    assert "截斷" in out.choices[0].message.content


@respx.mock
async def test_mixed_reply_pii_redacted_via_buffered_streaming_path(cb):
    """Same §3 fix, exercised through the buffered-streaming hook — a mixed
    tool_call + PII-text reply must come out redacted there too."""
    respx.get(url__regex=r".*/v1/data/dciso/output_policy.*").mock(
        return_value=httpx.Response(200, json={"result": {"enabled": True, "forbidden_markers": []}}))
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(side_effect=_decision_by_event_type(
        tool_result={"decision": "ALLOW", "reason_codes": ["POLICY_ALLOW"], "obligations": {}, "policy_version": "v0.1.0"},
        output_result={"decision": "MODIFY", "reason_codes": ["REDACT_OUTPUT_PII"], "obligations": {}, "policy_version": "v0.1.0"},
    ))
    src = [
        _stream_chunk(content="his number is A199456780"),
        _stream_chunk(tool_calls=[{"index": 0, "id": "call_1", "type": "function",
                                   "function": {"name": "read_file", "arguments": "{}"}}]),
        _stream_chunk(finish="tool_calls"),
    ]
    out = [c async for c in cb.governance_handler_instance.async_post_call_streaming_iterator_hook(
        None, _aiter(src), _data())]
    text = "".join((c["choices"][0]["delta"].get("content") or "") for c in out)
    assert "A199456780" not in text
    assert "已遮蔽" in text
    # tool call MODIFY-path keeps the (unmodified, since no argument_overrides
    # were given) tool call in the stream
    assert any(c["choices"][0]["delta"].get("tool_calls") for c in out)


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


# --------------------------------------------------------------------------- #
# ticket remediation §2 — an unexpected failure during egress checking must
# withhold the affected tool result(s) rather than let the unscanned original
# through to the upstream model.
# --------------------------------------------------------------------------- #
def _data_with_two_tool_results(content_a, content_b):
    return {
        "model": "governed-model",
        "messages": [
            {"role": "user", "content": "do two things"},
            {"role": "assistant", "content": None, "tool_calls": [
                _tc("terminal", {"command": "ls"}), _tc("terminal", {"command": "cat f"})]},
            {"role": "tool", "tool_call_id": "call_1", "content": content_a},
            {"role": "tool", "tool_call_id": "call_2", "content": content_b},
        ],
        "metadata": {"harness_type": "hermes", "session_id": "sess-1"},
        "litellm_call_id": "lc-b2",
    }


@respx.mock
async def test_egress_scan_exception_withholds_that_result_not_leaks_raw(cb, monkeypatch):
    monkeypatch.setenv("DCISO_EGRESS_DEST_CLASS", "external")

    def _boom(*a, **kw):
        raise RuntimeError("scan blew up")
    monkeypatch.setattr("gateway.callbacks.governance_callback.output_scan.scan_payload", _boom)

    d = _data_with_tool_result("super secret raw payload that must never ship unscanned")
    out = await cb.governance_handler_instance.async_pre_call_hook(None, None, d, "completion")
    assert "super secret raw payload" not in out["messages"][2]["content"]


@respx.mock
async def test_egress_failure_mid_loop_does_not_leak_later_messages(cb, monkeypatch):
    """Two tool results in one request; the scan throws on EVERY call. Neither
    message's raw content may survive — a failure on the first must not cause
    the second (not-yet-processed) message to be sent through untouched."""
    monkeypatch.setenv("DCISO_EGRESS_DEST_CLASS", "external")

    def _boom(*a, **kw):
        raise RuntimeError("scan blew up")
    monkeypatch.setattr("gateway.callbacks.governance_callback.output_scan.scan_payload", _boom)

    d = _data_with_two_tool_results("RAW-SECRET-A-must-not-leak", "RAW-SECRET-B-must-not-leak")
    out = await cb.governance_handler_instance.async_pre_call_hook(None, None, d, "completion")
    assert "RAW-SECRET-A-must-not-leak" not in out["messages"][2]["content"]
    assert "RAW-SECRET-B-must-not-leak" not in out["messages"][3]["content"]


@respx.mock
async def test_egress_policy_fetch_failure_withholds_all_tool_results(cb, monkeypatch):
    """A failure ABOVE the per-message loop (e.g. policy resolution itself
    blowing up, not just one message's scan) must fail closed for every tool
    result in the request, not just continue with defaults."""
    monkeypatch.setenv("DCISO_EGRESS_DEST_CLASS", "external")

    async def _boom():
        raise RuntimeError("policy fetch blew up")
    monkeypatch.setattr(cb.governance_handler_instance, "_get_egress_policy", _boom)

    d = _data_with_two_tool_results("RAW-SECRET-A-must-not-leak", "RAW-SECRET-B-must-not-leak")
    out = await cb.governance_handler_instance.async_pre_call_hook(None, None, d, "completion")
    assert "RAW-SECRET-A-must-not-leak" not in out["messages"][2]["content"]
    assert "RAW-SECRET-B-must-not-leak" not in out["messages"][3]["content"]


# --------------------------------------------------------------------------- #
# dest_class resolution — must reflect the REAL upstream host, never just the
# GATEWAY_ROUTE_MODE label (a route labelled "ollama"/"local" pointed at a
# genuinely public host must NOT be classified "local").
# --------------------------------------------------------------------------- #
def test_host_is_local_recognizes_private_and_loopback(cb):
    is_local = cb.governance_handler_instance._host_is_local
    assert is_local("127.0.0.1") is True
    assert is_local("localhost") is True
    assert is_local("192.168.1.10") is True
    assert is_local("10.0.0.5") is True
    assert is_local("172.16.0.9") is True
    assert is_local("") is False


def test_host_is_local_rejects_public_ip_and_hostnames(cb):
    is_local = cb.governance_handler_instance._host_is_local
    assert is_local("8.8.8.8") is False
    assert is_local("api.openai.com") is False
    assert is_local("ollama.example.com") is False


def test_dest_class_ignores_route_mode_label_for_a_public_host(cb, monkeypatch):
    # The bug being fixed: GATEWAY_ROUTE_MODE=ollama used to mean dest_class
    # "local" unconditionally. Here the upstream is a genuinely public host —
    # it must classify as external regardless of the route-mode label.
    monkeypatch.setenv("GATEWAY_ROUTE_MODE", "ollama")
    monkeypatch.setenv("GATEWAY_UPSTREAM_API_BASE", "https://ollama.example.com/v1")
    policy = cb.GovernanceCallback._EGRESS_POLICY_DEFAULT
    assert cb.governance_handler_instance._dest_class({}, policy) == "external"


def test_dest_class_is_local_for_a_real_lan_ollama(cb, monkeypatch):
    monkeypatch.setenv("GATEWAY_ROUTE_MODE", "ollama")
    monkeypatch.setenv("GATEWAY_UPSTREAM_API_BASE", "http://192.168.1.10:11434/v1")
    policy = cb.GovernanceCallback._EGRESS_POLICY_DEFAULT
    assert cb.governance_handler_instance._dest_class({}, policy) == "local"


def test_dest_class_approved_hosts_allowlist(cb, monkeypatch):
    monkeypatch.setenv("GATEWAY_UPSTREAM_API_BASE", "https://llm.partner.example.com/v1")
    policy = dict(cb.GovernanceCallback._EGRESS_POLICY_DEFAULT, approved_hosts=["partner.example.com"])
    assert cb.governance_handler_instance._dest_class({}, policy) == "approved"


def test_dest_class_approved_hosts_via_env(cb, monkeypatch):
    monkeypatch.setenv("GATEWAY_UPSTREAM_API_BASE", "https://llm.partner.example.com/v1")
    monkeypatch.setenv("DCISO_APPROVED_HOSTS", "partner.example.com")
    policy = cb.GovernanceCallback._EGRESS_POLICY_DEFAULT
    assert cb.governance_handler_instance._dest_class({}, policy) == "approved"


def test_dest_class_force_external_overrides_private_ip(cb, monkeypatch):
    # ticket remediation §4 — a LAN proxy that itself relays to the cloud: the
    # gateway only sees this private-IP first hop, so without an explicit
    # declaration it would be wrongly trusted as "local".
    monkeypatch.setenv("GATEWAY_UPSTREAM_API_BASE", "http://192.168.1.50:8080/v1")
    policy = dict(cb.GovernanceCallback._EGRESS_POLICY_DEFAULT, force_external_hosts=["192.168.1.50"])
    assert cb.governance_handler_instance._dest_class({}, policy) == "external"


def test_dest_class_force_external_via_env(cb, monkeypatch):
    monkeypatch.setenv("GATEWAY_UPSTREAM_API_BASE", "http://192.168.1.50:8080/v1")
    monkeypatch.setenv("DCISO_FORCE_EXTERNAL_HOSTS", "192.168.1.50")
    policy = cb.GovernanceCallback._EGRESS_POLICY_DEFAULT
    assert cb.governance_handler_instance._dest_class({}, policy) == "external"


def test_dest_class_without_force_external_private_ip_stays_local(cb, monkeypatch):
    # sanity counterpart — direct-to-LAN-Ollama must still classify "local"
    # when the operator has NOT declared it as a forwarding proxy.
    monkeypatch.setenv("GATEWAY_UPSTREAM_API_BASE", "http://192.168.1.50:11434/v1")
    policy = cb.GovernanceCallback._EGRESS_POLICY_DEFAULT
    assert cb.governance_handler_instance._dest_class({}, policy) == "local"


def test_dest_class_explicit_override_still_wins(cb, monkeypatch):
    # The explicit test/demo override is a deliberate operator action (unlike
    # the route-mode label) and must still take precedence.
    monkeypatch.setenv("GATEWAY_UPSTREAM_API_BASE", "https://ollama.example.com/v1")
    monkeypatch.setenv("DCISO_EGRESS_DEST_CLASS", "external")
    policy = cb.GovernanceCallback._EGRESS_POLICY_DEFAULT
    assert cb.governance_handler_instance._dest_class({}, policy) == "external"


def test_dest_class_unresolvable_upstream_fails_safe_to_external(cb, monkeypatch):
    monkeypatch.delenv("GATEWAY_UPSTREAM_API_BASE", raising=False)
    policy = cb.GovernanceCallback._EGRESS_POLICY_DEFAULT
    assert cb.governance_handler_instance._dest_class({}, policy) == "external"


@respx.mock
async def test_egress_sensitive_field_caught_by_pii_shape_without_the_label_word(cb, monkeypatch):
    """The gap this closes: content with no literal "身分證"/"ssn" marker word
    nearby, but a real ID-number-shaped string, must still be caught."""
    monkeypatch.setenv("DCISO_EGRESS_DEST_CLASS", "external")
    respx.get(url__regex=r".*/v1/data/dciso/egress_policy.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "enabled": True, "forbidden_markers": [], "sensitive_field_markers": ["身分證"],
            "class_rules": {"external": {"max_result_kb": 256, "redact_credentials": True,
                                        "block_forbidden": True, "block_if_sensitive_task": True,
                                        "block_sensitive_fields": True}},
            "withheld_notice": "[治理] withheld"}}))
    respx.post("http://ciso-advisor:9000/advise").mock(
        return_value=httpx.Response(200, json={"advice": "ALLOW", "risk_score": 1, "risk_level": "LOW"}))
    respx.post(url__regex=r".*/v1/data/dciso/governance/decision.*").mock(
        return_value=httpx.Response(200, json={"result": {
            "decision": "DENY", "reason_codes": ["EGRESS_SENSITIVE_FIELD"],
            "obligations": {}, "policy_version": "v0.1.0"}}))
    # No "身分證" word anywhere — just the number in A1-prefixed TW-ID shape.
    d = _data_with_tool_result("patient contact: his number starts with A199456780, call 0912-345-678")
    out = await cb.governance_handler_instance.async_pre_call_hook(None, None, d, "completion")
    assert "A199456780" not in out["messages"][2]["content"]
    assert "未送往模型" in out["messages"][2]["content"] or "withheld" in out["messages"][2]["content"]


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
