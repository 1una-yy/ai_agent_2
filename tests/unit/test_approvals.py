import time

import pytest

from gateway.governance import approvals
from gateway.governance.decision_orchestrator import OrchestrationOutcome
from gateway.governance.enforcer import Enforcer, ReplanTracker
from gateway.governance.adapters.hermes import HermesAdapter
from gateway.governance.schemas import (
    SCHEMA_VERSION, Decision, EnforcementPhase, EventType, GovernanceBlock,
    GovernanceEvent, ProposedAction, SoftAdvice, Source, Task, Verdict,
)


def _event(session="s-appr", canonical="send_email", args=None):
    return GovernanceEvent(
        schema_version=SCHEMA_VERSION, event_id="evt-appr", timestamp="2026-09-01T00:00:00Z",
        event_type=EventType.TOOL_EXECUTE_PROPOSED,
        enforcement_phase=EnforcementPhase.MODEL_RESPONSE_PRE_EXECUTION,
        source=Source(harness_type="hermes", harness_instance_id="h1", agent_id="a1", session_id=session),
        task=Task(task_id="t1"),
        proposed_action=ProposedAction(native_name=canonical, canonical_name=canonical, arguments=args or {"to": "x@y.z"}),
        governance=GovernanceBlock())


def _outcome(ev, verdict=Verdict.REQUIRE_REVIEW):
    return OrchestrationOutcome(
        event=ev, soft_advice=SoftAdvice(advice="ALLOW", risk_score=1, risk_level="LOW"),
        decision=Decision(decision=verdict, reason_codes=["TOOL_REVIEW_REQUIRED:send_email"],
                          policy_version="v0.1.0"),
        latency_ms=1.0)


def _resp():
    return {"choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "send_email", "arguments": "{\"to\": \"x@y.z\"}"}}]}}]}


def test_verify_without_secret_always_false(monkeypatch):
    monkeypatch.delenv("GOVERNANCE_APPROVAL_SECRET", raising=False)
    ok, why = approvals.verify("anything", "fp")
    assert ok is False and why == "no_server_secret"


def test_mint_requires_secret(monkeypatch):
    monkeypatch.delenv("GOVERNANCE_APPROVAL_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        approvals.mint("fp")


def test_roundtrip_valid_token(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_APPROVAL_SECRET", "s3cr3t")
    monkeypatch.delenv("AUDIT_DB_PATH", raising=False)
    ev = _event()
    fp = approvals.fingerprint_for_event(ev)
    tok = approvals.mint(fp, ttl_seconds=60, approver="alice")
    ok, why = approvals.verify(tok, fp)
    assert ok is True and why == "approved_by:alice"


def test_token_is_single_use_with_ledger(monkeypatch, tmp_path):
    monkeypatch.setenv("GOVERNANCE_APPROVAL_SECRET", "s3cr3t")
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.sqlite"))
    fp = "fp-abc"
    tok = approvals.mint(fp, ttl_seconds=60, approver="bob")
    ok1, why1 = approvals.verify(tok, fp)
    ok2, why2 = approvals.verify(tok, fp)
    assert ok1 is True
    assert ok2 is False and why2 == "already_used"
    # dry-run check does not spend the token
    fp2 = "fp-def"
    tok2 = approvals.mint(fp2, ttl_seconds=60)
    assert approvals.verify(tok2, fp2, consume=False)[0] is True
    assert approvals.verify(tok2, fp2)[0] is True  # still spendable once


def test_expired_token_rejected(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_APPROVAL_SECRET", "s3cr3t")
    fp = "abc"
    tok = approvals.mint(fp, ttl_seconds=-1)
    ok, why = approvals.verify(tok, fp)
    assert ok is False and why == "expired"


def test_fingerprint_mismatch_rejected(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_APPROVAL_SECRET", "s3cr3t")
    tok = approvals.mint("fp-for-action-A", ttl_seconds=60)
    ok, why = approvals.verify(tok, "fp-for-action-B")
    assert ok is False and why == "fingerprint_mismatch"


def test_tampered_signature_rejected(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_APPROVAL_SECRET", "s3cr3t")
    tok = approvals.mint("fp", ttl_seconds=60)
    ok, why = approvals.verify(tok[:-2] + "xx", "fp")
    assert ok is False and why in ("bad_signature", "malformed")


def test_enforcer_releases_review_only_with_valid_token(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_APPROVAL_SECRET", "s3cr3t")
    ev = _event()
    e = Enforcer(HermesAdapter(), ReplanTracker())

    # no token -> stays blocked (in-band review message)
    d0 = e.enforce(raw_response=_resp(), outcomes=[_outcome(ev)])
    assert d0.result.outcome == "REQUIRE_REVIEW"

    # wrong-action token -> still blocked
    bad = approvals.mint("different-fingerprint", ttl_seconds=60)
    d1 = e.enforce(raw_response=_resp(), outcomes=[_outcome(ev)], approval_token=bad)
    assert d1.result.outcome == "REQUIRE_REVIEW"

    # correct token -> released, audited as ALLOW + HUMAN_APPROVED, tool call kept
    good = approvals.mint(approvals.fingerprint_for_event(ev), ttl_seconds=60, approver="bob")
    d2 = e.enforce(raw_response=_resp(), outcomes=[_outcome(ev)], approval_token=good)
    assert d2.result.outcome == "ALLOW"
    assert any(rc.startswith("HUMAN_APPROVED") for rc in d2.result.reason_codes)
    assert d2.response["choices"][0]["message"]["tool_calls"] is not None


def test_token_does_not_rescue_a_hard_deny(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_APPROVAL_SECRET", "s3cr3t")
    ev = _event(canonical="terminal", args={"cmd": "x"})
    good = approvals.mint(approvals.fingerprint_for_event(ev), ttl_seconds=60)
    e = Enforcer(HermesAdapter(), ReplanTracker())
    d = e.enforce(raw_response=_resp(), outcomes=[_outcome(ev, Verdict.DENY)], approval_token=good)
    assert d.result.outcome == "DENY"  # approval tokens only apply to REQUIRE_REVIEW
