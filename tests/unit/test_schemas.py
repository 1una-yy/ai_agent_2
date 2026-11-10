import pytest
from pydantic import ValidationError

from gateway.governance.schemas import (
    AdviceAvailability,
    Decision,
    SoftAdvice,
    Verdict,
)


def test_soft_advice_unavailable_is_deny_never_allow():
    a = SoftAdvice.unavailable(AdviceAvailability.UNAVAILABLE)
    assert a.advice == Verdict.DENY
    assert a.risk_level.value == "CRITICAL"
    assert a.availability == AdviceAvailability.UNAVAILABLE


def test_decision_fail_closed_is_locked_down():
    d = Decision.fail_closed("HARD_PDP_UNREACHABLE")
    assert d.decision == Verdict.DENY
    assert d.obligations.read_only is True
    assert d.obligations.max_autonomy == "L0"
    assert d.obligations.denied_tools == ["*"]
    assert "HARD_PDP_UNREACHABLE" in d.reason_codes


def test_soft_advice_rejects_out_of_range_risk_score():
    with pytest.raises(ValidationError):
        SoftAdvice(advice="ALLOW", risk_score=999, risk_level="LOW")


def test_soft_advice_rejects_unknown_verdict():
    with pytest.raises(ValidationError):
        SoftAdvice(advice="MAYBE", risk_score=1, risk_level="LOW")


def test_decision_rejects_extra_fields():
    with pytest.raises(ValidationError):
        Decision.model_validate({"decision": "ALLOW", "surprise": 1})
