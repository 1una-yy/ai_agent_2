"""Phase A — fast output scan (credential + forbidden-marker detection)."""

from gateway.governance import output_scan


def test_clean_text_no_hits():
    sig = output_scan.scan_text("The hello folder has three files: a.txt, b.txt, notes.md")
    assert not sig.any_hit
    assert sig.output_len > 0 and len(sig.output_sha256) == 64


def test_detects_common_credentials():
    text = (
        "here is the config\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "github token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\nblah\n"
        'api_key: "s3cr3t-value-1234"\n'
    )
    sig = output_scan.scan_text(text)
    assert "aws_access_key_id" in sig.credential_hits
    assert "github_pat" in sig.credential_hits
    assert "private_key_block" in sig.credential_hits
    assert "generic_secret_assignment" in sig.credential_hits
    assert sig.as_signal_dict()["credential_hits"] == len(sig.credential_hits)


def test_forbidden_markers_case_insensitive():
    sig = output_scan.scan_text("This doc is INTERNAL ONLY, do not share.",
                                forbidden_markers=["internal only", "機密"])
    assert sig.forbidden_hits == ["internal only"]


def test_redact_replaces_only_credential_spans():
    text = "key AKIAIOSFODNN7EXAMPLE and a normal sentence about lunch."
    out = output_scan.redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "normal sentence about lunch" in out
    assert "已遮蔽" in out


def test_signal_dict_never_carries_raw_text():
    sig = output_scan.scan_text("token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12")
    d = sig.as_signal_dict()
    assert "ghp_" not in str(d)
    assert set(d) == {"output_len", "output_sha256", "credential_hits", "credential_types",
                      "forbidden_hits", "forbidden_markers", "pii_hits", "pii_types",
                      "truncated_scan"}


# --------------------------------------------------------------------------- #
# Structural PII patterns — matched by shape, not by a label word nearby.
# --------------------------------------------------------------------------- #
def test_detects_tw_national_id_without_the_label_word():
    sig = output_scan.scan_text("his number starts with A199456780 as far as I can tell")
    assert "tw_national_id" in sig.pii_hits
    assert sig.any_hit is True


def test_detects_tw_mobile_phone():
    sig = output_scan.scan_text("call him at 0912-345-678 tomorrow")
    assert "tw_mobile_phone" in sig.pii_hits


def test_detects_ssn_and_credit_card_shapes():
    sig = output_scan.scan_text("ssn 123-45-6789, card 4111 1111 1111 1111")
    assert "ssn" in sig.pii_hits
    assert "credit_card" in sig.pii_hits


def test_clean_text_has_no_pii_hits():
    sig = output_scan.scan_text("the weather today is nice and sunny")
    assert sig.pii_hits == []


def test_redact_removes_pii_shapes_too():
    out = output_scan.redact("id A199456780, phone 0912-345-678, normal words here")
    assert "A199456780" not in out
    assert "0912-345-678" not in out
    assert "normal words here" in out
    assert out.count("已遮蔽") == 2


def test_scan_payload_sensitive_field_hit_from_pii_shape_alone():
    """The gap this closes: no "身分證"/"ssn" marker word anywhere in the
    text, but a real ID-number-shaped string — egress must still flag it."""
    sig = output_scan.scan_payload(
        "contact record: A199456780, reachable at 0912-345-678",
        sensitive_field_markers=["身分證", "ssn"])
    assert "tw_national_id" in sig.sensitive_field_hits
    assert "tw_mobile_phone" in sig.sensitive_field_hits
    assert sig.any_hit is True


# --------------------------------------------------------------------------- #
# Phase B — egress payload scan
# --------------------------------------------------------------------------- #
def test_scan_payload_flags_size_and_fields_and_creds():
    text = "user record: name=Bob, password=hunter2hunter2, notes: -----BEGIN PRIVATE KEY-----"
    sig = output_scan.scan_payload(
        text, forbidden_markers=[], sensitive_field_markers=["password", "ssn"],
        max_bytes=10)
    assert sig.oversize is True
    assert "password" in sig.sensitive_field_hits
    assert "private_key_block" in sig.credential_hits
    d = sig.as_signal_dict()
    assert d["oversize"] is True and d["sensitive_field_hits"] == 1
    assert "hunter2" not in str(d)   # raw value never in signals


def test_scan_payload_no_size_limit_when_zero():
    sig = output_scan.scan_payload("x" * 5000, max_bytes=0)
    assert sig.oversize is False


def test_truncate_bytes_cuts_and_marks():
    out = output_scan.truncate_bytes("A" * 1000, 100)
    assert out.startswith("A" * 100) and out.count("A") == 100   # body cut to the budget
    assert "截斷" in out
    assert output_scan.truncate_bytes("short", 100) == "short"
