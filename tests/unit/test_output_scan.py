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
                      "forbidden_hits", "forbidden_markers", "truncated_scan"}


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
