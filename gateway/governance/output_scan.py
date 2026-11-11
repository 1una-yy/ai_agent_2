"""Fast, deterministic scan of a model's final answer (Phase A — output side).

Cheap and predictable: regexes for common credential formats + a caller-supplied
list of forbidden-disclosure markers. Never a guarantee it finds everything —
it handles the clear cases so the expensive CISO review is reserved for real
risk. Results feed a GovernanceEvent (counts + types, NOT the raw text); OPA
still decides ALLOW / DENY / MODIFY(redact).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

# (type, compiled pattern) — structural, so they live in code not data.json.
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("bearer_token", re.compile(r"(?i)\b(?:bearer|authorization:\s*bearer)\s+[A-Za-z0-9._\-]{20,}\b")),
    ("generic_secret_assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|passwd|password|token|client[_-]?secret)\s*[=:]\s*['\"][^'\"\s]{12,}['\"]")),
]

# Structural PII patterns — matched by SHAPE, not by a label word appearing
# nearby. Closes the gap where `sensitive_field_markers` (plain keyword
# matching, e.g. "身分證") misses the data entirely because the model
# rephrased it without ever using that literal word (e.g. "his ID starts with
# A1..." or a bare CSV dump). Kept conservative: real structural formats only,
# not generic digit runs, to avoid flooding every reply with false positives.
_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("tw_national_id", re.compile(r"\b[A-Za-z][12]\d{8}\b")),
    ("tw_mobile_phone", re.compile(r"\b09\d{2}[-\s]?\d{3}[-\s]?\d{3}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b|\b\d{16}\b")),
]

_REDACTION = "[已遮蔽:{kind}]"


@dataclass
class OutputSignals:
    output_len: int = 0
    output_sha256: str = ""
    credential_hits: list[str] = field(default_factory=list)   # types, deduped, ordered
    forbidden_hits: list[str] = field(default_factory=list)    # markers matched
    pii_hits: list[str] = field(default_factory=list)          # structural PII pattern types
    truncated_scan: bool = False

    @property
    def any_hit(self) -> bool:
        return bool(self.credential_hits or self.forbidden_hits or self.pii_hits)

    def as_signal_dict(self) -> dict:
        """Goes into the GovernanceEvent — counts/types only, never raw text."""
        return {
            "output_len": self.output_len,
            "output_sha256": self.output_sha256,
            "credential_hits": len(self.credential_hits),
            "credential_types": list(self.credential_hits),
            "forbidden_hits": len(self.forbidden_hits),
            "forbidden_markers": list(self.forbidden_hits),
            "pii_hits": len(self.pii_hits),
            "pii_types": list(self.pii_hits),
            "truncated_scan": self.truncated_scan,
        }


def scan_text(text: str | None, forbidden_markers: list[str] | None = None,
              max_scan: int = 200_000) -> OutputSignals:
    text = text or ""
    full_len = len(text)
    sha = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    window = text[:max_scan]
    sig = OutputSignals(output_len=full_len, output_sha256=sha,
                        truncated_scan=full_len > max_scan)

    seen: set[str] = set()
    for kind, pat in _CREDENTIAL_PATTERNS:
        if pat.search(window) and kind not in seen:
            seen.add(kind)
            sig.credential_hits.append(kind)

    low = window.lower()
    for marker in forbidden_markers or []:
        m = str(marker).strip()
        if m and m.lower() in low:
            sig.forbidden_hits.append(m)

    for kind, pat in _PII_PATTERNS:
        if pat.search(window) and kind not in sig.pii_hits:
            sig.pii_hits.append(kind)
    return sig


def redact(text: str | None, max_scan: int = 200_000) -> str:
    """Replace credential- and PII-shaped spans with a marker. Leaves
    everything else untouched. Used when OPA returns MODIFY(redact)."""
    text = text or ""
    head, tail = text[:max_scan], text[max_scan:]
    for kind, pat in _CREDENTIAL_PATTERNS:
        head = pat.sub(_REDACTION.format(kind=kind), head)
    for kind, pat in _PII_PATTERNS:
        head = pat.sub(_REDACTION.format(kind=kind), head)
    return head + tail


def truncate_unscanned(text: str | None, max_chars: int) -> str:
    """Drop everything past the scanned character window (the same slice
    `scan_text` used to produce its signals) and append a marker. Used when
    OPA returns MODIFY(`OUTPUT_TRUNCATE_UNSCANNED`) — a reply longer than the
    scan window must never deliver its unscanned tail verbatim just because
    the scanned PREFIX happened to come back clean."""
    text = text or ""
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n…[治理：內容過長，後段未掃描，已截斷]"


# --------------------------------------------------------------------------- #
# Egress side (Phase B) — a tool result about to be sent to a model endpoint.
# --------------------------------------------------------------------------- #
@dataclass
class PayloadSignals:
    byte_len: int = 0
    sha256: str = ""
    credential_hits: list[str] = field(default_factory=list)
    forbidden_hits: list[str] = field(default_factory=list)
    sensitive_field_hits: list[str] = field(default_factory=list)
    oversize: bool = False

    @property
    def any_hit(self) -> bool:
        return bool(self.credential_hits or self.forbidden_hits or self.sensitive_field_hits)

    def as_signal_dict(self) -> dict:
        return {
            "byte_len": self.byte_len,
            "sha256": self.sha256,
            "credential_hits": len(self.credential_hits),
            "credential_types": list(self.credential_hits),
            "forbidden_hits": len(self.forbidden_hits),
            "sensitive_field_hits": len(self.sensitive_field_hits),
            "sensitive_fields": list(self.sensitive_field_hits),
            "oversize": self.oversize,
        }


def scan_payload(text: str | None, *, forbidden_markers: list[str] | None = None,
                 sensitive_field_markers: list[str] | None = None,
                 max_bytes: int = 0, max_scan: int = 200_000) -> PayloadSignals:
    text = text or ""
    raw = text.encode("utf-8", "replace")
    sig = PayloadSignals(byte_len=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                         oversize=bool(max_bytes) and len(raw) > max_bytes)
    window = text[:max_scan]
    seen: set[str] = set()
    for kind, pat in _CREDENTIAL_PATTERNS:
        if pat.search(window) and kind not in seen:
            seen.add(kind)
            sig.credential_hits.append(kind)
    low = window.lower()
    for marker in forbidden_markers or []:
        m = str(marker).strip().lower()
        if m and m in low:
            sig.forbidden_hits.append(str(marker).strip())
    for marker in sensitive_field_markers or []:
        m = str(marker).strip().lower()
        if m and m in low:
            sig.sensitive_field_hits.append(str(marker).strip())

    # Structural PII hits count as sensitive fields too — a real ID-number-
    # shaped string triggers this even when the model never says the word
    # "身分證"/"SSN" next to it (see _PII_PATTERNS above).
    for kind, pat in _PII_PATTERNS:
        if pat.search(window) and kind not in sig.sensitive_field_hits:
            sig.sensitive_field_hits.append(kind)
    return sig


def truncate_bytes(text: str | None, max_bytes: int) -> str:
    """Cut to a UTF-8 byte budget on a character boundary, append a marker."""
    text = text or ""
    if max_bytes <= 0 or len(text.encode("utf-8")) <= max_bytes:
        return text
    enc = text.encode("utf-8")[:max_bytes]
    cut = enc.decode("utf-8", "ignore")
    return cut + "\n…[治理:工具結果過大，已截斷]"
