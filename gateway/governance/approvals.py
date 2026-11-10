"""Verifiable human-approval tokens for REQUIRE_REVIEW (ticket §8, §13).

MVP contract: the gateway NEVER auto-retries or auto-allows a REQUIRE_REVIEW
action. A human (out of band) approves a specific proposed action; the review
system mints a short-TTL HMAC token bound to that action; the client resubmits
the same action carrying the token in `metadata.dciso.approval_token`.

The token is bound to a **stable fingerprint** of the action
(session + canonical name + arguments), NOT the ephemeral event_id, so it
survives the resubmission. It is single-purpose, expiring, and server-signed:
a forged or stale token simply fails `verify()` and the action stays blocked.

Secret: `GOVERNANCE_APPROVAL_SECRET` (required to mint; if unset, verify always
returns False so nothing is ever auto-allowed by accident).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

from gateway.governance.schemas import GovernanceEvent

_SECRET_ENV = "GOVERNANCE_APPROVAL_SECRET"


def action_fingerprint(session_id: str, canonical_name: str, arguments: dict[str, Any]) -> str:
    payload = json.dumps(
        {"s": session_id, "c": canonical_name, "a": arguments},
        sort_keys=True, ensure_ascii=False, default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fingerprint_for_event(event: GovernanceEvent) -> str:
    return action_fingerprint(
        event.source.session_id,
        event.proposed_action.canonical_name,
        event.proposed_action.arguments,
    )


def _secret() -> bytes | None:
    val = os.environ.get(_SECRET_ENV, "")
    return val.encode("utf-8") if val else None


def _sign(msg: bytes, secret: bytes) -> str:
    return base64.urlsafe_b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).decode()


def mint(fingerprint: str, ttl_seconds: int = 900, approver: str = "unknown") -> str:
    """Called by a review system, not by the gateway. Raises if no secret."""
    secret = _secret()
    if secret is None:
        raise RuntimeError(f"{_SECRET_ENV} not set; cannot mint approval tokens")
    exp = int(time.time()) + int(ttl_seconds)
    body = f"{fingerprint}.{exp}.{approver}"
    return f"{body}.{_sign(body.encode('utf-8'), secret)}"


# --------------------------------------------------------------------------- #
# one-time-use ledger — a valid token releases exactly ONE action, once.
# Backed by the audit SQLite; if that is unavailable the ledger is skipped and
# the reason notes it (still HMAC + TTL + fingerprint bound — just replayable
# until expiry). Ledger failure never turns a deny into an allow.
# --------------------------------------------------------------------------- #
_LEDGER_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS approval_nonce ("
    " sig TEXT PRIMARY KEY, fingerprint TEXT, exp INTEGER,"
    " used_at REAL NOT NULL);"
)


def _ledger_path() -> str | None:
    return os.environ.get("AUDIT_DB_PATH")


def _ledger_conn():
    import sqlite3

    path = _ledger_path()
    if not path:
        return None
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(_LEDGER_SCHEMA)
    return conn


def _consume_nonce(sig: str, fingerprint: str, exp: int) -> tuple[bool, str]:
    """Returns (fresh, note). fresh=False => the token was already spent."""
    try:
        conn = _ledger_conn()
    except Exception:  # noqa: BLE001
        return True, "ledger_unavailable"
    if conn is None:
        return True, "ledger_disabled"
    try:
        with conn:
            conn.execute("DELETE FROM approval_nonce WHERE exp < ?", (int(time.time()),))
            try:
                conn.execute(
                    "INSERT INTO approval_nonce (sig, fingerprint, exp, used_at) VALUES (?,?,?,?)",
                    (sig, fingerprint, exp, time.time()),
                )
            except Exception:  # noqa: BLE001 - PRIMARY KEY conflict = already used
                return False, "already_used"
        return True, "consumed"
    finally:
        conn.close()


def verify(
    token: str | None, expected_fingerprint: str, *, consume: bool = True
) -> tuple[bool, str]:
    """Returns (ok, reason). Never raises. False whenever anything is off.
    On success, spends the token in the one-time-use ledger (unless consume=False,
    used for dry-run checks)."""
    if not token:
        return False, "no_token"
    secret = _secret()
    if secret is None:
        return False, "no_server_secret"
    parts = token.split(".")
    if len(parts) != 4:
        return False, "malformed"
    fp, exp_s, approver, sig = parts
    body = f"{fp}.{exp_s}.{approver}"
    if not hmac.compare_digest(sig, _sign(body.encode("utf-8"), secret)):
        return False, "bad_signature"
    try:
        exp = int(exp_s)
    except ValueError:
        return False, "bad_exp"
    if time.time() > exp:
        return False, "expired"
    if not hmac.compare_digest(fp, expected_fingerprint):
        return False, "fingerprint_mismatch"
    if consume:
        fresh, note = _consume_nonce(sig, fp, exp)
        if not fresh:
            return False, note  # "already_used"
        return True, f"approved_by:{approver}"
    return True, f"approved_by:{approver}"
