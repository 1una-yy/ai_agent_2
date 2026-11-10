"""Append-only audit / evidence writer (ticket §10 Task 6).

MVP store: SQLite with an INSERT-only access pattern (no UPDATE/DELETE in
code). One row per governed decision. The dashboard reads this table.

Fail-closed contract: if a row cannot be written, the caller must treat the
governed action as DENY for sensitive actions. `write()` raises on failure;
it never swallows.

Redaction: raw request/response are NOT stored — only sha-256 hashes and a
minimized, secret-scrubbed summary.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Optional

from gateway.governance.schemas import (
    Decision,
    EnforcementResult,
    GovernanceEvent,
    SoftAdvice,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    row_id            TEXT PRIMARY KEY,
    ts_epoch          REAL NOT NULL,
    ts_rfc3339        TEXT NOT NULL,
    correlation_id    TEXT,
    event_id          TEXT NOT NULL,
    session_id        TEXT,
    task_id           TEXT,
    harness_type      TEXT,
    harness_instance  TEXT,
    enforcement_phase TEXT,
    event_type        TEXT,
    native_name       TEXT,
    canonical_name    TEXT,
    request_hash      TEXT,
    response_hash     TEXT,
    event_json        TEXT NOT NULL,   -- normalized GovernanceEvent (already minimized)
    soft_advice_json  TEXT,
    hard_decision_json TEXT,
    enforcement_json  TEXT,
    outcome           TEXT,
    reason_codes      TEXT,
    policy_version    TEXT,
    soft_availability TEXT,
    replan_attempt    INTEGER DEFAULT 0,
    user_message      TEXT,
    latency_ms        REAL,
    error_class       TEXT,
    timings           TEXT,          -- Phase E: {model_ms, governance_ms, ciso_ms, opa_ms}
    hold              TEXT           -- Phase D: NONE | REVIEW_HOLD | ADVISORY
);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_event   ON audit_log(event_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(ts_epoch);
"""

_SECRET_KEYS = {
    "api_key", "authorization", "password", "secret", "token", "access_token",
    "openai_api_key", "bearer",
}


def sha256_json(obj: Any) -> str:
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def scrub(obj: Any, _depth: int = 0) -> Any:
    """Recursively drop obvious secret-bearing keys and truncate long strings."""
    if _depth > 8:
        return "<max-depth>"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in _SECRET_KEYS:
                out[k] = "<redacted>"
            else:
                out[k] = scrub(v, _depth + 1)
        return out
    if isinstance(obj, list):
        return [scrub(v, _depth + 1) for v in obj[:50]]
    if isinstance(obj, str) and len(obj) > 4000:
        return obj[:4000] + "…<truncated>"
    return obj


class AuditWriter:
    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or os.environ.get("AUDIT_DB_PATH", "/data/audit.sqlite")
        self._lock = threading.Lock()
        self._ready = False

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _ensure(self) -> None:
        """Lazily create the parent dir + schema on first write, so merely
        constructing an AuditWriter never touches the filesystem."""
        if self._ready:
            return
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)
            # additive migrations for a pre-existing DB (SQLite ignores IF NOT
            # EXISTS for columns, so ALTER + swallow the duplicate error)
            for col, typ in (("timings", "TEXT"), ("hold", "TEXT")):
                try:
                    conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col} {typ}")
                except sqlite3.OperationalError:
                    pass
        self._ready = True

    def write(
        self,
        *,
        event: GovernanceEvent,
        soft_advice: Optional[SoftAdvice],
        decision: Optional[Decision],
        enforcement: Optional[EnforcementResult],
        raw_request: Any = None,
        raw_response: Any = None,
        latency_ms: Optional[float] = None,
        error_class: Optional[str] = None,
    ) -> str:
        """Insert one evidence row. Raises on failure (fail-closed upstream)."""
        row_id = str(uuid.uuid4())
        ev_dump = event.model_dump(mode="json")
        row = (
            row_id,
            time.time(),
            event.timestamp,
            event.correlation_id,
            event.event_id,
            event.source.session_id,
            event.task.task_id,
            event.source.harness_type,
            event.source.harness_instance_id,
            event.enforcement_phase.value,
            event.event_type.value,
            event.proposed_action.native_name,
            event.proposed_action.canonical_name,
            sha256_json(scrub(raw_request)) if raw_request is not None else None,
            sha256_json(scrub(raw_response)) if raw_response is not None else None,
            json.dumps(scrub(ev_dump), ensure_ascii=False),
            json.dumps(soft_advice.model_dump(mode="json"), ensure_ascii=False) if soft_advice else None,
            json.dumps(decision.model_dump(mode="json"), ensure_ascii=False) if decision else None,
            json.dumps(enforcement.model_dump(mode="json"), ensure_ascii=False) if enforcement else None,
            enforcement.outcome if enforcement else None,
            # batch-level reason codes match the `outcome` column; per-event
            # detail stays in hard_decision_json.
            json.dumps(
                (enforcement.reason_codes if enforcement and enforcement.reason_codes
                 else (decision.reason_codes if decision else [])),
                ensure_ascii=False,
            ),
            decision.policy_version if decision else None,
            soft_advice.availability.value if soft_advice else None,
            enforcement.replan_attempt if enforcement else 0,
            enforcement.user_message if enforcement else None,
            latency_ms,
            error_class,
            json.dumps(enforcement.timings, ensure_ascii=False)
            if enforcement and getattr(enforcement, "timings", None) else None,
            getattr(enforcement, "hold", None) if enforcement else None,
        )
        cols = (
            "row_id, ts_epoch, ts_rfc3339, correlation_id, event_id, session_id, task_id, "
            "harness_type, harness_instance, enforcement_phase, event_type, native_name, "
            "canonical_name, request_hash, response_hash, event_json, soft_advice_json, "
            "hard_decision_json, enforcement_json, outcome, reason_codes, policy_version, "
            "soft_availability, replan_attempt, user_message, latency_ms, error_class, "
            "timings, hold"
        )
        placeholders = ",".join(["?"] * len(row))
        self._ensure()
        with self._lock, self._connect() as conn:
            conn.execute(f"INSERT INTO audit_log ({cols}) VALUES ({placeholders})", row)
            conn.commit()
        return row_id
