#!/usr/bin/env python3
"""Generate a sample audit evidence chain (ticket §12 deliverable 9).

Runs a fixed set of scenarios through the real governance pipeline
(HermesAdapter -> DecisionOrchestrator -> Enforcer -> AuditWriter) into a
throwaway SQLite DB, then writes the rows to docs/sample-evidence.jsonl.

Uses a live OPA if `opa` (or $OPA_BIN) is available; otherwise it falls back to
a tiny deterministic PDP stub so the artifact is always reproducible. The CISO
side always uses a deterministic stub here.

    python demo/gen-sample-evidence.py
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from gateway.governance.adapters.hermes import HermesAdapter  # noqa: E402
from gateway.governance.audit import AuditWriter  # noqa: E402
from gateway.governance.clients.opa import OPAClient  # noqa: E402
from gateway.governance.decision_orchestrator import DecisionOrchestrator  # noqa: E402
from gateway.governance.enforcer import Enforcer, ReplanTracker  # noqa: E402
from gateway.governance.schemas import Decision, SoftAdvice, Verdict  # noqa: E402

OUT = os.path.join(ROOT, "docs", "sample-evidence.jsonl")
OPA_BIN = os.environ.get("OPA_BIN") or shutil.which("opa")


class _StubCiso:
    def __init__(self, advice: SoftAdvice) -> None:
        self._a = advice

    async def advise(self, event) -> SoftAdvice:
        return self._a


class _StubPdp:
    """Deterministic offline stand-in mirroring the rego's headline rules."""

    async def decide(self, event, advice) -> Decision:
        pa = event.proposed_action
        classes = set(event.task.data_classification)
        if pa.canonical_name in {"terminal", "shell", "db_write", "credential_access"}:
            return Decision(decision=Verdict.DENY, reason_codes=[f"DANGEROUS_TOOL_DENIED:{pa.canonical_name}"],
                            policy_version="v0.1.0(stub)")
        if classes & {"PHI", "PII", "SECRET"} and pa.destination:
            return Decision(decision=Verdict.DENY, reason_codes=["EXTERNAL_SENSITIVE_TRANSFER_DENIED"],
                            policy_version="v0.1.0(stub)")
        if event.event_type.value == "agent.spawn" and event.governance.requested_autonomy in {"L3", "L4"}:
            return Decision(decision=Verdict.MODIFY, reason_codes=["AUTONOMY_DOWNGRADED_TO_CEILING"],
                            policy_version="v0.1.0(stub)")
        if pa.canonical_name not in {"read_file", "list_files", "search", "agent.spawn"}:
            return Decision(decision=Verdict.DENY, reason_codes=["UNKNOWN_TOOL"], policy_version="v0.1.0(stub)")
        return Decision(decision=Verdict.ALLOW, reason_codes=["POLICY_ALLOW"], policy_version="v0.1.0(stub)")


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _start_opa():
    if not OPA_BIN:
        return None, None
    port = _free_port()
    proc = subprocess.Popen(
        [OPA_BIN, "run", "--server", f"--addr=127.0.0.1:{port}", "--ignore=tests",
         "--log-level=error", os.path.join(ROOT, "policy")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    import urllib.request
    for _ in range(100):
        try:
            if urllib.request.urlopen(f"http://127.0.0.1:{port}/health").status == 200:
                return proc, f"http://127.0.0.1:{port}"
        except Exception:  # noqa: BLE001
            time.sleep(0.05)
    proc.terminate()
    return None, None


def _tc(name, args):
    return {"id": "call_1", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def _resp(tcs):
    return {"id": "chatcmpl-sample", "choices": [{"index": 0, "finish_reason": "tool_calls",
            "message": {"role": "assistant", "content": None, "tool_calls": tcs}}]}


SCENARIOS = [
    ("safe-read", {"harness_type": "hermes", "session_id": "sample-1"},
     [_tc("read_file", {"path": "/workspace/notes.md"})], SoftAdvice(advice="ALLOW", risk_score=3, risk_level="LOW")),
    ("phi-exfil", {"harness_type": "hermes", "session_id": "sample-2",
                   "dciso": {"task": {"data_classification": ["PHI"]}}},
     [_tc("http_request", {"url": "https://external.example.com", "destination": "https://external.example.com"})],
     SoftAdvice(advice="ALLOW", risk_score=10, risk_level="LOW")),  # CISO fooled; hard policy still DENY
    ("terminal", {"harness_type": "hermes", "session_id": "sample-3"},
     [_tc("terminal", {"cmd": "rm -rf /"})], SoftAdvice(advice="DENY", risk_score=90, risk_level="HIGH")),
    ("delegate-L4", {"harness_type": "hermes", "session_id": "sample-4",
                     "dciso": {"governance": {"capability_level": "C2"}}},
     [_tc("delegate_task", {"autonomy": "L4", "allowed_tools": ["read_file"]})],
     SoftAdvice(advice="MODIFY", risk_score=45, risk_level="MEDIUM")),
    ("unknown-tool", {"harness_type": "hermes", "session_id": "sample-5"},
     [_tc("quantum_teleport", {"x": 1})], SoftAdvice(advice="ALLOW", risk_score=1, risk_level="LOW")),
]


async def main() -> None:
    opa_proc, opa_url = _start_opa()
    pdp_note = f"live OPA @ {opa_url}" if opa_url else "offline stub PDP"
    print(f"[gen] PDP: {pdp_note}")
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "audit.sqlite")
    writer = AuditWriter(db)
    adapter = HermesAdapter()
    tracker = ReplanTracker()

    try:
        for name, md, tcs, advice in SCENARIOS:
            req = {"model": "governed-model", "metadata": md, "messages": [{"role": "user", "content": name}]}
            events = adapter.normalize_response(req, _resp(tcs))
            opa = OPAClient(base_url=opa_url) if opa_url else _StubPdp()
            orch = DecisionOrchestrator(ciso=_StubCiso(advice), opa=opa)
            outcomes = [await orch.evaluate(ev) for ev in events]
            disp = Enforcer(adapter, tracker).enforce(raw_response=_resp(tcs), outcomes=outcomes)
            for ev, oc in zip(events, outcomes):
                writer.write(event=ev, soft_advice=oc.soft_advice, decision=oc.decision,
                             enforcement=disp.result, raw_request=req, raw_response=_resp(tcs),
                             latency_ms=oc.latency_ms, error_class=oc.error_class)
            print(f"[gen] {name:14s} -> {disp.result.outcome:15s} {disp.result.reason_codes}")
    finally:
        if opa_proc:
            opa_proc.terminate()

    # export
    import sqlite3
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT * FROM audit_log ORDER BY ts_epoch").fetchall()]
    con.close()
    with open(OUT, "w", encoding="utf-8") as fh:
        for r in rows:
            for k in ("event_json", "soft_advice_json", "hard_decision_json", "enforcement_json"):
                if r.get(k):
                    try:
                        r[k] = json.loads(r[k])
                    except (TypeError, ValueError):
                        pass
            # volatile fields blanked so the artifact is diff-stable
            r["row_id"] = "<uuid>"
            r["ts_epoch"] = 0
            r["latency_ms"] = None
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"[gen] wrote {len(rows)} evidence rows -> {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    asyncio.run(main())
