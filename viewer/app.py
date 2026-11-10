"""Governance Dashboard (deliberate addition — see PLAN §E).

READ-ONLY. No auth, no write endpoints. Renders the governance pipeline for
each audited decision so an operator can see *what the CISO governed and how*:

    raw request summary
      -> normalized GovernanceEvent
      -> CISO SoftAdvice (advice / risk / reason codes / explanation)
      -> OPA Decision (decision / reason codes / obligations / policy_version)
      -> Enforcer action  (what Hermes actually received, re-plan count)

Bound to 127.0.0.1 by compose; never expose publicly. It only shows columns the
audit writer already redacted.
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

DB_PATH = os.environ.get("AUDIT_DB_PATH", "/data/audit.sqlite")
app = FastAPI(title="DCISO Governance Dashboard", version="0.1.0")


def _ro_conn() -> sqlite3.Connection:
    uri = f"file:{DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=3.0)
    conn.row_factory = sqlite3.Row
    return conn


def _rows(where: str = "", params: tuple = (), limit: int = 200) -> list[dict[str, Any]]:
    try:
        with _ro_conn() as c:
            q = (
                "SELECT row_id, ts_rfc3339, event_id, session_id, harness_type, "
                "event_type, native_name, canonical_name, outcome, reason_codes, "
                "policy_version, soft_availability, replan_attempt, latency_ms, error_class, "
                "enforcement_phase, correlation_id, enforcement_json "
                "FROM audit_log " + where + " ORDER BY ts_epoch DESC LIMIT ?"
            )
            return [dict(r) for r in c.execute(q, (*params, limit)).fetchall()]
    except sqlite3.OperationalError:
        return []


def _stats() -> dict[str, Any]:
    out: dict[str, Any] = {"total": 0, "by_outcome": {}, "sessions": 0,
                           "avg_latency_ms": None, "top_reasons": [], "denied_actions": [],
                           "gov_fast_ms": None, "gov_escalated_ms": None, "model_ms": None}
    try:
        with _ro_conn() as c:
            out["total"] = c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            for oc, n in c.execute("SELECT outcome, COUNT(*) FROM audit_log GROUP BY outcome"):
                out["by_outcome"][oc or "?"] = n
            out["sessions"] = c.execute("SELECT COUNT(DISTINCT session_id) FROM audit_log").fetchone()[0]
            row = c.execute("SELECT AVG(latency_ms) FROM audit_log WHERE latency_ms IS NOT NULL").fetchone()
            out["avg_latency_ms"] = round(row[0], 1) if row and row[0] is not None else None
            # Phase E — model vs governance time split (from the `timings` json)
            try:
                fast, esc, model = [], [], []
                for tj, ej in c.execute(
                    "SELECT timings, enforcement_json FROM audit_log WHERE timings IS NOT NULL "
                    "ORDER BY ts_epoch DESC LIMIT 500"
                ):
                    t = json.loads(tj or "{}")
                    g = t.get("governance_ms")
                    if t.get("model_ms") is not None:
                        model.append(t["model_ms"])
                    if g is None:
                        continue
                    escalated = True
                    try:
                        escalated = (json.loads(ej or "{}") or {}).get("escalated", True)
                    except (TypeError, ValueError):
                        pass
                    (esc if escalated else fast).append(g)
                avg = lambda xs: round(sum(xs) / len(xs), 1) if xs else None  # noqa: E731
                out["gov_fast_ms"] = avg(fast)
                out["gov_escalated_ms"] = avg(esc)
                out["model_ms"] = avg(model)
            except sqlite3.OperationalError:
                pass
            reasons: dict[str, int] = {}
            actions: dict[str, int] = {}
            for rc, oc, canon in c.execute(
                "SELECT reason_codes, outcome, canonical_name FROM audit_log WHERE outcome != 'ALLOW'"
            ):
                try:
                    for r in json.loads(rc or "[]"):
                        key = r.split(":")[0]
                        reasons[key] = reasons.get(key, 0) + 1
                except (TypeError, ValueError):
                    pass
                if oc == "DENY" and canon and canon not in ("-", "unknown"):
                    actions[canon] = actions.get(canon, 0) + 1
            out["top_reasons"] = sorted(reasons.items(), key=lambda x: -x[1])[:6]
            out["denied_actions"] = sorted(actions.items(), key=lambda x: -x[1])[:6]
    except sqlite3.OperationalError:
        pass
    return out


def _full(row_id: str) -> dict[str, Any] | None:
    try:
        with _ro_conn() as c:
            r = c.execute("SELECT * FROM audit_log WHERE row_id=? OR event_id=?",
                          (row_id, row_id)).fetchone()
            return dict(r) if r else None
    except sqlite3.OperationalError:
        return None


# --------------------------------------------------------------------------- #
# JSON API
# --------------------------------------------------------------------------- #
@app.get("/health/liveness")
async def liveness():
    return {"status": "alive"}


@app.get("/health/policy")
async def policy():
    return {"ready": os.path.exists(DB_PATH), "db": DB_PATH}


@app.get("/api/events")
async def api_events(outcome: str | None = None, session_id: str | None = None):
    clauses, params = [], []
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)
    if session_id:
        clauses.append("session_id = ?")
        params.append(session_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return {"events": _rows(where, tuple(params))}


@app.get("/api/stats")
async def api_stats():
    return _stats()


@app.get("/api/event/{row_id}")
async def api_event(row_id: str):
    row = _full(row_id)
    if not row:
        return JSONResponse(status_code=404, content={"error": "not found"})
    for k in ("event_json", "soft_advice_json", "hard_decision_json", "enforcement_json"):
        if row.get(k):
            try:
                row[k] = json.loads(row[k])
            except (TypeError, ValueError):
                pass
    return row


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
_STYLE = """
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#e2e2e2;--card:#fafafa;
--allow:#0a7c2f;--deny:#c0281c;--modify:#b26a00;--review:#6b3fa0;--code:#f3f3f3}
@media(prefers-color-scheme:dark){:root{--bg:#151515;--fg:#eaeaea;--mut:#9a9a9a;
--line:#2e2e2e;--card:#1d1d1d;--code:#232323;--allow:#4ec97a;--deny:#ff6b5e;
--modify:#e0a24a;--review:#b58be0}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--fg)}a{color:inherit}
header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:baseline}
h1{font-size:15px;margin:0;font-weight:700}.sub{color:var(--mut);font-size:12px}
main{padding:16px 20px;max-width:1100px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}
tr:hover td{background:var(--card)}
.badge{padding:1px 7px;border-radius:10px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}
.ALLOW{background:var(--allow)}.DENY{background:var(--deny)}.MODIFY{background:var(--modify)}
.REQUIRE_REVIEW{background:var(--review)}
.tag{display:inline-block;padding:1px 6px;border-radius:9px;font-size:10.5px;font-weight:700;white-space:nowrap;margin:1px 0}
.tag.hold{background:#7c2d12;color:#fed7aa}
.tag.adv{background:#78350f;color:#fde68a}
.tag.red{background:#164e63;color:#a5f3fc}
.tag.fast{background:#334155;color:#cbd5e1}
.filters{margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap}
.filters a{padding:3px 10px;border:1px solid var(--line);border-radius:14px;text-decoration:none;font-size:12px}
.pipe{display:grid;gap:10px;margin-top:8px}
.step{border:1px solid var(--line);border-radius:8px;background:var(--card)}
.step>.t{padding:8px 12px;border-bottom:1px solid var(--line);font-weight:700;font-size:12px;
letter-spacing:.03em;text-transform:uppercase;color:var(--mut)}
.step pre{margin:0;padding:12px;overflow:auto;background:var(--code);font-size:12px;
border-radius:0 0 8px 8px}
.kv{display:flex;flex-wrap:wrap;gap:6px 18px;padding:10px 12px}
.kv div{font-size:12px}.kv b{color:var(--mut);font-weight:600}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.back{font-size:12px;color:var(--mut);text-decoration:none}
.arrow{text-align:center;color:var(--mut);font-size:16px}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px}
.stat{border:1px solid var(--line);border-radius:8px;background:var(--card);padding:8px 12px;min-width:88px}
.stat .n{font-size:19px;font-weight:800;line-height:1.1}
.stat .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.stat.ALLOW .n{color:var(--allow)}.stat.DENY .n{color:var(--deny)}
.stat.MODIFY .n{color:var(--modify)}.stat.REQUIRE_REVIEW .n{color:var(--review)}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:-6px 0 14px}
.chip{font-size:11px;border:1px solid var(--line);border-radius:12px;padding:2px 9px;color:var(--mut)}
.chip b{color:var(--fg)}
"""


def _badge(o: str | None) -> str:
    o = o or "-"
    cls = o if o in ("ALLOW", "DENY", "MODIFY", "REQUIRE_REVIEW") else ""
    return f'<span class="badge {cls}">{o}</span>'


_PHASE_LABEL = {
    "model_response_pre_execution": "①提議",
    "tool_execution_pre_dispatch": "②執行前",
    "tool_result_pre_send": "③結果→模型",
    "model_output_pre_delivery": "④回答→使用者",
}


def _layer(phase: str | None) -> str:
    return _PHASE_LABEL.get(phase or "", "-")


def _semantics(enforcement_json: str | None) -> str:
    """Phase D — honest badges: is the action actually held, or just flagged?"""
    try:
        e = json.loads(enforcement_json or "{}")
    except (TypeError, ValueError):
        return ""
    tags = []
    hold = e.get("hold")
    if hold == "REVIEW_HOLD":
        tags.append('<span class="tag hold">⏸ 已擋下·待核准</span>')
    elif hold == "ADVISORY":
        adv = e.get("advisory") or {}
        tags.append(f'<span class="tag adv">⚑ 資安長示警·已放行 ({adv.get("risk_score", "?")})</span>')
    if e.get("redacted"):
        tags.append('<span class="tag red">✂ 已遮蔽/截斷</span>')
    if e.get("escalated") is False:
        tags.append('<span class="tag fast">⚡ 快速路徑</span>')
    return " ".join(tags)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, outcome: str | None = None, session_id: str | None = None):
    clauses, params = [], []
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)
    if session_id:
        clauses.append("session_id = ?")
        params.append(session_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = _rows(where, tuple(params))

    def f(label, qs):
        return f'<a href="/?{qs}">{label}</a>'

    filt = " ".join([
        f("all", ""), f("ALLOW", "outcome=ALLOW"), f("DENY", "outcome=DENY"),
        f("MODIFY", "outcome=MODIFY"), f("REQUIRE_REVIEW", "outcome=REQUIRE_REVIEW"),
    ])
    body = "".join(
        f"<tr><td class='mono'><a href='/event/{r['row_id']}'>{r['ts_rfc3339']}</a></td>"
        f"<td class='mono'><a href='/event/{r['event_id']}'>{(r['event_id'] or '-')[:8]}</a></td>"
        f"<td>{_badge(r['outcome'])}</td>"
        f"<td class='mono'>{_layer(r['enforcement_phase'])}</td>"
        f"<td>{r['harness_type'] or '-'}</td>"
        f"<td class='mono'>{(r['canonical_name'] or '-')}</td>"
        f"<td class='mono' title='{r['reason_codes'] or ''}'>{(r['reason_codes'] or '')[:52]}</td>"
        f"<td>{_semantics(r.get('enforcement_json'))}</td>"
        f"<td>{r['replan_attempt']}</td>"
        f"<td><a class='mono' href='/session/{r['session_id']}'>{(r['session_id'] or '-')[:16]}</a></td></tr>"
        for r in rows
    ) or "<tr><td colspan=10 class='sub'>no audited decisions yet</td></tr>"

    s = _stats()
    order = ["ALLOW", "DENY", "MODIFY", "REQUIRE_REVIEW"]
    stat_cards = (
        f"<div class=stat><div class=n>{s['total']}</div><div class=l>decisions</div></div>"
        + "".join(
            f"<div class='stat {oc}'><div class=n>{s['by_outcome'].get(oc, 0)}</div><div class=l>{oc.replace('REQUIRE_','')}</div></div>"
            for oc in order
        )
        + f"<div class=stat><div class=n>{s['sessions']}</div><div class=l>sessions</div></div>"
        + f"<div class=stat><div class=n>{s['model_ms'] or '-'}</div><div class=l>model ms</div></div>"
        + f"<div class=stat><div class=n>{s['gov_fast_ms'] or '-'}</div><div class=l>gov ms · fast</div></div>"
        + f"<div class=stat><div class=n>{s['gov_escalated_ms'] or '-'}</div><div class=l>gov ms · escalated</div></div>"
    )
    chips = "".join(f"<span class=chip>{_esc(k)} <b>{v}</b></span>" for k, v in s["top_reasons"]) or ""
    dchips = "".join(f"<span class=chip>blocked <b>{_esc(k)}</b> ×{v}</span>" for k, v in s["denied_actions"])

    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<meta http-equiv=refresh content=5><title>DCISO Governance Dashboard</title><style>{_STYLE}</style></head>
<body><header><h1>DCISO Governance Dashboard</h1>
<span class=sub>read-only · auto-refresh 5s</span></header>
<main>
<div class=stats>{stat_cards}</div>
<div class=chips>{chips}{dchips}</div>
<div class=filters>{filt}</div>
<table><thead><tr><th>time</th><th>event id</th><th>outcome</th><th>phase</th><th>harness</th><th>action</th>
<th>reason codes</th><th>semantics</th><th>replan</th><th>session</th></tr></thead>
<tbody>{body}</tbody></table></main></body></html>"""


def _step(title: str, payload: Any) -> str:
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload, ensure_ascii=False, indent=2)
    return f"<div class=step><div class=t>{title}</div><pre>{_esc(str(payload))}</pre></div>"


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@app.get("/event/{row_id}", response_class=HTMLResponse)
async def event_detail(row_id: str):
    row = _full(row_id)
    if not row:
        return HTMLResponse("<p>not found</p>", status_code=404)

    def j(key):
        try:
            return json.loads(row[key]) if row.get(key) else None
        except (TypeError, ValueError):
            return row.get(key)

    ev, soft, hard, enf = j("event_json"), j("soft_advice_json"), j("hard_decision_json"), j("enforcement_json")
    arrow = "<div class=arrow>&darr;</div>"
    head = (
        "<div class=kv>"
        f"<div><b>event_id</b> <span class=mono>{row['event_id']}</span></div>"
        f"<div><b>outcome</b> {_badge(row['outcome'])}</div>"
        f"<div><b>policy</b> <span class=mono>{row['policy_version'] or '-'}</span></div>"
        f"<div><b>latency</b> {row['latency_ms'] or '-'} ms</div>"
        f"<div><b>soft availability</b> <span class=mono>{row['soft_availability'] or '-'}</span></div>"
        f"<div><b>replan attempt</b> {row['replan_attempt']}</div>"
        f"<div><b>error class</b> <span class=mono>{row['error_class'] or '-'}</span></div>"
        f"<div><b>request hash</b> <span class=mono>{(row['request_hash'] or '-')[:24]}…</span></div>"
        f"<div><b>response hash</b> <span class=mono>{(row['response_hash'] or '-')[:24]}…</span></div>"
        "</div>"
    )
    pipe = arrow.join([
        _step("1 · request (redacted summary)", (ev or {}).get("_request_summary", "see audit row hashes above")),
        _step("2 · normalized GovernanceEvent", ev),
        _step("3 · CISO SoftAdvice (advisory only)", soft or "— none (plain response / not consulted) —"),
        _step("4 · OPA Decision (final authority)", hard or "— none —"),
        _step("5 · Enforcer — what Hermes received", enf or "— none —"),
    ])
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<title>event {row['event_id']}</title><style>{_STYLE}</style></head>
<body><header><h1>Governance flow</h1>
<a class=back href='/'>&larr; all decisions</a>
<a class=back href='/session/{row['session_id']}'>session &rarr;</a></header>
<main>{head}<div class=pipe>{pipe}</div></main></body></html>"""


@app.get("/session/{session_id}", response_class=HTMLResponse)
async def session_timeline(session_id: str):
    rows = _rows("WHERE session_id = ?", (session_id,), limit=500)
    rows = list(reversed(rows))
    items = "".join(
        f"<tr><td class=mono><a href='/event/{r['row_id']}'>{r['ts_rfc3339']}</a></td>"
        f"<td>{_badge(r['outcome'])}</td><td class=mono>{r['canonical_name'] or '-'}</td>"
        f"<td class=mono>{(r['reason_codes'] or '')[:70]}</td><td>{r['replan_attempt']}</td></tr>"
        for r in rows
    ) or "<tr><td colspan=5 class=sub>no rows for this session</td></tr>"
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta http-equiv=refresh content=5><title>session {session_id}</title><style>{_STYLE}</style></head>
<body><header><h1>Session timeline</h1><span class=sub class=mono>{session_id}</span>
<a class=back href='/'>&larr; all</a></header>
<main><table><thead><tr><th>time</th><th>outcome</th><th>action</th><th>reason codes</th><th>replan</th>
</tr></thead><tbody>{items}</tbody></table></main></body></html>"""
