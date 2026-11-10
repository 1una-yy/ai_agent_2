"""Generic OpenAI-compatible harness adapter — govern ANY AI agent.

Every agent/client that speaks the OpenAI `/v1/chat/completions` schema puts
proposed tool calls in the same place: `choices[].message.tool_calls[].function
.{name, arguments}`. That is all Layer 1 governance needs. This adapter does the
deterministic normalization for all of them — Hermes, Claude Code, Cursor,
Aider, LangChain/LangGraph, AutoGen, CrewAI, a raw OpenAI SDK script, …

No risk judgement here (that is the CISO + OPA). No harness-specific hooks — the
agent is governed purely by being pointed at the gateway as its `base_url`.

Selection: this adapter is the CATCH-ALL. It is registered last, so a specific
adapter (e.g. HermesAdapter) still wins when it matches. Disable the catch-all
with DCISO_GENERIC_ADAPTER=0 (then non-Hermes traffic fails closed as
UNKNOWN_HARNESS again).

Sub-agent spawns: a tool call whose name is in the delegation set (defaults
below, extend with DCISO_DELEGATION_TOOLS or a DCISO_MAPPING_PATH json) is
mapped to canonical `agent.spawn` so the autonomy-ceiling / parent-grant rules
apply. Everything else keeps its native name and meets the Hard Policy's tool
lists + default-deny.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from gateway.governance.schemas import (
    SCHEMA_VERSION,
    Decision,
    EnforcementPhase,
    EventType,
    GovernanceBlock,
    GovernanceEvent,
    GrantConstraints,
    ProposedAction,
    Source,
    Task,
    Verdict,
)

_SPAWN_CANONICAL = "agent.spawn"

# Common "spawn a sub-agent / hand off" tool names across frameworks. Broad on
# purpose — a false map to agent.spawn just means the spawn rules also run.
_DEFAULT_DELEGATION = {
    "delegate_task", "spawn_agent", "spawn_subagent", "create_agent",
    "create_subagent", "run_agent", "start_agent", "dispatch_agent",
    "task", "agent", "subagent", "handoff", "transfer_to_agent",
    "transfer_to", "call_agent", "invoke_agent", "delegate",
}

# harness_type values the Hard Policy knows (kept in sync with
# policy/data.json -> known_harness_types). An explicit value outside this set
# is normalised to the generic default so it still classifies.
_KNOWN_HARNESS = {
    "hermes", "openai-compatible", "openai", "generic", "langchain",
    "langgraph", "autogen", "crewai", "claude-code", "cursor", "aider",
    "continue", "openai-agents-sdk", "llamaindex", "semantic-kernel",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _gov_defaults() -> dict[str, Any]:
    return {
        "requested_autonomy": os.environ.get("GOV_DEFAULT_AUTONOMY", "L1"),
        "capability_level": os.environ.get("GOV_DEFAULT_CAPABILITY", "C1"),
        "odd_state": os.environ.get("GOV_DEFAULT_ODD_STATE", "NORMAL"),
    }


class GenericOpenAIAdapter:
    name = "openai-compatible"
    _mapping_env = "DCISO_MAPPING_PATH"
    _delegation_env = "DCISO_DELEGATION_TOOLS"
    _catch_all = True  # subclasses that match explicitly set this False

    def __init__(self) -> None:
        self.spawn_names = set(_DEFAULT_DELEGATION)
        extra = os.environ.get(self._delegation_env, "")
        self.spawn_names |= {s.strip() for s in extra.split(",") if s.strip()}
        self.mapping: dict[str, str] = {}
        path = os.environ.get(self._mapping_env)
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    self.mapping = {str(k): str(v) for k, v in json.load(fh).items()}
            except Exception:  # noqa: BLE001 - a bad mapping file must not crash the gate
                self.mapping = {}

    # ------------------------------------------------------------------ #
    # selection
    # ------------------------------------------------------------------ #
    def matches(self, request_metadata: dict[str, Any]) -> bool:
        if not self._catch_all:
            return False
        if os.environ.get("DCISO_GENERIC_ADAPTER", "1") == "0":
            return False
        return True

    def _emit_harness_type(self, md: dict[str, Any]) -> str:
        requested = str((md or {}).get("harness_type") or "").strip().lower()
        if requested in _KNOWN_HARNESS:
            return requested
        return self.name

    # ------------------------------------------------------------------ #
    # context
    # ------------------------------------------------------------------ #
    def _context(self, request: dict[str, Any]) -> dict[str, Any]:
        md = request.get("metadata") or {}
        dciso_md = md.get("dciso") or {}
        gov = _gov_defaults()
        gov.update({k: v for k, v in dciso_md.get("governance", {}).items() if v is not None})

        session_id = (
            dciso_md.get("session_id")
            or md.get("session_id")
            or request.get("user")
            or "unknown-session"
        )
        task = dciso_md.get("task") or {}
        return {
            "harness_type": self._emit_harness_type(md),
            "session_id": str(session_id),
            "harness_instance_id": str(dciso_md.get("harness_instance_id", md.get("harness_instance_id", f"{self.name}-unknown"))),
            "agent_id": str(dciso_md.get("agent_id", "main-agent")),
            "gov": gov,
            "task_id": str(task.get("task_id", uuid.uuid4())),
            "parent_task_id": task.get("parent_task_id"),
            "purpose": str(task.get("purpose", ""))[:500],
            "data_classification": list(task.get("data_classification", ["internal"])),
            "parent_grant": dciso_md.get("parent_grant"),
            "correlation_id": str(md.get("litellm_call_id") or dciso_md.get("correlation_id") or uuid.uuid4()),
        }

    # ------------------------------------------------------------------ #
    # normalization
    # ------------------------------------------------------------------ #
    def normalize_request(self, request: dict[str, Any]) -> list[GovernanceEvent]:
        return []

    def normalize_response(
        self, request: dict[str, Any], response: dict[str, Any]
    ) -> list[GovernanceEvent]:
        ctx = self._context(request)
        events: list[GovernanceEvent] = []
        for choice in response.get("choices", []) or []:
            message = choice.get("message") or {}
            for tc in message.get("tool_calls") or []:
                events.append(self._event_for_tool_call(tc, ctx))
        return events

    def _is_spawn(self, native_name: str) -> bool:
        return (
            self.mapping.get(native_name) == _SPAWN_CANONICAL
            or native_name in self.spawn_names
            or native_name.lower() in self.spawn_names
        )

    def _event_for_tool_call(self, tc: dict[str, Any], ctx: dict[str, Any]) -> GovernanceEvent:
        fn = (tc or {}).get("function") or {}
        native_name = str(fn.get("name") or "unknown")
        args = self._parse_args(fn.get("arguments"))
        if self._is_spawn(native_name):
            return self._spawn_event(native_name, args, ctx, tool_call_id=tc.get("id"))
        canonical = self.mapping.get(native_name, native_name)
        return self._tool_event(native_name, canonical, args, ctx, tool_call_id=tc.get("id"))

    @staticmethod
    def _parse_args(raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {"_value": parsed}
            except json.JSONDecodeError:
                return {"_unparseable_arguments": True}
        return {}

    def _base_gov(self, ctx: dict[str, Any]) -> dict[str, Any]:
        g = ctx["gov"]
        return {
            "requested_autonomy": g["requested_autonomy"],
            "capability_level": g["capability_level"],
            "odd_state": g["odd_state"],
            "subagent_depth": 0,
        }

    def _source(self, ctx: dict[str, Any]) -> Source:
        return Source(
            harness_type=ctx["harness_type"],
            harness_instance_id=ctx["harness_instance_id"],
            agent_id=ctx["agent_id"],
            session_id=ctx["session_id"],
        )

    def _task(self, ctx: dict[str, Any]) -> Task:
        return Task(
            task_id=ctx["task_id"],
            parent_task_id=ctx["parent_task_id"],
            purpose=ctx["purpose"],
            data_classification=ctx["data_classification"],
        )

    def _tool_event(
        self, native: str, canonical: str, args: dict[str, Any], ctx: dict[str, Any], tool_call_id: Any
    ) -> GovernanceEvent:
        gov = GovernanceBlock(**self._base_gov(ctx))
        return GovernanceEvent(
            schema_version=SCHEMA_VERSION,
            event_id=str(uuid.uuid4()),
            timestamp=_now(),
            event_type=EventType.TOOL_EXECUTE_PROPOSED,
            enforcement_phase=EnforcementPhase.MODEL_RESPONSE_PRE_EXECUTION,
            source=self._source(ctx),
            task=self._task(ctx),
            proposed_action=ProposedAction(
                native_name=native,
                canonical_name=canonical,
                arguments=args,
                resource=args.get("path") or args.get("resource") or args.get("url"),
                destination=args.get("destination") or args.get("to") or args.get("url"),
            ),
            governance=gov,
            correlation_id=f'{ctx["correlation_id"]}::{tool_call_id or "0"}',
        )

    def _spawn_event(
        self, native: str, args: dict[str, Any], ctx: dict[str, Any], tool_call_id: Any
    ) -> GovernanceEvent:
        base_gov = self._base_gov(ctx)
        child_autonomy = args.get("autonomy") or args.get("max_autonomy") or base_gov["requested_autonomy"]
        base_gov["requested_autonomy"] = str(child_autonomy)
        base_gov["subagent_depth"] = int(args.get("depth", 0) or 0)

        pg_raw = ctx.get("parent_grant")
        parent_grant = None
        if isinstance(pg_raw, dict):
            parent_grant = GrantConstraints(
                max_autonomy=str(pg_raw.get("max_autonomy", "L0")),
                max_subagent_depth=int(pg_raw.get("max_subagent_depth", 0) or 0),
                allowed_tools=list(pg_raw.get("allowed_tools", [])),
                denied_tools=list(pg_raw.get("denied_tools", [])),
                data_scope=list(pg_raw.get("data_scope", [])),
                ttl_seconds=pg_raw.get("ttl_seconds"),
            )
        gov = GovernanceBlock(**base_gov, parent_grant=parent_grant)

        requested_tools = (
            args.get("allowed_tools")
            or args.get("tools")
            or args.get("toolset")
            or []
        )
        norm_args = dict(args)
        norm_args["allowed_tools"] = list(requested_tools)

        return GovernanceEvent(
            schema_version=SCHEMA_VERSION,
            event_id=str(uuid.uuid4()),
            timestamp=_now(),
            event_type=EventType.AGENT_SPAWN,
            enforcement_phase=EnforcementPhase.MODEL_RESPONSE_PRE_EXECUTION,
            source=self._source(ctx),
            task=self._task(ctx),
            proposed_action=ProposedAction(
                native_name=native,
                canonical_name=_SPAWN_CANONICAL,
                arguments=norm_args,
                resource=None,
                destination=None,
            ),
            governance=gov,
            correlation_id=f'{ctx["correlation_id"]}::{tool_call_id or "0"}',
        )

    # ------------------------------------------------------------------ #
    # enforcement — deterministic ALLOW / MODIFY shaping. DENY / REVIEW
    # synthesis is harness-agnostic and lives in enforcer.py.
    # ------------------------------------------------------------------ #
    def enforce(self, response: dict[str, Any], decision: Decision) -> dict[str, Any]:
        if decision.decision == Verdict.MODIFY:
            return self._apply_modify(response, decision)
        return response

    def _apply_modify(self, response: dict[str, Any], decision: Decision) -> dict[str, Any]:
        overrides = decision.obligations.argument_overrides or {}
        denied = set(decision.obligations.denied_tools or [])
        for choice in response.get("choices", []) or []:
            msg = choice.get("message") or {}
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") or {}
                args = self._parse_args(fn.get("arguments"))
                is_spawn = self._is_spawn(str(fn.get("name") or ""))

                for k, v in overrides.items():
                    args[k] = v

                if is_spawn:
                    ob = decision.obligations
                    for key in ("autonomy", "max_autonomy"):
                        if key in args:
                            args[key] = ob.max_autonomy
                    if "depth" in args:
                        try:
                            args["depth"] = min(int(args["depth"]), ob.max_subagent_depth)
                        except (TypeError, ValueError):
                            args["depth"] = ob.max_subagent_depth
                    if "allowed_tools" in args and isinstance(args["allowed_tools"], list):
                        args["allowed_tools"] = [
                            t for t in args["allowed_tools"]
                            if t not in denied and (not ob.allowed_tools or t in ob.allowed_tools)
                        ]
                fn["arguments"] = json.dumps(args, ensure_ascii=False)
        return response
