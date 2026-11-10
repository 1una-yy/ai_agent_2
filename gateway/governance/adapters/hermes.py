"""Hermes harness adapter (ticket §10 Task 3).

Thin specialisation of GenericOpenAIAdapter: Hermes speaks the standard OpenAI
chat-completion schema, so all normalization / enforcement is inherited. Hermes
only adds:

  * explicit selection on `harness_type == "hermes"` (not the catch-all),
  * a NARROW delegation mapping (`delegate_task` -> `agent.spawn`), extendable
    via HERMES_MAPPING_PATH without a code change (PLAN §A.3 R1),
  * `normalize_tool_execution` for the optional Layer 2 `pre_tool_call` hook.

Deterministic mapping only — NO risk judgement here.
"""

from __future__ import annotations

import json
import os
from typing import Any

from gateway.governance.adapters.generic import GenericOpenAIAdapter, _SPAWN_CANONICAL
from gateway.governance.schemas import EnforcementPhase, GovernanceEvent

_DEFAULT_MAPPING = {"delegate_task": "agent.spawn"}


def _load_mapping() -> dict[str, str]:
    path = os.environ.get("HERMES_MAPPING_PATH")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            extra = json.load(fh)
        return {**_DEFAULT_MAPPING, **extra}
    return dict(_DEFAULT_MAPPING)


class HermesAdapter(GenericOpenAIAdapter):
    name = "hermes"
    _catch_all = False

    def __init__(self) -> None:
        super().__init__()
        # Hermes uses an EXPLICIT mapping table, not the generic broad
        # delegation-name heuristic — keep spawn detection tight.
        self.mapping = _load_mapping()
        self.spawn_names = {k for k, v in self.mapping.items() if v == _SPAWN_CANONICAL}

    def matches(self, request_metadata: dict[str, Any]) -> bool:
        return (request_metadata or {}).get("harness_type") == "hermes"

    def _emit_harness_type(self, md: dict[str, Any]) -> str:
        return "hermes"

    # ------------------------------------------------------------------ #
    # Layer 2 — Hermes `pre_tool_call` hook: the tool is about to RUN.
    # Payload: {tool_name, tool_input, session_id, cwd, extra:{task_id,
    # tool_call_id, dciso:{...}}}
    # ------------------------------------------------------------------ #
    def normalize_tool_execution(self, payload: dict[str, Any]) -> GovernanceEvent:
        extra = payload.get("extra") or {}
        pseudo_request = {"metadata": {"harness_type": "hermes",
                                       "dciso": extra.get("dciso") or {},
                                       "session_id": payload.get("session_id")}}
        ctx = self._context(pseudo_request)
        ev = self._event_for_tool_call(
            {"id": extra.get("tool_call_id"),
             "function": {"name": payload.get("tool_name") or "unknown",
                          "arguments": payload.get("tool_input") or {}}},
            ctx,
        )
        ev.enforcement_phase = EnforcementPhase.TOOL_EXECUTION_PRE_DISPATCH
        if payload.get("cwd"):
            ev.proposed_action.resource = ev.proposed_action.resource or str(payload["cwd"])
        return ev
