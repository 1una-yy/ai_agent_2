"""Adapter registry + selection (ticket §10 Task 3, §14).

Selection is by explicit request metadata only. If no adapter matches, that is
itself a fail-closed condition — the caller must DENY (unknown harness).
"""

from __future__ import annotations

from typing import Any, Optional

from gateway.governance.adapters.base import HarnessAdapter
from gateway.governance.adapters.generic import GenericOpenAIAdapter
from gateway.governance.adapters.hermes import HermesAdapter

# Specific adapters first; the generic OpenAI-compatible catch-all LAST so any
# agent pointed at the gateway is governed (disable with DCISO_GENERIC_ADAPTER=0).
_REGISTRY: list[HarnessAdapter] = [HermesAdapter(), GenericOpenAIAdapter()]


def register(adapter: HarnessAdapter) -> None:
    _REGISTRY.append(adapter)


def select_adapter(request_metadata: dict[str, Any]) -> Optional[HarnessAdapter]:
    for adapter in _REGISTRY:
        try:
            if adapter.matches(request_metadata or {}):
                return adapter
        except Exception:  # noqa: BLE001 - a broken adapter must not select
            continue
    return None


def known_harness_types() -> list[str]:
    return [getattr(a, "name", "?") for a in _REGISTRY]
