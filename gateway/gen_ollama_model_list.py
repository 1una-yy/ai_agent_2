#!/usr/bin/env python3
"""Expose every tool-capable model on the operator's on-prem Ollama server as
its own named LiteLLM model_list entry, all pinned to the SAME api_base /
api_key as the fixed `governed-model` default.

Why: the gateway deliberately ignores whatever model name a client sends and
always routes to ONE fixed upstream (`GATEWAY_UPSTREAM_MODEL`) — this stops a
client from side-stepping governance by naming some other provider/endpoint.
Letting the governed Hermes pick among SEVERAL on-prem Ollama models does not
reopen that hole: every entry generated here still points at the operator's
own `OLLAMA_BASE_URL` with the operator's own key, and `governance_callback`
intercepts the request regardless of which model_list entry matched. Only the
model ID becomes client-choosable — the endpoint and credentials do not.

Used by gateway/entrypoint.sh (GATEWAY_ROUTE_MODE=ollama): queries
`$OLLAMA_BASE_URL/api/tags`, keeps the models advertising a "tools"
capability (the same field `dciso ollama-models` already prints), and writes
an augmented copy of config.yaml with one extra model_list entry per
discovered model — so Hermes's own /model picker shows them all.

Never fatal: if the Ollama server can't be reached or returns something
unexpected, the template config is written back unchanged (only the one
fixed default model stays exposed) rather than blocking gateway startup.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request

import yaml


def _discover_models(base: str, timeout: float) -> list[str]:
    url = f"{base.rstrip('/')}/api/tags"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        payload = json.load(resp)
    names: list[str] = []
    for m in payload.get("models", []) or []:
        name = m.get("name") or m.get("model")
        caps = m.get("capabilities") or []
        if name and "tools" in caps:
            names.append(name)
    return names


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True, help="OLLAMA_BASE_URL, no trailing slash expected")
    p.add_argument("--template", required=True, help="path to the base config.yaml")
    p.add_argument("--out", required=True, help="path to write the augmented config.yaml")
    p.add_argument("--api-key", default="ollama-unused")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--default-model", default="", help="model id already exposed as governed-model — skipped to avoid a duplicate entry")
    a = p.parse_args()

    with open(a.template, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    cfg.setdefault("model_list", [])

    try:
        names = _discover_models(a.base, a.timeout)
    except Exception as exc:  # noqa: BLE001 - never block gateway startup over this
        print(f"[gateway] could not list models at {a.base}/api/tags ({type(exc).__name__}: {exc}); "
              f"only the fixed default model is exposed", file=sys.stderr)
        names = []

    default_bare = a.default_model.split("/", 1)[-1] if a.default_model else ""
    added = 0
    for name in names:
        if name == default_bare:
            continue  # already present as the `governed-model` alias
        entry_model = name if name.startswith(("ollama_chat/", "ollama/")) else f"ollama_chat/{name}"
        cfg["model_list"].append({
            "model_name": name,
            "litellm_params": {
                "model": entry_model,
                "api_base": a.base,
                "api_key": a.api_key,
            },
        })
        added += 1

    with open(a.out, "w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, sort_keys=False)
    print(f"[gateway] on-prem Ollama: exposed {added} additional tool-capable model(s) "
          f"for the governed client to pick from (plus the fixed default)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
