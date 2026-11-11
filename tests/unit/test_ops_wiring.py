"""Static wiring checks for bin/dciso + the compose files (remediation §4, §6).

These don't need a running Docker daemon or Hermes — they parse/grep the
actual deploy artifacts so a future edit that silently drops a required
env var / host mapping / failure check is caught here instead of only on a
real Linux VM.
"""

from __future__ import annotations

import os
import re

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _override_constructor(loader, node):
    # docker-compose.ciso-hermes.yml uses `!override` (Compose v2.24+) on a
    # mapping — for structural inspection we only need the underlying dict.
    return loader.construct_mapping(node, deep=True)


def _load_yaml(path: str) -> dict:
    loader = yaml.SafeLoader
    loader.add_constructor("!override", _override_constructor)
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        return yaml.load(fh, Loader=loader)


# --------------------------------------------------------------------------- #
# ticket remediation §4 — DCISO_APPROVED_HOSTS / DCISO_FORCE_EXTERNAL_HOSTS
# must actually reach the gateway container.
# --------------------------------------------------------------------------- #
def test_compose_gateway_passes_approved_and_force_external_hosts():
    compose = _load_yaml("docker-compose.yml")
    gw_env = compose["services"]["gateway"]["environment"]
    assert "DCISO_APPROVED_HOSTS" in gw_env
    assert "DCISO_FORCE_EXTERNAL_HOSTS" in gw_env


def test_compose_gateway_passes_ollama_expose_all_models():
    compose = _load_yaml("docker-compose.yml")
    gw_env = compose["services"]["gateway"]["environment"]
    assert "OLLAMA_EXPOSE_ALL_MODELS" in gw_env


# --------------------------------------------------------------------------- #
# ticket remediation §6 — Linux Docker Engine needs the explicit
# host.docker.internal mapping on EVERY service that talks to a host sidecar
# (gateway already had it; pep did not).
# --------------------------------------------------------------------------- #
def test_compose_pep_has_host_docker_internal_mapping():
    compose = _load_yaml("docker-compose.yml")
    pep_hosts = compose["services"]["pep"].get("extra_hosts", [])
    assert any("host.docker.internal:host-gateway" in h for h in pep_hosts)


def test_compose_gateway_has_host_docker_internal_mapping():
    compose = _load_yaml("docker-compose.yml")
    gw_hosts = compose["services"]["gateway"].get("extra_hosts", [])
    assert any("host.docker.internal:host-gateway" in h for h in gw_hosts)


# --------------------------------------------------------------------------- #
# ticket remediation §6 — the host sidecar's actual port (HOST_CISO_PORT,
# which the operator can override) must be the SAME value the gateway and
# pep are told to call, for both services, in the ciso-hermes override.
# --------------------------------------------------------------------------- #
def test_ciso_hermes_override_uses_configurable_port_not_hardcoded():
    compose = _load_yaml("docker-compose.ciso-hermes.yml")
    gw_url = compose["services"]["gateway"]["environment"]["CISO_ADVISOR_URL"]
    pep_url = compose["services"]["pep"]["environment"]["CISO_ADVISOR_URL"]
    assert "HOST_CISO_PORT" in gw_url
    assert "HOST_CISO_PORT" in pep_url
    assert gw_url == pep_url, "gateway and pep must point at the exact same advisor host:port"


def test_bin_dciso_exports_host_ciso_port_to_compose_in_ollama_hermes_mode():
    with open(os.path.join(ROOT, "bin", "dciso"), encoding="utf-8") as fh:
        src = fh.read()
    # the up-ollama compose invocation must export HOST_CISO_PORT so the
    # ciso-hermes override file's ${HOST_CISO_PORT:-9009} substitution sees
    # the same port the host sidecar actually bound (HOST_CISO_PORT may be
    # overridden by the operator; it must not silently diverge per service).
    m = re.search(r'cmd_up_ollama\(\).*?\n\}', src, re.S)
    assert m, "cmd_up_ollama() function not found"
    body = m.group(0)
    assert 'HOST_CISO_PORT="$HOST_CISO_PORT"' in body or "HOST_CISO_PORT=\"$HOST_CISO_PORT\"" in body


# --------------------------------------------------------------------------- #
# ticket remediation §6 — a health-check timeout must be a real failure: a
# non-zero exit code, and the caller must NOT go on to print success.
# --------------------------------------------------------------------------- #
def test_wait_healthy_returns_nonzero_on_timeout():
    with open(os.path.join(ROOT, "bin", "dciso"), encoding="utf-8") as fh:
        src = fh.read()
    m = re.search(r'_wait_healthy\(\) \{.*?\n\}', src, re.S)
    assert m, "_wait_healthy() function not found"
    body = m.group(0)
    assert re.search(r'warn\s+"services did not all report healthy', body)
    # the return/exit must come AFTER the warn (i.e. the function no longer
    # falls through to an implicit zero exit status)
    warn_pos = body.index("services did not all report healthy")
    tail = body[warn_pos:]
    assert re.search(r'return\s+1\b|exit\s+1\b', tail)


def test_every_wait_healthy_call_site_checks_its_result():
    with open(os.path.join(ROOT, "bin", "dciso"), encoding="utf-8") as fh:
        lines = fh.readlines()
    call_sites = [i for i, ln in enumerate(lines)
                  if re.match(r'^\s*_wait_healthy\b', ln) and "_wait_healthy()" not in ln]
    assert len(call_sites) >= 5, "expected _wait_healthy to be called from every `up`-style command"
    for i in call_sites:
        assert "||" in lines[i] and "die" in lines[i], (
            f"bin/dciso:{i + 1} calls _wait_healthy without checking its exit code: {lines[i]!r}")
