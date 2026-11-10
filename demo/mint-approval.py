#!/usr/bin/env python3
"""Mint a human-approval token for a REQUIRE_REVIEW action (demo / operator aid).

In production this belongs to a review system with its own authn/authz. Here it
is a thin CLI so you can exercise the resubmit-with-token flow.

    export GOVERNANCE_APPROVAL_SECRET=...        # same value the gateway has
    # from the 409 body / dashboard you know the action:
    python demo/mint-approval.py --session sess-1 --tool send_email \
        --args '{"to":"ops@corp.internal"}' --ttl 900 --approver alice

Then resubmit the SAME request with:
    "metadata": {"dciso": {"approval_token": "<printed token>"}}
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from gateway.governance import approvals  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--session", required=True)
    p.add_argument("--tool", required=True, help="canonical action name (e.g. send_email, agent.spawn)")
    p.add_argument("--args", default="{}", help="JSON object of the proposed action arguments (must match exactly)")
    p.add_argument("--ttl", type=int, default=900)
    p.add_argument("--approver", default="operator")
    a = p.parse_args()

    if not os.environ.get("GOVERNANCE_APPROVAL_SECRET"):
        print("error: set GOVERNANCE_APPROVAL_SECRET (same as the gateway)", file=sys.stderr)
        return 2
    try:
        args = json.loads(a.args)
        assert isinstance(args, dict)
    except (json.JSONDecodeError, AssertionError):
        print("error: --args must be a JSON object", file=sys.stderr)
        return 2

    fp = approvals.action_fingerprint(a.session, a.tool, args)
    token = approvals.mint(fp, ttl_seconds=a.ttl, approver=a.approver)
    print(json.dumps({"fingerprint": fp, "approval_token": token, "ttl_seconds": a.ttl,
                      "resubmit_metadata": {"dciso": {"approval_token": token}}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
