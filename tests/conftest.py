import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# deterministic defaults for the governance core under test
os.environ.setdefault("REPLAN_MAX_ATTEMPTS", "2")
os.environ.setdefault("GOV_DEFAULT_AUTONOMY", "L1")
os.environ.setdefault("GOV_DEFAULT_CAPABILITY", "C1")
