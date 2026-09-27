from __future__ import annotations

import runpy
from pathlib import Path


def test_housekeeping_claim_security():
    runpy.run_path(str(Path(__file__).with_name("housekeeping-claim-security.py")), run_name="__main__")
