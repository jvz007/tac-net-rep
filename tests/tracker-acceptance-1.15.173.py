#!/usr/bin/env python3
"""Single acceptance runner for every tracker row still open before 1.15.173.

Core-owned rows executed here:
D2, D3, L10, F1, F2, F4, F5, F6, F7, F11.
Companion UI 0.12.67 owns the browser-side acceptance for D2/D3 and F1/F2/F4-F10.
"""
from __future__ import annotations
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TESTS = [
    "d2-d3-restore-orchestration-1.15.173.py",
    "l10-publication-final-1.15.173.py",
    "tracker-http-feature-boundary-1.15.172.py",
    "f4-core-ui-context-1.15.178.py",
    "f11-openapi-final-1.15.178.py",
]

for name in TESTS:
    proc = subprocess.run([sys.executable, str(ROOT / "tests" / name)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode:
        raise AssertionError(f"{name} failed:\n{proc.stdout}")
    if "PASS" not in proc.stdout:
        raise AssertionError(f"{name} did not report PASS:\n{proc.stdout}")

print("[TEST] PASS tracker acceptance Core rows D2/D3/L10/F1/F2/F4/F5/F6/F7/F11")
