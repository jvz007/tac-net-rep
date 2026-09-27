#!/usr/bin/env python3
"""Closure guard for open-list M9 in Core 1.15.119."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "scripts" / "trust-policy-cli.py").read_text(encoding="utf-8")

start = source.index("def recover_corrupt_pending")
end = source.index("\ndef write_pending", start)
block = source[start:end]

assert "target = LEVELS[-1]" in block, "M9: corrupt pending recovery must select the strongest supported trust floor"
assert "recovery_mode='fail_closed_strongest'" in block, "M9: root audit must identify fail-closed strongest-floor recovery"
assert "clear_pending()" in block, "M9: corrupt pending state must be cleared after recovery"
assert block.index("write_policy(target") < block.index("clear_pending()"), "M9: pending state must not be cleared before the stronger policy is written"

print("M9 strongest-floor corrupt pending closure guard: PASS")
