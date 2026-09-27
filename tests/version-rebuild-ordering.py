#!/usr/bin/env python3
"""Regression: Tec-Tac numeric rebuild suffixes must sort after their base release."""
from pathlib import Path
import importlib.util
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "module_state.py"
spec = importlib.util.spec_from_file_location("tec_tac_module_state_under_test", MODULE)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = module
spec.loader.exec_module(module)

satisfies = module.version_satisfies

# Release pipeline semantics: rebuilds are newer than the original release.
assert satisfies("1.15.115-1", ">1.15.115")
assert satisfies("1.15.115", "<1.15.115-1")
assert satisfies("1.15.115-2", ">1.15.115-1")
assert satisfies("1.15.115-10", ">1.15.115-2")
assert not satisfies("1.15.115-2", ">1.15.115-10")

# Normal core-version ordering remains authoritative.
assert satisfies("1.15.116", ">1.15.115-99")
assert satisfies("1.16.0", ">1.15.999-99")

# Ordinary prerelease suffixes retain their previous below-release behavior.
assert satisfies("1.15.116-alpha", "<1.15.116")
assert satisfies("1.15.116", ">1.15.116-alpha")

# Exact rebuild constraints remain exact.
assert satisfies("1.15.115-1", "==1.15.115-1")
assert not satisfies("1.15.115-2", "==1.15.115-1")

print("version rebuild ordering regression: PASS")
