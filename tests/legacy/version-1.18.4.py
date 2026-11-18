#!/usr/bin/env python3
"""Regression: Core 1.18.4 keeps every module-facing name and every module accepts it."""
import importlib
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PKG_DIR = ROOT / "framwork" / "tec_tac"
if "fcntl" not in sys.modules:
    try:
        import fcntl  # noqa: F401
    except ImportError:  # Windows: only version_satisfies is used here
        sys.modules["fcntl"] = types.ModuleType("fcntl")
# Register the package without running its __init__ (no Django needed).
package_stub = types.ModuleType("tec_tac")
package_stub.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package_stub
module = importlib.import_module("tec_tac.module_state")
satisfies = module.version_satisfies

# Moved to tests/legacy in 1.18.5: the current VERSION and root notes belong to the newest version test.
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["id"] == "tec-tac"
assert package["type"] == "tec-tac-framework"
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.4.md").is_file()
text = (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.4.md").read_text(encoding="utf-8")
for needle in ("Module-facing", "What is not in this release", "lifecycle lock", "restore was not started", "Johan test checklist", "FAIL"):
    assert needle in text, needle

for constraint in (">=1.17.124,<2.0.0", ">=1.17.13,<2.0.0", ">=1.17.109,<2.0.0", ">1.17.124-9"):
    assert satisfies("1.18.4", constraint), constraint
assert not satisfies("1.18.4", "<1.18.4")
assert satisfies("1.18.4", ">=1.18.3,<2.0.0")
assert satisfies("1.18.4-1", ">1.18.4")
assert satisfies("1.18.4", ">1.18.0")

print("version 1.18.4 regression: PASS")
