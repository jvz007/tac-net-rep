#!/usr/bin/env python3
"""Regression: Core 1.18.7 keeps every module-facing name; recovery files are private."""
import importlib
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
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

raw = (ROOT / "VERSION").read_bytes()
assert raw == b"1.18.7-1\n", raw

package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == "1.18.7-1"
assert package["id"] == "tec-tac"
assert package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == ["RELEASE_NOTES_1.18.7-1.md"], notes
for v in ("1.17.124", "1.18.0", "1.18.1", "1.18.2", "1.18.3", "1.18.4", "1.18.5", "1.18.6"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{v}.md").is_file(), v

text = (ROOT / "RELEASE_NOTES_1.18.7-1.md").read_text(encoding="utf-8")
for needle in ("Fixed after review", "Module-facing", "What is not in this release", "Assumptions", "Johan test checklist", "FAIL", "0700", "2>/dev/null"):
    assert needle in text, needle
assert text.count("## Module-facing") == 1

for constraint in (">=1.17.124,<2.0.0", ">=1.17.13,<2.0.0", ">=1.17.109,<2.0.0", ">1.17.124-9"):
    assert satisfies("1.18.7", constraint), constraint
assert not satisfies("1.18.7-1", "<1.18.7")
assert satisfies("1.18.7", ">=1.18.5,<2.0.0")
assert satisfies("1.18.7-1", ">1.18.7")
assert satisfies("1.18.7", ">1.18.0")

print("version 1.18.7 regression: PASS")
