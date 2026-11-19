#!/usr/bin/env python3
"""Regression: Core 1.18.13 and its rebuilds (sandbox root `run/systemd/incoming`, post-run re-check, real-shape probe) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.13", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for v in ("1.18.10", "1.18.11", "1.18.12"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{v}.md").is_file(), v
assert (ROOT / "tests" / "legacy" / "version-1.18.12.py").is_file() and not (ROOT / "tests" / "version-1.18.12.py").exists()
legacy_lines = (ROOT / "tests" / "legacy" / "version-1.18.11.py").read_text(encoding="utf-8").splitlines()
assert legacy_lines[19] == 'assert "parents[2]" in legacy and "parents[1]" not in legacy', legacy_lines[19]

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 19 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("skeleton.changed", "real_unit_shape", "run/systemd/incoming", "ALL CANARY STEPS PASSED", "FAIL", "Send back", "What could not be run", "Assumptions"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "Ethnocentric"):
    assert forbidden not in text.lower()
print("version 1.18.13 regression: PASS")
