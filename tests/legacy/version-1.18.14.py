#!/usr/bin/env python3
"""Regression: Core 1.18.14 and its rebuilds (core.sandbox: no `+` property commands, helper-side credential clean-up) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.14", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for v in ("1.18.11", "1.18.12", "1.18.13"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{v}.md").is_file(), v
assert (ROOT / "tests" / "legacy" / "version-1.18.13.py").is_file() and not (ROOT / "tests" / "version-1.18.13.py").exists()
assert (ROOT / "tests" / "sandbox-canary-1.18.14.sh").is_file()

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 19 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("ExecStartPost", "--finish", "sandbox-canary-1.18.14.sh", "ALL CANARY STEPS PASSED", "FAIL", "Send back", "What could not be run", "Assumptions",
               "What is not in this release", "live cgroup poll"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "Ethnocentric"):
    assert forbidden not in text.lower()
print("version 1.18.14 regression: PASS")
