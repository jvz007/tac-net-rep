#!/usr/bin/env python3
"""Regression: Core 1.18.15 and its rebuilds (core.sandbox canary: private /run proof, memory probe, row ids, swept run.ended, lingered credential row) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.15", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for v in ("1.18.11", "1.18.12", "1.18.13", "1.18.14"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{v}.md").is_file(), v
assert (ROOT / "tests" / "legacy" / "version-1.18.14.py").is_file() and not (ROOT / "tests" / "version-1.18.14.py").exists()
assert (ROOT / "tests" / "sandbox-canary-1.18.15.sh").is_file()

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 19 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("private per-run /run", "swept", "run.credentials_lingered", "ROW <id> <verdict>", "sandbox-canary-1.18.15.sh", "ALL CANARY STEPS PASSED", "FAIL",
               "What could not be run", "Assumptions", "What is not in this release", "Johan test checklist"):
    assert needle in text, needle
checklist = text[text.index("## Johan test checklist"):text.index("## What could not be run")]
for step in ("a. ", "b. ", "c. ", "d. ", "e. ", "f. "):
    assert step in checklist, step
for forbidden in ("kindly", "don't hesitate", "Ethnocentric"):
    assert forbidden not in text.lower()
print("version 1.18.15 regression: PASS")
