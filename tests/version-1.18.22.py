#!/usr/bin/env python3
"""Regression: Core 1.18.22 and its rebuilds (the canary prints the full text of a cut row) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.22", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.21.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.21.py").is_file() and not (ROOT / "tests" / "version-1.18.21.py").exists()
for name in ("tests/sandbox-canary-detail-1.18.22.py", "tests/sandbox-canary-script-1.18.22.py", "tests/sandbox-canary-1.18.22.sh"):
    assert (ROOT / name).is_file(), name

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 19 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("What could not be run", "Johan dev02 checklist", "What changed and why", "FAIL", "Assumptions", "What is not in this release", "SANDBOX_ENABLED"):
    assert needle in text, needle
checklist = text[text.index("## Johan dev02 checklist"):]
for step in ("a. ", "b. ", "c. ", "d. ", "e. ", "f. "):
    assert step in checklist, step
for forbidden in ("kindly", "don't hesitate", "Ethnocentric"):
    assert forbidden not in text.lower()
for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.22.py", "tests/sandbox-canary-detail-1.18.22.py",
             "tests/sandbox-canary-script-1.18.22.py", "tests/sandbox-canary-1.18.22.sh", "scripts/sandbox-helper.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
print("version 1.18.22 regression: PASS")
