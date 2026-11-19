#!/usr/bin/env python3
"""Regression: Core 1.18.16 and its rebuilds (core.sandbox canary: memory proof from the kernel's counters, no second run.ended, /run seen line) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.16", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.15.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.15.py").is_file() and not (ROOT / "tests" / "version-1.18.15.py").exists()
assert (ROOT / "tests" / "sandbox-canary-1.18.16.sh").is_file()

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 19 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("memory.events", "memory_events", "CANARYRUNSEEN", "run_already_ended", "sandbox-canary-1.18.16.sh", "ALL CANARY STEPS PASSED", "FAIL",
               "What could not be run", "Assumptions", "What is not in this release", "Johan test checklist", "What changed and why"):
    assert needle in text, needle
checklist = text[text.index("## Johan test checklist"):text.index("## What could not be run")]
for step in ("a. ", "b. ", "c. ", "d. ", "e. ", "f. "):
    assert step in checklist, step
for forbidden in ("kindly", "don't hesitate", "Ethnocentric"):
    assert forbidden not in text.lower()
for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.16.py", "tests/sandbox-canary-1.18.16.sh",
             "tests/sandbox-memory-1.18.16.py", "tests/sandbox-sweep-ended-twice-1.18.16.py", "tests/sandbox-run-seen-1.18.16.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
print("version 1.18.16 regression: PASS")
