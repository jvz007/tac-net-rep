#!/usr/bin/env python3
"""Regression: Core 1.18.17 and its rebuilds (core.sandbox: unit result from systemd, reset-failed, memory row on the unit result) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.17", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.16.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.16.py").is_file() and not (ROOT / "tests" / "version-1.18.16.py").exists()
assert (ROOT / "tests" / "sandbox-canary-1.18.17.sh").is_file()

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 19 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("unit_result", "reset-failed", "read_unit_result", "ALL CANARY STEPS PASSED", "sandbox-canary-1.18.17.sh", "FAIL",
               "What could not be run", "Assumptions", "What is not in this release", "Johan test checklist", "What changed and why"):
    assert needle in text, needle
checklist = text[text.index("## Johan test checklist"):text.index("## What could not be run")]
for step in ("a. ", "b. ", "c. ", "d. ", "e. ", "f. "):
    assert step in checklist, step
for forbidden in ("kindly", "don't hesitate", "Ethnocentric"):
    assert forbidden not in text.lower()
script = (ROOT / "tests" / "sandbox-canary-1.18.17.sh").read_text(encoding="utf-8")
for needle in ("ALL CANARY STEPS PASSED", "tectac-plantest-", "reset-failed", "list-units --state=failed", "oom-kill", "read_unit_result"):
    assert needle in script, needle
assert not [line for line in script.splitlines() if "systemd-run --wait" in line and "--collect" in line], "the plain test unit is started without --collect"
for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.17.py", "tests/sandbox-canary-1.18.17.sh",
             "tests/sandbox-unit-result-1.18.17.py", "tests/sandbox-sweep-failed-1.18.17.py", "tests/sandbox-memory-1.18.17.py",
             "tests/sandbox-harness-1.17.118.py", "scripts/sandbox-helper.py", "docs/sandbox-capability.md"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
print("version 1.18.17 regression: PASS")
