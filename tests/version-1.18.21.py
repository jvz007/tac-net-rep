#!/usr/bin/env python3
"""Regression: Core 1.18.21 and its rebuilds (one live tick chain per install run) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.21", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.20.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.20.py").is_file() and not (ROOT / "tests" / "version-1.18.20.py").exists()
assert (ROOT / "tests" / "online-install-chain-1.18.21.py").is_file()

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 19 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("seq", "BUSY_DELAY_SECONDS", "advance_module_install_run", "Retired checks", "What could not be run", "Johan dev02 checklist",
               "What changed and why", "FAIL", "Assumptions", "Findings closed"):
    assert needle in text, needle
checklist = text[text.index("## Johan dev02 checklist"):]
for step in ("a. ", "b. ", "c. ", "d. ", "e. ", "f. "):
    assert step in checklist, step
for forbidden in ("kindly", "don't hesitate", "Ethnocentric"):
    assert forbidden not in text.lower()
for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.21.py", "tests/online-install-chain-1.18.21.py",
             "tests/online-install-run-1.18.20.py", "framwork/tec_tac/module_install_run.py", "framwork/tec_tac/module_install_run_views.py",
             "framwork/tec_tac/tasks.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("framwork/tec_tac/contracts.py", "framwork/tec_tac/module_repository.py", "docs/module-repositories.md", "docs/troubleshooting-diagnostics.md"):
    data = (ROOT / name).read_bytes()
    assert data.count(b"\r\n") == data.count(b"\n"), name + " must keep CRLF line endings"
print("version 1.18.21 regression: PASS")
