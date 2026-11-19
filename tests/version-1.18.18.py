#!/usr/bin/env python3
"""Regression: Core 1.18.18 and its rebuilds (premium untick audit row, Licensing allowed_modules 1.1.0) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.18", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.17.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.17.py").is_file() and not (ROOT / "tests" / "version-1.18.17.py").exists()
assert (ROOT / "tests" / "premium-untick-audit-1.18.18.py").is_file()

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 19 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("deny", "outcome", "licensing.allowed_modules", "1.1.0", "0.10.7", "licensing_unavailable", "FAIL",
               "What could not be run", "Assumptions", "What is not in this release", "Johan test checklist", "What changed and why"):
    assert needle in text, needle
checklist = text[text.index("## Johan test checklist"):text.index("## What could not be run")]
for step in ("a. ", "b. ", "c. ", "d. "):
    assert step in checklist, step
for forbidden in ("kindly", "don't hesitate", "Ethnocentric"):
    assert forbidden not in text.lower()
for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.18.py",
             "tests/premium-untick-audit-1.18.18.py", "framwork/tec_tac/module_allowed_views.py",
             "framwork/tec_tac/licensing_catalogue_source.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("framwork/tec_tac/contracts.py", "docs/module-repositories.md", "tests/allowed-modules-route-1.18.10.py"):
    data = (ROOT / name).read_bytes()
    assert data.count(b"\r\n") == data.count(b"\n"), name + " must keep CRLF line endings"
print("version 1.18.18 regression: PASS")
