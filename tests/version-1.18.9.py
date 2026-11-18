#!/usr/bin/env python3
"""Regression: Core 1.18.9 (R2 diagnostics checks) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

assert (ROOT / "VERSION").read_bytes() == b"1.18.9\n"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == "1.18.9" and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == ["RELEASE_NOTES_1.18.9.md"], notes
for v in ("1.17.124", "1.18.0", "1.18.1", "1.18.2", "1.18.3", "1.18.4", "1.18.5", "1.18.6", "1.18.7", "1.18.8"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{v}.md").is_file(), v
for v in ("1.18.7", "1.18.8"):
    assert (ROOT / "tests" / "legacy" / f"version-{v}.py").is_file() and not (ROOT / "tests" / f"version-{v}.py").exists(), v
legacy = (ROOT / "tests" / "legacy" / "version-1.18.8.py").read_text(encoding="utf-8")
assert "parents[2]" in legacy and "parents[1]" not in legacy

text = (ROOT / "RELEASE_NOTES_1.18.9.md").read_text(encoding="utf-8")
assert text.startswith("# Tec-Tac Framework 1.18.9\n\nDate: 18 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("core.install.source-ownership", "core.ui.module-sync", "Assumptions", "What is not in this release", "What could not be run",
               "Johan test checklist", "FAIL", "systemctl is-enabled tec-tac-ui-sync-publish.path", "ls -ld / /opt /opt/tec-tac-src"):
    assert needle in text, needle
assert b"\r" not in (ROOT / "install.sh").read_bytes()
print("version 1.18.9 regression: PASS")
