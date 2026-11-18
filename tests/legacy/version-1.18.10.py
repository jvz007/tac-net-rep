#!/usr/bin/env python3
"""Regression: Core 1.18.10 (allowed-module routes, diagnostics containment) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

assert (ROOT / "VERSION").read_bytes() == b"1.18.10\n"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == "1.18.10" and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == ["RELEASE_NOTES_1.18.10.md"], notes
for v in ("1.18.8", "1.18.9"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{v}.md").is_file(), v
assert (ROOT / "tests" / "legacy" / "version-1.18.9.py").is_file() and not (ROOT / "tests" / "version-1.18.9.py").exists()
legacy = (ROOT / "tests" / "legacy" / "version-1.18.9.py").read_text(encoding="utf-8")
assert "parents[2]" in legacy

text = (ROOT / "RELEASE_NOTES_1.18.10.md").read_text(encoding="utf-8")
assert text.startswith("# Tec-Tac Framework 1.18.10\n\nDate: 18 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("modules/catalog/allowed/", "modules/catalog/allowed/refresh/", "modules/catalog/allowed/selection/", "core.privileged_operations",
               "Assumptions", "What is not in this release", "What could not be run", "Johan test checklist", "FAIL", "Send back",
               "core.install.source-ownership", "core.ui.module-sync", "provider", "premium"):
    assert needle in text, needle
print("version 1.18.10 regression: PASS")
