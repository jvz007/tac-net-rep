#!/usr/bin/env python3
"""Regression: Core 1.18.11 and its rebuilds (core modules always stay installed and on) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.11", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for v in ("1.18.9", "1.18.10"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{v}.md").is_file(), v
for v in ("1.18.9", "1.18.10"):
    assert (ROOT / "tests" / "legacy" / f"version-{v}.py").is_file() and not (ROOT / "tests" / f"version-{v}.py").exists(), v
legacy = (ROOT / "tests" / "legacy" / "version-1.18.10.py").read_text(encoding="utf-8")
assert "parents[2]" in legacy and "parents[1]" not in legacy

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 18 November 2026.")
assert text.count("## Module-facing change") == 1
for needle in ("Johan test checklist", "FAIL", "Send back", "core_module_locked", "tectac_module_state", "What could not be run", "Assumptions",
               "What is not in this release", "always_on", "lifecycle_locked", "server command (tectac_module_state)", "--server-command", "Fixed after review"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "Ethnocentric"):
    assert forbidden not in text.lower() or forbidden == "", forbidden
print("version 1.18.11 regression: PASS")
