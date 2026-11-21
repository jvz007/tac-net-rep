#!/usr/bin/env python3
"""Regression: Core 1.18.33 (file transfers: binary chunk, binary answer, 204 and 408 pass through, AD-69 transfer rows; contract 1.18.0) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.33", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.32.md").is_file() and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.31.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.32.py").is_file() and not (ROOT / "tests" / "version-1.18.32.py").exists(), "version-1.18.32.py is retired to tests/legacy"
assert (ROOT / "tests" / "tactical-operation-file-transfer-1.18.33.py").is_file()
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
assert "tactical-operation-file-transfer-1.18.33.py" in integrity, "release integrity runs the new test before every pack"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 21 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 5 and checklist.count("FAIL:") >= 5, "every step has a PASS and a FAIL line"
for needle in ("1.18.0", "binary_body", "binary_response", "audit.transfer", "read_binary_body", "transfer:<session id>", "408", "204", "invalid_content_range",
               "length_required", "binary_body_required", "binary_body_not_allowed", "MAX_BINARY_BODY_BYTES", "Tactical 1.5.2", "Django", "reviews/requests/core.md",
               "AD-69", "remote-background", "framework >=1.18.33"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "docs/releases/RELEASE_NOTES_1.18.32.md", "tests/version-1.18.33.py", "tests/legacy/version-1.18.32.py",
             "tests/tactical-operation-file-transfer-1.18.33.py", "framwork/tec_tac/tactical_operations.py", "tests/release-integrity.sh"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("docs/tactical-operations.md", "framwork/tec_tac/contracts.py"):
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"

# The rebuild guard matches this version (a stray 1.18.33-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.33" + "-" + r"\d")
assert label.search("x 1.18.33" + "-1") and not label.search("x 1.18.32" + "-1"), "the guard pattern checks 1.18.33"

# No rebuild label (this version, a dash and a digit) in any file except VERSION, tec_tac_package.json and the release notes.
names = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"], capture_output=True, check=False).stdout.decode("utf-8", "replace").split("\0")
if not any(names):
    names = [str(p.relative_to(ROOT)).replace("\\", "/") for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
for name in names:
    if not name or name in ("VERSION", "tec_tac_package.json") or name.startswith(("RELEASE_NOTES_", "tests/legacy/", "docs/releases/")):
        continue
    path = ROOT / name
    if not path.is_file() or path.suffix in (".png", ".zip", ".sig", ".ico", ".gz"):
        continue
    assert not label.search(path.read_bytes().decode("utf-8", "replace")), name + " carries a rebuild label"
print("version 1.18.33 regression: PASS")
