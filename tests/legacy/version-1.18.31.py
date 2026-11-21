#!/usr/bin/env python3
"""Regression: Core 1.18.31 (migration 0038 pinned, no floating migration dependency) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.31", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.30.md").is_file() and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.29.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.30.py").is_file() and not (ROOT / "tests" / "version-1.18.30.py").exists(), "version-1.18.30.py is retired to tests/legacy"
assert (ROOT / "tests" / "migration-no-floating-dependency-1.18.31.py").is_file()

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 21 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 4 and checklist.count("FAIL:") >= 4, "every step has a PASS and a FAIL line"
for needle in ("0042_copy_mesh_permission_to_terminal", "__latest__", "InconsistentMigrationHistory", "accounts `0043`", "Django"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.31.py", "tests/migration-no-floating-dependency-1.18.31.py", "tests/communicator-service-user-1.18.31.py",
             "framwork/tec_tac/migrations/0038_communicator_service_user.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"

# No rebuild label (this version, a dash and a digit) in any file except VERSION, tec_tac_package.json and the release notes.
label = re.compile("1" + r"\.18\.31" + "-" + r"\d")
names = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"], capture_output=True, check=False).stdout.decode("utf-8", "replace").split("\0")
if not any(names):
    names = [str(p.relative_to(ROOT)).replace("\\", "/") for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
for name in names:
    if not name or name in ("VERSION", "tec_tac_package.json") or name.startswith(("RELEASE_NOTES_", "tests/legacy/")):
        continue
    path = ROOT / name
    if not path.is_file() or path.suffix in (".png", ".zip", ".sig", ".ico", ".gz"):
        continue
    assert not label.search(path.read_bytes().decode("utf-8", "replace")), name + " carries a rebuild label"
print("version 1.18.31 regression: PASS")
