#!/usr/bin/env python3
"""Regression: Core 1.18.32 (agent status and version, contract 1.13.0; service-user model defaults; 1.18.31 notes corrected) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.32", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.31.md").is_file() and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.30.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.31.py").is_file() and not (ROOT / "tests" / "version-1.18.31.py").exists(), "version-1.18.31.py is retired to tests/legacy"
for name in ("resources-agent-status-version-1.18.32.py", "communicator-service-user-defaults-1.18.32.py"):
    assert (ROOT / "tests" / name).is_file(), name

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 21 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 4 and checklist.count("FAIL:") >= 4, "every step has a PASS and a FAIL line"
for needle in ("1.13.0", "`status`", "`version`", "remote-background 0.11.2", "framework >=1.18.32", "model_defaults", "Django", "reviews/requests/core.md",
               "BACKLOG-new-findings.md", "repair migration"):
    assert needle in text, needle
assert "1.18.31 release notes said" in text, "the notes say plainly that the 1.18.31 notes were corrected"
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

old = (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.31.md").read_text(encoding="utf-8")
assert "No behaviour changes." not in old, "the wrong 1.18.31 opening is gone"
assert "0045" in old and "live" in old and "0042_copy_mesh_permission_to_terminal" in old, "the 1.18.31 notes name 0045 and the live columns"
assert "0045_communicator_service_user_retry.py` (new)" in old[old.index("## What changed and why"):old.index("## Assumptions")], "0045 is listed under What changed and why"
assert "communicator-service-user-1.18.31.py" in old[old.index("## New tests"):old.index("## What could not be run here")]

for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "docs/releases/RELEASE_NOTES_1.18.31.md", "tests/version-1.18.32.py", "tests/legacy/version-1.18.31.py",
             "tests/resources-agent-status-version-1.18.32.py", "tests/communicator-service-user-defaults-1.18.32.py", "framwork/tec_tac/migrations/0038_communicator_service_user.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"

# The rebuild guard matches this version (a stray 1.18.32-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.32" + "-" + r"\d")
assert label.search("x 1.18.32" + "-1") and not label.search("x 1.18.31" + "-1"), "the guard pattern checks 1.18.32"
legacy_guard = (ROOT / "tests" / "legacy" / "version-1.18.31.py").read_text(encoding="utf-8")
assert 'r"\\.18\\.31" + "-"' in legacy_guard and 'r"\\.18\\.30" + "-"' not in legacy_guard, "the 1.18.31 guard checks 1.18.31"

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
print("version 1.18.32 regression: PASS")
