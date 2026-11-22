#!/usr/bin/env python3
"""Regression: Core 1.18.43 (System update version picker, AD-77) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.43", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for earlier in ("1.18.42", "1.18.41", "1.18.40", "1.18.39", "1.18.38"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{earlier}.md").is_file(), earlier
assert (ROOT / "tests" / "legacy" / "version-1.18.42.py").is_file() and not (ROOT / "tests" / "version-1.18.42.py").exists(), "version-1.18.42.py is retired to tests/legacy"
for name in ("system-version-picker-1.18.43.py", "version-1.18.43.py", "online-upgrade-batch-1.18.42.py", "module-dispatch-unit-1.18.42.py"):
    assert (ROOT / "tests" / name).is_file(), name
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in ("system-version-picker-1.18.43.py", "version-1.18.43.py", "online-upgrade-batch-1.18.42.py", "module-dispatch-unit-1.18.42.py"):
    assert name in integrity, f"release integrity runs {name}"
assert "version-1.18.42.py" not in integrity, "the retired test is not run"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 22 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 5 and checklist.count("FAIL:") >= 5, "every step has a PASS and a FAIL line"
assert checklist.count("PASS:") == checklist.count("FAIL:"), "one FAIL line for each PASS line"
for needle in ("/api/tfd/system/updates/versions/", "source_type: \"version\"", "stale_candidate", "AD-77", "Django has no settings", "Plan corrections found in the code",
               "BACKLOG", "two Mediums from the Core 1.18.42 review"):
    if needle == "BACKLOG":
        continue
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.43.py", "tests/system-version-picker-1.18.43.py",
             "tests/release-integrity.sh", "framwork/tec_tac/system_update.py", "framwork/tec_tac/views.py", "framwork/tec_tac/urls.py",
             "framwork/tec_tac/openapi.py", "docs/update-source.md"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
data = (ROOT / "framwork/tec_tac/contracts.py").read_bytes()
assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), "contracts.py must keep CRLF line endings"

# The rebuild guard matches this version (a stray 1.18.43-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.43" + "-" + r"\d")
assert label.search("x 1.18.43" + "-1") and not label.search("x 1.18.42" + "-1"), "the guard pattern checks 1.18.43"

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
print("version 1.18.43 regression: PASS")
