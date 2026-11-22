#!/usr/bin/env python3
"""Regression: Core 1.18.41 (scheduled server-wide reports decided by the schedule owner, CQ93 option 2, AD-76) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.41", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for earlier in ("1.18.40", "1.18.39", "1.18.38", "1.18.37"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{earlier}.md").is_file(), earlier
assert (ROOT / "tests" / "legacy" / "version-1.18.40.py").is_file() and not (ROOT / "tests" / "version-1.18.40.py").exists(), "version-1.18.40.py is retired to tests/legacy"
for name in ("reporting-schedule-run-1.18.41.py", "version-1.18.41.py", "installer-serve-cost-1.18.40.py"):
    assert (ROOT / "tests" / name).is_file(), name
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in ("reporting-schedule-run-1.18.41.py", "version-1.18.41.py", "installer-serve-cost-1.18.40.py", "endpoint-agent-installer-1.18.39.py"):
    assert name in integrity, f"release integrity runs {name}"
assert "version-1.18.40.py" not in integrity, "the retired version test is not run"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 22 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 5 and checklist.count("FAIL:") >= 5, "every step has a PASS and a FAIL line"
assert checklist.count("PASS:") == checklist.count("FAIL:"), "one FAIL line for each PASS line"
for needle in ("CQ93", "AD-76", "schedule_run", "ScheduledReportRefused", "using(", "reportmanager", "sentinelone", "Django is not installed", "Run now",
               "A scheduled report may show server-wide data only when the person who last saved the schedule is a superuser."):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.41.py", "tests/reporting-schedule-run-1.18.41.py",
             "tests/release-integrity.sh"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("framwork/tec_tac/reporting.py", "framwork/tec_tac/contracts.py", "docs/module-reporting.md"):
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"

# The rebuild guard matches this version (a stray 1.18.41-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.41" + "-" + r"\d")
assert label.search("x 1.18.41" + "-1") and not label.search("x 1.18.40" + "-1"), "the guard pattern checks 1.18.41"

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
print("version 1.18.41 regression: PASS")
