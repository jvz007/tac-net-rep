#!/usr/bin/env python3
"""Regression: Core 1.18.44 (core.result_checks 1.0.0, B2) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.44", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for earlier in ("1.18.43", "1.18.42", "1.18.41", "1.18.40", "1.18.39", "1.18.38"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{earlier}.md").is_file(), earlier
assert (ROOT / "tests" / "legacy" / "version-1.18.43.py").is_file() and not (ROOT / "tests" / "version-1.18.43.py").exists(), "version-1.18.43.py is retired to tests/legacy"
for name in ("result-checks-1.18.44.py", "version-1.18.44.py", "system-version-picker-1.18.43.py", "online-upgrade-batch-1.18.42.py"):
    assert (ROOT / "tests" / name).is_file(), name
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in ("result-checks-1.18.44.py", "version-1.18.44.py", "system-version-picker-1.18.43.py", "online-upgrade-batch-1.18.42.py"):
    assert name in integrity, f"release integrity runs {name}"
assert "version-1.18.43.py" not in integrity, "the retired test is not run"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 22 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 5 and checklist.count("FAIL:") >= 5, "every step has a PASS and a FAIL line"
assert checklist.count("PASS:") == checklist.count("FAIL:"), "one FAIL line for each PASS line"
for needle in ("core.result_checks", "0048_result_checks", "makemigrations --check --dry-run", "/api/tfd/ui/result-checks/", "tec_tac.run_result_check",
               "Plan corrections found in the code", "swappable_dependency", "Nothing else was built", "1.18.43 and 1.18.42 reviews", "Script Execution 0.7.1", "UI 0.13.4"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.44.py", "tests/result-checks-1.18.44.py", "tests/release-integrity.sh",
            "framwork/tec_tac/result_checks.py", "framwork/tec_tac/result_check_views.py", "framwork/tec_tac/migrations/0048_result_checks.py", "framwork/tec_tac/tasks.py",
            "framwork/tec_tac/urls.py", "framwork/tec_tac/openapi.py", "framwork/tec_tac/management/commands/tec_tac_scheduler_tick.py", "docs/result-checks.md")
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("framwork/tec_tac/contracts.py", "framwork/tec_tac/models.py", "framwork/tec_tac/apps.py", "docs/capabilities.md"):
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"

# The rebuild guard matches this version (a stray 1.18.44-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.44" + "-" + r"\d")
assert label.search("x 1.18.44" + "-1") and not label.search("x 1.18.43" + "-1"), "the guard pattern checks 1.18.44"

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
print("version 1.18.44 regression: PASS")
