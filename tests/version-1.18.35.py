#!/usr/bin/env python3
"""Regression: Core 1.18.35 (upgrade several modules at once: optional purpose on the online plan and install routes, one correlation id per run;
failed transfer end row with its own once-only key; metadata key restored) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.35", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.34.md").is_file() and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.33.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.34.py").is_file() and not (ROOT / "tests" / "version-1.18.34.py").exists(), "version-1.18.34.py is retired to tests/legacy"
assert (ROOT / "tests" / "online-upgrade-run-1.18.35.py").is_file()
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in ("online-upgrade-run-1.18.35.py", "online-install-plan-1.18.19.py", "online-install-run-1.18.20.py", "online-install-chain-1.18.21.py",
             "tactical-operation-file-transfer-audit-1.18.34.py"):
    assert name in integrity, f"release integrity runs {name}"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 21 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 5 and checklist.count("FAIL:") >= 5, "every step has a PASS and a FAIL line"
for needle in ("purpose", "not_installed", "other_source", "current_version", "correlation_id", "Welcome", "refusal_codes_without_row_added_in_1_18_0",
               "tectac:transfer-end-failed", "Remote Background", "Django", "reviews/requests/core.md", "1.18.0"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

operations = (ROOT / "framwork" / "tec_tac" / "tactical_operations.py").read_text(encoding="utf-8")
assert 'CAPABILITY_VERSION = "1.18.0"' in operations
for needle in ("_failed_end_row_key", "_failed_end_row_forget", "_end_row_written", '"refusal_codes_without_row_added_in_1_18_0": []'):
    assert needle in operations, needle

for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.35.py", "tests/online-upgrade-run-1.18.35.py",
             "framwork/tec_tac/tactical_operations.py", "framwork/tec_tac/module_install_plan.py", "framwork/tec_tac/module_install_run.py",
             "framwork/tec_tac/module_install_run_views.py", "framwork/tec_tac/module_allowed_views.py", "tests/release-integrity.sh"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("docs/tactical-operations.md", "docs/module-repositories.md", "framwork/tec_tac/contracts.py", "framwork/tec_tac/module_repository.py"):
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"

# The rebuild guard matches this version (a stray 1.18.35-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.35" + "-" + r"\d")
assert label.search("x 1.18.35" + "-1") and not label.search("x 1.18.34" + "-1"), "the guard pattern checks 1.18.35"

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
print("version 1.18.35 regression: PASS")
