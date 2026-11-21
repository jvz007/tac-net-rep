#!/usr/bin/env python3
"""Regression: Core 1.18.36 (the command row allows softwarerepository fixed templates, communicator on a legacy path) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.36", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.35.md").is_file() and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.34.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.35.py").is_file() and not (ROOT / "tests" / "version-1.18.35.py").exists(), "version-1.18.35.py is retired to tests/legacy"
for name in ("system-command-callers-1.18.36.py", "system-command-callers-integration-1.18.36.py"):
    assert (ROOT / "tests" / name).is_file(), name
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in ("system-command-callers-1.18.36.py", "system-command-callers-integration-1.18.36.py", "online-upgrade-run-1.18.35.py", "online-install-plan-1.18.19.py",
             "tactical-operation-file-transfer-audit-1.18.34.py"):
    assert name in integrity, f"release integrity runs {name}"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 21 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 5 and checklist.count("FAIL:") >= 5, "every step has a PASS and a FAIL line"
for needle in ("softwarerepository.deploy", "legacy_callers", "caller_module", "action_not_allowed", "bad_parameters", "One module per schedule", "1.6.0", "10^9", "0123456789",
               "AD-13", "CQ175", "AD-60", "remote-background.command", "Django", "tectac-communicator", "LEGACY_CALLERS = ()"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

system_commands = (ROOT / "framwork" / "tec_tac" / "system_commands.py").read_text(encoding="utf-8")
for needle in ('CALLERS = ("softwarerepository",)', 'LEGACY_CALLERS = ("communicator",)', "REGISTRANTS = CALLERS + LEGACY_CALLERS", 'RIGHT_DEPLOY = "softwarerepository.deploy"',
               "def templates_belong_to(", "def resolve(command, cleaned, caller=None)"):
    assert needle in system_commands, needle
actions = (ROOT / "framwork" / "tec_tac" / "system_actions.py").read_text(encoding="utf-8")
assert 'CAPABILITY_VERSION = "1.6.0"' in actions and "callers=_sc.REGISTRANTS," in actions

for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.36.py", "tests/system-command-callers-1.18.36.py",
             "tests/system-command-callers-integration-1.18.36.py", "framwork/tec_tac/system_actions.py", "tests/release-integrity.sh"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("docs/system-actions.md", "framwork/tec_tac/contracts.py", "framwork/tec_tac/system_commands.py", "framwork/tec_tac/system_action_confirmation.py"):
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"

# The rebuild guard matches this version (a stray 1.18.36-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.36" + "-" + r"\d")
assert label.search("x 1.18.36" + "-1") and not label.search("x 1.18.35" + "-1"), "the guard pattern checks 1.18.36"

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
print("version 1.18.36 regression: PASS")
