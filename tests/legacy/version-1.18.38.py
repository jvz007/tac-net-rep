#!/usr/bin/env python3
"""Regression: Core 1.18.38 (bulk upgrade release selection, log redaction, OpenAPI group, counter lifetime) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.38", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for earlier in ("1.18.37", "1.18.36", "1.18.35"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{earlier}.md").is_file(), earlier
assert (ROOT / "tests" / "legacy" / "version-1.18.37.py").is_file() and not (ROOT / "tests" / "version-1.18.37.py").exists(), "version-1.18.37.py is retired to tests/legacy"
for name in ("agent-downloads-1.18.37.py", "agent-downloads-fixes-1.18.38.py", "online-upgrade-release-1.18.38.py", "version-1.18.38.py"):
    assert (ROOT / "tests" / name).is_file(), name
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in ("online-upgrade-release-1.18.38.py", "agent-downloads-fixes-1.18.38.py", "version-1.18.38.py", "agent-downloads-1.18.37.py", "online-upgrade-run-1.18.35.py"):
    assert name in integrity, f"release integrity runs {name}"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 21 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 5 and checklist.count("FAIL:") >= 5, "every step has a PASS and a FAIL line"
for needle in ("select_release", "upgrade_selector", "upgrade_release", "_recheck_upgrade", "log_redaction.py", "<redacted>", "Agent Downloads", "cache.touch",
               "sentinelone", "Module-facing change", "None to the call shape", "Django is not installed", "Retry-After", "not_in_catalogue_cache"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.38.py", "tests/online-upgrade-release-1.18.38.py", "tests/agent-downloads-fixes-1.18.38.py",
             "framwork/tec_tac/agent_downloads.py", "framwork/tec_tac/log_redaction.py", "framwork/tec_tac/module_install_plan.py", "framwork/tec_tac/module_install_run.py",
             "framwork/tec_tac/openapi.py", "tests/release-integrity.sh", "docs/agent-downloads.md"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("framwork/tec_tac/apps.py", "framwork/tec_tac/module_repository.py", "framwork/tec_tac/contracts.py", "docs/module-repositories.md"):
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"

# The rebuild guard matches this version (a stray 1.18.38-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.38" + "-" + r"\d")
assert label.search("x 1.18.38" + "-1") and not label.search("x 1.18.36" + "-1"), "the guard pattern checks 1.18.38"

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
print("version 1.18.38 regression: PASS")
