#!/usr/bin/env python3
"""Regression: Core 1.18.29 (re-verify runners after a runtime action, canary after install or update, contract text) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.29", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.28.md").is_file() and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.27.md").is_file()
for name in ("version-1.18.28.py", "sandbox-installer-1.18.28.py", "sandbox-contract-1.18.28.py", "sandbox-doc-text-1.18.28.py"):
    assert (ROOT / "tests" / "legacy" / name).is_file() and not (ROOT / "tests" / name).exists(), name + " is retired to tests/legacy"
for name in ("sandbox-installer-1.18.29.py", "sandbox-contract-1.18.29.py", "sandbox-doc-text-1.18.29.py", "sandbox-reverify-1.18.29.py",
             "server-maintenance-sandbox-reverify-1.18.29.py", "sandbox-install-canary-1.18.29.sh", "sandbox-canary-1.18.28.sh"):
    assert (ROOT / "tests" / name).is_file(), name

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 20 November 2026.")
for heading in ("## Module-facing changes", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Where the plan did not fit the code")]
assert checklist.count("PASS:") >= 4 and checklist.count("FAIL:") >= 4, "every step has a PASS and a FAIL line"
for needle in ("Sandbox: active", "canary_ok", "Repair runtime", "Django", "systemd", "core.sandbox stays 1.1.0".replace("core.sandbox", "`core.sandbox`")):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.29.py", "install.sh", "uninstall.sh", "scripts/sandbox-helper.py",
             "scripts/server-maintenance-helper.py", "docs/sandbox-capability.md", "docs/server-maintenance-capability.md", "docs/system-update-logs.md",
             "tests/sandbox-install-canary-1.18.29.sh", "framwork/tec_tac/sandbox.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_bytes()
assert b"\r\n" in contracts and contracts.count(b"\n") == contracts.count(b"\r\n"), "contracts.py keeps its CRLF line endings"
helper = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
sandbox = (ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
assert "\nSANDBOX_ENABLED = True\n" in helper and "\nSANDBOX_ENABLED = True\n" in sandbox, "the kill switch stays on"
assert "SANDBOX_ENABLED = False" not in helper + sandbox, "no constant says False"

# No rebuild label (this version, a dash and a digit) in any file except VERSION, tec_tac_package.json and the release notes.
# The pattern is built from pieces so this file does not contain the label itself.
label = re.compile("1" + r"\.18\.29" + "-" + r"\d")
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
print("version 1.18.29 regression: PASS")
