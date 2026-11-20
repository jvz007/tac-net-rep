#!/usr/bin/env python3
"""Regression: Core 1.18.28 and its rebuilds (core.sandbox kill switch on, AD-65 amendment, Johan, 20 November 2026) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.28", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.27.md").is_file() and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.26.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.27.py").is_file() and not (ROOT / "tests" / "version-1.18.27.py").exists()
assert (ROOT / "tests" / "sandbox-canary-1.18.27.sh").is_file(), "the 1.18.27 script stays in tests/, as the 1.18.26 script did"
for name in ("sandbox-switch-on-1.18.27.py", "sandbox-contract-1.18.27.py", "sandbox-doc-text-1.18.27.py", "sandbox-installer-1.18.27.py", "sandbox-verify-code-1.18.27-2.py",
             "sandbox-canary-1.18.27.py", "sandbox-canary-script-1.18.27.py", "sandbox-canary-network-1.18.27.py", "sandbox-canary-network-driver-1.18.27.py",
             "sandbox-canary-patchc-1.18.27.py", "sandbox-canary-patchc-driver-1.18.27.py", "sandbox-django-launch-1.18.27.py", "sandbox-helper-register-1.18.27.py",
             "sandbox-launch-1.18.27.py"):
    assert (ROOT / "tests" / "legacy" / name).is_file() and not (ROOT / "tests" / name).exists(), name + " is retired to tests/legacy"
for name in ("scripts/sandbox-selftest.py", "scripts/sandbox-helper.py", "scripts/sandbox-launcher.py", "scripts/sandbox-egress.py", "scripts/sandbox-canary-runner.py",
             "tests/sandbox_test_support.py", "tests/sandbox-canary-1.18.28.sh", "tests/sandbox-canary-network-1.18.28.py", "tests/sandbox-canary-patchc-1.18.28.py",
             "tests/sandbox-canary-network-driver-1.18.28.py", "tests/sandbox-canary-patchc-driver-1.18.28.py", "tests/sandbox-canary-script-1.18.28.py",
             "tests/sandbox-contract-1.18.28.py", "tests/sandbox-launch-1.18.28.py", "tests/sandbox-django-launch-1.18.28.py", "tests/sandbox-canary-1.18.28.py",
             "tests/sandbox-helper-register-1.18.28.py", "tests/sandbox-switch-on-1.18.28.py", "tests/sandbox-doc-text-1.18.28.py", "tests/sandbox-installer-1.18.28.py",
             "tests/sandbox-verify-code-1.18.28.py"):
    assert (ROOT / name).is_file(), name

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 20 November 2026.")
assert text.count("## Module-facing change") == 1
for heading in ("## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests", "## What could not be run",
                "## Johan dev02 checklist", "## Where the plan did not fit the code", "## Exit list", "## Main stays held"):
    assert heading in text, heading
for needle in ("SANDBOX_ENABLED", "sandbox_not_ready", "sandbox_disabled", "active", "1.1.0", "AD-65", "main", "cancel", "ubuntu 24.04 as the dev box", "26.04",
               "sandbox-canary-1.18.28.sh", "Django", "systemd", "not_owner", "ai"):
    assert needle in text, needle
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Where the plan did not fit the code")]
for step in ("a. ", "b. ", "c. "):
    assert step in checklist, step
assert checklist.count("PASS:") >= 3 and checklist.count("FAIL:") >= 3, "every step has a PASS and a FAIL line"
assert "cd /opt/tec-tac-src/framework && cat VERSION" in text
assert "ALL CANARY STEPS PASSED" in checklist and "0 ATTACK SUCCEEDED" in checklist and "0 NOT RUN" in checklist
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()
for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.28.py", "scripts/sandbox-selftest.py", "scripts/sandbox-helper.py",
             "scripts/sandbox-launcher.py", "scripts/sandbox-egress.py", "scripts/sandbox-canary-runner.py", "install.sh", "uninstall.sh", "docs/sandbox-capability.md",
             "tests/sandbox-canary-1.18.28.sh", "tests/sandbox-canary-network-1.18.28.py", "tests/sandbox-canary-patchc-1.18.28.py", "framwork/tec_tac/sandbox.py",
             "framwork/tec_tac/sandbox_views.py", "framwork/tec_tac/registry.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_bytes()
assert b"\r\n" in contracts and contracts.count(b"\n") == contracts.count(b"\r\n"), "contracts.py keeps its CRLF line endings"
helper = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
sandbox = (ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
assert "\nSANDBOX_ENABLED = True\n" in helper and "\nSANDBOX_ENABLED = True\n" in sandbox, "the kill switch is on in 1.18.28 (AD-65 amendment)"
assert "SANDBOX_ENABLED = False" not in helper + sandbox, "no constant says False"
install = (ROOT / "install.sh").read_text(encoding="utf-8")
assert "RuntimeDirectoryPreserve=yes" in install, "install.sh keeps RuntimeDirectoryPreserve=yes"

# No rebuild label (1.18.28, a dash and a digit) in any file except VERSION, tec_tac_package.json and the release notes: the promotion check stops on it.
# The pattern is built from pieces so this file does not contain the label itself.
import re
import subprocess

label = re.compile("1" + r"\.18\.28" + "-" + r"\d")
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
print("version 1.18.28 regression: PASS")
