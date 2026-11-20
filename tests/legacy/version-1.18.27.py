#!/usr/bin/env python3
"""Regression: Core 1.18.27 and its rebuilds (core.sandbox switched on, AD-65, and the two held 1.18.26 findings) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.27", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.26.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.26.py").is_file() and not (ROOT / "tests" / "version-1.18.26.py").exists()
assert (ROOT / "tests" / "sandbox-canary-1.18.26.sh").is_file(), "the 1.18.26 script stays in tests/, as the 1.18.25 script did"
for name in ("sandbox-contract-1.17.116.py", "sandbox-launch-1.17.118.py", "sandbox-django-launch-1.17.118.py", "sandbox-canary-1.17.118.py", "sandbox-private-network-1.18.24.py",
             "sandbox-run-private-1.18.15.py", "sandbox-selftest-split-1.18.26.py", "sandbox-own-public-address-1.18.26.py", "sandbox-canary-network-1.18.26.py",
             "sandbox-canary-network-driver-1.18.26.py", "sandbox-canary-patchc-1.18.26.py", "sandbox-canary-patchc-driver-1.18.26.py", "sandbox-canary-script-1.18.26.py", "sandbox-doc-text-1.18.25.py", "sandbox-doc-text-1.18.26.py",
             "sandbox-egress-own-names-1.18.25.py", "sandbox-file-view-1.18.8.py", "sandbox-helper-register-1.17.116.py", "sandbox-installer-1.17.116.py", "sandbox-selftest-1.17.116.py",
             "sandbox-unit-builder-1.17.118.py", "sandbox-skeleton-run-1.18.13.py"):
    assert (ROOT / "tests" / "legacy" / name).is_file() and not (ROOT / "tests" / name).exists(), name + " is retired to tests/legacy"
for name in ("scripts/sandbox-selftest.py", "scripts/sandbox-helper.py", "scripts/sandbox-launcher.py", "scripts/sandbox-egress.py", "scripts/sandbox-canary-runner.py",
             "tests/sandbox_test_support.py", "tests/sandbox-canary-1.18.27.sh", "tests/sandbox-canary-network-1.18.27.py", "tests/sandbox-canary-patchc-1.18.27.py",
             "tests/sandbox-canary-network-driver-1.18.27.py", "tests/sandbox-canary-patchc-driver-1.18.27.py", "tests/sandbox-canary-script-1.18.27.py",
             "tests/sandbox-contract-1.18.27.py", "tests/sandbox-launch-1.18.27.py", "tests/sandbox-django-launch-1.18.27.py", "tests/sandbox-canary-1.18.27.py",
             "tests/sandbox-private-network-1.18.27.py", "tests/sandbox-run-private-1.18.27.py", "tests/sandbox-selftest-split-1.18.27.py",
             "tests/sandbox-own-public-address-1.18.27.py", "tests/sandbox-own-name-dns-1.18.27.py", "tests/sandbox-switch-on-1.18.27.py", "tests/sandbox-doc-text-1.18.27.py",
             "tests/sandbox-egress-own-names-1.18.27.py", "tests/sandbox-file-view-1.18.27.py", "tests/sandbox-helper-register-1.18.27.py", "tests/sandbox-installer-1.18.27.py",
             "tests/sandbox-selftest-1.18.27.py", "tests/sandbox-unit-builder-1.18.27.py", "tests/sandbox-skeleton-run-1.18.27.py"):
    assert (ROOT / name).is_file(), name

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 20 November 2026.")
assert text.count("## Module-facing change") == 1
for heading in ("## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests", "## What could not be run",
                "## Johan dev02 checklist", "## Where the plan did not fit the code", "## Exit list", "## Main stays held", "## Proof from 1.18.26"):
    assert heading in text, heading
for needle in ("SANDBOX_ENABLED", "sandbox_not_ready", "active", "1.1.0", "allowed_hosts", "requires framework >=1.18.27" if False else "framework >=1.18.27",
               "146 OK", "p95 403 ms", "AD-65", "main", "cancel", "AAAA", "status.json", "sha256", "trap", "sandbox-canary-1.18.27.sh", "Django", "systemd"):
    assert needle in text, needle
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Where the plan did not fit the code")]
for step in ("a. ", "b. "):
    assert step in checklist, step
assert checklist.count("PASS:") >= 2 and checklist.count("FAIL:") >= 2, "every step has a PASS and a FAIL line"
assert "cd /opt/tec-tac-src/framework && cat VERSION" in text
assert "SANDBOX_ENABLED = True`" not in text.split("## Fixed after review")[0].replace("needs `SANDBOX_ENABLED = True`", "").replace("requires `SANDBOX_ENABLED = True`", ""), "the notes never say the shipped constant is True"
assert "to be sure the switch is on" not in text, "the notes do not claim the switch is on"
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()
for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.27.py", "scripts/sandbox-selftest.py", "scripts/sandbox-helper.py",
             "scripts/sandbox-launcher.py", "scripts/sandbox-egress.py", "scripts/sandbox-canary-runner.py", "install.sh", "uninstall.sh", "docs/sandbox-capability.md",
             "tests/sandbox-canary-1.18.27.sh", "tests/sandbox-canary-network-1.18.27.py", "tests/sandbox-canary-patchc-1.18.27.py", "framwork/tec_tac/sandbox.py",
             "framwork/tec_tac/sandbox_views.py", "framwork/tec_tac/registry.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_bytes()
assert b"\r\n" in contracts and contracts.count(b"\n") == contracts.count(b"\r\n"), "contracts.py keeps its CRLF line endings"
helper = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
sandbox = (ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
assert "SANDBOX_ENABLED = False" in helper and "SANDBOX_ENABLED = False" in sandbox and "SANDBOX_ENABLED = True" not in helper + sandbox, "the kill switch is off (AD-65 condition not met)"
install = (ROOT / "install.sh").read_text(encoding="utf-8")
assert "RuntimeDirectoryPreserve=yes" in install, "install.sh keeps RuntimeDirectoryPreserve=yes"
print("version 1.18.27 regression: PASS")
