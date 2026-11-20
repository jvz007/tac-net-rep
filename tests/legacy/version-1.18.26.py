#!/usr/bin/env python3
"""Regression: Core 1.18.26 and its rebuilds (core.sandbox Patch C and the three held 1.18.25 findings) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.26", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.25.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.25.py").is_file() and not (ROOT / "tests" / "version-1.18.25.py").exists()
assert (ROOT / "tests" / "sandbox-canary-1.18.25.sh").is_file(), "the 1.18.25 script stays in tests/, as the 1.18.24 script did"
for name in ("sandbox-canary-network-1.18.25.py", "sandbox-canary-network-driver-1.18.25.py", "sandbox-canary-network-runner-1.18.25.py", "sandbox-canary-patchc-1.18.25.py",
             "sandbox-canary-patchc-driver-1.18.25.py", "sandbox-canary-patchc-runner-1.18.25.py", "sandbox-canary-script-1.18.25.py"):
    assert (ROOT / "tests" / "legacy" / name).is_file() and not (ROOT / "tests" / name).exists(), name + " is retired to tests/legacy"
for name in ("scripts/sandbox-selftest.py", "scripts/sandbox-helper.py", "scripts/sandbox-launcher.py", "scripts/sandbox-egress.py", "scripts/sandbox-canary-runner.py",
             "tests/sandbox_test_support.py", "tests/sandbox-canary-1.18.26.sh", "tests/sandbox-canary-network-1.18.26.py", "tests/sandbox-canary-patchc-1.18.26.py",
             "tests/sandbox-canary-patchc-runner-1.18.26.py", "tests/sandbox-canary-patchc-driver-1.18.26.py", "tests/sandbox-canary-network-driver-1.18.26.py",
             "tests/sandbox-canary-network-runner-1.18.26.py", "tests/sandbox-canary-script-1.18.26.py", "tests/sandbox-launcher-patchc-1.18.26.py",
             "tests/sandbox-doc-text-1.18.26.py", "tests/sandbox-selftest-split-1.18.26.py", "tests/sandbox-shebang-1.18.26.py", "tests/sandbox-registration-types-1.18.26.py",
             "tests/sandbox-syscall-filter-1.18.26.py", "tests/sandbox-own-public-address-1.18.26.py", "tests/sandbox-egress-proxy-1.18.26.py"):
    assert (ROOT / name).is_file(), name

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 20 November 2026.")
assert text.count("## Module-facing change") == 1
for heading in ("## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests", "## What could not be run",
                "## Johan dev02 checklist", "## Where the plan did not fit the code", "## Exit list"):
    assert heading in text, heading
for needle in ("SANDBOX_ENABLED", "kill_leftovers", "sandbox-selftest.py", "0700", "#!/usr/bin/python3 -I", "pattern", "io_uring_setup", "keyctl", "dns_lookup_name",
               "pb-proxy-refuse-own-public-address", "address_blocked", "OWN_LOOKUP_SECONDS", "sandbox_test_support.py", "3,446", "1,706", "Django", "systemd", "real DNS",
               "sandbox-canary-1.18.26.sh", "server_maintenance_actions", "LEFTOVER"):
    assert needle in text, needle
for row in ("pc-leftover-before-credential", "pc-returned-credential-untrusted", "pc-selftest-in-sudoers", "pc-helper-shebang-no-i", "pc-registration-type-checks",
            "pc-pattern-field", "pc-io-uring-reachable", "pc-userfaultfd-reachable", "pc-keyctl-reachable"):
    assert row in text, row
assert "cd /opt/tec-tac-src/framework && cat VERSION" in text
assert "sudo bash tests/sandbox-canary-1.18.26.sh 2>&1 | tee ~/sandbox-canary-1.18.26-$(date +%Y%m%d-%H%M).log" in text
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
for step in ("a. ", "b. ", "c. ", "d. "):
    assert step in checklist, step
assert checklist.count("PASS:") >= 4 and checklist.count("FAIL:") >= 4, "every step has a PASS and a FAIL line"
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()
for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.26.py", "scripts/sandbox-selftest.py", "scripts/sandbox-helper.py",
             "scripts/sandbox-launcher.py", "scripts/sandbox-egress.py", "scripts/sandbox-canary-runner.py", "install.sh", "uninstall.sh", "docs/sandbox-capability.md",
             "tests/sandbox-canary-1.18.26.sh", "tests/sandbox-canary-network-1.18.26.py", "tests/sandbox-canary-patchc-1.18.26.py", "tests/sandbox-canary-script-1.18.26.py",
             "framwork/tec_tac/registry.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_bytes()
assert b"\r\n" in contracts and contracts.count(b"\n") == contracts.count(b"\r\n"), "contracts.py keeps its CRLF line endings"
helper = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
assert "SANDBOX_ENABLED = False" in helper, "the kill switch stays off"
install = (ROOT / "install.sh").read_text(encoding="utf-8")
assert "RuntimeDirectoryPreserve=yes" in install, "install.sh keeps RuntimeDirectoryPreserve=yes"
print("version 1.18.26 regression: PASS")
