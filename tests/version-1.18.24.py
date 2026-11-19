#!/usr/bin/env python3
"""Regression: Core 1.18.24 and its rebuilds (core.sandbox Patch B: the network wall and the egress door) release bookkeeping."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.24", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.23.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.23.py").is_file() and not (ROOT / "tests" / "version-1.18.23.py").exists()
for name in ("tests/sandbox-canary-1.18.23.sh", "tests/sandbox-canary-network-1.18.23.py", "tests/sandbox-canary-network-driver-1.18.23.py",
             "tests/sandbox-canary-script-1.18.23.py"):
    assert (ROOT / name).is_file(), name + " stays in tests/"
for name in ("sandbox-address-numeric-1.17.120.py", "sandbox-resolv-bind-1.17.123.py", "sandbox-unix-1.17.124.py", "sandbox-canary-network-runner-1.18.23.py",
             "sandbox-canary-script-1.17.123.py", "sandbox-canary-script-1.17.124.py", "sandbox-canary-script-1.18.8.py"):
    assert (ROOT / "tests" / "legacy" / name).is_file() and not (ROOT / "tests" / name).exists(), name + " is retired to tests/legacy"
for name in ("scripts/sandbox-egress.py", "tests/sandbox-canary-1.18.24.sh", "tests/sandbox-canary-network-1.18.24.py"):
    assert (ROOT / name).is_file(), name

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 19 November 2026.")
assert text.count("## Module-facing change") == 1
for heading in ("### `allowed_hosts` is allowed again (additive)", "### Reserved proxy environment names", "### What a run's network is now",
                "### `AF_UNIX` is allowed for the egress door"):
    assert heading in text, heading
for needle in ("What could not be run", "Johan dev02 checklist", "What changed and why", "FAIL", "Assumptions", "What is not in this release", "SANDBOX_ENABLED",
               "Retired checks", "The Patch B exit list", "sandbox-canary-1.18.24.sh", "PrivateNetwork=yes", "selftest_ms"):
    assert needle in text, needle
for row in ("pb-public-tcp-443-1-1-1-1", "pb-public-tcp-80-1-1-1-1", "pb-public-tcp-443-9-9-9-9", "pb-direct-allowed-host-443", "pb-dns-resolv-conf-listed",
            "pb-dns-getaddrinfo", "pb-dns-listed-server-answers", "pb-dns-public-9-9-9-9-answers", "pb-proc-net-tcp", "pb-proc-net-udp", "pb-interfaces-beyond-lo",
            "pb-default-route", "pb-proxy-allowed-443", "pb-proxy-refuse-host", "pb-proxy-refuse-ip-literal", "pb-proxy-refuse-private", "pb-proxy-refuse-own-address",
            "pb-proxy-refuse-port-80", "pb-proxy-refuse-port-22", "pb-listener-from-host", "pb-ping-socket-echo"):
    assert row in text, row
checklist = text[text.index("## Johan dev02 checklist"):]
for step in ("a. ", "b. ", "c. ", "d. ", "e. "):
    assert step in checklist, step
assert "cd /opt/tec-tac-src/framework && cat VERSION && sudo bash tests/sandbox-canary-1.18.24.sh 2>&1 | tee ~/sandbox-canary-1.18.24-$(date +%Y%m%d-%H%M).log" in checklist
assert checklist.count("PASS:") >= 5 and checklist.count("FAIL:") >= 5, "every step has a PASS and a FAIL line"
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()
for name in ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.24.py", "scripts/sandbox-egress.py", "scripts/sandbox-helper.py",
             "scripts/sandbox-launcher.py", "scripts/sandbox-canary-runner.py", "install.sh", "uninstall.sh", "tests/sandbox-canary-1.18.24.sh",
             "tests/sandbox-canary-network-1.18.24.py", "tests/sandbox-canary-script-1.18.24.py"):
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
helper = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
assert "SANDBOX_ENABLED = False" in helper, "the kill switch stays off"
print("version 1.18.24 regression: PASS")
