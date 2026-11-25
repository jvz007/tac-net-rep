#!/usr/bin/env python3
"""Regression: Core 1.18.47 (core.probe_transport 1.1.0, C2 of the probe channel plan: the tunnel) release bookkeeping."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.47", version
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for earlier in ("1.18.46", "1.18.45", "1.18.44", "1.18.43", "1.18.42", "1.18.41", "1.18.40", "1.18.39", "1.18.38"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{earlier}.md").is_file(), earlier
assert (ROOT / "tests" / "legacy" / "version-1.18.46.py").is_file() and not (ROOT / "tests" / "version-1.18.46.py").exists(), "version-1.18.46.py is retired to tests/legacy"
new_tests = ("probe-tunnel-ticket-1.18.47.py", "probe-tunnel-relay-1.18.47.py", "probe-tunnel-end-1.18.47.py", "probe-tunnel-isolation-1.18.47.py",
             "probe-transport-hardening-1.18.47.py", "probe-transport-contract-1.18.47.py", "probe-transport-docs-1.18.47.py", "version-1.18.47.py")
kept_tests = ("probe-transport-identity-1.18.46.py", "probe-transport-consumer-1.18.46.py", "probe-transport-isolation-1.18.46.py")
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in (*new_tests, *kept_tests, "probe_transport_harness.py"):
    assert (ROOT / "tests" / name).is_file(), name
for name in (*new_tests, *kept_tests):
    assert name in integrity, f"release integrity runs {name}"
for retired in ("version-1.18.46.py", "probe-transport-contract-1.18.46.py", "probe-transport-docs-1.18.46.py"):
    assert retired not in integrity and not (ROOT / "tests" / retired).exists(), f"the retired test {retired} is not run"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 25 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## Retired or changed checks", "## New tests",
                "## What could not be run here", "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 7 and checklist.count("PASS:") == checklist.count("FAIL:"), "every step has a PASS and a FAIL line"
module_facing = text[text.index("## Module-facing change"):text.index("## Closes")]
for needle in ("core.probe_transport", "1.1.0", "pure addition", "networkprobe", "M2", "issue_tunnel_ticket", "end_tunnels_for_probe", "tunnel.closed", "1.0.0 operations only"):
    assert needle in module_facing, needle
for needle in ("AD-54", "wrong_scheme", "4503", "1013", "docs/probe-transport.md", "Plan corrections found in the code", "protocol_error", "Django", "10 MiB", "No contract file exists"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.47.py", "tests/release-integrity.sh", "tests/probe_transport_harness.py",
            *(f"tests/{n}" for n in new_tests), *(f"tests/{n}" for n in kept_tests), "framwork/tec_tac/probe_transport.py", "framwork/tec_tac/probe_transport_consumer.py",
            "framwork/tec_tac/probe_tunnel.py", "framwork/tec_tac/probe_tunnel_consumer.py", "docs/probe-transport.md")
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("framwork/tec_tac/contracts.py", "framwork/tec_tac/apps.py", "framwork/tec_tac/audit.py", "docs/capabilities.md"):
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"

# The rebuild guard matches this version (a stray 1.18.47-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.47" + "-" + r"\d")
assert label.search("x 1.18.47" + "-1") and not label.search("x 1.18.46" + "-1"), "the guard pattern checks 1.18.47"

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
print("version 1.18.47 regression: PASS")
