#!/usr/bin/env python3
"""Regression: Core 1.18.55 (Console enrolment audit actor, background session end, celery process check) release bookkeeping and line endings."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.55", version
assert (ROOT / "VERSION").read_bytes() == version.encode("ascii"), "VERSION has no trailing newline"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.54.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.54.py").is_file() and not (ROOT / "tests" / "version-1.18.54.py").exists(), "version-1.18.54.py is retired to tests/legacy"

integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in ("console-certificates-actor-1.18.55.py", "probe-tunnel-end-queue-1.18.55.py", "install-service-key-group-1.18.55.sh",
             "diagnostics-secret-key-fallback-1.18.55.py", "version-1.18.55.py"):
    assert (ROOT / "tests" / name).is_file() and name in integrity, name
assert "version-1.18.54.py" not in integrity, "the retired version test is not run"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 26 November 2026."), text[:80]
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## New tests", "## What could not be run here",
                "## Johan dev02 checklist", "## Not in this release", "## Main stays held"):
    assert heading in text, heading
module_facing = text[text.index("## Module-facing change"):text.index("## Closes")]
assert "None." in module_facing and "Celery task" in module_facing and "enrolment rows" in module_facing
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Not in this release")]
for step in ("**A.", "**B.", "**C.", "**D.", "**E.", "**F."):
    assert step in checklist, step
assert checklist.count("PASS") >= 6 and checklist.count("FAIL") >= 6
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

# the code the notes describe
cert = (ROOT / "framwork" / "tec_tac" / "console_certificates.py").read_text(encoding="utf-8")
assert "def engineer_actor(user)" in cert and 'via="enrolment_code"' in cert
tasks = (ROOT / "framwork" / "tec_tac" / "tasks.py").read_text(encoding="utf-8")
assert '"tec_tac.end_console_certificate_sessions"' in tasks
install = (ROOT / "install.sh").read_text(encoding="utf-8")
assert "service_group_check()" in install and install.count('service_group_check "${key_svc}"') == 1

# line endings per file: each keeps what it had
lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "install.sh", "uninstall.sh", "tests/release-integrity.sh",
            "tests/install-service-key-group-1.18.54.sh", "tests/install-service-key-group-1.18.55.sh", "tests/version-1.18.55.py",
            "tests/diagnostics-secret-key-fallback-1.18.55.py", "tests/console-certificates-actor-1.18.55.py", "tests/probe-tunnel-end-queue-1.18.55.py",
            "framwork/tec_tac/console_certificates.py", "framwork/tec_tac/probe_tunnel.py", "framwork/tec_tac/tasks.py",
            "framwork/tec_tac/diagnostics.py", "framwork/tec_tac/diagnostics_install.py")
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("docs/console-certificates.md", "docs/probe-transport.md"):
    data = (ROOT / name).read_bytes()
    assert data.count(b"\n") == data.count(b"\r\n") or b"\r" not in data, name + " must not mix line endings"

# The rebuild guard matches this version (a stray 1.18.55-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.55" + "-" + r"\d")
assert label.search("x 1.18.55" + "-1") and not label.search("x 1.18.54" + "-1"), "the guard pattern checks 1.18.55"
names = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"], capture_output=True, check=False).stdout.decode("utf-8", "replace").split("\0")
if not any(names):
    names = [str(p.relative_to(ROOT)).replace("\\", "/") for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
for name in names:
    if not name or name in ("VERSION", "tec_tac_package.json") or name.startswith(("RELEASE_NOTES_", "tests/legacy/", "docs/releases/")):
        continue
    path = ROOT / name
    if not path.is_file() or path.suffix in (".png", ".zip", ".sig", ".ico", ".gz", ".pyc"):
        continue
    assert not label.search(path.read_bytes().decode("utf-8", "replace")), name + " carries a rebuild label"

print("version 1.18.55 regression: PASS")
