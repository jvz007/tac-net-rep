#!/usr/bin/env python3
"""Regression: Core 1.18.59 (the Console request proof is checked once per HTTP request) release bookkeeping and line endings."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.59", version
assert (ROOT / "VERSION").read_bytes() == version.encode("ascii"), "VERSION has no trailing newline"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.58.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.58.py").is_file() and not (ROOT / "tests" / "version-1.18.58.py").exists(), "version-1.18.58.py is retired to tests/legacy"

integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
NEW_TESTS = ("console-sessions-once-per-request-1.18.59.py", "version-1.18.59.py")
for name in NEW_TESTS:
    assert (ROOT / "tests" / name).is_file() and name in integrity, name
assert "version-1.18.58.py" not in integrity, "the retired test is not run under its old name"
for name in ("console-sessions-request-proof-1.18.56.py", "console-sessions-authenticate-account-1.18.57.py", "console-sessions-isolation-1.18.56.py",
             "console-sessions-signin-1.18.56.py", "console-sessions-revoke-1.18.56.py", "console-sessions-capability-1.18.56.py", "console-sessions-docs-1.18.56.py"):
    assert name in integrity, f"{name} still runs"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 27 November 2026."), text[:80]
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## New tests", "## What could not be run here",
                "## Johan dev02 checklist", "## Not in this release", "## Main stays held"):
    assert heading in text, heading
module_facing = text[text.index("## Module-facing change"):text.index("## Closes")]
for needle in ("core.console_session", "1.0.0", "networkprobe", "ConsoleSessionAuthentication", "proof_replayed"):
    assert needle in module_facing, needle
closes = text[text.index("## Closes"):text.index("## What changed and why")]
assert "ORDER" in closes and "Core 1.18.59" in closes and "Console request proof refused as replayed on every Tactical-routed request" in closes
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Not in this release")]
for step in ("**1.", "**2.", "**3.", "**4."):
    assert step in checklist, step
assert checklist.count("PASS") >= 4 and checklist.count("FAIL") >= 4 and checklist.count("Send back") >= 4
for topic in ("0.1.6", "3 minutes", "proof_replayed", "session_revoked"):
    assert topic in checklist, topic
couldnt = text[text.index("## What could not be run here"):text.index("## Johan dev02 checklist")]
assert "Django" in couldnt and "ruff" in couldnt and "middleware" in couldnt, "says plainly what ran and what did not"
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()
assert "R 9" not in text, "no price in these notes"

# the code the notes describe
app = ROOT / "framwork" / "tec_tac"
code = (app / "console_sessions.py").read_text(encoding="utf-8")
for needle in ("_tectac_console_auth_result", "def _authenticate_once", "def authenticate(self, request):", 'CAPABILITY_VERSION = "1.0.0"'):
    assert needle in code, needle
assert "the proof is checked once per HTTP request" in (ROOT / "docs" / "console-sessions.md").read_text(encoding="utf-8")
assert "Since 1.18.59 the proof is checked once per HTTP request" in (app / "contracts.py").read_bytes().decode("utf-8")

# line endings per file: each keeps what it had; new files are LF
crlf_files = ("framwork/tec_tac/contracts.py",)
lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/release-integrity.sh", "framwork/tec_tac/console_sessions.py",
            "docs/console-sessions.md", *[f"tests/{name}" for name in NEW_TESTS])
for name in crlf_files:
    data = (ROOT / name).read_bytes()
    assert data.count(b"\r\n") == data.count(b"\n") and data.count(b"\n") > 0, name + " must keep CRLF line endings on every line"
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"

# The rebuild guard matches this version (a stray 1.18.59-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.59" + "-" + r"\d")
assert label.search("x 1.18.59" + "-1") and not label.search("x 1.18.58" + "-1"), "the guard pattern checks 1.18.59"
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

print("version 1.18.59 regression: PASS")
