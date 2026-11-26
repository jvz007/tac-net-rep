#!/usr/bin/env python3
"""Regression: Core 1.18.56 (Engineer Console sessions, C1) release bookkeeping and line endings."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.56", version
assert (ROOT / "VERSION").read_bytes() == version.encode("ascii"), "VERSION has no trailing newline"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.55.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.55.py").is_file() and not (ROOT / "tests" / "version-1.18.55.py").exists(), "version-1.18.55.py is retired to tests/legacy"

integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
NEW_TESTS = ("console-sessions-migration-1.18.56.py", "console-sessions-signin-1.18.56.py", "console-sessions-request-proof-1.18.56.py", "console-sessions-isolation-1.18.56.py",
             "console-sessions-revoke-1.18.56.py", "probe-tunnel-console-serial-1.18.56.py", "probe-tunnel-end-lows-1.18.56.py", "console-sessions-capability-1.18.56.py",
             "console-sessions-docs-1.18.56.py", "console-sessions-example-client-1.18.56.py", "version-1.18.56.py")
for name in NEW_TESTS:
    assert (ROOT / "tests" / name).is_file() and name in integrity, name
assert (ROOT / "tests" / "console_sessions_harness.py").is_file()
assert "version-1.18.55.py" not in integrity, "the retired version test is not run"
for name in ("console-certificates-connect-1.18.53.py", "probe-tunnel-certificates-1.18.53.py", "probe-tunnel-end-queue-1.18.55.py", "access-events-1.18.50.py", "access-events-1.18.51.py"):
    assert name in integrity, f"{name} still runs"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 26 November 2026."), text[:80]
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## New tests", "## What could not be run here",
                "## Johan dev02 checklist", "## Not in this release", "## Main stays held"):
    assert heading in text, heading
module_facing = text[text.index("## Module-facing change"):text.index("## Closes")]
for needle in ("core.console_session", "1.0.0", "console", "access_events.mark_changed", "certificate_engineer_mismatch", "core.probe_transport", "networkprobe"):
    assert needle in module_facing, needle
closes = text[text.index("## Closes"):text.index("## What changed and why")]
assert "Core 1.18.56 = C1 Console sessions" in closes and closes.count("Held Low") == 2
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Not in this release")]
for step in ("**A.", "**B.", "**C.", "**D.", "**E.", "**F.", "**G.", "**H.", "**I.", "**J.", "**K.", "**L.", "**M."):
    assert step in checklist, step
assert checklist.count("PASS") >= 13 and checklist.count("FAIL") >= 13 and checklist.count("Send back") >= 13
for topic in ("authenticator code", "single sign-on", "replayed", "without a proof", "normal route", "idle limit", "revoked certificate", "Replacing the CA", "deactivated", "administrator ends",
              "Sign-out", "audit rows"):
    assert topic.lower() in checklist.lower(), topic
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()
assert "R 9" not in text, "no price in these notes"

# the code the notes describe
app = ROOT / "framwork" / "tec_tac"
sessions = (app / "console_sessions.py").read_text(encoding="utf-8")
for needle in ("class ConsoleSessionAuthentication", "class ConsoleSessionAuthenticated", "def console_info", 'CONSOLE_MIN_VERSION = "0.1.1"', 'CAPABILITY_VERSION = "1.0.0"', "def redeem", "def authorise"):
    assert needle in sessions, needle
migration = (app / "migrations" / "0050_console_sessions.py").read_text(encoding="utf-8")
assert '("tec_tac", "0049_console_certificates")' in migration
assert (ROOT / "docs" / "console-sessions.md").is_file() and (ROOT / "examples" / "console-session-client.py").is_file()
assert "_certificate_row(" in (app / "console_certificates.py").read_text(encoding="utf-8")
assert "def console_session_ended" in (app / "probe_tunnel.py").read_text(encoding="utf-8")

# line endings per file: each keeps what it had; new files are LF
crlf_files = ("framwork/tec_tac/models.py", "framwork/tec_tac/audit.py", "framwork/tec_tac/contracts.py", "framwork/tec_tac/apps.py", "framwork/tec_tac/rbac.py", "docs/capabilities.md")
lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "install.sh", "tests/release-integrity.sh", "tests/version-1.18.56.py",
            "framwork/tec_tac/session_security.py", "framwork/tec_tac/console_certificates.py", "framwork/tec_tac/probe_tunnel.py", "framwork/tec_tac/probe_transport.py",
            "framwork/tec_tac/access_events.py", "framwork/tec_tac/throttles.py", "framwork/tec_tac/urls.py", "framwork/tec_tac/openapi.py", "framwork/tec_tac/tasks.py",
            "framwork/tec_tac/console_certificate_views.py", "framwork/tec_tac/console_sessions.py", "framwork/tec_tac/console_session_views.py",
            "framwork/tec_tac/migrations/0050_console_sessions.py", "docs/console-certificates.md", "docs/probe-transport.md", "docs/console-sessions.md",
            "examples/console-session-client.py", "tests/console_sessions_harness.py", *[f"tests/{name}" for name in NEW_TESTS])
for name in crlf_files:
    data = (ROOT / name).read_bytes()
    assert data.count(b"\r\n") == data.count(b"\n") and data.count(b"\n") > 0, name + " must keep CRLF line endings on every line"
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"

# The rebuild guard matches this version (a stray 1.18.56-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.56" + "-" + r"\d")
assert label.search("x 1.18.56" + "-1") and not label.search("x 1.18.55" + "-1"), "the guard pattern checks 1.18.56"
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

print("version 1.18.56 regression: PASS")
