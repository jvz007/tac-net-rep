#!/usr/bin/env python3
"""Regression: Core 1.18.57 (Engineer Console enrolment with PKCE, and the account check of ConsoleSessionAuthentication) release bookkeeping and line endings."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.57", version
assert (ROOT / "VERSION").read_bytes() == version.encode("ascii"), "VERSION has no trailing newline"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.56.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.56.py").is_file() and not (ROOT / "tests" / "version-1.18.56.py").exists(), "version-1.18.56.py is retired to tests/legacy"

integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
NEW_TESTS = ("console-enrolment-pkce-1.18.57.py", "console-sessions-authenticate-account-1.18.57.py", "console-sessions-example-client-1.18.57.py", "version-1.18.57.py")
for name in NEW_TESTS:
    assert (ROOT / "tests" / name).is_file() and name in integrity, name
assert "version-1.18.56.py" not in integrity and "console-sessions-example-client-1.18.56.py" not in integrity, "the retired and renamed tests are not run under their old names"
for name in ("console-certificates-enrol-1.18.52.py", "console-certificates-routes-1.18.52.py", "console-certificates-apikey-1.18.53.py", "console-certificates-actor-1.18.55.py",
             "console-sessions-request-proof-1.18.56.py", "console-sessions-revoke-1.18.56.py", "console-sessions-docs-1.18.56.py", "console-sessions-migration-1.18.56.py"):
    assert name in integrity, f"{name} still runs"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 26 November 2026."), text[:80]
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## New tests", "## What could not be run here",
                "## Johan dev02 checklist", "## Not in this release", "## Main stays held"):
    assert heading in text, heading
module_facing = text[text.index("## Module-facing change"):text.index("## Closes")]
for needle in ("None", "core.console_session", "1.0.0", "core.probe_transport", "1.3.0", "networkprobe", "code_challenge", "code_verifier", "ConsoleSessionAuthentication"):
    assert needle in module_facing, needle
closes = text[text.index("## Closes"):text.index("## What changed and why")]
assert "Core 1.18.57 = C2" in closes and "held low" in closes.lower()
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Not in this release")]
for step in ("**1.", "**2.", "**3.", "**4.", "**5."):
    assert step in checklist, step
assert checklist.count("PASS") >= 5 and checklist.count("FAIL") >= 5 and checklist.count("Send back") >= 5
for topic in ("pkce", "verifier_invalid", "code_invalid", "account_inactive", "deactivate"):
    assert topic.lower() in checklist.lower(), topic
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()
assert "R 9" not in text, "no price in these notes"

# the code the notes describe
app = ROOT / "framwork" / "tec_tac"
certs = (app / "console_certificates.py").read_text(encoding="utf-8")
for needle in ("ENROL_OPTIONAL_KEYS", "CHALLENGE_PATTERN", "verifier_invalid", "hmac.compare_digest", "code_challenge"):
    assert needle in certs, needle
assert 'code_challenge = models.CharField(max_length=43, blank=True, default="")' in (app / "models.py").read_bytes().decode("utf-8")
migration = (app / "migrations" / "0051_console_enrolment_pkce.py").read_text(encoding="utf-8")
assert '("tec_tac", "0050_console_sessions")' in migration
assert "cc.account_problem(user)" in (app / "console_sessions.py").read_text(encoding="utf-8")
assert (ROOT / "docs" / "console-certificates.md").is_file() and "def cmd_pkce" in (ROOT / "examples" / "console-session-client.py").read_text(encoding="utf-8")

# line endings per file: each keeps what it had; new files are LF
crlf_files = ("framwork/tec_tac/models.py", "framwork/tec_tac/audit.py", "framwork/tec_tac/contracts.py", "framwork/tec_tac/apps.py", "framwork/tec_tac/rbac.py", "docs/capabilities.md")
lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "install.sh", "tests/release-integrity.sh", "tests/version-1.18.57.py",
            "framwork/tec_tac/console_certificates.py", "framwork/tec_tac/console_certificate_views.py", "framwork/tec_tac/console_sessions.py",
            "framwork/tec_tac/migrations/0050_console_sessions.py", "framwork/tec_tac/migrations/0051_console_enrolment_pkce.py", "docs/console-certificates.md",
            "docs/console-sessions.md", "examples/console-session-client.py", "tests/console_sessions_harness.py", "tests/console_certificates_harness.py",
            *[f"tests/{name}" for name in NEW_TESTS])
for name in crlf_files:
    data = (ROOT / name).read_bytes()
    assert data.count(b"\r\n") == data.count(b"\n") and data.count(b"\n") > 0, name + " must keep CRLF line endings on every line"
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"

# The rebuild guard matches this version (a stray 1.18.57-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.57" + "-" + r"\d")
assert label.search("x 1.18.57" + "-1") and not label.search("x 1.18.56" + "-1"), "the guard pattern checks 1.18.57"
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

print("version 1.18.57 regression: PASS")
