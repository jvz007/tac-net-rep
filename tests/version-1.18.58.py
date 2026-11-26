#!/usr/bin/env python3
"""Regression: Core 1.18.58 (the Tec-Tac web address for the Engineer Console, and the tunnel permission list) release bookkeeping and line endings."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.58", version
assert (ROOT / "VERSION").read_bytes() == version.encode("ascii"), "VERSION has no trailing newline"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.57.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.57.py").is_file() and not (ROOT / "tests" / "version-1.18.57.py").exists(), "version-1.18.57.py is retired to tests/legacy"

integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
NEW_TESTS = ("probe-tunnel-permissions-1.18.58.py", "console-ui-url-setting-1.18.58.py", "console-ui-url-1.18.58.py", "version-1.18.58.py")
for name in NEW_TESTS:
    assert (ROOT / "tests" / name).is_file() and name in integrity, name
assert "version-1.18.57.py" not in integrity, "the retired test is not run under its old name"
for name in ("console-enrolment-pkce-1.18.57.py", "console-certificates-setting-1.18.52.py", "console-sessions-isolation-1.18.56.py", "probe-transport-contract-1.18.47.py",
             "probe-tunnel-console-serial-1.18.56.py", "console-certificates-enrol-1.18.52.py"):
    assert name in integrity, f"{name} still runs"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 26 November 2026."), text[:80]
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## New tests", "## What could not be run here",
                "## Johan dev02 checklist", "## Not in this release", "## Main stays held"):
    assert heading in text, heading
module_facing = text[text.index("## Module-facing change"):text.index("## Closes")]
for needle in ("core.probe_transport", "1.4.0", "1.3.0", "networkprobe", "permissions", "permission_count", "compatibility path", "ui_url", "sign-in-info", "console_ui_url", "Core-internal"):
    assert needle in module_facing, needle
closes = text[text.index("## Closes"):text.index("## What changed and why")]
assert "ORDER" in closes and "Core 1.18.58" in closes and "Console needs the Tec-Tac web address" in closes and "issue_tunnel_ticket takes a list of permissions" in closes and "filed twice" in closes
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Not in this release")]
for step in ("**1.", "**2.", "**3.", "**4.", "**5.", "**6."):
    assert step in checklist, step
assert checklist.count("PASS") >= 6 and checklist.count("FAIL") >= 6 and checklist.count("Send back") >= 6
for topic in ("ui_url", "sign-in-info", "console_ui_url", "ui_url_unavailable", "429", "no-store", "permission_missing", "networkprobe 0.2.29"):
    assert topic.lower() in checklist.lower(), topic
couldnt = text[text.index("## What could not be run here"):text.index("## Johan dev02 checklist")]
assert "Django" in couldnt and "ruff" in couldnt, "says plainly what ran and what did not"
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()
assert "R 9" not in text, "no price in these notes"

# the code the notes describe
app = ROOT / "framwork" / "tec_tac"
certs = (app / "console_certificates.py").read_text(encoding="utf-8")
for needle in ("def console_ui_url", "def sign_in_info_limited", "SIGN_IN_INFO_PER_MINUTE = 30", '"ui_url": console_ui_url()', "configured_frontend_origins"):
    assert needle in certs, needle
settings_text = (app / "runtime_settings.py").read_text(encoding="utf-8")
for needle in ("console_ui_url", "validate_console_ui_url", "CONSOLE_UI_URL_DENIED", "MAX_CONSOLE_UI_URL_LENGTH = 300"):
    assert needle in settings_text, needle
assert "ui_url_unavailable" in (app / "console_session_views.py").read_text(encoding="utf-8")
assert "sign-in-info" in (app / "urls.py").read_text(encoding="utf-8")
assert 'console_ui_url = models.CharField(max_length=300, blank=True, default="")' in (app / "models.py").read_bytes().decode("utf-8")
migration = (app / "migrations" / "0052_console_ui_url.py").read_text(encoding="utf-8")
assert '("tec_tac", "0051_console_enrolment_pkce")' in migration and migration.count("dependencies = [") == 1
transport = (app / "probe_transport.py").read_text(encoding="utf-8")
assert "CAPABILITY_VERSION = \"1.4.0\"" in transport and '"permission_count"' in transport
tunnel = (app / "probe_tunnel.py").read_text(encoding="utf-8")
for needle in ("def _permissions_of", "MAX_PERMISSIONS = 4", "permission_count"):
    assert needle in tunnel, needle
assert "permission_lost" not in tunnel, "the end detail stays permission_missing"
contracts = (app / "contracts.py").read_bytes().decode("utf-8")
for needle in ("/api/tfd/console-sessions/sign-in-info/", "console_ui_url", "core.probe_transport 1.4.0", "ui_url"):
    assert needle in contracts, needle
assert "Permission lists (1.4.0)" in (ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")

# line endings per file: each keeps what it had; new files are LF
crlf_files = ("framwork/tec_tac/models.py", "framwork/tec_tac/audit.py", "framwork/tec_tac/contracts.py", "framwork/tec_tac/apps.py", "framwork/tec_tac/rbac.py", "docs/capabilities.md")
lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "install.sh", "tests/release-integrity.sh", "tests/version-1.18.58.py",
            "framwork/tec_tac/console_certificates.py", "framwork/tec_tac/console_session_views.py", "framwork/tec_tac/probe_tunnel.py", "framwork/tec_tac/probe_transport.py",
            "framwork/tec_tac/runtime_settings.py", "framwork/tec_tac/urls.py", "framwork/tec_tac/migrations/0051_console_enrolment_pkce.py",
            "framwork/tec_tac/migrations/0052_console_ui_url.py", "docs/console-certificates.md", "docs/console-sessions.md", "docs/probe-transport.md",
            "docs/runtime-settings.md", "tests/console_certificates_harness.py", *[f"tests/{name}" for name in NEW_TESTS])
for name in crlf_files:
    data = (ROOT / name).read_bytes()
    assert data.count(b"\r\n") == data.count(b"\n") and data.count(b"\n") > 0, name + " must keep CRLF line endings on every line"
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"

# The rebuild guard matches this version (a stray 1.18.58-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.58" + "-" + r"\d")
assert label.search("x 1.18.58" + "-1") and not label.search("x 1.18.57" + "-1"), "the guard pattern checks 1.18.58"
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

print("version 1.18.58 regression: PASS")
