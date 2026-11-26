#!/usr/bin/env python3
"""Regression: Core 1.18.54 (the Tactical group on daphne, celery and celerybeat) release bookkeeping, documents and line endings."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.54", version
assert (ROOT / "VERSION").read_bytes() == version.encode("ascii"), "VERSION has no trailing newline"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
assert (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.53.md").is_file()
assert (ROOT / "tests" / "legacy" / "version-1.18.53.py").is_file() and not (ROOT / "tests" / "version-1.18.53.py").exists(), "version-1.18.53.py is retired to tests/legacy"

integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in ("install-service-key-group-1.18.54.sh", "diagnostics-secret-key-access-1.18.54.py", "version-1.18.54.py"):
    assert (ROOT / "tests" / name).is_file() and name in integrity, name
assert "version-1.18.53.py" not in integrity, "the retired version test is not run"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 26 November 2026."), text[:80]
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## New tests", "## What could not be run here",
                "## Johan dev02 checklist", "## Not in this release", "## Main stays held"):
    assert heading in text, heading
module_facing = text[text.index("## Module-facing change"):text.index("## Closes")]
assert "None." in module_facing and "core.secrets" in module_facing
for needle in ("rmm", "daphne", "celery", "celerybeat", "tec-tac-groups.conf", "core.secret_store.service-access", "master_key_unavailable", "Django, systemd, root"):
    assert needle in text, needle
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Not in this release")]
for step in ("**A.", "**B.", "**C.", "**D.", "**E."):
    assert step in checklist, step
assert checklist.count("PASS") >= 5 and checklist.count("FAIL") >= 5
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

# the documents
secret = (ROOT / "docs" / "secret-store.md").read_bytes().decode("utf-8")
diag = (ROOT / "docs" / "troubleshooting-diagnostics.md").read_bytes().decode("utf-8")
for name, doc in (("secret-store.md", secret), ("troubleshooting-diagnostics.md", diag)):
    assert "tec-tac.conf" in doc and "supplementary group" in doc, name
    assert "systemctl show daphne -p SupplementaryGroups --value" in doc, name
    for line in doc.splitlines():
        low = line.lower()
        assert not ("readable by `www-data`" in low and "not" not in low and "nothing" not in low), f"{name}: a line says the key is made readable by www-data"
assert "core.secret_store.service-access" in diag
assert "`unreadable`" in secret and "ls -l /etc/tec-tac/secrets/master.key" in secret

# the contract wording is unchanged
contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_bytes().decode("utf-8")
assert "master_key_unavailable" in contracts

# line endings per file: each keeps what it had
lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "install.sh", "uninstall.sh", "tests/release-integrity.sh", "tests/install-service-key-group-1.18.54.sh",
            "tests/diagnostics-secret-key-access-1.18.54.py", "tests/version-1.18.54.py", "framwork/tec_tac/diagnostics.py", "framwork/tec_tac/diagnostics_install.py")
crlf_files = ("docs/secret-store.md", "docs/troubleshooting-diagnostics.md")
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in crlf_files:
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"

# the literal the foundation test greps for is still there, and the key is never granted wider
install = (ROOT / "install.sh").read_text(encoding="utf-8")
assert "SupplementaryGroups=${TACTICAL_GROUP}" in install and "KEY_GROUP_SERVICES=\"rmm daphne celery celerybeat\"" in install

# The rebuild guard matches this version (a stray 1.18.54-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.54" + "-" + r"\d")
assert label.search("x 1.18.54" + "-1") and not label.search("x 1.18.53" + "-1"), "the guard pattern checks 1.18.54"
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

print("version 1.18.54 regression: PASS")
