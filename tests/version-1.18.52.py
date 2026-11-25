#!/usr/bin/env python3
"""Regression: Core 1.18.52 (Engineer Console certificates, C3) release bookkeeping, line endings and the promise that C3 does not touch the tunnel."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.52", version
assert (ROOT / "VERSION").read_bytes() == version.encode("ascii"), "VERSION has no trailing newline"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for earlier in ("1.18.51", "1.18.50", "1.18.49", "1.18.48", "1.18.47", "1.18.46", "1.18.45", "1.18.44", "1.18.43", "1.18.42", "1.18.41", "1.18.40", "1.18.39", "1.18.38"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{earlier}.md").is_file(), earlier
assert (ROOT / "tests" / "legacy" / "version-1.18.51.py").is_file() and not (ROOT / "tests" / "version-1.18.51.py").exists(), "version-1.18.51.py is retired to tests/legacy"

new_tests = ("console-certificates-ca-1.18.52.py", "console-certificates-enrol-1.18.52.py", "console-certificates-routes-1.18.52.py",
             "console-certificates-setting-1.18.52.py", "version-1.18.52.py")
kept_tests = ("access-events-1.18.51.py", "probe-tunnel-limits-1.18.51.py", "access-events-1.18.50.py", "tunnel-scope-recheck-1.18.50.py", "probe-tunnel-limits-1.18.50.py",
              "result-checks-system-check-1.18.45.py", "runtime-settings-permission-1.17.2.py")
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in (*new_tests, "console_certificates_harness.py", *kept_tests):
    assert (ROOT / "tests" / name).is_file(), name
for name in (*new_tests, *kept_tests[:-1]):
    assert name in integrity, f"release integrity runs {name}"
assert "version-1.18.51.py" not in integrity, "the retired version test is not run"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 25 November 2026.")
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## New tests", "## What could not be run here",
                "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 5 and checklist.count("PASS:") == checklist.count("FAIL:"), "every step has a PASS and a FAIL line"
module_facing = text[text.index("## Module-facing change"):text.index("## Closes")]
for needle in ("modules/", "console-certificates", "core.console_certificates.view", "core.console_certificates.manage", "console_certificate_validity_days", "No capability"):
    assert needle in module_facing, needle
for needle in ("does not protect the tunnel yet", "Core 1.18.53", "does not end a tunnel", "not enforced", "burns the code", "replaced", "0049_console_certificates", "Django", "PostgreSQL"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

# the document says it plainly too
doc = (ROOT / "docs" / "console-certificates.md").read_text(encoding="utf-8")
for needle in ("## Not enforced yet", "certificate authority (CA)", "tectac-console-enrol-v1", "base64url without padding", "master key", "Clock skew", "ca/replace/"):
    assert needle in doc, needle
assert "console_certificate_validity_days" in (ROOT / "docs" / "runtime-settings.md").read_text(encoding="utf-8")
assert "core_console_ca" in (ROOT / "docs" / "secret-store.md").read_bytes().decode("utf-8")

# C3 does not change the tunnel: the three tunnel files never mention the certificates, and the contract stays 1.2.0
for name in ("probe_tunnel.py", "probe_tunnel_consumer.py", "probe_transport.py"):
    body = (APP / name).read_text(encoding="utf-8")
    assert "console_certificate" not in body and "console-cert" not in body and "core_console" not in body, name + " must not mention the Console certificates in C3"
assert 'CAPABILITY_VERSION = "1.2.0"' in (APP / "probe_transport.py").read_text(encoding="utf-8"), "core.probe_transport stays 1.2.0"

# line endings per file: new files LF, touched files keep theirs
lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/version-1.18.52.py", "tests/release-integrity.sh", "tests/console_certificates_harness.py",
            *(f"tests/{n}" for n in new_tests), "framwork/tec_tac/console_certificates.py", "framwork/tec_tac/console_certificate_views.py",
            "framwork/tec_tac/migrations/0049_console_certificates.py", "framwork/tec_tac/urls.py", "framwork/tec_tac/throttles.py", "framwork/tec_tac/runtime_settings.py",
            "framwork/tec_tac/openapi.py", "docs/console-certificates.md", "docs/runtime-settings.md")
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in ("framwork/tec_tac/audit.py", "framwork/tec_tac/models.py", "framwork/tec_tac/rbac.py", "framwork/tec_tac/contracts.py", "docs/secret-store.md"):
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"

# nothing imports cryptography or Django models at module level in the two new Core files (rule 1.13: a fault must not stop Tactical at start-up)
for name in ("console_certificates.py", "console_certificate_views.py"):
    for line in (APP / name).read_text(encoding="utf-8").splitlines():
        if line.startswith(("import cryptography", "from cryptography", "from django.db", "from .models", "from . import models", "from . import secret_store", "from .secret_store")):
            raise AssertionError(f"{name} imports {line!r} at module level; import it inside the function")

# The rebuild guard matches this version (a stray 1.18.52-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.52" + "-" + r"\d")
assert label.search("x 1.18.52" + "-1") and not label.search("x 1.18.51" + "-1"), "the guard pattern checks 1.18.52"

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

print("version 1.18.52 regression: PASS")
