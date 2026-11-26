#!/usr/bin/env python3
"""Regression: Core 1.18.53 (Engineer Console certificates, C4, and the API-key refusal) release bookkeeping, line endings and the promise that the tunnel
files import the certificate logic only inside functions."""
import ast
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
assert version.split("-")[0] == "1.18.53", version
assert (ROOT / "VERSION").read_bytes() == version.encode("ascii"), "VERSION has no trailing newline"
package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == version and package["id"] == "tec-tac" and package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == [f"RELEASE_NOTES_{version}.md"], notes
for earlier in ("1.18.52", "1.18.51", "1.18.50", "1.18.49", "1.18.48", "1.18.47", "1.18.46", "1.18.45", "1.18.44", "1.18.43", "1.18.42", "1.18.41", "1.18.40", "1.18.39", "1.18.38"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{earlier}.md").is_file(), earlier
assert (ROOT / "tests" / "legacy" / "version-1.18.52.py").is_file() and not (ROOT / "tests" / "version-1.18.52.py").exists(), "version-1.18.52.py is retired to tests/legacy"
history = (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.18.52.md").read_text(encoding="utf-8")
assert "or an API key for the signed-in calls" in history, "the 1.18.52 notes are kept unchanged as history"

new_tests = ("console-certificates-connect-1.18.53.py", "console-certificates-apikey-1.18.53.py", "probe-tunnel-certificates-1.18.53.py", "version-1.18.53.py")
kept_tests = ("console-certificates-ca-1.18.52.py", "console-certificates-enrol-1.18.52.py", "console-certificates-routes-1.18.52.py", "console-certificates-setting-1.18.52.py",
              "probe-transport-contract-1.18.47.py", "probe-transport-docs-1.18.47.py", "tunnel-scope-recheck-1.18.50.py", "access-events-1.18.51.py",
              "result-checks-system-check-1.18.45.py")
integrity = (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
for name in (*new_tests, "console_certificates_harness.py", "probe_transport_harness.py", *kept_tests):
    assert (ROOT / "tests" / name).is_file(), name
for name in (*new_tests, *kept_tests):
    assert name in integrity, f"release integrity runs {name}"
assert "version-1.18.52.py" not in integrity, "the retired version test is not run"

text = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
assert text.startswith(f"# Tec-Tac Framework {version}\n\nDate: 25 November 2026."), text[:80]
for heading in ("## Module-facing change", "## Closes", "## What changed and why", "## Assumptions", "## New tests", "## What could not be run here",
                "## Johan dev02 checklist", "## Exit list", "## Main stays held"):
    assert heading in text, heading
checklist = text[text.index("## Johan dev02 checklist"):text.index("## Exit list")]
assert checklist.count("PASS:") >= 9 and checklist.count("PASS:") == checklist.count("FAIL:"), "every step has a PASS and a FAIL line"
assert "or an API key for the signed-in calls" not in checklist and "Use a browser session for the signed-in calls" in checklist, "the checklist carries no API-key hint"
module_facing = text[text.index("## Module-facing change"):text.index("## Closes")]
for needle in ("networkprobe", "console_certificate_required", "core.probe_transport", "1.3.0", "modules/", "issue_tunnel_ticket", "additive", "CORE_STATUS"):
    assert needle in module_facing, needle
for needle in ("interactive_session_required", "certificate_revoked", "ca_replaced", "certificate_expired", "proof_stale", "X-Tectac-Server-Proof", "Daphne", "uvicorn",
               "Django", "PostgreSQL", "last_used_at", "custom:console-cert-refused", "cert_serial"):
    assert needle in text, needle
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    assert forbidden not in text.lower()

# the documents: the wire format is there, the old caveat is gone
doc = (ROOT / "docs" / "console-certificates.md").read_text(encoding="utf-8")
assert "Not enforced yet" not in doc and "not enforced yet" not in doc.lower()
for needle in ("## The tunnel connect, exactly (for the Console developer)", "tectac-console-connect-v1", "tectac-core-connect-v1", "X-Tectac-Console-Cert", "X-Tectac-Console-Proof",
               "X-Tectac-Server-Proof", "base64url without padding", "Clock skew", "120 seconds", "interactive signed-in session", "interactive_session_required", "last_used_at",
               "8a652abf7512959a7ecf7abe32a2bb4634c0b03fc93008b0365ed67933bff00c", "certificate authority (CA)", "ca/replace/"):
    assert needle in doc, needle
for reason in ("certificate_required", "certificate_invalid", "certificate_expired", "certificate_revoked", "certificate_engineer_mismatch", "proof_invalid", "proof_stale"):
    assert f"`{reason}`" in doc, reason
assert "## Not enforced" not in doc
probe_doc = (ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
assert "### Console certificates (1.3.0)" in probe_doc and "console_certificate_required" in probe_doc
assert "`core.probe_transport` 1.3.0" in (ROOT / "docs" / "capabilities.md").read_bytes().decode("utf-8")
assert "last_used_at stays null" not in (APP / "contracts.py").read_bytes().decode("utf-8") and "In C3 a revoke changes the database only" not in (APP / "contracts.py").read_bytes().decode("utf-8")
assert "stays empty until Core 1.18.53" not in (APP / "models.py").read_bytes().decode("utf-8")

# the contract is 1.3.0, and the tunnel files import the certificate logic, cryptography and models only inside functions (rule 1.13)
probe_transport = (APP / "probe_transport.py").read_text(encoding="utf-8")
assert 'CAPABILITY_VERSION = "1.3.0"' in probe_transport, "core.probe_transport is 1.3.0"
assert '"cert_serial"' in probe_transport.split("TUNNEL_AUDIT_KEYS = (")[1].split(")")[0], "cert_serial is an allowed audit key"
for name in ("probe_tunnel.py", "probe_tunnel_consumer.py", "probe_transport.py"):
    tree = ast.parse((APP / name).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            spelled = ast.unparse(node)
            assert "console_certificates" not in spelled and "cryptography" not in spelled and "models" not in spelled and "secret_store" not in spelled, \
                f"{name} imports {spelled!r} at module level; import it inside the function"
tunnel_source = (APP / "probe_tunnel.py").read_text(encoding="utf-8")
assert "from . import console_certificates" in tunnel_source, "probe_tunnel imports the certificate logic lazily"
functions_with_import = [fn.name for fn in ast.walk(ast.parse(tunnel_source)) if isinstance(fn, ast.FunctionDef)
                         and any(isinstance(n, ast.ImportFrom) and any(a.name == "console_certificates" for a in n.names) for n in ast.walk(fn))]
assert functions_with_import == ["_certs"], functions_with_import
for name in ("console_certificates.py", "console_certificate_views.py"):
    for line in (APP / name).read_text(encoding="utf-8").splitlines():
        if line.startswith(("import cryptography", "from cryptography", "from django.db", "from .models", "from . import models", "from . import secret_store", "from .secret_store",
                            "from . import probe_tunnel", "from .probe_tunnel")):
            raise AssertionError(f"{name} imports {line!r} at module level; import it inside the function")

# line endings per file: each file keeps what it had, new files are LF (git ls-files --eol, with a byte check as well)
lf_files = ("VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{version}.md", "tests/release-integrity.sh", "tests/console_certificates_harness.py", "tests/probe_transport_harness.py",
            *(f"tests/{n}" for n in new_tests), "tests/probe-transport-contract-1.18.47.py", "tests/probe-transport-docs-1.18.47.py", "tests/legacy/version-1.18.52.py",
            "docs/releases/RELEASE_NOTES_1.18.52.md", "framwork/tec_tac/console_certificates.py", "framwork/tec_tac/console_certificate_views.py", "framwork/tec_tac/probe_tunnel.py",
            "framwork/tec_tac/probe_tunnel_consumer.py", "framwork/tec_tac/probe_transport.py", "docs/console-certificates.md", "docs/probe-transport.md")
crlf_files = ("framwork/tec_tac/audit.py", "framwork/tec_tac/models.py", "framwork/tec_tac/rbac.py", "framwork/tec_tac/contracts.py", "docs/secret-store.md", "docs/capabilities.md")
for name in lf_files:
    assert b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings"
for name in crlf_files:
    data = (ROOT / name).read_bytes()
    assert b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings"
try:
    listing = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--eol", "--cached", "--others", "--exclude-standard", "--", *lf_files, *crlf_files], capture_output=True, check=False).stdout.decode("utf-8", "replace")
except OSError:
    listing = ""
for line in listing.splitlines():
    columns, _tab, path = line.partition("\t")
    if not path:
        continue
    working = [c for c in columns.split() if c.startswith("w/")]
    expected = "crlf" if path in crlf_files else None
    if working and working[0] in ("w/lf", "w/crlf", "w/mixed"):
        assert working[0] != "w/mixed", f"{path} has mixed line endings"
        if expected:
            assert working[0] == "w/crlf", f"{path}: git sees {working[0]}"
        elif path in lf_files:
            assert working[0] == "w/lf", f"{path}: git sees {working[0]}"

# The rebuild guard matches this version (a stray 1.18.53-<digit> fails), and not the one before.
label = re.compile("1" + r"\.18\.53" + "-" + r"\d")
assert label.search("x 1.18.53" + "-1") and not label.search("x 1.18.52" + "-1"), "the guard pattern checks 1.18.53"

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

print("version 1.18.53 regression: PASS")
