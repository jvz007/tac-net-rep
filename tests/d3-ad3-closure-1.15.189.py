#!/usr/bin/env python3
"""Final D3/AD-3 closure acceptance for Core 1.15.189."""
from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(rel: str) -> str:
    proc = subprocess.run(
        [sys.executable, str(ROOT / rel)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if proc.returncode:
        raise AssertionError(f"{rel} failed ({proc.returncode})\n{proc.stdout}")
    return proc.stdout


out = run("tests/server-backup-d3-destructive-restore-1.15.189.py")
assert "destructive restore records missing hash and blocks mismatches" in out, out

out = subprocess.run(
    ["bash", str(ROOT / "tests" / "server-backup-review-hardening.sh")],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)
if out.returncode:
    raise AssertionError(f"server-backup-review-hardening.sh failed ({out.returncode})\n{out.stdout}")

server_backup = (ROOT / "framwork" / "tec_tac" / "server_backup.py").read_text(encoding="utf-8")
install = (ROOT / "install.sh").read_text(encoding="utf-8")
doc = (ROOT / "docs" / "server-backup-capability.md").read_text(encoding="utf-8")

assert 'CAPABILITY_VERSION = "1.9.0"' in server_backup
assert "version='>=1.6.0,<2.0.0'" in install
assert "capability version 1.9.0" in doc
assert "created_at" in doc and "core_version" in doc and "hash_file" in doc
assert "recovery_signer.key_id" not in doc

for stale in (
    "tests/recovery-key-boundary-1.15.160.py",
    "tests/recovery-key-boundary-1.15.163.py",
    "tests/recovery-key-export-1.15.155.py",
    "tests/recovery-key-import-1.15.157.py",
    "tests/recovery-trust-http-boundary.py",
    "tests/recovery-trust-async-core.py",
    "tests/recovery-trust-session-guard.py",
):
    assert not (ROOT / stale).exists(), stale

print("[TEST] PASS D3 AD-3 final closure 1.15.189")
