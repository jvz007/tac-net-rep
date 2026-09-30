#!/usr/bin/env python3
"""AD-3 final acceptance for seamless backup restore.

Runs the behavioral regressions that prove the final D3 decision:
- new backups publish archive + sidecar + adjacent SHA-256 on every destination;
- hash mismatch blocks while a missing companion is explicitly not_verified;
- new bundles are unsigned, old signed bundles remain readable without trust;
- inventory/validation expose source provenance;
- recovery trust/key-export surfaces are removed.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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


out = run("tests/server-backup-d2-d3.py")
assert "AD-3 hash verification and legacy signed-bundle compatibility" in out, out

out = run("tests/l10-publication-final-1.15.173.py")
assert "archive + sidecar + SHA-256 publication on local/FTP/rclone/SCP" in out, out

out = run("tests/server-backup-decision-closure-1.15.166.py")
assert "provenance, hash state and downgrade closure" in out, out

out = run("tests/backup-restore-ui-boundary-1.15.162.py")
assert "backup restore UI HTTP boundary" in out, out

helper = (ROOT / "scripts" / "server-backup-helper.py").read_text(encoding="utf-8")
views = (ROOT / "framwork" / "tec_tac" / "server_backup_views.py").read_text(encoding="utf-8")
urls = (ROOT / "framwork" / "tec_tac" / "urls.py").read_text(encoding="utf-8")
contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
install = (ROOT / "install.sh").read_text(encoding="utf-8")

assert not (ROOT / "scripts" / "recovery-key-cli.py").exists()
assert "operation_trust_recovery_signer" not in helper
assert "create_recovery_signature" not in helper
assert "RecoveryTrustView" not in views
assert "recovery/trust" not in urls
assert "/api/tfd/system/recovery/trust/" not in contracts
assert "rm -f /usr/local/sbin/tec-tac-recovery-key" in install

print("[TEST] PASS D3 AD-3 final seamless restore acceptance 1.15.188")
