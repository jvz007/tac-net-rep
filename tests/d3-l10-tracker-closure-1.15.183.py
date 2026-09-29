#!/usr/bin/env python3
from __future__ import annotations
import os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def run(cmd):
    p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode:
        raise AssertionError(f"command failed ({p.returncode}): {' '.join(cmd)}\n{p.stdout}")
    return p.stdout

# D3 must remain ordinary-CI portable: when this acceptance runner itself is
# privileged, prove the recovery signer/trust regression also passes as nobody.
d3 = [sys.executable, str(ROOT / 'tests' / 'server-backup-d2-d3.py')]
if os.geteuid() == 0:
    nobody = subprocess.run(['id','-u','nobody'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if nobody.returncode == 0:
        d3 = ['runuser','-u','nobody','--',sys.executable,str(ROOT / 'tests' / 'server-backup-d2-d3.py')]
out = run(d3)
assert 'PASS D2/D3 recovery continuity' in out, out

# L10 is behavioral across local, FTP, rclone and SCP. It forces archive
# publication failures after sidecar publication and also proves success leaves
# the pair visible.
out = run([sys.executable, str(ROOT / 'tests' / 'l10-publication-final-1.15.173.py')])
assert 'PASS L10 final atomic publication on local/FTP/rclone/SCP' in out, out

print('[TEST] PASS tracker D3/L10 final closure acceptance 1.15.183')
