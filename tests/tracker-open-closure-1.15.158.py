#!/usr/bin/env python3
from __future__ import annotations
import os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def run(path,*args,as_nobody=False,timeout=80):
    cmd=[sys.executable,path,*args] if path.endswith('.py') else ['bash',path,*args]
    if as_nobody and os.geteuid()==0:
        cmd=['runuser','-u','nobody','--',*cmd]
    p=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,timeout=timeout)
    if p.returncode:
        raise AssertionError(f"{path} failed ({p.returncode})\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}")
# D2/D3
for t in ('tests/server-backup-d2-d3.py','tests/server-backup-d2-version-transition.py','tests/server-backup-d3-service-state.py'): run(t)
# M18 historical regressions must execute against current code.
run('tests/review-regressions-1.15.52.py'); run('tests/review-1.15.52-rebuild.sh')
# L04/L07
run('tests/test_core_leftovers_1_15_139.py'); run('tests/root-bash-boundary.py')
# L10/L15/L76
run('tests/backup-closure-1.15.145.py'); run('tests/backup-recovery-system-update-1.15.140.py'); run('tests/server-backup-recovery-trust.py',as_nobody=True)
# L24/L25
run('tests/scheduler-legacy-target-regression.py'); run('tests/scheduler-legacy-endpoint-pk-compat.py')
# L26/L27
run('tests/trust-policy-tracker-closure-1.15.158.py')
# L61 remaining portable formerly-root-only tests.
run('tests/privileged-helper-environment.py',as_nobody=True); run('tests/module-artifact-immutable-claim.py',as_nobody=True)
# L63
run('tests/release-archive-integrity.py')
print('[TEST] PASS tracker open/partial closure 1.15.158: D2 D3 M18 L04 L07 L10 L15 L24 L25 L26 L27 L61 L63 L76')
