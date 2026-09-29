#!/usr/bin/env python3
"""Run the exact portable regressions that together satisfy D2 and D3.

D2 done-when coverage:
- an older Core version is explicitly reported before restore;
- the restored tree is verified at that older version;
- current security/trust state wins over stale backup state.

D3 done-when coverage:
- recovery source server, installation ID and signer fingerprint are preserved;
- signer trust is bound to the identity confirmed by the operator;
- service-state restoration is preserved;
- all tests are portable and do not require running as root.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

if os.geteuid() == 0:
    # The acceptance requirement is portability, not root-only execution. Run
    # the same child tests as nobody when available so a root CI container does
    # not accidentally mask that requirement.
    nobody = '/usr/sbin/runuser' if Path('/usr/sbin/runuser').exists() else None
else:
    nobody = None

TESTS = [
    'server-backup-d2-d3.py',
    'server-backup-decision-closure-1.15.166.py',
    'server-backup-d3-service-state.py',
]

for name in TESTS:
    path = ROOT / 'tests' / name
    if nobody:
        argv = [nobody, '-u', 'nobody', '--', sys.executable, str(path)]
    else:
        argv = [sys.executable, str(path)]
    proc = subprocess.run(argv, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode:
        raise AssertionError(f'{name} failed:\n{proc.stdout}')
    if 'PASS' not in proc.stdout:
        raise AssertionError(f'{name} did not report behavioral PASS:\n{proc.stdout}')

print('[TEST] PASS D2/D3 final portable downgrade, identity, trust and service-state acceptance')
