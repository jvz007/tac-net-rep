#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys
ROOT=Path(__file__).resolve().parents[1]
for name in (
    'tracker-behavior-closure-1.15.161.py',
    'server-backup-d2-d3.py',
    'server-backup-decision-closure-1.15.166.py',
):
    subprocess.run([sys.executable, str(ROOT/'tests'/name)], check=True, cwd=ROOT)
print('[TEST] PASS tracker closure D2 D3 L10')
