#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, os, stat
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
FILES=[
 'scripts/server-backup-helper.py','scripts/system-update-helper.py','scripts/module-v2-job-helper.py',
 'scripts/module-hotfix-job-helper.py','scripts/module-job-helper.py',
]

def load(rel,idx):
    spec=importlib.util.spec_from_file_location(f'bash_boundary_{idx}', ROOT/rel)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

for idx,rel in enumerate(FILES):
    mod=load(rel,idx)
    calls=[]
    class FakePath:
        def __init__(self,raw): self.raw=str(raw)
        def stat(self):
            calls.append(self.raw)
            return SimpleNamespace(st_mode=stat.S_IFREG|0o755, st_uid=0)
        def __str__(self): return self.raw
    real_path,real_access=mod.Path,mod.os.access
    try:
        mod.Path=FakePath
        mod.os.access=lambda path,mode: True
        mod._TRUSTED_BASH_CACHE=None
        first=mod._trusted_bash(); second=mod._trusted_bash()
    finally:
        mod.Path,mod.os.access=real_path,real_access
    assert first=='/bin/bash' and second=='/bin/bash', (rel,first,second)
    assert calls==['/bin/bash'], f'{rel} resolved Bash more than once: {calls}'
print('[TEST] PASS L07 trusted Bash resolves once per helper process and enforces fixed-list boundary')
