#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import os
import pathlib
import stat
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    'scripts/server-backup-helper.py',
    'scripts/system-update-helper.py',
    'scripts/module-v2-job-helper.py',
    'scripts/module-hotfix-job-helper.py',
    'scripts/module-job-helper.py',
]


def load_with_counted_bash_boundary(rel: str, idx: int):
    calls = []
    real_stat = pathlib.Path.stat
    real_access = os.access

    def fake_stat(self, *args, **kwargs):
        raw = str(self)
        if raw in {'/bin/bash', '/usr/bin/bash'}:
            calls.append(raw)
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        return real_stat(self, *args, **kwargs)

    def fake_access(path, mode):
        if str(path) in {'/bin/bash', '/usr/bin/bash'}:
            return True
        return real_access(path, mode)

    pathlib.Path.stat = fake_stat
    os.access = fake_access
    try:
        spec = importlib.util.spec_from_file_location(f'bash_boundary_{idx}', ROOT / rel)
        mod = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)
    finally:
        pathlib.Path.stat = real_stat
        os.access = real_access
    return mod, calls


for idx, rel in enumerate(FILES):
    mod, calls = load_with_counted_bash_boundary(rel, idx)
    assert mod.TRUSTED_BASH == '/bin/bash', (rel, mod.TRUSTED_BASH)
    assert calls == ['/bin/bash'], f'{rel} did not resolve Bash exactly once at process/module startup: {calls}'
    # Runtime use is the prevalidated immutable path; no resolver remains callable.
    assert not hasattr(mod, '_trusted_bash'), f'{rel} still exposes a per-call Bash resolver'

print('[TEST] PASS L07 trusted Bash is resolved exactly once per helper process from the fixed root-owned boundary')
