#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import os
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

REAL_OPEN = os.open
REAL_FSTAT = os.fstat
REAL_CLOSE = os.close


def load_with_fake_candidates(rel: str, idx: int, candidates: dict[str, dict]):
    calls = []
    fd_map = {}
    next_fd = 9000

    def fake_open(path, flags, *args, **kwargs):
        nonlocal next_fd
        raw = str(path)
        if raw in {'/bin/bash', '/usr/bin/bash'}:
            calls.append((raw, flags))
            spec = candidates.get(raw, {'error': FileNotFoundError(raw)})
            if 'error' in spec:
                raise spec['error']
            fd = next_fd
            next_fd += 1
            fd_map[fd] = spec
            return fd
        return REAL_OPEN(path, flags, *args, **kwargs)

    def fake_fstat(fd):
        if fd in fd_map:
            spec = fd_map[fd]
            return SimpleNamespace(st_mode=spec['mode'], st_uid=spec['uid'])
        return REAL_FSTAT(fd)

    def fake_close(fd):
        if fd in fd_map:
            fd_map.pop(fd, None)
            return None
        return REAL_CLOSE(fd)

    os.open = fake_open
    os.fstat = fake_fstat
    os.close = fake_close
    try:
        spec = importlib.util.spec_from_file_location(f'bash_boundary_{idx}', ROOT / rel)
        mod = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)
    finally:
        os.open = REAL_OPEN
        os.fstat = REAL_FSTAT
        os.close = REAL_CLOSE
    return mod, calls


def accepted(mode=stat.S_IFREG | 0o755, uid=0):
    return {'mode': mode, 'uid': uid}


for idx, rel in enumerate(FILES):
    mod, calls = load_with_fake_candidates(rel, idx, {'/bin/bash': accepted()})
    assert mod.TRUSTED_BASH == '/bin/bash', (rel, mod.TRUSTED_BASH)
    assert [c[0] for c in calls] == ['/bin/bash'], f'{rel} did not resolve Bash exactly once at startup: {calls}'
    assert calls[0][1] & getattr(os, 'O_NOFOLLOW', 0), f'{rel} did not use O_NOFOLLOW for Bash'

    # The production resolver must fall back to /usr/bin/bash when /bin/bash is absent.
    original_open, original_fstat, original_close = mod.os.open, mod.os.fstat, mod.os.close
    try:
        fd_map = {}
        opened = []
        seq = iter([FileNotFoundError('/bin/bash'), accepted()])
        def call_open(path, flags, *args, **kwargs):
            raw = str(path); opened.append(raw); entry = next(seq)
            if isinstance(entry, BaseException): raise entry
            fd = 9100; fd_map[fd] = entry; return fd
        mod.os.open = call_open
        mod.os.fstat = lambda fd: SimpleNamespace(st_mode=fd_map[fd]['mode'], st_uid=fd_map[fd]['uid'])
        mod.os.close = lambda fd: fd_map.pop(fd, None)
        assert mod._resolve_trusted_bash() == '/usr/bin/bash'
        assert opened == ['/bin/bash', '/usr/bin/bash']

        # Unsafe /bin candidates must not be accepted; /usr fallback remains usable.
        for unsafe in (
            accepted(uid=1000),
            accepted(mode=stat.S_IFREG | 0o775),
            accepted(mode=stat.S_IFDIR | 0o755),
            accepted(mode=stat.S_IFREG | 0o644),
        ):
            fd_map.clear(); opened.clear(); seq = iter([unsafe, accepted()])
            assert mod._resolve_trusted_bash() == '/usr/bin/bash'
            assert opened == ['/bin/bash', '/usr/bin/bash']

        # If both fixed candidates are unsafe/missing, fail closed.
        fd_map.clear(); opened.clear(); seq = iter([accepted(uid=1000), accepted(mode=stat.S_IFREG | 0o666)])
        try:
            mod._resolve_trusted_bash()
        except RuntimeError as exc:
            assert 'trusted root-owned executable bash' in str(exc)
        else:
            raise AssertionError(f'{rel} accepted unsafe Bash candidates')
    finally:
        mod.os.open, mod.os.fstat, mod.os.close = original_open, original_fstat, original_close

print('[TEST] PASS L07 trusted Bash resolves once, falls back safely, and rejects unsafe executables')
