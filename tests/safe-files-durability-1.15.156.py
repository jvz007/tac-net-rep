#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOD_PATH = ROOT / 'framwork' / 'tec_tac' / 'safe_files.py'
spec = importlib.util.spec_from_file_location('tec_tac_safe_files_test', MOD_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_atomic_json_flushes_parent_directory():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / 'state.json'
        calls = []
        real = mod._fsync_directory
        mod._fsync_directory = lambda path: calls.append(Path(path))
        try:
            mod.atomic_json(target, {'ok': True})
        finally:
            mod._fsync_directory = real
        assert json.loads(target.read_text()) == {'ok': True}
        assert calls == [root], calls


def test_directory_fsync_uses_directory_descriptor():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        opened = []
        synced = []
        closed = []
        real_open, real_fsync, real_close = mod.os.open, mod.os.fsync, mod.os.close
        def fake_open(path, flags):
            opened.append((Path(path), flags))
            return 4321
        mod.os.open = fake_open
        mod.os.fsync = lambda fd: synced.append(fd)
        mod.os.close = lambda fd: closed.append(fd)
        try:
            mod._fsync_directory(root)
        finally:
            mod.os.open, mod.os.fsync, mod.os.close = real_open, real_fsync, real_close
        assert opened and opened[0][0] == root
        assert synced == [4321]
        assert closed == [4321]


if __name__ == '__main__':
    test_atomic_json_flushes_parent_directory()
    test_directory_fsync_uses_directory_descriptor()
    print('safe-files-durability-1.15.156: PASS')
