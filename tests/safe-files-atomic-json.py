#!/usr/bin/env python3
import importlib.util
import json
import os
import stat
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('safe_files', ROOT / 'framwork/tec_tac/safe_files.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    target = root / 'state.json'
    trap = root / 'trap.txt'
    trap.write_text('unchanged', encoding='utf-8')
    predictable = root / 'state.json.tmp'
    predictable.symlink_to(trap)

    mod.atomic_json(target, {'writer': 'first'}, mode=0o640)
    assert json.loads(target.read_text()) == {'writer': 'first'}
    assert trap.read_text() == 'unchanged'
    assert predictable.is_symlink(), 'predictable symlink should never be touched'
    assert stat.S_IMODE(target.stat().st_mode) == 0o640

    errors = []
    def writer(i):
        try:
            for n in range(40):
                mod.atomic_json(target, {'writer': i, 'iteration': n}, mode=0o640)
                json.loads(target.read_text(encoding='utf-8'))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert not errors, errors
    final = json.loads(target.read_text(encoding='utf-8'))
    assert set(final) == {'writer', 'iteration'}
    assert not list(root.glob('.state.json.*.tmp')), 'temporary files leaked'

for name in ('module_manager.py','system_update.py','server_backup.py','module_repository.py','server_maintenance.py'):
    text = (ROOT / 'framwork/tec_tac' / name).read_text(encoding='utf-8')
    assert 'from .safe_files import atomic_json' in text, name
    assert 'path.name + ".tmp"' not in text, name

print('safe-files atomic JSON regression: PASS')
