#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import json
import os
import pathlib
import stat
import sys
import tempfile

root = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location('hk_config_test', root / 'framwork/tec_tac/housekeeping.py')
hk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hk)

payload = {'policies': {k: dict(v) for k, v in hk.DEFAULT_POLICIES.items()}, 'allow_zero_destructive': False}

with tempfile.TemporaryDirectory() as td:
    base = pathlib.Path(td)
    housekeeping_root = base / 'housekeeping'
    housekeeping_root.mkdir(mode=0o755)
    os.chmod(housekeeping_root, 0o755)
    config_dir = housekeeping_root / 'config'
    config_dir.mkdir(mode=0o770)
    os.chmod(config_dir, 0o770)

    hk.ROOT = housekeeping_root
    hk.CONFIG_DIR = config_dir
    hk.CONFIG = config_dir / 'config.json'

    result = hk.save_config(payload)
    assert result['allow_zero_destructive'] is False
    assert hk.CONFIG.is_file()
    assert not (housekeeping_root / 'config.json').exists(), 'config must not be written directly into root-owned housekeeping parent'
    saved = json.loads(hk.CONFIG.read_text(encoding='utf-8'))
    assert saved['policies']['module_staging']['days'] == hk.DEFAULT_POLICIES['module_staging']['days']
    assert stat.S_IMODE(hk.CONFIG.stat().st_mode) == 0o640
    assert not list(config_dir.glob('.config.*.tmp')), 'atomic temp file must be cleaned'

    # Existing config symlink must be replaced, never followed.
    sentinel = base / 'sentinel.json'
    sentinel.write_text('sentinel', encoding='utf-8')
    hk.CONFIG.unlink()
    hk.CONFIG.symlink_to(sentinel)
    hk.save_config(payload)
    assert sentinel.read_text(encoding='utf-8') == 'sentinel'
    assert hk.CONFIG.is_file() and not hk.CONFIG.is_symlink()

    # Missing/unavailable config child must become a bounded HousekeepingError.
    hk.CONFIG.unlink()
    config_dir.rmdir()
    try:
        hk.save_config(payload)
    except hk.HousekeepingError as exc:
        assert str(exc) == 'Unable to save housekeeping configuration.'
    else:
        raise AssertionError('missing config directory should fail with HousekeepingError')

install = (root / 'install.sh').read_text(encoding='utf-8')
assert 'for hk_dir in requests results running config' in install
assert 'LEGACY_HOUSEKEEPING_CONFIG="${HOUSEKEEPING_ROOT}/config.json"' in install
assert 'HOUSEKEEPING_CONFIG="${HOUSEKEEPING_ROOT}/config/config.json"' in install
assert '"${HOUSEKEEPING_ROOT}/config"' in install
print('housekeeping config storage: PASS')
