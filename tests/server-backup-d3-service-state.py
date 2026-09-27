#!/usr/bin/env python3
"""D3 regression: restore/rollback preserves pre-operation service activity."""
import importlib.util
import io
import pathlib
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_backup_helper_d3_state', ROOT / 'scripts' / 'server-backup-helper.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)

active = {'rmm', 'celery', 'celerybeat', 'nginx', 'nats'}
actions = []
original_run = h.subprocess.run


def fake_run(argv, **kwargs):
    cmd = list(argv)
    if cmd[:3] == ['systemctl', 'is-active', '--quiet']:
        return SimpleNamespace(returncode=0 if cmd[3] in active else 3)
    if len(cmd) == 3 and cmd[0] == 'systemctl' and cmd[1] in {'start', 'stop'}:
        actions.append((cmd[1], cmd[2]))
        return SimpleNamespace(returncode=0)
    raise AssertionError(f'unexpected subprocess call: {cmd}')

try:
    h.subprocess.run = fake_run
    captured = h.capture_restore_service_state()
    assert captured['rmm'] is True
    assert captured['nats'] is True
    assert captured['meshcentral'] is False
    assert captured['daphne'] is False

    h.service_start_after_restore(io.StringIO(), captured)
    expected = {
        ('start', 'rmm'), ('start', 'celery'), ('start', 'celerybeat'), ('start', 'nginx'), ('start', 'nats'),
        ('stop', 'daphne'), ('stop', 'nats-api'), ('stop', 'meshcentral'),
    }
    assert set(actions) == expected, actions

    # Missing historical state remains backward compatible: required services
    # start, optional services remain stopped rather than being enabled blindly.
    actions.clear()
    h.service_start_after_restore(io.StringIO(), None)
    assert ('start', 'rmm') in actions and ('start', 'nginx') in actions
    assert ('stop', 'meshcentral') in actions and ('stop', 'nats') in actions
finally:
    h.subprocess.run = original_run

source=(ROOT/'scripts'/'server-backup-helper.py').read_text(encoding='utf-8')
assert '"service_state": capture_restore_service_state()' in source
assert 'service_start_after_restore(log, snapshot.get("service_state"))' in source
print('[TEST] PASS D3 restore preserves pre-operation Tactical service runtime state')
