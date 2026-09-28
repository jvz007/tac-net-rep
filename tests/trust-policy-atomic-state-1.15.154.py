#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_cli_uses_unique_atomic_files_for_policy_and_pending():
    mod = load_script('trust_policy_cli_115154', 'trust-policy-cli.py')
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        policy = root / 'update-trust-policy.json'
        pending = root / 'pending-trust-policy-revert.json'
        victim_policy = root / 'policy-victim'
        victim_pending = root / 'pending-victim'
        victim_policy.write_text('safe-policy', encoding='utf-8')
        victim_pending.write_text('safe-pending', encoding='utf-8')
        (root / 'update-trust-policy.json.tmp').symlink_to(victim_policy)
        (root / 'pending-trust-policy-revert.json.tmp').symlink_to(victim_pending)

        old = (mod.POLICY_ROOT, mod.POLICY_FILE, mod.PENDING_FILE)
        old_chown, old_fchown = mod.os.chown, mod.os.fchown
        mod.POLICY_ROOT, mod.POLICY_FILE, mod.PENDING_FILE = root, policy, pending
        mod.os.chown = lambda *args, **kwargs: None
        mod.os.fchown = lambda *args, **kwargs: None
        os.environ['TEC_TAC_TEST_ALLOW_NONROOT'] = '1'
        try:
            result = mod.write_policy('signed_production', updated_by='test')
            assert result['minimum_level'] == 'signed_production'
            assert json.loads(policy.read_text(encoding='utf-8'))['minimum_level'] == 'signed_production'
            mod.write_pending({
                'schema': 1,
                'change_id': 'test-change',
                'previous_level': 'secure_signed',
                'temporary_level': 'signed_production',
                'expires_at': '2026-09-29T00:00:00Z',
            })
            assert json.loads(pending.read_text(encoding='utf-8'))['change_id'] == 'test-change'
            assert victim_policy.read_text(encoding='utf-8') == 'safe-policy'
            assert victim_pending.read_text(encoding='utf-8') == 'safe-pending'
            assert list(root.glob('.update-trust-policy.json.*.tmp')) == []
            assert list(root.glob('.pending-trust-policy-revert.json.*.tmp')) == []
        finally:
            mod.POLICY_ROOT, mod.POLICY_FILE, mod.PENDING_FILE = old
            mod.os.chown, mod.os.fchown = old_chown, old_fchown
            os.environ.pop('TEC_TAC_TEST_ALLOW_NONROOT', None)


def test_migration_ignores_preplanted_pid_temp_name():
    mod = load_script('trust_policy_migration_115154', 'trust-policy-migration.py')
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        target = root / 'update-trust-policy.json'
        victim = root / 'victim'
        victim.write_text('safe', encoding='utf-8')
        planted = root / f'update-trust-policy.json.tmp.{os.getpid()}'
        planted.symlink_to(victim)
        payload = {'schema': 1, 'minimum_level': 'secure_signed', 'updated_by': 'test'}
        mod._write_policy(target, payload)
        assert json.loads(target.read_text(encoding='utf-8'))['minimum_level'] == 'secure_signed'
        assert victim.read_text(encoding='utf-8') == 'safe'
        assert planted.is_symlink()
        assert list(root.glob('.update-trust-policy.json.*.tmp')) == []


if __name__ == '__main__':
    test_cli_uses_unique_atomic_files_for_policy_and_pending()
    test_migration_ignores_preplanted_pid_temp_name()
    print('trust policy atomic state 1.15.154: PASS')
