#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXED_CONFIG = Path('/opt/tec-tac/etc/tec-tac.conf')


def load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'unable to load {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


os.environ['TEC_TAC_CONFIG_FILE'] = '/tmp/attacker-controlled.conf'
os.environ['TEC_TAC_FRAMEWORK_SIGNED_RELEASE_MIN_VERSION'] = '0.0.1'
os.environ['TEC_TAC_ATTACKER_OVERRIDE'] = 'owned'

helpers = [
    load('module_job_helper_env_test', 'scripts/module-job-helper.py'),
    load('module_v2_helper_env_test', 'scripts/module-v2-job-helper.py'),
    load('module_hotfix_helper_env_test', 'scripts/module-hotfix-job-helper.py'),
    load('system_update_helper_env_test', 'scripts/system-update-helper.py'),
]
trust = load('privileged_trust_env_test', 'scripts/privileged-trust.py')

for helper in helpers:
    assert helper.CONFIG == FIXED_CONFIG, (helper.__name__, helper.CONFIG)
    env = helper.privileged_env()
    assert 'TEC_TAC_CONFIG_FILE' not in env
    assert 'TEC_TAC_ATTACKER_OVERRIDE' not in env
    assert 'TEC_TAC_FRAMEWORK_SIGNED_RELEASE_MIN_VERSION' not in env
    allowed = helper.privileged_env({'TEC_TAC_UI_ROOT': '/safe/ui'})
    assert allowed['TEC_TAC_UI_ROOT'] == '/safe/ui'
    assert 'TEC_TAC_ATTACKER_OVERRIDE' not in allowed

with tempfile.TemporaryDirectory(prefix='tectac-env-test-') as td:
    root = Path(td)
    safe = root / 'tec-tac.conf'
    safe.write_text('TEC_TAC_FRAMEWORK_SIGNED_RELEASE_MIN_VERSION=9.9.9\nTACTICAL_USER=tactical\n', encoding='utf-8')
    safe.chmod(0o644)

    for helper in helpers:
        helper.CONFIG = safe
        parsed = helper.load_config()
        assert parsed.get('TACTICAL_USER') == 'tactical'

    system_update = helpers[-1]
    assert system_update._signed_release_min_version('framework') == '9.9.9'

    writable = root / 'writable.conf'
    writable.write_text('TACTICAL_USER=tactical\n', encoding='utf-8')
    writable.chmod(0o666)
    for helper in helpers:
        helper.CONFIG = writable
        try:
            helper.load_config()
        except RuntimeError as exc:
            assert 'root-owned' in str(exc) or 'writable' in str(exc)
        else:
            raise AssertionError(f'{helper.__name__} accepted group/world-writable config')

    target = root / 'target.conf'
    target.write_text('TACTICAL_USER=tactical\n', encoding='utf-8')
    target.chmod(0o644)
    link = root / 'link.conf'
    link.symlink_to(target)
    for helper in helpers:
        helper.CONFIG = link
        try:
            helper.load_config()
        except RuntimeError as exc:
            assert 'non-symlink' in str(exc)
        else:
            raise AssertionError(f'{helper.__name__} accepted symlinked config')

    trust.CONFIG = safe
    parsed = trust._config()
    assert parsed.get('TACTICAL_USER') == 'tactical'
    trust.CONFIG = link
    try:
        trust._config()
    except RuntimeError as exc:
        assert 'non-symlink' in str(exc)
    else:
        raise AssertionError('privileged trust helper accepted symlinked config')

print('[TEST] PASS privileged helper environment/config trust boundary')
