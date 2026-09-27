#!/usr/bin/env python3
"""D2 regression: older Core restore must finish on the backup-declared version."""
import importlib.util
import io
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_backup_helper_d2_version', ROOT / 'scripts' / 'server-backup-helper.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

with tempfile.TemporaryDirectory() as td:
    td = pathlib.Path(td)
    framework = td / 'framework'
    runtime = td / 'runtime'
    framework.mkdir(); runtime.mkdir()
    config = {
        'TEC_TAC_FRAMEWORK_SOURCE': str(framework),
        'TEC_TAC_ROOT': str(runtime),
    }

    # Transition detection explicitly permits going backwards.
    (framework / 'VERSION').write_text('1.15.121\n', encoding='utf-8')
    manifest = {'components': {'tec_tac': {'framework_version': '1.15.108'}}}
    transition = h._restore_version_transition(config, manifest)
    assert transition['current_core_version'] == '1.15.121'
    assert transition['restored_core_version'] == '1.15.108'
    assert transition['is_core_downgrade'] is True
    assert transition['version_verified'] is False
    assert transition['effective_core_version'] is None

    # Once the older payload is installed, exact version verification succeeds.
    (framework / 'VERSION').write_text('1.15.108\n', encoding='utf-8')
    log = io.StringIO()
    effective = h._verify_restored_core_version(config, {'framework_version': '1.15.108'}, log)
    assert effective == '1.15.108'
    assert 'verified restored Core version: 1.15.108' in log.getvalue()

    # A restore that silently remains on the newer version is not considered complete.
    (framework / 'VERSION').write_text('1.15.121\n', encoding='utf-8')
    try:
        h._verify_restored_core_version(config, {'framework_version': '1.15.108'}, io.StringIO())
    except RuntimeError as exc:
        assert 'backup declares 1.15.108' in str(exc)
        assert 'installed Core reports 1.15.121' in str(exc)
    else:
        raise AssertionError('D2 restore accepted a Core version different from the backup manifest')

print('[TEST] PASS D2 exact restored-Core version transition')
