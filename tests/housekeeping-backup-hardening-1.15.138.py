from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


# L40: FIFO substitution must fail without blocking the root helper.
h = load('tt_housekeeping_138', 'scripts/housekeeping-helper.py')
with tempfile.TemporaryDirectory() as td:
    base = pathlib.Path(td)
    fifo = base / 'request.json'
    os.mkfifo(fifo)
    started = time.monotonic()
    try:
        h._read_request_nofollow(fifo)
    except RuntimeError as exc:
        must('regular file' in str(exc), f'wrong FIFO rejection: {exc}')
    else:
        raise AssertionError('FIFO housekeeping request was accepted')
    must(time.monotonic() - started < 1.0, 'FIFO request open blocked')

# L14: helpers resolve the installer-selected custom config through the fixed,
# root-owned pointer rather than trusting a sudo environment variable.
sbh = load('tt_backup_138', 'scripts/server-backup-helper.py')
smh = load('tt_maint_138', 'scripts/server-maintenance-helper.py')
with tempfile.TemporaryDirectory() as td:
    base = pathlib.Path(td)
    custom = base / 'custom-tec-tac.conf'
    custom.write_text('TEC_TAC_ROOT=/srv/tec-tac\n', encoding='utf-8')
    pointer = base / 'config-path'
    pointer.write_text(str(custom) + '\n', encoding='utf-8')
    os.chmod(pointer, 0o644)
    must(sbh._installed_config_path(pointer, pathlib.Path('/fallback')) == custom, 'backup helper ignored custom config pointer')
    must(smh._installed_config_path(pointer, pathlib.Path('/fallback')) == custom, 'maintenance helper ignored custom config pointer')
    pointer.unlink()
    pointer.symlink_to(custom)
    for mod in (sbh, smh):
        try:
            mod._installed_config_path(pointer, pathlib.Path('/fallback'))
        except RuntimeError:
            pass
        else:
            raise AssertionError('symlinked config pointer was trusted')

# L15: disk preflight must account for the host rollback snapshot. Make free
# space exactly equal to the old 3x bundle estimate; the additional host bytes
# must now make the disk check fail.
report = sbh._vr_new({'restore_mode': 'tec_tac'}, 'bundle.tgz')
config = {
    'TEC_TAC_SERVER_BACKUP_ROOT': '/tmp/tt-138-backup',
    'TACTICAL_ROOT': '/tmp/tt-138-tactical',
    'TEC_TAC_STATE_ROOT': '/tmp/tt-138-state',
    'TEC_TAC_ROOT': '/tmp/tt-138-core',
    'TEC_TAC_FRAMEWORK_SOURCE': '/tmp/tt-138-fw',
    'TEC_TAC_UI_SOURCE': '/tmp/tt-138-ui',
    'TEC_TAC_UI_DEPLOY_ROOT': '/tmp/tt-138-ui-deploy',
}
old_disk = sbh.shutil.disk_usage
old_snapshot_est = sbh._preflight_host_snapshot_bytes
old_mutation = sbh._mutation_active
old_which = sbh.shutil.which
try:
    class DU:
        total = 10 * 1024**3
        used = 7 * 1024**3
        free = 3 * 1024**3
    sbh.shutil.disk_usage = lambda _p: DU()
    sbh._preflight_host_snapshot_bytes = lambda _c, _m: 4096
    sbh._mutation_active = lambda _c: False
    sbh.shutil.which = lambda name: '/bin/true'
    sbh.validate_target_preflight(config, report, 'tec_tac', 1024**3)
finally:
    sbh.shutil.disk_usage = old_disk
    sbh._preflight_host_snapshot_bytes = old_snapshot_est
    sbh._mutation_active = old_mutation
    sbh.shutil.which = old_which
check = next(c for c in report['sections']['target']['checks'] if c['id'] == 'target.disk')
must(check['status'] == 'failed', f'host snapshot bytes did not affect disk preflight: {check}')
must('host_snapshot_estimate=4096' in check['detail'], f'host snapshot estimate missing from detail: {check}')

# L16: regression must discover installer privileged paths rather than only a
# fixed expected list, so a newly-added literal cannot escape rollback review.
rollback_test = (ROOT / 'tests' / 'server-backup-host-rollback.py').read_text(encoding='utf-8')
must('installer_discovered_paths' in rollback_test, 'rollback test does not discover new installer targets')
must('new privileged installer target is not covered' in rollback_test, 'rollback test lacks new-target failure')

# L41: pytest-visible wrapper must exist and expose a test_* callable.
pytest_wrapper = ROOT / 'tests' / 'test_housekeeping_claim_security.py'
must(pytest_wrapper.is_file(), 'pytest-discoverable housekeeping claim wrapper missing')
wrapper_text = pytest_wrapper.read_text(encoding='utf-8')
must('def test_housekeeping_claim_security' in wrapper_text, 'housekeeping claim test is not pytest discoverable')

print('[TEST] PASS housekeeping/backup hardening 1.15.138')
