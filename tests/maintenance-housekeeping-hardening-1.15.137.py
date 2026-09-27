#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import time
import types
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

sm = load('sm_137', 'scripts/server-maintenance-helper.py')
hk = load('hk_137', 'scripts/housekeeping-helper.py')

# L35: pre-claim/pre-upgrade public-only maintenance jobs remain cancellable.
with tempfile.TemporaryDirectory() as raw:
    td = pathlib.Path(raw)
    state = td / 'sm'
    sm.STATE_ROOT = state
    sm.JOBS_ROOT = state / 'jobs'
    sm.CANCEL_ROOT = state / 'cancel-requests'
    sm.LOGS_ROOT = state / 'logs'
    sm.RUNNING_ROOT = state / 'running'
    sm.AUDIT_FILE = state / 'audit.jsonl'
    sm.LOCK_FILE = state / 'lock'
    sm.REGISTRY_ROOT = td / 'registry'
    sm.ACTION_ROOT = td / 'actions'
    sm.tactical_gid = lambda: os.getgid()
    for p in (sm.JOBS_ROOT, sm.CANCEL_ROOT, sm.LOGS_ROOT, sm.RUNNING_ROOT, sm.REGISTRY_ROOT, sm.ACTION_ROOT):
        p.mkdir(parents=True, exist_ok=True)
    jid = '11111111-1111-4111-8111-111111111111'
    job = {
        'id': jid, 'action': 'legacy.action', 'status': 'running', 'stage': 'running',
        'context': {'source_module': 'legacy'}, 'unit': 'attacker-controlled.service',
        'lock': {'scope': 'global', 'state': 'acquired', 'acquired_at': 'old'},
        'exit_result': None, 'failure': None,
    }
    sm.atomic_json(sm.JOBS_ROOT / f'{jid}.json', job)
    sm.atomic_json(sm.CANCEL_ROOT / f'{jid}.json', {'job_id': jid, 'context': {'requested_by': 'tester'}})
    calls = []
    old_run = sm.subprocess.run
    sm.subprocess.run = lambda argv, **kw: (calls.append(list(argv)) or types.SimpleNamespace(returncode=0, stderr=''))
    try:
        sm.cancel_job(jid)
    finally:
        sm.subprocess.run = old_run
    final = json.loads((sm.JOBS_ROOT / f'{jid}.json').read_text())
    assert final['status'] == 'cancelled', final
    assert calls == [['systemctl', 'stop', sm._systemd_unit(jid)]], calls
    assert 'attacker-controlled.service' not in ' '.join(calls[0])

# L36: no-follow state reads reject FIFOs without blocking.
with tempfile.TemporaryDirectory() as raw:
    fifo = pathlib.Path(raw) / 'state.json'
    os.mkfifo(fifo)
    started = time.monotonic()
    try:
        sm._read_json_nofollow(fifo)
    except RuntimeError as exc:
        assert 'regular file' in str(exc)
    else:
        raise AssertionError('FIFO state file was accepted')
    assert time.monotonic() - started < 1.0, 'FIFO read blocked'

# L37: config trust check and content read use the same no-follow descriptor.
with tempfile.TemporaryDirectory() as raw:
    td = pathlib.Path(raw)
    cfg = td / 'tec-tac.conf'
    safe = td / 'safe.conf'
    evil = td / 'evil.conf'
    safe.write_text('TEC_TAC_SERVER_MAINTENANCE_ROOT=/safe\n', encoding='utf-8')
    evil.write_text('TEC_TAC_SERVER_MAINTENANCE_ROOT=/evil\n', encoding='utf-8')
    os.chmod(safe, 0o600); os.chmod(evil, 0o600)
    cfg.write_text(safe.read_text(), encoding='utf-8'); os.chmod(cfg, 0o600)
    sm.CONFIG = cfg
    real_open = os.open
    switched = {'done': False}
    def racing_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if pathlib.Path(path) == cfg and not switched['done']:
            switched['done'] = True
            cfg.unlink()
            cfg.symlink_to(evil)
        return fd
    old_open = sm.os.open
    old_fstat = sm.os.fstat
    sm.os.open = racing_open
    if os.geteuid() != 0:
        sm.os.fstat = lambda fd: types.SimpleNamespace(**{**vars(old_fstat(fd)), 'st_uid': 0})
    try:
        values = sm._root_owned_layout()
    finally:
        sm.os.open = old_open
        sm.os.fstat = old_fstat
    assert values['TEC_TAC_SERVER_MAINTENANCE_ROOT'] == '/safe', values

# L38/L39: claims are no-clobber; results are root-published/read-only to Tactical.
with tempfile.TemporaryDirectory() as raw:
    td = pathlib.Path(raw)
    hk.STATE = td
    hk.ROOT = td / 'housekeeping'
    hk.RESULTS = hk.ROOT / 'results'
    hk.RUNNING = hk.ROOT / 'running'
    requests = hk.ROOT / 'requests'
    hk.ROOT.mkdir(); requests.mkdir(); hk.RESULTS.mkdir(mode=0o750); hk.RUNNING.mkdir(mode=0o700)
    reqid = str(uuid.uuid4())
    req = requests / f'{reqid}.json'
    req.write_text(json.dumps({'dry_run': True}), encoding='utf-8')
    first = hk.claim_request(req)
    original = first.read_bytes()
    try:
        hk.claim_request(req)
    except RuntimeError as exc:
        assert 'already claimed' in str(exc)
    else:
        raise AssertionError('duplicate housekeeping claim replaced the first claim')
    assert first.read_bytes() == original

    result_id = str(uuid.uuid4())
    published = hk._write_result(result_id, {'ok': True})
    assert published.is_file()
    os.chmod(hk.RESULTS, 0o770)
    try:
        hk._write_result(str(uuid.uuid4()), {'ok': True})
    except RuntimeError as exc:
        assert 'group/world writable' in str(exc)
    else:
        raise AssertionError('group-writable housekeeping results directory was accepted')

install = (ROOT / 'install.sh').read_text(encoding='utf-8')
assert 'chmod 2750 "${HOUSEKEEPING_ROOT}/results"' in install
assert '"${HOUSEKEEPING_ROOT}/results" "${HOUSEKEEPING_ROOT}/config"' not in install.split('chmod 2770', 1)[-1].split('\n', 1)[0]

print('maintenance/housekeeping hardening 1.15.137: PASS')
