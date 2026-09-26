import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('housekeeping_helper', ROOT / 'scripts' / 'housekeeping-helper.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

with tempfile.TemporaryDirectory() as td:
    base = pathlib.Path(td)
    h.STATE = base
    h.ROOT = base / 'housekeeping'
    h.RESULTS = h.ROOT / 'results'
    h.RUNNING = h.ROOT / 'running'
    requests = h.ROOT / 'requests'
    requests.mkdir(parents=True)
    h.RESULTS.mkdir()
    h.RUNNING.mkdir(mode=0o700)

    request_id = str(uuid.uuid4())
    source = requests / f'{request_id}.json'
    original = {'dry_run': True, 'categories': [], 'policies': {}, 'allow_zero_destructive': False}
    source.write_text(json.dumps(original), encoding='utf-8')

    claimed = h.claim_request(source)
    assert claimed.parent == h.RUNNING
    assert claimed.name == f'{request_id}.json'
    assert claimed.stat().st_mode & 0o777 == 0o600

    # The mutable Tactical-side request can change after claim, but execution
    # must continue from the root-owned claimed copy.
    source.write_text(json.dumps({'allow_zero_destructive': True}), encoding='utf-8')
    assert json.loads(claimed.read_text(encoding='utf-8')) == original

    claimed.unlink()
    source.unlink()

    target = requests / 'target.json'
    target.write_text('{}', encoding='utf-8')
    link_id = str(uuid.uuid4())
    link = requests / f'{link_id}.json'
    link.symlink_to(target)
    try:
        h.claim_request(link)
    except OSError:
        pass
    else:
        raise AssertionError('symlinked housekeeping request was accepted')
    link.unlink()

    # Regression: a swapped running/ symlink must be rejected before any
    # chmod/chown/write follows it.
    sentinel = base / 'sentinel-running'
    sentinel.mkdir(mode=0o755)
    before = sentinel.lstat()
    h.RUNNING.rmdir()
    h.RUNNING.symlink_to(sentinel, target_is_directory=True)
    run_id = str(uuid.uuid4())
    run_req = requests / f'{run_id}.json'
    run_req.write_text(json.dumps(original), encoding='utf-8')
    try:
        h.claim_request(run_req)
    except RuntimeError:
        pass
    else:
        raise AssertionError('symlinked running directory was accepted')
    after = sentinel.lstat()
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode) == 0o755
    assert after.st_uid == before.st_uid and after.st_gid == before.st_gid
    assert not (sentinel / f'{run_id}.json').exists()
    h.RUNNING.unlink()
    h.RUNNING.mkdir(mode=0o700)

    # Regression: a swapped results/ symlink must likewise be rejected before
    # result publication can alter the sentinel directory or create a result.
    sentinel_results = base / 'sentinel-results'
    sentinel_results.mkdir(mode=0o755)
    before = sentinel_results.lstat()
    h.RESULTS.rmdir()
    h.RESULTS.symlink_to(sentinel_results, target_is_directory=True)
    result_id = str(uuid.uuid4())
    try:
        h._write_result(result_id, {'ok': True})
    except RuntimeError:
        pass
    else:
        raise AssertionError('symlinked results directory was accepted')
    after = sentinel_results.lstat()
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode) == 0o755
    assert after.st_uid == before.st_uid and after.st_gid == before.st_gid
    assert not (sentinel_results / f'{result_id}.json').exists()

print('housekeeping request claim security: PASS')
