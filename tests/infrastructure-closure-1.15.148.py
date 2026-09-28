#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import types
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def run(cmd, *, user=None):
    full = list(cmd)
    if user and os.geteuid() == 0 and shutil_which('runuser') and user_exists(user):
        full = ['runuser', '-u', user, '--', *full]
    subprocess.run(full, cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def shutil_which(name: str):
    import shutil
    return shutil.which(name)


def user_exists(name: str) -> bool:
    import pwd
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def test_m18_current_review_regressions_and_root_split():
    subprocess.run(['python3', 'tests/review-regressions-1.15.52.py'], cwd=ROOT, check=True)
    subprocess.run(['bash', 'tests/review-1.15.52-rebuild.sh'], cwd=ROOT, check=True)
    normal = '\n'.join((ROOT / p).read_text() for p in (
        'tests/review-hygiene-foundation.sh',
        'tests/module-management-foundation.sh',
        'tests/system-update-foundation.sh',
    ))
    root_runner = (ROOT / 'tests/root-required-foundation.sh').read_text()
    for name in ('system-update-claim-security.py', 'module-v2-verified-bytes-boundary.py'):
        assert f'python3 "${{ROOT}}/tests/{name}"' not in normal, f'{name} still executes in normal runner'
        assert f'python3 "${{ROOT}}/tests/{name}"' in root_runner, f'{name} missing from root-required runner'


def test_l61_portable_tests_are_wired_and_nonroot_capable():
    review = (ROOT / 'tests/review-hygiene-foundation.sh').read_text()
    tests = (
        'privileged-helper-environment.py',
        'module-artifact-immutable-claim.py',
        'server-backup-recovery-trust.py',
    )
    for name in tests:
        assert name in review, f'{name} not wired into review hygiene'
        cmd = ['python3', str(ROOT / 'tests' / name)]
        if os.geteuid() == 0 and shutil_which('runuser') and user_exists('nobody'):
            cmd = ['runuser', '-u', 'nobody', '--', *cmd]
        subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def test_l04_v1_staged_reader_rejects_symlink_and_fifo():
    mod = load_script('module_job_helper_148', 'scripts/module-job-helper.py')
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / 'real.json'
        target.write_text(json.dumps({'id': 'x'}))
        link = root / 'link.json'
        link.symlink_to(target)
        try:
            mod._read_json_nofollow(link, label='staged module metadata')
        except SystemExit:
            pass
        else:
            raise AssertionError('symlinked staged metadata was accepted')

        if hasattr(os, 'mkfifo'):
            fifo = root / 'fifo.json'
            os.mkfifo(fifo)
            try:
                mod._read_json_nofollow(fifo, label='staged module metadata')
            except SystemExit:
                pass
            else:
                raise AssertionError('FIFO staged metadata was accepted')


def test_l07_trusted_bash_runtime_fallback_and_permissions():
    subprocess.run(
        ['python3', str(ROOT / 'tests/root-bash-boundary.py')],
        cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def test_l36_maintenance_load_job_rejects_symlink_and_fifo():
    mod = load_script('maintenance_148', 'scripts/server-maintenance-helper.py')
    job_id = str(uuid.uuid4())
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        mod.JOBS_ROOT = root
        real = root / 'real.json'
        real.write_text(json.dumps({'id': job_id}))
        link = root / f'{job_id}.json'
        link.symlink_to(real)
        try:
            mod.load_job(job_id)
        except OSError:
            pass
        else:
            raise AssertionError('load_job followed symlink')
        link.unlink()

        if hasattr(os, 'mkfifo'):
            os.mkfifo(link)
            try:
                mod.load_job(job_id)
            except RuntimeError:
                pass
            else:
                raise AssertionError('load_job accepted FIFO')


def main():
    tests = [v for k,v in globals().items() if k.startswith('test_') and callable(v)]
    for test in sorted(tests, key=lambda f: f.__name__):
        test()
    print('[TEST] PASS infrastructure closure 1.15.148')


if __name__ == '__main__':
    main()
