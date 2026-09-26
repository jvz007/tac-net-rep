#!/usr/bin/env python3
"""Regression: v2 must verify, extract and install the exact same root-private bytes."""
import hashlib
import importlib.util
import json
import os
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


worker = load('module_v2_verified_bytes_test', ROOT / 'scripts' / 'module-v2-job-helper.py')


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def module_zip(path: Path, module_id: str, version: str, marker: str):
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr(f'extensions/{module_id}/tec_tac.json', json.dumps({
            'type': 'extension', 'id': module_id, 'version': version,
        }))
        zf.writestr(f'extensions/{module_id}/payload.txt', marker)


def bundle_zip(path: Path, child: Path, module_id: str, version: str):
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr('tec_tac_bundle.json', json.dumps({
            'type': 'bundle', 'id': 'suite', 'version': '1.0.0',
            'packages': [{'file': 'packages/a.zip', 'id': module_id, 'version': version}],
        }))
        zf.writestr('packages/a.zip', child.read_bytes())


def expect_hash_failure(fn, label: str):
    try:
        fn()
    except RuntimeError as exc:
        if 'SHA-256 changed after trust verification' not in str(exc):
            raise AssertionError(f'{label}: unexpected error: {exc}') from exc
    else:
        raise AssertionError(f'{label}: swapped artifact was accepted')


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    claim = root / 'claimed'
    execution = root / 'execution'
    claim.mkdir(); execution.mkdir()
    os.chmod(claim, 0o700); os.chmod(execution, 0o700)

    pkg_a = root / 'pkg-a.zip'; pkg_b = root / 'pkg-b.zip'
    module_zip(pkg_a, 'alpha', '1.0.0', 'SIGNED-A')
    module_zip(pkg_b, 'alpha', '1.0.0', 'UNSIGNED-B')
    bun_a = root / 'bundle-a.zip'; bun_b = root / 'bundle-b.zip'
    bundle_zip(bun_a, pkg_a, 'alpha', '1.0.0')
    bundle_zip(bun_b, pkg_b, 'alpha', '1.0.0')

    # Snapshot A out of the claim directory. Replacing the original claimed
    # pathname afterwards must not influence the execution copy.
    claimed_bundle = claim / 'bundle.zip'
    claimed_bundle.write_bytes(bun_a.read_bytes())
    os.chmod(claimed_bundle, 0o600)
    execution_bundle = Path(worker._execution_artifact_copy(claimed_bundle, claim, execution, 'bundle'))
    claimed_bundle.write_bytes(bun_b.read_bytes())
    assert sha(execution_bundle) == sha(bun_a), 'claim-path replacement changed execution snapshot'

    mapping = [{'id': 'alpha', 'file': 'packages/a.zip', 'version': '1.0.0'}]

    # Reviewer case: the verifier reports trust for A and then the file it was
    # asked to verify is swapped to B before extraction. The mandatory hash
    # re-check must stop B before extraction/install planning.
    original_verify = worker._privileged_verify_artifact
    def swap_after_verify(_config, path, signature=None, metadata=None):
        path = Path(path)
        trust = {
            'package_sha256': sha(path),
            'artifact_modules': [{'id': 'alpha', 'version': '1.0.0', 'previous_module_ids': []}],
            'artifact_package_files': mapping,
        }
        path.write_bytes(bun_b.read_bytes())
        return trust
    worker._privileged_verify_artifact = swap_after_verify
    try:
        job = {'action': 'bundle_install', 'bundle_path': str(execution_bundle), 'source': 'upload'}
        trust = worker._verify_v2_job_trust({}, job)[0]
        extract_root = root / 'bundle-run'
        extract_root.mkdir()
        expect_hash_failure(lambda: worker.bundle_packages(job, extract_root, trust), 'bundle install')
        assert not (extract_root / 'bundle').exists(), 'swapped bundle reached extraction'
    finally:
        worker._privileged_verify_artifact = original_verify

    # Standalone batch artifact: no post-verification copy is permitted and the
    # same hash boundary must reject mutation before install_packages can see it.
    standalone = execution / 'standalone-alpha.zip'
    standalone.write_bytes(pkg_a.read_bytes())
    trust = {
        'package_sha256': sha(standalone),
        'artifact_modules': [{'id': 'alpha', 'version': '1.0.0', 'previous_module_ids': []}],
        'artifact_package_files': [],
    }
    standalone.write_bytes(pkg_b.read_bytes())
    batch = {'artifacts': [{'kind': 'package', 'id': 'alpha', 'path': str(standalone), 'source': 'upload'}]}
    batch_run = root / 'batch-run'; batch_run.mkdir()
    expect_hash_failure(lambda: worker.batch_packages(batch, batch_run, [trust]), 'standalone batch')

    # Bundle inside a batch has the same exact-bytes requirement.
    batch_bundle = execution / 'batch-bundle.zip'
    batch_bundle.write_bytes(bun_a.read_bytes())
    trust = {
        'package_sha256': sha(batch_bundle),
        'artifact_modules': [{'id': 'alpha', 'version': '1.0.0', 'previous_module_ids': []}],
        'artifact_package_files': mapping,
    }
    batch_bundle.write_bytes(bun_b.read_bytes())
    batch = {'artifacts': [{'kind': 'bundle', 'bundle_path': str(batch_bundle), 'source': 'upload'}]}
    batch_bundle_run = root / 'batch-bundle-run'; batch_bundle_run.mkdir()
    expect_hash_failure(lambda: worker.batch_packages(batch, batch_bundle_run, [trust]), 'batch bundle')
    assert not (batch_bundle_run / 'bundle-0').exists(), 'swapped batch bundle reached extraction'

print('PASS v2 verification/extraction/install use one root-private byte identity')
