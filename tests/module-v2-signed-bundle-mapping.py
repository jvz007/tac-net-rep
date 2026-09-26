#!/usr/bin/env python3
import importlib.util
import json
import hashlib
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

trust = load('privileged_trust_test', ROOT / 'scripts' / 'privileged-trust.py')
worker = load('module_v2_worker_test', ROOT / 'scripts' / 'module-v2-job-helper.py')

def module_zip(path: Path, module_id: str, version: str):
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr(f'extensions/{module_id}/tec_tac.json', json.dumps({
            'type': 'extension', 'id': module_id, 'version': version,
        }))

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    a = root / 'a.zip'; b = root / 'b.zip'
    module_zip(a, 'alpha', '1.2.3')
    module_zip(b, 'beta', '4.5.6')

    bundle = root / 'bundle.zip'
    with zipfile.ZipFile(bundle, 'w') as zf:
        zf.writestr('tec_tac_bundle.json', json.dumps({
            'type': 'bundle', 'id': 'suite', 'version': '9.0.0',
            'packages': [
                {'file': 'packages/a.zip', 'id': 'alpha', 'version': '1.2.3'},
                'packages/b.zip',
            ],
        }))
        zf.writestr('packages/a.zip', a.read_bytes())
        zf.writestr('packages/b.zip', b.read_bytes())

    mapping = trust._artifact_bundle_package_files(bundle)
    assert mapping == [
        {'id': 'alpha', 'file': 'packages/a.zip', 'version': '1.2.3'},
        {'id': 'beta', 'file': 'packages/b.zip', 'version': '4.5.6'},
    ], mapping


    nested = root / 'nested-bundle.zip'
    with zipfile.ZipFile(nested, 'w') as zf:
        zf.writestr('suite/tec_tac_bundle.json', json.dumps({
            'type': 'bundle', 'id': 'nested', 'version': '1.0.0',
            'packages': ['packages/a.zip'],
        }))
        zf.writestr('suite/packages/a.zip', a.read_bytes())
    nested_mapping = trust._artifact_bundle_package_files(nested)
    assert nested_mapping == [{'id': 'alpha', 'file': 'suite/packages/a.zip', 'version': '1.2.3'}], nested_mapping

    bad = root / 'bad-bundle.zip'
    with zipfile.ZipFile(bad, 'w') as zf:
        zf.writestr('tec_tac_bundle.json', json.dumps({
            'type': 'bundle', 'id': 'suite', 'version': '9.0.0',
            'packages': [{'file': 'packages/a.zip', 'id': 'beta', 'version': '1.2.3'}],
        }))
        zf.writestr('packages/a.zip', a.read_bytes())
    try:
        trust._artifact_bundle_package_files(bad)
    except RuntimeError as exc:
        assert 'expected module' in str(exc)
    else:
        raise AssertionError('signed bundle id mismatch was accepted')

    running = root / 'running'; running.mkdir()
    # The mutable job lies: it reverses the module ids and versions for the two files.
    # bundle_packages must ignore this mapping and use only the root-verifier result.
    job = {
        'bundle_path': str(bundle),
        'source': 'upload',
        'bundle': {'package_files': [
            {'id': 'beta', 'file': 'packages/a.zip', 'version': '99.0.0'},
            {'id': 'alpha', 'file': 'packages/b.zip', 'version': '99.0.0'},
        ]},
    }
    rows = worker.bundle_packages(job, running, {'artifact_package_files': mapping, 'package_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest()})
    assert [(r['id'], r['version'], Path(r['path']).name) for r in rows] == [
        ('alpha', '1.2.3', 'a.zip'), ('beta', '4.5.6', 'b.zip')
    ], rows

    running2 = root / 'running2'; running2.mkdir()
    batch = {
        'artifacts': [{
            'kind': 'bundle', 'bundle_path': str(bundle), 'source': 'upload',
            'package_files': [
                {'id': 'beta', 'file': 'packages/a.zip', 'version': '99.0.0'},
                {'id': 'alpha', 'file': 'packages/b.zip', 'version': '99.0.0'},
            ],
        }]
    }
    rows = worker.batch_packages(batch, running2, [{'artifact_package_files': mapping, 'package_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest()}])
    assert [(r['id'], r['version'], Path(r['path']).name) for r in rows] == [
        ('alpha', '1.2.3', 'a.zip'), ('beta', '4.5.6', 'b.zip')
    ], rows

print('PASS v2 bundle child file/module mapping is derived from root-verified signed bytes')
