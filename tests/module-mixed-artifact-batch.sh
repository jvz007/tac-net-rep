#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT/framwork/tec_tac/module_manager_v2.py" "$ROOT/scripts/module-v2-job-helper.py" <<'PY'
import ast
import shutil
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

manager_path = Path(sys.argv[1])
helper_path = Path(sys.argv[2])

# Exercise stage_multiple_packages with one standalone package plus one bundle.
source = manager_path.read_text(encoding='utf-8')
tree = ast.parse(source)
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'stage_multiple_packages')
module = ast.Module(body=[node], type_ignores=[])
ast.fix_missing_locations(module)

class ModuleManagerV2Error(RuntimeError):
    pass
class ModuleManagerError(RuntimeError):
    pass

class Upload:
    def __init__(self, name): self.name = name

stages = {
    'standalone.zip': {
        'kind': 'package', 'upload_id': str(uuid.uuid4()),
        'preview': {'id': 'standalone', 'extension_version': '1.0.0', 'dependencies': {}, 'runtime_requirements': []},
    },
    'suite-bundle.zip': {
        'kind': 'bundle', 'upload_id': str(uuid.uuid4()),
        'preview': {
            'kind': 'bundle', 'id': 'suite', 'version': '2.0.0',
            'packages': [
                {'id': 'base', 'extension_version': '2.0.0', 'dependencies': {}, 'runtime_requirements': []},
                {'id': 'consumer', 'extension_version': '2.0.0', 'dependencies': {'base': '>=2'}, 'runtime_requirements': []},
            ],
        },
    },
}

def stage_uploaded_artifact(upload): return dict(stages[upload.name])
def resolve_install_plan(candidates):
    ids = [c['id'] for c in candidates]
    assert ids == ['standalone', 'base', 'consumer'], ids
    return {'valid': True, 'problems': [], 'order': ['standalone', 'base', 'consumer'], 'actions': []}
def _utcnow(): return 'now'
def _atomic_json(path, payload): pass
def discard_v2_stage(upload_id): pass

def _load_stage(upload_id): raise AssertionError('package preview should already contain id')
def _package_metadata(path): raise AssertionError('should not reload package metadata')

with tempfile.TemporaryDirectory() as td:
    ns = {
        'ModuleManagerV2Error': ModuleManagerV2Error,
        'ModuleManagerError': ModuleManagerError,
        'Path': Path,
        'uuid': uuid,
        'BATCHES_ROOT': Path(td),
        'stage_uploaded_artifact': stage_uploaded_artifact,
        'resolve_install_plan': resolve_install_plan,
        '_utcnow': _utcnow,
        '_atomic_json': _atomic_json,
        'discard_v2_stage': discard_v2_stage,
        '_load_stage': _load_stage,
        '_package_metadata': _package_metadata,
    }
    exec(compile(module, '<stage_multiple_packages>', 'exec'), ns)
    payload = ns['stage_multiple_packages']([Upload('standalone.zip'), Upload('suite-bundle.zip')])
    assert payload['kind'] == 'batch'
    assert len(payload['artifacts']) == 2
    assert [x['kind'] for x in payload['artifacts']] == ['package', 'bundle']
    assert [x['preview']['id'] for x in payload['packages']] == ['standalone', 'base', 'consumer']
    assert payload['plan']['valid'] is True

# Exercise worker expansion: one standalone staged package + one bundle becomes
# three concrete install packages in a single batch.
source = helper_path.read_text(encoding='utf-8')
tree = ast.parse(source)
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'batch_packages')
module = ast.Module(body=[node], type_ignores=[])
ast.fix_missing_locations(module)

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    staged = root / 'staged'
    running = root / 'running'
    staged.mkdir(); running.mkdir()
    standalone = staged / 'standalone.zip'
    standalone.write_bytes(b'package')
    bundle = staged / 'bundle.zip'
    with zipfile.ZipFile(bundle, 'w') as zf:
        zf.writestr('packages/base.zip', b'base')
        zf.writestr('packages/consumer.zip', b'consumer')

    ns = {'Path': Path, 'shutil': shutil, 'zipfile': zipfile, 'STAGED_ROOT': staged}
    exec(compile(module, '<batch_packages>', 'exec'), ns)
    result = ns['batch_packages']({
        'artifacts': [
            {'kind': 'package', 'id': 'standalone', 'path': str(standalone), 'upload_id': str(uuid.uuid4())},
            {'kind': 'bundle', 'bundle_id': 'suite', 'bundle_path': str(bundle), 'upload_id': str(uuid.uuid4()),
             'package_files': [
                 {'id': 'base', 'file': 'packages/base.zip', 'version': '2.0.0'},
                 {'id': 'consumer', 'file': 'packages/consumer.zip', 'version': '2.0.0'},
             ]},
        ]
    }, running)
    assert [x['id'] for x in result] == ['standalone', 'base', 'consumer'], result
    assert all(Path(x['path']).is_file() for x in result)

print('PASS mixed package/bundle multi-file batches are flattened and installable')
PY
