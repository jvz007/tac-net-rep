#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT/framwork/tec_tac/module_manager_v2.py" <<'PY'
import ast
import hashlib
import json
import os
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

source_path = Path(sys.argv[1])
source = source_path.read_text(encoding='utf-8')
tree = ast.parse(source)
names = {'_PathUpload', '_copy_upload', '_bundle_manifest_count', 'stage_uploaded_artifact'}
nodes=[]
for node in tree.body:
    if isinstance(node, ast.ClassDef) and node.name in names:
        nodes.append(node)
    elif isinstance(node, ast.FunctionDef) and node.name in names:
        nodes.append(node)
module=ast.Module(body=nodes, type_ignores=[])
ast.fix_missing_locations(module)

class ModuleManagerError(RuntimeError): pass
class ModuleManagerV2Error(ModuleManagerError): pass
class LicensingRequirementError(ModuleManagerV2Error): pass

class Upload:
    def __init__(self, path, name):
        self.path=Path(path); self.name=name; self.size=self.path.stat().st_size
    def chunks(self, chunk_size=65536):
        with self.path.open('rb') as handle:
            while True:
                chunk=handle.read(chunk_size)
                if not chunk: break
                yield chunk

with tempfile.TemporaryDirectory() as td:
    root=Path(td)
    bundles=root/'bundles'; staged_root=root/'staged'; bundles.mkdir(); staged_root.mkdir()
    calls={'package':0,'bundle':0}

    def _atomic_json(path,payload):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(payload),encoding='utf-8')
    def _utcnow(): return 'now'
    def _inspect_bundle(path):
        calls['bundle']+=1
        return {'kind':'bundle','id':'suite','version':'1.0.0','packages':[{'id':'a','extension_version':'1.0.0'}], 'plan':{'valid':True}}
    def stage_uploaded_package(upload, signature_upload=None, metadata_upload=None):
        calls['package']+=1
        # This is the legacy failure a valid bundle must never reach.
        if upload.name == 'suite.zip':
            raise ModuleManagerError('Package must contain exactly one extension manifest; found 0')
        uid=str(uuid.uuid4())
        path=staged_root/f'{uid}.zip'
        with path.open('wb') as out:
            for chunk in upload.chunks(): out.write(chunk)
        _atomic_json(staged_root/f'{uid}.json', {'package_path':str(path)})
        return {'upload_id':uid,'filename':upload.name}
    def _load_stage(uid): return json.loads((staged_root/f'{uid}.json').read_text())
    def _package_metadata(path): return {'id':'single','extension_version':'1.0.0','installable':True}
    def _enforce_candidate_licensing(preview): return None
    def resolve_install_plan(candidates): return {'valid':True,'order':[c['id'] for c in candidates],'actions':[]}
    def _copy_sidecar(upload, path): raise AssertionError('unexpected sidecar in structural classification test')
    def _verify_stage_trust(meta, **kwargs):
        return {'signed':False,'verified':False,'trusted':False,'state':'unsigned','package_sha256':'test'}

    ns={
      'Path':Path,'hashlib':hashlib,'os':os,'uuid':uuid,'zipfile':zipfile,
      'MAX_PACKAGE_BYTES':50*1024*1024,'BUNDLES_ROOT':bundles,'STAGED_ROOT':staged_root,
      'BUNDLE_MANIFEST':'tec_tac_bundle.json','ModuleManagerError':ModuleManagerError,
      'ModuleManagerV2Error':ModuleManagerV2Error,'LicensingRequirementError':LicensingRequirementError,
      '_atomic_json':_atomic_json,'_utcnow':_utcnow,'_inspect_bundle':_inspect_bundle,
      'stage_uploaded_package':stage_uploaded_package,'_load_stage':_load_stage,
      '_package_metadata':_package_metadata,'_enforce_candidate_licensing':_enforce_candidate_licensing,
      'resolve_install_plan':resolve_install_plan,'_copy_sidecar':_copy_sidecar,'_verify_stage_trust':_verify_stage_trust,
    }
    exec(compile(module,'<bundle-intake>','exec'),ns)

    bundle=root/'suite.zip'
    with zipfile.ZipFile(bundle,'w') as zf:
        zf.writestr('tec_tac_bundle.json','{}')
        zf.writestr('packages/a.zip',b'a')
    out=ns['stage_uploaded_artifact'](Upload(bundle,'suite.zip'))
    assert out['kind']=='bundle', out
    assert calls['bundle']==1
    assert calls['package']==0, 'bundle incorrectly entered legacy single-package parser'

    package=root/'single.zip'
    with zipfile.ZipFile(package,'w') as zf:
        zf.writestr('extensions/single/tec_tac.json','{}')
    out=ns['stage_uploaded_artifact'](Upload(package,'single.zip'))
    assert out['preview']['kind']=='package', out
    assert calls['package']==1

print('PASS bundle-first artifact classification avoids legacy extension-manifest error')
PY
