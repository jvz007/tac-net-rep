#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT/framwork/tec_tac/module_repository.py" <<'PY'
import ast
import hashlib
import sys
import tempfile
import urllib.parse
from pathlib import Path

path=Path(sys.argv[1]); tree=ast.parse(path.read_text())
node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='stage_repository_package')
module=ast.Module(body=[node],type_ignores=[]); ast.fix_missing_locations(module)

class ModuleRepositoryError(RuntimeError): pass
class LicensingRequirementError(RuntimeError): pass
class _PathUpload:
    def __init__(self,path,name): self.path=Path(path); self.name=name; self.size=self.path.stat().st_size
    def chunks(self,chunk_size=65536): yield self.path.read_bytes()

payload=b'bundle-bytes'; digest=hashlib.sha256(payload).hexdigest(); attached={}
def _repo(rid): return {'id':rid,'name':'Repo','trust':'internal','url':'https://repo/index.json','enabled':True}
def installed_catalog_v2(): return []
def _cached_modules(repo): return [{'id':'alerts','version':'0.4.0','download_url':'https://repo/alerts-suite.zip','sha256':digest}]
def version_satisfies(a,b): return False
def _fetch(url,maxsize): return payload
def stage_uploaded_artifact(upload, signature_upload=None, metadata_upload=None):
    return {'kind':'bundle','upload_id':'u1','preview':{'kind':'bundle','id':'alerts-suite','version':'0.4.0','packages':[{'id':'alerts','extension_version':'0.4.0'},{'id':'notifications','extension_version':'0.1.0'}]}}
def discard_v2_stage(uid): raise AssertionError('valid bundle should not be discarded')
def attach_source_provenance(uid,source): attached.update(source)
def _utcnow(): return 'now'

ns=globals().copy(); ns.update({'MAX_PACKAGE_BYTES':50*1024*1024, 'urllib':urllib, 'tempfile':tempfile})
exec(compile(module,'<repo-stage>','exec'),ns)
out=ns['stage_repository_package']('r1','alerts','0.4.0')
assert out['kind']=='bundle'
assert out['source']['artifact_kind']=='bundle'
assert out['source']['bundle_id']=='alerts-suite'
assert attached['requested_module_id']=='alerts'
print('PASS repository staging accepts bundles containing the requested module/version')
PY
