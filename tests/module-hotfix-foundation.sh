#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ -f "${ROOT}/framwork/tec_tac/module_hotfix.py" ]] || fail "module hotfix manager missing"
[[ -f "${ROOT}/framwork/tec_tac/module_hotfix_views.py" ]] || fail "module hotfix API views missing"
[[ -f "${ROOT}/scripts/module-hotfix-job-helper.py" ]] || fail "module hotfix privileged helper missing"
[[ -f "${ROOT}/docs/module-hotfixes.md" ]] || fail "module hotfix documentation missing"

grep -q 'modules/hotfixes/inspect/' "${ROOT}/framwork/tec_tac/urls.py" || fail "hotfix inspect route missing"
grep -q 'hotfixes/<str:hotfix_id>/rollback/' "${ROOT}/framwork/tec_tac/urls.py" || fail "hotfix rollback route missing"
grep -q '/usr/local/sbin/tec-tac-module-hotfix' "${ROOT}/install.sh" || fail "hotfix helper install missing"
grep -q 'MODULE_HOTFIX_SUDOERS' "${ROOT}/install.sh" || fail "hotfix sudoers install missing"
grep -q 'tec-tac-module-hotfix --supersede' "${ROOT}/scripts/install-extension.sh" || fail "normal module upgrade does not supersede hotfixes"
grep -q 'tec-tac-module-hotfix --supersede' "${ROOT}/scripts/remove-extension.sh" || fail "module removal does not retire hotfixes"
grep -q 'hotfix_summary' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "module catalog hotfix summary missing"

python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/module_hotfix.py" \
  "${ROOT}/framwork/tec_tac/module_hotfix_views.py" \
  "${ROOT}/scripts/module-hotfix-job-helper.py"

PYTHONPATH="${ROOT}/framwork" python3 - "${ROOT}" <<'PY'
import hashlib
import json
import tempfile
import zipfile
from pathlib import Path
import tec_tac.module_hotfix as hotfix

root = Path(__import__('sys').argv[1])
with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    ext = base / 'extensions' / 'cybercns'
    rep = base / 'reportsets' / 'cybercns'
    ext.mkdir(parents=True); rep.mkdir(parents=True)
    for directory, kind in ((ext, 'extension'), (rep, 'reportset')):
        (directory / 'tec_tac.json').write_text(json.dumps({
            'id': 'cybercns', 'type': kind, 'version': '0.1.13', 'python_paths': ['.'], 'django_apps': []
        }), encoding='utf-8')
    target = ext / 'cybercns' / 'secrets.py'
    target.parent.mkdir()
    original = b"VALUE = 'old'\n"
    replacement = b"VALUE = 'new'\n"
    target.write_bytes(original)
    config = base / 'tec-tac.conf'
    config.write_text(f'TEC_TAC_EXTENSIONS_ROOT={base / "extensions"}\nTEC_TAC_REPORTSETS_ROOT={base / "reportsets"}\n', encoding='utf-8')
    hotfix.CONFIG_FILE = config
    hotfix.HOTFIX_APPLIED_ROOT = base / 'applied'
    before = hashlib.sha256(original).hexdigest()
    after = hashlib.sha256(replacement).hexdigest()
    manifest = {
        'type': 'tec-tac-hotfix', 'schema': 1, 'id': 'HF001', 'module_id': 'cybercns', 'base_version': '0.1.13',
        'description': 'test', 'targets': [{
            'component': 'extension', 'path': 'cybercns/secrets.py', 'sha256_before': before, 'sha256_after': after,
        }],
    }
    package = base / 'hotfix.zip'
    with zipfile.ZipFile(package, 'w') as zf:
        zf.writestr('cybercns-0.1.13-HF001/tec_tac_hotfix.json', json.dumps(manifest))
        zf.writestr('cybercns-0.1.13-HF001/payload/extension/cybercns/secrets.py', replacement)
    preview = hotfix.inspect_hotfix_archive(package)
    assert preview['module_id'] == 'cybercns'
    assert preview['id'] == 'HF001'
    assert preview['base_version'] == '0.1.13'
    assert preview['reload'] == 'django'
    assert preview['validation']['python_compile'] is True
    assert preview['validation']['django_check'] is True
    assert preview['targets'][0]['installed_sha256'] == before

    bad = dict(manifest)
    bad['targets'] = [dict(manifest['targets'][0], path='migrations/0002_bad.py')]
    bad_pkg = base / 'bad.zip'
    with zipfile.ZipFile(bad_pkg, 'w') as zf:
        zf.writestr('tec_tac_hotfix.json', json.dumps(bad))
        zf.writestr('payload/extension/migrations/0002_bad.py', replacement)
    try:
        hotfix.inspect_hotfix_archive(bad_pkg)
    except hotfix.ModuleHotfixError as exc:
        assert 'migrations' in str(exc)
    else:
        raise AssertionError('migration hotfix target was not rejected')

print('[TEST] managed module hotfix contract OK')
PY

python3 - "${ROOT}" <<'PY_HELPER'
import hashlib
import importlib.util
import json
import tempfile
import zipfile
from pathlib import Path
import sys

root=Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('hotfix_helper', root/'scripts/module-hotfix-job-helper.py')
helper=importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
with tempfile.TemporaryDirectory() as tmp:
    base=Path(tmp)
    helper.HOTFIX_ROOT=base/'hotfixes'; helper.STAGED_ROOT=helper.HOTFIX_ROOT/'staged'; helper.JOBS_ROOT=helper.HOTFIX_ROOT/'jobs'
    helper.LOGS_ROOT=helper.HOTFIX_ROOT/'logs'; helper.RUNNING_ROOT=helper.HOTFIX_ROOT/'running'; helper.BACKUPS_ROOT=helper.HOTFIX_ROOT/'backups'
    helper.APPLIED_ROOT=helper.HOTFIX_ROOT/'applied'; helper.HISTORY_ROOT=helper.HOTFIX_ROOT/'history'
    for path in (helper.STAGED_ROOT,helper.JOBS_ROOT,helper.LOGS_ROOT,helper.RUNNING_ROOT,helper.BACKUPS_ROOT,helper.APPLIED_ROOT,helper.HISTORY_ROOT): path.mkdir(parents=True,exist_ok=True)
    ext=base/'extensions/cybercns'; rep=base/'reportsets/cybercns'; ext.mkdir(parents=True); rep.mkdir(parents=True)
    for module_root,ptype in ((ext,'extension'),(rep,'reportset')):
        (module_root/'tec_tac.json').write_text(json.dumps({'id':'cybercns','type':ptype,'version':'0.1.13'}),encoding='utf-8')
    target=ext/'cybercns/secrets.py'; target.parent.mkdir(); original=b"VALUE='old'\n"; replacement=b"VALUE='new'\n"; target.write_bytes(original)
    before=hashlib.sha256(original).hexdigest(); after=hashlib.sha256(replacement).hexdigest()
    manifest={'type':'tec-tac-hotfix','schema':1,'id':'HF001','module_id':'cybercns','base_version':'0.1.13','targets':[{'component':'extension','path':'cybercns/secrets.py','sha256_before':before,'sha256_after':after}]}
    package=helper.STAGED_ROOT/'package.zip'
    with zipfile.ZipFile(package,'w') as archive:
        archive.writestr('wrapper/tec_tac_hotfix.json',json.dumps(manifest)); archive.writestr('wrapper/payload/extension/cybercns/secrets.py',replacement)
    config={'TEC_TAC_EXTENSIONS_ROOT':str(base/'extensions'),'TEC_TAC_REPORTSETS_ROOT':str(base/'reportsets'),'TACTICAL_USER':'root'}
    helper.validate_runtime=lambda *args,**kwargs: None; helper.sync_reload=lambda *args,**kwargs: None
    apply={'id':'00000000-0000-0000-0000-000000000001','module_id':'cybercns','hotfix_id':'HF001','package_path':str(package),'package_sha256':helper.sha256_file(package),'base_version':'0.1.13','requested_by':'test','upload_id':'00000000-0000-0000-0000-000000000002'}
    apply_path=helper.JOBS_ROOT/(apply['id']+'.json'); helper.atomic_json(apply_path,apply)
    with (helper.LOGS_ROOT/'apply.log').open('w',encoding='utf-8') as log: helper.apply_job(apply_path,apply,config,log)
    assert target.read_bytes()==replacement
    rollback={'id':'00000000-0000-0000-0000-000000000003','module_id':'cybercns','hotfix_id':'HF001','requested_by':'test'}
    rollback_path=helper.JOBS_ROOT/(rollback['id']+'.json'); helper.atomic_json(rollback_path,rollback)
    with (helper.LOGS_ROOT/'rollback.log').open('w',encoding='utf-8') as log: helper.rollback_job(rollback_path,rollback,config,log)
    assert target.read_bytes()==original
    assert not (helper.APPLIED_ROOT/'cybercns/HF001.json').exists()
print('[TEST] privileged hotfix apply/rollback transaction OK')
PY_HELPER

echo "[TEST] PASS managed module hotfix foundation"
