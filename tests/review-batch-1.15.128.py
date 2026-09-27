#!/usr/bin/env python3
from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(sys.argv[1]).resolve()
HELPER = ROOT / 'scripts/server-backup-helper.py'
MAINT = ROOT / 'scripts/server-maintenance-helper.py'
REPO_VIEWS = ROOT / 'framwork/tec_tac/module_repository_views.py'

spec = importlib.util.spec_from_file_location('sb128', HELPER)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

class DummyLog:
    def __init__(self): self.lines=[]
    def write(self, text): self.lines.append(text)

# M19a: a native Tactical archive is temporary job staging and must be removed
# even if a later Tec-Tac/bundle step fails.
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    native = td / 'rmm-backup-test.tar'
    native.write_bytes(b'native')
    stage = td / 'stage'; stage.mkdir()
    class Lock:
        def close(self): pass
    h.acquire_lock = lambda config: Lock()
    h.roots = lambda config=None: {'staging': stage}
    h.set_job_stage = lambda *a, **k: None
    h.create_tactical_component = lambda config, log, job_id: (native, {'included': True, 'size_bytes': 6, 'sha256': hashlib.sha256(b'native').hexdigest()})
    def fail_tec(*a, **k): raise RuntimeError('later component failed')
    h.create_tec_tac_component = fail_tec
    job={'id':'00000000-0000-0000-0000-000000000001','request':{'backup_class':'daily','destinations':[],'include_tactical':True,'include_tec_tac':True}}
    try:
        h.operation_create_backup({}, job, DummyLog())
    except RuntimeError as exc:
        assert 'later component failed' in str(exc)
    else:
        raise AssertionError('expected later create-backup failure')
    assert not native.exists(), 'native Tactical archive survived a later create-backup failure'
print('M19 native Tactical staging cleanup: PASS')

# M19b: non-managers must never receive raw repository sync error details.
source = REPO_VIEWS.read_text(encoding='utf-8')
tree = ast.parse(source)
nodes=[]
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in {'_redact_repository_urls','_redact_repository_status_for_non_manager'}:
        nodes.append(node)
ns={'_SENSITIVE_REPOSITORY_KEYS': {'url','download_url','signature_url','release_metadata_url','source_url','repository_url'}}
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(REPO_VIEWS), 'exec'), ns)
payload=[{'id':'r1','url':'https://secret.example/repo.json','sync':{'status':'error','error':'TLS failed for https://secret.example/token?q=x'}}]
redacted=ns['_redact_repository_status_for_non_manager'](payload)
assert redacted[0]['sync']['error']=='Repository synchronization failed.'
assert 'url' not in redacted[0]
nested=ns['_redact_repository_status_for_non_manager']({'repositories':payload})
assert nested['repositories'][0]['sync']['error']=='Repository synchronization failed.'
assert 'url' not in nested['repositories'][0]
print('M19 repository sync error redaction: PASS')

# L09: size-only remote copies are not enough to delete local staging.
assert h.destination_results_strongly_verified([{'ok':True,'size_verified':True,'hash_verified':True}]) is True
assert h.destination_results_strongly_verified([{'ok':True,'size_verified':True,'hash_verified':False,'hash_supported':False}]) is False
assert h.destination_results_strongly_verified([]) is False
print('L09 strong verification gate: PASS')

# L10: every publisher makes the sidecar visible before the final archive.
text = HELPER.read_text(encoding='utf-8')
ftp_side=text.index('ftp.rename(partial_sidecar, final_sidecar)')
ftp_archive=text.index('ftp.rename(partial_name, archive.name)', ftp_side)
assert ftp_side < ftp_archive
r_side=text.index('["rclone", "moveto", partial_sidecar, sidecar_remote')
r_archive=text.index('["rclone", "moveto", partial_remote, archive_remote', r_side)
assert r_side < r_archive
scp_side=text.index('"mv -f -- {ps} {s} && "')
scp_archive=text.index('"(mv -f -- {p} {f}', scp_side)
assert scp_side < scp_archive
local_side=text.index('os.replace(sidecar_tmp, target_sidecar)')
local_archive=text.index('os.replace(archive_tmp, target)', local_side)
assert local_side < local_archive
print('L10 sidecar-first publication: PASS')

# L11: safe data filtering must preserve numeric ownership metadata.
member=tarfile.TarInfo('safe/file.txt'); member.uid=1234; member.gid=5678; member.uname='u'; member.gname='g'; member.size=0
with tempfile.TemporaryDirectory() as td:
    filtered=h._data_filter_preserve_numeric_owner(member, td)
    assert filtered.uid==1234 and filtered.gid==5678
    assert filtered.uname=='u' and filtered.gname=='g'
    bad=tarfile.TarInfo('../escape')
    try:
        h._data_filter_preserve_numeric_owner(bad, td)
    except (tarfile.FilterError, tarfile.OutsideDestinationError):
        pass
    else:
        raise AssertionError('data filter accepted an escaping member')
print('L11 numeric owner preservation: PASS')

# L12: ambiguous legacy FTP records must not silently switch transport mode.
base={'id':'ftp1','type':'ftp','host':'backup.example','username':'backup','remote_path':'backups'}
try:
    h.validate_destination(base,{})
except RuntimeError as exc:
    assert 'tls_mode is required' in str(exc)
else:
    raise AssertionError('FTP destination without tls_mode was silently accepted')
secure=h.validate_destination({**base,'tls_mode':'explicit'}, {})
assert secure['tls_mode']=='explicit'
plain=h.validate_destination({**base,'tls_mode':'none','allow_insecure_transport':True}, {})
assert plain['tls_mode']=='none'
print('L12 explicit FTP transport mode: PASS')

# L13: a malformed root config must not make either helper fail during import.
# Execute temporary copies with CONFIG redirected to a deliberately invalid file.
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    bad=td/'bad.conf'; bad.write_text('TEC_TAC_SERVER_BACKUP_ROOT=relative/path\nTEC_TAC_SERVER_MAINTENANCE_ROOT=relative/path\n', encoding='utf-8')
    os.chmod(bad,0o600)
    for original, label in ((HELPER,'backup'),(MAINT,'maintenance')):
        copy=td/f'{label}.py'
        src=original.read_text(encoding='utf-8').replace('CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")', f'CONFIG = Path({str(bad)!r})', 1)
        copy.write_text(src, encoding='utf-8')
        code=f'''\nimport importlib.util\nspec=importlib.util.spec_from_file_location("x", {str(copy)!r})\nm=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\ntry:\n    m.load_config()\nexcept RuntimeError:\n    pass\nelse:\n    raise AssertionError("invalid config did not fail closed at operation time")\n'''
        subprocess.run([sys.executable,'-c',code],check=True)
print('L13 import-safe invalid config handling: PASS')

print('review batch 1.15.128: PASS')
