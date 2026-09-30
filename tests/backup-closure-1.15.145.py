#!/usr/bin/env python3
from __future__ import annotations
import ast, hashlib, importlib.util, io, json, os, pathlib, stat, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]

def load(name, rel):
    spec=importlib.util.spec_from_file_location(name, ROOT/rel); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
h=load('backup145','scripts/server-backup-helper.py')
sm=load('maint145','scripts/server-maintenance-helper.py')

def must(c,m):
    if not c: raise AssertionError(m)
class Log:
    def write(self,*a): pass

# M19a: native Tactical tar is transient even if a later component fails.
with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td); native=td/'rmm-backup-test.tar'; native.write_bytes(b'x'); stage=td/'stage'; stage.mkdir()
    class Lock:
        def close(self): pass
    old=(h.acquire_lock,h.roots,h.set_job_stage,h.create_tactical_component,h.create_tec_tac_component)
    h.acquire_lock=lambda c:Lock(); h.roots=lambda c=None:{'staging':stage}; h.set_job_stage=lambda *a,**k:None
    h.create_tactical_component=lambda *a,**k:(native,{'included':True,'size_bytes':1,'sha256':hashlib.sha256(b'x').hexdigest()})
    h.create_tec_tac_component=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('later failure'))
    try:
        try:h.operation_create_backup({}, {'id':'1','request':{'backup_class':'daily','destinations':[],'include_tactical':True,'include_tec_tac':True}}, Log())
        except RuntimeError: pass
        must(not native.exists(),'native Tactical tar survived later failure')
    finally:
        h.acquire_lock,h.roots,h.set_job_stage,h.create_tactical_component,h.create_tec_tac_component=old

# M19b: execute real redaction helper and repository error policy.
src=(ROOT/'framwork/tec_tac/module_repository_views.py').read_text(); tree=ast.parse(src)
nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in {'_redact_repository_status_for_non_manager','_repository_error'}]
class Resp:
    def __init__(self,data,status=200): self.data=data; self.status_code=status
ns={'_SENSITIVE_REPOSITORY_KEYS':{'url','download_url','signature_url','release_metadata_url','source_url','repository_url'},'Response':Resp,'_can_manage_modules':lambda u:bool(u)}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'repo_views','exec'),ns)
payload=[{'url':'https://secret.invalid','sync':{'error':'TLS token=secret'}}]
r=ns['_redact_repository_status_for_non_manager'](payload)
must('url' not in r[0] and r[0]['sync']['error']=='Repository synchronization failed.','non-manager status leaked raw repository detail')
must(ns['_repository_error'](type('R',(),{'user':False})(),RuntimeError('secret')).data['detail']=='Repository operation failed.','non-manager error leaked raw detail')
must(ns['_repository_error'](type('R',(),{'user':True})(),RuntimeError('secret')).data['detail']=='secret','manager lost diagnostic detail')

# L10: local publication never exposes archive before sidecar; failure after sidecar leaves no new archive.
with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td); srcp=td/'src.tgz'; srcp.write_bytes(b'abc'); dest=td/'dest'; meta={'size_bytes':3,'sha256':hashlib.sha256(b'abc').hexdigest()}
    calls=[]; real_replace=h.os.replace
    def repl(a,b):
        calls.append((pathlib.Path(a).name,pathlib.Path(b).name))
        if str(b).endswith('src.tgz'): raise RuntimeError('archive publish fail')
        return real_replace(a,b)
    h.os.replace=repl
    try:
        try:h.store_local({'id':'x','type':'local','path':str(dest)},srcp,meta)
        except RuntimeError: pass
        else: raise AssertionError('local archive publication failure not raised')
    finally:h.os.replace=real_replace
    final_side=next(i for i,(_,b) in enumerate(calls) if b=='src.tgz.tectac.json')
    final_hash=next(i for i,(_,b) in enumerate(calls) if b=='src.tgz.sha256')
    archive_attempt=next(i for i,(_,b) in enumerate(calls) if b=='src.tgz')
    must(final_side < archive_attempt,'local archive attempted before sidecar')
    must(final_hash < archive_attempt,'local archive attempted before hash companion')
    must(not (dest/'src.tgz').exists(),'local archive visible after failed archive publish')
    must(not (dest/'src.tgz.tectac.json').exists(),'local sidecar survived failed archive publish')
    must(not (dest/'src.tgz.sha256').exists(),'local hash companion survived failed archive publish')

# L10 FTP: if final archive rename fails, published sidecar is removed.
class FTP:
    def __init__(self): self.deleted=[]; self.renamed=[]
    def storbinary(self,*a,**k): pass
    def size(self,n):
        if n in {'a.tgz','a.tgz.tectac.json','a.tgz.sha256'}:
            raise h.ftplib.error_perm('550 not found')
        return 3
    def retrbinary(self,cmd,cb,blocksize=0): cb(b'abc')
    def delete(self,n): self.deleted.append(n)
    def rename(self,a,b):
        self.renamed.append((a,b))
        if b=='a.tgz': raise RuntimeError('rename fail')
    def quit(self): pass
    def close(self): pass
ftp=FTP(); old=(h.ftp_connect,h.ftp_prepare_path); h.ftp_connect=lambda *a,**k:ftp; h.ftp_prepare_path=lambda *a,**k:None
with tempfile.TemporaryDirectory() as td:
    p=pathlib.Path(td)/'a.tgz'; p.write_bytes(b'abc'); meta={'size_bytes':3,'sha256':hashlib.sha256(b'abc').hexdigest()}
    try:
        try:h.ftp_store({}, {'id':'x','type':'ftp','host':'h','port':21,'username':'u','remote_path':'/'},p,meta,Log())
        except RuntimeError: pass
        else: raise AssertionError('FTP archive rename failure not raised')
    finally:h.ftp_connect,h.ftp_prepare_path=old
must(('a.tgz.tectac.json.partial','a.tgz.tectac.json') in ftp.renamed,'FTP did not publish sidecar first')
must(('a.tgz.sha256.partial','a.tgz.sha256') in ftp.renamed,'FTP did not publish hash companion before archive')
must(ftp.renamed.index(('a.tgz.tectac.json.partial','a.tgz.tectac.json')) < ftp.renamed.index(('a.tgz.partial','a.tgz')),'FTP archive attempted before sidecar')
must(ftp.renamed.index(('a.tgz.sha256.partial','a.tgz.sha256')) < ftp.renamed.index(('a.tgz.partial','a.tgz')),'FTP archive attempted before hash companion')
must('a.tgz.tectac.json' in ftp.deleted,'FTP did not roll back published sidecar')
must('a.tgz.sha256' in ftp.deleted,'FTP did not roll back published hash companion')

# L14: all backup/recovery helpers resolve installer-selected config through a root-owned no-follow pointer.
with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td); custom=td/'custom.conf'; custom.write_text('TEC_TAC_ROOT=/srv/tec-tac\n'); os.chmod(custom,0o600)
    ptr=td/'config-path'; ptr.write_text(str(custom)+'\n'); os.chmod(ptr,0o600)
    must(h._installed_config_path(ptr,pathlib.Path('/fallback'))==custom,'backup helper ignored custom config')
    must(sm._installed_config_path(ptr,pathlib.Path('/fallback'))==custom,'maintenance helper ignored custom config')
    ptr.unlink(); ptr.symlink_to(custom)
    for fn in (h._installed_config_path,sm._installed_config_path):
        try:fn(ptr,pathlib.Path('/fallback'))
        except RuntimeError: pass
        else: raise AssertionError('symlinked config pointer accepted')

# L15: host snapshot bytes materially change the real disk preflight decision.
report=h._vr_new({'restore_mode':'tec_tac'},'bundle.tgz'); cfg={'TEC_TAC_SERVER_BACKUP_ROOT':'/tmp/x','TACTICAL_ROOT':'/tmp/t','TEC_TAC_STATE_ROOT':'/tmp/s','TEC_TAC_ROOT':'/tmp/c','TEC_TAC_FRAMEWORK_SOURCE':'/tmp/f','TEC_TAC_UI_SOURCE':'/tmp/u','TEC_TAC_UI_DEPLOY_ROOT':'/tmp/d'}
old=(h.shutil.disk_usage,h._preflight_host_snapshot_bytes,h._mutation_active,h.shutil.which)
class DU: total=10*1024**3; used=7*1024**3; free=3*1024**3
h.shutil.disk_usage=lambda p:DU(); h._preflight_host_snapshot_bytes=lambda c,m:4096; h._mutation_active=lambda c:False; h.shutil.which=lambda n:'/bin/true'
try:h.validate_target_preflight(cfg,report,'tec_tac',1024**3)
finally:h.shutil.disk_usage,h._preflight_host_snapshot_bytes,h._mutation_active,h.shutil.which=old
check=next(c for c in report['sections']['target']['checks'] if c['id']=='target.disk')
must(check['status']=='failed' and 'host_snapshot_estimate=4096' in check['detail'],'host snapshot omitted from disk preflight')

# L76 superseded by AD-3: new backups use hash companions; recovery-key/trust tooling is removed.
helper_source=(ROOT/'scripts/server-backup-helper.py').read_text()
install_source=(ROOT/'install.sh').read_text()
must(not (ROOT/'scripts/recovery-key-cli.py').exists(),'AD-3 recovery-key CLI still shipped')
must('operation_trust_recovery_signer' not in helper_source,'AD-3 trust operation still present')
must('create_recovery_signature' not in helper_source,'AD-3 new-backup signing helper still present')
must('rm -f /usr/local/sbin/tec-tac-recovery-key' in install_source,'upgrade does not remove legacy recovery-key CLI')
print('backup-closure-1.15.145: PASS')
