#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import types
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class Log:
    def write(self, *_args):
        pass


# ---------------------------------------------------------------------------
# L10: final recovery names are immutable on every transport. Existing final
# archive/sidecar evidence must never be deleted or replaced by a retry.
# ---------------------------------------------------------------------------
h = load('backup165', 'scripts/server-backup-helper.py')
metadata = {'size_bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}

# FTP: an existing final pair is detected before STOR/rename and stays byte-exact.
class ExistingFTP:
    def __init__(self):
        self.objects = {'same.tgz': b'old-archive', 'same.tgz.tectac.json': b'old-sidecar'}
        self.stores = []
    def size(self, name):
        if name not in self.objects:
            raise h.ftplib.error_perm('550 not found')
        return len(self.objects[name])
    def storbinary(self, command, fh, blocksize=0):
        self.stores.append(command)
        self.objects[command.split(' ', 1)[1]] = fh.read()
    def delete(self, name): self.objects.pop(name, None)
    def rename(self, src, dst): self.objects[dst] = self.objects.pop(src)
    def quit(self): pass
    def close(self): pass

with tempfile.TemporaryDirectory() as td:
    archive = Path(td) / 'same.tgz'; archive.write_bytes(b'abc')
    ftp = ExistingFTP()
    old_connect, old_prepare = h.ftp_connect, h.ftp_prepare_path
    h.ftp_connect = lambda *_a, **_k: ftp
    h.ftp_prepare_path = lambda *_a, **_k: None
    try:
        try:
            h.ftp_store({}, {'id':'ftp','type':'ftp','host':'h','port':21,'username':'u','remote_path':'/'}, archive, metadata, Log())
        except RuntimeError as exc:
            must('immutable' in str(exc).lower(), f'FTP collision failed for wrong reason: {exc}')
        else:
            raise AssertionError('FTP overwrote an existing final recovery pair')
    finally:
        h.ftp_connect, h.ftp_prepare_path = old_connect, old_prepare
    must(ftp.objects['same.tgz'] == b'old-archive', 'FTP changed existing final archive')
    must(ftp.objects['same.tgz.tectac.json'] == b'old-sidecar', 'FTP changed existing final sidecar')
    must(not ftp.stores, 'FTP uploaded partial data before checking final-name collision')

# rclone: --stat sees an existing final; no copy/move/delete is allowed.
with tempfile.TemporaryDirectory() as td:
    base = Path(td); archive = base/'same.tgz'; archive.write_bytes(b'abc')
    old_cfg, old_subrun, old_logged = h.make_rclone_config, h.subprocess.run, h.run_logged
    mutations=[]
    h.make_rclone_config = lambda *_a, **_k: base/'rclone.conf'
    def fake_subrun(argv, **kwargs):
        if argv[1] == 'lsjson' and '--stat' in argv:
            return SimpleNamespace(returncode=0, stdout=json.dumps({'Name':'same.tgz','Size':11}), stderr='')
        if argv[1] == 'deletefile':
            mutations.append(tuple(argv)); return SimpleNamespace(returncode=0, stdout='', stderr='')
        raise AssertionError(argv)
    h.subprocess.run = fake_subrun
    h.run_logged = lambda argv, *_a, **_k: mutations.append(tuple(argv))
    try:
        try:
            h.store_rclone({}, {'id':'r','type':'s3','bucket':'b','remote_path':'.'}, archive, metadata, Log())
        except RuntimeError as exc:
            must('immutable' in str(exc).lower(), f'rclone collision failed for wrong reason: {exc}')
        else:
            raise AssertionError('rclone accepted an existing final recovery name')
    finally:
        h.make_rclone_config, h.subprocess.run, h.run_logged = old_cfg, old_subrun, old_logged
    must(not any(call[1] in {'copyto','moveto'} for call in mutations), f'rclone copied or published after collision: {mutations}')
    must(not any(call[1]=='deletefile' and not (call[2].endswith('.partial') or call[2].endswith('.tectac.json.partial')) for call in mutations), f'rclone deleted existing final evidence after collision: {mutations}')

# SCP: remote preflight failure happens before any scp upload.
with tempfile.TemporaryDirectory() as td:
    base=Path(td); staging=base/'staging'; staging.mkdir(); archive=base/'same.tgz'; archive.write_bytes(b'abc')
    old_roots, old_args, old_logged, old_subrun = h.roots, h.scp_args, h.run_logged, h.subprocess.run
    h.roots=lambda _cfg=None: {'staging': staging}
    h.scp_args=lambda *_a, **_k: ([], [])
    calls=[]
    def fake_logged(argv, *_a, **_k):
        calls.append(tuple(argv))
        if argv[0]=='ssh' and isinstance(argv[-1], str) and argv[-1].startswith('test ! -e'):
            raise RuntimeError('remote final exists')
        return None
    h.run_logged=fake_logged
    h.subprocess.run=lambda argv, **kwargs: SimpleNamespace(returncode=0, stdout='', stderr='')
    try:
        try:
            h.store_scp({}, {'id':'s','type':'scp','host':'h','port':22,'username':'u','remote_path':'/backup'}, archive, metadata, Log())
        except RuntimeError as exc:
            must('immutable' in str(exc).lower(), f'SCP collision failed for wrong reason: {exc}')
        else:
            raise AssertionError('SCP accepted an existing final recovery name')
    finally:
        h.roots, h.scp_args, h.run_logged, h.subprocess.run = old_roots, old_args, old_logged, old_subrun
    must(not any(call and call[0]=='scp' for call in calls), 'SCP uploaded data before final-name collision check')


# ---------------------------------------------------------------------------
# L24: migration repair must fail closed exactly where runtime would reject
# unsupported keys, rather than silently dropping them and widening a schedule.
# ---------------------------------------------------------------------------
class _Field:
    def __init__(self,*a,**k): pass
class _RunPython:
    noop=staticmethod(lambda *a,**k: None)
    def __init__(self,*a,**k): pass
class _AddField:
    def __init__(self,*a,**k): pass
class _Migration: pass
fake_migrations=types.SimpleNamespace(Migration=_Migration,RunPython=_RunPython,AddField=_AddField)
fake_models=types.SimpleNamespace(CharField=_Field)
django=types.ModuleType('django'); django_db=types.ModuleType('django.db')
django_db.migrations=fake_migrations; django_db.models=fake_models
sys.modules.setdefault('django',django); sys.modules.setdefault('django.db',django_db)
sys.modules.setdefault('django.db.migrations',fake_migrations); sys.modules.setdefault('django.db.models',fake_models)
mig15=runpy.run_path(str(ROOT/'framwork/tec_tac/migrations/0015_scheduler_target_canonicalization.py'))
for bad in (
    {'type':'none','ids':[1]},
    {'type':'clients','client_id':7,'unexpected':True},
    {'type':'dynamic','scope':{'site_id':9},'filter':{},'unexpected':True},
    {'type':'dynamic','scope':{'site_id':9,'unexpected':True},'filter':{}},
):
    try:
        mig15['_legacy_normalize'](bad)
    except ValueError:
        pass
    else:
        raise AssertionError(f'0015 widened unsupported target shape instead of failing closed: {bad!r}')

runtime=load('targets165','framwork/tec_tac/scheduler_targets.py')
valid_legacy={'type':'clients','client_id':7}
migrated=mig15['_legacy_normalize'](valid_legacy)
must(migrated=={'type':'clients','ids':[7]}, f'valid legacy target migrated incorrectly: {migrated}')
must(runtime.normalize_scheduler_targets(migrated)==migrated, 'migration output is not runtime-idempotent')

# Actual 0020 repair must quarantine an invalid row and leave its evidence intact.
class Row:
    def __init__(self, targets):
        self.targets=targets; self.enabled=True; self.target_state='valid'; self.target_state_detail=''; self.saved=[]
    def save(self, update_fields=None): self.saved.append(tuple(update_fields or ()))
invalid=Row({'type':'clients','client_id':7,'unexpected':True})
valid=Row({'type':'clients','client_id':7})
class _All:
    def iterator(self): return iter([invalid, valid])
class Schedule: objects=types.SimpleNamespace(all=lambda: _All())
class Run:
    class NoTouch:
        def __getattr__(self,name): raise AssertionError(f'0020 touched immutable run history: {name}')
    objects=NoTouch()
class AgentValues:
    def values_list(self,*a): return []
class Agent: objects=types.SimpleNamespace(all=lambda: AgentValues())
class Apps:
    def get_model(self,a,m): return {('tec_tac','TecTacSchedule'):Schedule,('tec_tac','TecTacScheduleRun'):Run,('agents','Agent'):Agent}[(a,m)]
legacy_mod=types.ModuleType('tec_tac.migrations.0015_scheduler_target_canonicalization')
legacy_mod.canonicalize_existing_targets=mig15['canonicalize_existing_targets']
sys.modules[legacy_mod.__name__]=legacy_mod
mig20=runpy.run_path(str(ROOT/'framwork/tec_tac/migrations/0020_scheduler_target_parity_repair.py'))
mig20['repair_scheduler_targets'](Apps(),None)
must(invalid.enabled is False and invalid.target_state=='invalid', '0020 did not quarantine runtime-invalid legacy row')
must(invalid.targets=={'type':'clients','client_id':7,'unexpected':True}, '0020 rewrote invalid evidence')
must(valid.targets=={'type':'clients','ids':[7]}, '0020 did not canonicalize valid legacy row')


# ---------------------------------------------------------------------------
# L25: endpoint identity is canonicalized immediately before execution too, so
# PK aliases cannot leak to handlers even if a module/old row bypassed REST save.
# ---------------------------------------------------------------------------
adapter_source=(ROOT/'framwork/tec_tac/resources_adapter.py').read_text(encoding='utf-8')
atree=ast.parse(adapter_source)
node=next(n for n in atree.body if isinstance(n,ast.FunctionDef) and n.name=='canonical_agent_target_ids')
mod=ast.Module(body=[node],type_ignores=[]); ast.fix_missing_locations(mod)
class AdapterError(RuntimeError): pass
class Q:
    def __init__(self,*a,**k): pass
    def __or__(self,o): return self
class QS:
    def __init__(self,rows): self.rows=rows
    def filter(self,*a,**k): return self
    def values_list(self,*a): return list(self.rows)
class AgentManager(QS): pass
rows=[(77,'agent-a'),(88,'77'),(99,'agent-c')]
Agent=types.SimpleNamespace(objects=AgentManager(rows))
ans={'Q':Q,'TacticalResourceAdapterError':AdapterError,'_models':lambda:(None,None,Agent)}
exec(compile(mod,str(ROOT/'framwork/tec_tac/resources_adapter.py'),'exec'),ans)
must(ans['canonical_agent_target_ids'](identifiers=['99'])==['agent-c'], 'global runtime resolver did not canonicalize PK to agent_id')
try:
    ans['canonical_agent_target_ids'](identifiers=['77'])
except AdapterError:
    pass
else:
    raise AssertionError('global runtime resolver guessed an ambiguous numeric endpoint token')

# Execute the production scheduler helper with the real resolver contract.
sched_source=(ROOT/'framwork/tec_tac/scheduler.py').read_text(encoding='utf-8')
stree=ast.parse(sched_source)
snode=next(n for n in stree.body if isinstance(n,ast.FunctionDef) and n.name=='_canonicalize_persisted_endpoint_identity')
smod=ast.Module(body=[snode],type_ignores=[]); ast.fix_missing_locations(smod)
class ShapeError(ValueError): pass
fake_adapter=types.SimpleNamespace(
    TacticalResourceAdapterError=AdapterError,
    canonical_agent_target_ids=lambda *, identifiers: ['agent-a','agent-b'] if list(identifiers)==['1','2'] else (_ for _ in ()).throw(AdapterError('ambiguous')),
)
# satisfy imports performed inside the helper
pkg=types.ModuleType('tec_tac'); pkg.__path__=[]
sys.modules.setdefault('tec_tac',pkg)
sys.modules['tec_tac.resources_adapter']=fake_adapter
stargets=types.ModuleType('tec_tac.scheduler_targets'); stargets.SchedulerTargetShapeError=ShapeError
sys.modules['tec_tac.scheduler_targets']=stargets
sns={'__name__':'tec_tac.scheduler'}
exec(compile(smod,str(ROOT/'framwork/tec_tac/scheduler.py'),'exec'),sns)
out=sns['_canonicalize_persisted_endpoint_identity']({'type':'endpoints','ids':['1','2']})
must(out=={'type':'endpoints','ids':['agent-a','agent-b']}, f'execution canonicalizer lost native type or ids: {out}')
try:
    sns['_canonicalize_persisted_endpoint_identity']({'type':'endpoint','ids':['ambiguous']})
except ShapeError:
    pass
else:
    raise AssertionError('execution canonicalizer did not fail closed on ambiguous endpoint identity')

print('[TEST] PASS tracker closure 1.15.165: L10 L24 L25')
