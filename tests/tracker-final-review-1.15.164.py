#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def must(value, message):
    if not value:
        raise AssertionError(message)


h = load('backup164', 'scripts/server-backup-helper.py')

# L10: a recovery bundle is built privately, and local publication never exposes
# a final archive before its sidecar. Both sidecar and archive publication
# failures leave no final archive/sidecar pair behind.
with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    old_identity, old_sig = h.recovery_identity, h.create_recovery_signature
    h.recovery_identity = lambda _cfg: {
        'installation_id': 'test-install', 'server_name': 'test-rmm',
        'key_id': 'test-key', 'public_key_sha256': 'ab' * 32,
    }
    h.create_recovery_signature = lambda *_a, **_k: {
        'schema': 1, 'algorithm': 'ed25519', 'key_id': 'test-key',
        'public_key_sha256': 'ab' * 32, 'signature': 'AA==', 'public_key_pem': 'x',
    }
    try:
        bundle, _manifest = h.create_recovery_bundle({}, base, backup_class='manual')
    finally:
        h.recovery_identity, h.create_recovery_signature = old_identity, old_sig
    must(bundle.parent == base, 'recovery bundle was exposed outside private staging before publication')
    must('/rmmbackups/' not in str(bundle), 'recovery bundle was created directly in final local backup storage')

with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    src = base / 'source' / 'tec-tac-backup-test.tgz'
    src.parent.mkdir(); src.write_bytes(b'payload')
    metadata = {'size_bytes': src.stat().st_size, 'sha256': hashlib.sha256(src.read_bytes()).hexdigest()}
    dest = base / 'dest'
    destination = {'id': 'local', 'type': 'local', 'path': str(dest)}
    target = dest / src.name
    sidecar = target.with_name(target.name + '.tectac.json')
    real_replace = h.os.replace

    # Sidecar publication failure: archive must never become final.
    def fail_sidecar(a, b):
        if Path(b) == sidecar:
            raise RuntimeError('sidecar publish failed')
        return real_replace(a, b)
    h.os.replace = fail_sidecar
    try:
        try: h.store_local(destination, src, metadata)
        except RuntimeError: pass
        else: raise AssertionError('sidecar publication failure was swallowed')
    finally:
        h.os.replace = real_replace
    must(not target.exists(), 'archive was published after sidecar publication failed')
    must(not sidecar.exists(), 'failed sidecar publication left a final sidecar')

    # Archive publication failure after sidecar succeeds: roll the final sidecar back.
    def fail_archive(a, b):
        if Path(b) == target:
            raise RuntimeError('archive publish failed')
        return real_replace(a, b)
    h.os.replace = fail_archive
    try:
        try: h.store_local(destination, src, metadata)
        except RuntimeError: pass
        else: raise AssertionError('archive publication failure was swallowed')
    finally:
        h.os.replace = real_replace
    must(not target.exists(), 'failed final publication left an archive')
    must(not sidecar.exists(), 'failed final publication left a mismatched sidecar')

    # The old same-target path is forbidden: final storage is never a build workspace.
    dest.mkdir(exist_ok=True)
    same = dest / 'same.tgz'; same.write_bytes(b'x')
    same_meta = {'size_bytes': 1, 'sha256': hashlib.sha256(b'x').hexdigest()}
    try: h.store_local(destination, same, same_meta)
    except RuntimeError as exc: must('may not already be the final archive' in str(exc), str(exc))
    else: raise AssertionError('same-target final publication path was accepted')

# The no-destination create-backup path must publish through store_local rather
# than leave the private build artifact as the final recovery copy.
with tempfile.TemporaryDirectory() as td:
    base = Path(td); staging = base/'staging'; staging.mkdir(); final = base/'rmmbackups'
    originals = {
        'roots': h.roots, 'lock': h.acquire_lock, 'stage': h.set_job_stage,
        'tec': h.create_tec_tac_component, 'validate': h.validate_recovery_bundle,
        'identity': h.recovery_identity, 'sig': h.create_recovery_signature,
        'localroot': h.DEFAULT_LOCAL_RECOVERY_ROOT,
    }
    h.roots = lambda _cfg=None: {'staging': staging}
    h.acquire_lock = lambda _cfg: SimpleNamespace(close=lambda: None)
    h.set_job_stage = lambda *_a, **_k: None
    def fake_tec(_cfg, path):
        path.write_bytes(b'tec-tac-component')
        return {'included': True, 'size_bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'framework_version': '1.15.164'}
    h.create_tec_tac_component = fake_tec
    h.validate_recovery_bundle = lambda *_a, **_k: {'ok': True}
    h.recovery_identity = lambda _cfg: {'installation_id':'test-install','server_name':'test-rmm','key_id':'test-key','public_key_sha256':'ab'*32}
    h.create_recovery_signature = lambda *_a, **_k: {'schema':1,'algorithm':'ed25519','key_id':'test-key','public_key_sha256':'ab'*32,'signature':'AA==','public_key_pem':'x'}
    h.DEFAULT_LOCAL_RECOVERY_ROOT = final
    try:
        result = h.operation_create_backup({}, {'id':'11111111-1111-4111-8111-111111111111','request':{
            'backup_class':'manual','destinations':[],'include_tactical':False,'include_tec_tac':True,
        }}, SimpleNamespace(write=lambda *_a: None))
    finally:
        h.roots=originals['roots']; h.acquire_lock=originals['lock']; h.set_job_stage=originals['stage']
        h.create_tec_tac_component=originals['tec']; h.validate_recovery_bundle=originals['validate']
        h.recovery_identity=originals['identity']; h.create_recovery_signature=originals['sig']; h.DEFAULT_LOCAL_RECOVERY_ROOT=originals['localroot']
    final_archive = Path(result['local_path'])
    must(final_archive.parent == final and final_archive.is_file(), 'no-destination backup was not published to final local storage')
    must(final_archive.with_name(final_archive.name+'.tectac.json').is_file(), 'published local recovery archive has no sidecar')
    must(not any(staging.rglob('tec-tac-backup-*.tgz')), 'private staging recovery bundle survived operation cleanup')

# L15: preflight estimates the complete rollback snapshot, including PostgreSQL
# dumps for full/Tactical restore, and those bytes change the real disk decision.
old_pg = h._postgres_query
queries = []
def fake_pg(sql):
    queries.append(sql)
    if "tacticalrmm" in sql: return str(700 * 1024 * 1024)
    if "meshcentral" in sql: return str(300 * 1024 * 1024)
    return '0'
h._postgres_query = fake_pg
try:
    db_bytes = h._preflight_database_snapshot_bytes('full')
    must(db_bytes == 1000 * 1024 * 1024, f'database snapshot estimate wrong: {db_bytes}')
    must(h._preflight_database_snapshot_bytes('tec_tac') == 0, 'Tec-Tac-only restore should not estimate DB rollback dumps')
finally:
    h._postgres_query = old_pg
must(any('pg_database_size' in q for q in queries), 'database estimate did not use PostgreSQL size data')

with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    old = {
        'roots': h.roots, 'disk': h.shutil.disk_usage, 'host': h._preflight_host_snapshot_bytes,
        'pg': h._postgres_query, 'mut': h._mutation_active, 'which': h.shutil.which,
        'dns': h.socket.getaddrinfo, 'osr': h._os_release, 'machine': h.platform.machine,
        'ident': h.tactical_identity,
    }
    h.roots = lambda _cfg=None: {'staging': base}
    h.shutil.disk_usage = lambda _path: SimpleNamespace(total=10 * 1024**3, used=0, free=2200 * 1024**2)
    h._preflight_host_snapshot_bytes = lambda _cfg, _mode: 100 * 1024 * 1024
    h._postgres_query = fake_pg
    h._mutation_active = lambda _cfg: False
    h.shutil.which = lambda _name: '/bin/true'
    h.socket.getaddrinfo = lambda *_a, **_k: [(None, None, None, None, None)]
    h._os_release = lambda: {'ID': 'ubuntu', 'VERSION_ID': '22.04'}
    h.platform.machine = lambda: 'x86_64'
    h.tactical_identity = lambda _cfg: (0, 0, 'tactical', '/tmp')
    try:
        report = h._vr_new({'restore_mode': 'full'}, 'bundle.tgz')
        h.validate_target_preflight({
            'TEC_TAC_SERVER_BACKUP_ROOT': str(base/'backup'), 'TACTICAL_ROOT': str(base/'tactical'),
            'TEC_TAC_STATE_ROOT': str(base/'state'), 'TEC_TAC_ROOT': str(base/'runtime'),
            'TEC_TAC_FRAMEWORK_SOURCE': str(base/'framework'), 'TEC_TAC_UI_SOURCE': str(base/'ui'),
            'TEC_TAC_UI_DEPLOY_ROOT': str(base/'deploy'),
        }, report, 'full', 400 * 1024 * 1024)
    finally:
        h.roots=old['roots']; h.shutil.disk_usage=old['disk']; h._preflight_host_snapshot_bytes=old['host']
        h._postgres_query=old['pg']; h._mutation_active=old['mut']; h.shutil.which=old['which']
        h.socket.getaddrinfo=old['dns']; h._os_release=old['osr']; h.platform.machine=old['machine']; h.tactical_identity=old['ident']
    disk = next(row for row in report['sections']['target']['checks'] if row['id']=='target.disk')
    must(disk['status']=='failed', 'database+host rollback snapshot bytes did not affect preflight disk decision')
    must('database_snapshot_estimate=' in disk['detail'], 'disk detail omitted database rollback estimate')

# L24: migration 0015 produces current runtime-valid canonical types and fails
# closed for dynamic filters that encode Tactical scope outside targets.scope.
mig_path = ROOT/'framwork/tec_tac/migrations/0015_scheduler_target_canonicalization.py'
mig_tree = ast.parse(mig_path.read_text())
names = {'_NATIVE','_ALIASES','_RESERVED_FILTER_SCOPE_KEYS','_scope_alias_token','_reserved_filter_value','_reject_unknown_keys','_values','_ids','_extract_native','_legacy_normalize','_endpoint_rows','_canonical_endpoint_ids','_canonicalize_endpoint_identity','canonicalize_existing_targets'}
nodes=[]
for n in mig_tree.body:
    if isinstance(n, ast.Import): nodes.append(n)
    elif isinstance(n, ast.Assign) and any(isinstance(t,ast.Name) and t.id in names for t in n.targets): nodes.append(n)
    elif isinstance(n, ast.FunctionDef) and n.name in names: nodes.append(n)
mig={}; exec(compile(ast.Module(body=nodes,type_ignores=[]),str(mig_path),'exec'),mig)
targets = load('targets164','framwork/tec_tac/scheduler_targets.py')

class Row:
    def __init__(self, targets): self.targets=targets; self.enabled=True; self.target_state='valid'; self.target_state_detail=''; self.saved=[]
    def save(self, update_fields=None): self.saved.append(tuple(update_fields or ()))
rows=[
    Row({'type':'clients','client_id':7}),
    Row({'type':'agents','agent_id':'42'}),
    Row({'type':'dynamic','scope':{'site_id':9},'filter':{'name':'server'}}),
    Row({'type':'dynamic','scope':{'site_id':9},'filter':{'field':'site_id'}}),
]
class SO:
    def all(self): return self
    def iterator(self): return iter(rows)
class Schedule: objects=SO()
class RO:
    def __getattr__(self,name): raise AssertionError(f'migration touched immutable run history via {name}')
class Run: objects=RO()
class AV:
    def values_list(self,*a): return [(42,'agent-42')]
class AO:
    def all(self): return AV()
class Agent: objects=AO()
class Apps:
    def get_model(self,a,m):
        if (a,m)==('tec_tac','TecTacSchedule'): return Schedule
        if (a,m)==('tec_tac','TecTacScheduleRun'): return Run
        if (a,m)==('agents','Agent'): return Agent
        raise AssertionError((a,m))
mig['canonicalize_existing_targets'](Apps(),None)
must(rows[0].targets=={'type':'clients','ids':[7]}, f'plural client type was not preserved: {rows[0].targets}')
must(rows[1].targets=={'type':'agents','ids':['agent-42']}, f'agent target type was not preserved: {rows[1].targets}')
must(rows[2].targets=={'type':'dynamic','scope':{'type':'site','ids':[9]},'filter':{'name':'server'}}, 'valid dynamic target changed unexpectedly')
for row in rows[:3]: must(targets.normalize_scheduler_targets(row.targets)==row.targets, 'migration output disagrees with runtime normalizer')
must(rows[3].enabled is False and rows[3].target_state=='invalid', 'runtime-invalid dynamic scope alias in filter was not quarantined')
must(rows[3].targets['filter']['field']=='site_id', 'invalid target evidence was rewritten')
repair=(ROOT/'framwork/tec_tac/migrations/0020_scheduler_target_parity_repair.py').read_text()
must('0019_scheduler_endpoint_identity' in repair and 'canonicalize_existing_targets' in repair, 'repair migration does not re-run target parity repair')
must('targets_snapshot' not in repair, 'repair migration references immutable run history')

# Runtime canonicalizes identifier values while preserving the module-declared
# native target vocabulary for persistence and handler dispatch.
must(targets.normalize_scheduler_targets({'type':'clients','ids':[1]})=={'type':'clients','ids':[1]}, 'runtime rewrote plural client type')
must(targets.normalize_scheduler_targets({'type':'agents','ids':['agent-42']})=={'type':'agents','ids':['agent-42']}, 'runtime rewrote agent target type')

# L25: scope snapshots must preserve unambiguous PK aliases while excluding a
# numeric token that can mean one Agent PK and another Agent's agent_id.
adapter_path=ROOT/'framwork/tec_tac/resources_adapter.py'
atree=ast.parse(adapter_path.read_text())
needed={'scheduler_scope_snapshot','canonical_agent_target_ids_in_scope','agent_target_identifiers_in_scope'}
anodes=[n for n in atree.body if isinstance(n,ast.FunctionDef) and n.name in needed]
class AdapterError(RuntimeError): pass
class Q:
    def __init__(self,*a,**k): pass
    def __or__(self,o): return self
class QS:
    def __init__(self, rows): self.rows=list(rows)
    def filter(self,*a,**k): return self
    def values_list(self,*fields,**kw):
        if fields==('pk','agent_id'): return list(self.rows)
        if fields==('pk',) and kw.get('flat'): return [r[0] for r in self.rows]
        raise AssertionError((fields,kw))
class Manager:
    def __init__(self,rows): self.rows=rows
    def all(self): return QS(self.rows)
class Site: objects=Manager([])
class Agent2: objects=Manager([(42,'agent-42'),(77,'agent-77'),(88,'77')])
class Rel:
    def values_list(self,*a,**k): return []
class Role: can_view_clients=Rel(); can_view_sites=Rel()
ans={'TacticalResourceAdapterError':AdapterError,'Q':Q,'_models':lambda:(None,Site,Agent2),'_scope_queryset':lambda qs,**kw:qs,'_role_for_user':lambda u:Role(),'_role_scope_unrestricted':lambda **kw:False}
exec(compile(ast.Module(body=anodes,type_ignores=[]),str(adapter_path),'exec'),ans)
snap=ans['scheduler_scope_snapshot'](user=object())
must('42' in snap['endpoint_ids'] and 'agent-42' in snap['endpoint_ids'], 'unambiguous legacy/canonical aliases missing')
must('77' not in snap['endpoint_ids'], 'ambiguous numeric endpoint alias leaked into history scope snapshot')
try: ans['canonical_agent_target_ids_in_scope'](user=object(),identifiers=['77'])
except AdapterError: pass
else: raise AssertionError('ambiguous numeric endpoint token persisted instead of failing closed')

print('[TEST] PASS final tracker review closure 1.15.164: L10 L15 L24 L25')
