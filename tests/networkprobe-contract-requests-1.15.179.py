#!/usr/bin/env python3
from pathlib import Path
import ast
import importlib.util
import sys
import types

ROOT=Path(__file__).resolve().parents[1]
audit_path=ROOT/'framwork/tec_tac/audit.py'
audit_text=audit_path.read_text()
views=(ROOT/'framwork/tec_tac/views.py').read_text()
contracts=(ROOT/'framwork/tec_tac/contracts.py').read_text()

ast.parse(audit_text); ast.parse(views); ast.parse(contracts)
for token in ('class AuditActor','def service_audit_actor','def device_audit_actor','actor_kind','actor_identity','actor_module_id','operation_context'):
    assert token in audit_text, token
assert 'non-human audit actor module_id must match' in audit_text
assert '"name": "service_audit_actor"' in contracts
assert '"name": "device_audit_actor"' in contracts
for token in ('"locale": locale','"timeZone": time_zone','"dateTimeFormat": date_time_format'):
    assert token in views, token
for token in ('"locale"','"timeZone"','"dateTimeFormat"'):
    assert token in contracts, token

# Load audit contract without Tactical/Django. Core module provenance is self-contained.
spec=importlib.util.spec_from_file_location('tec_tac_audit_contract_test', audit_path)
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)

created=[]
class Manager:
    def create(self, **kwargs):
        created.append(kwargs)
        return types.SimpleNamespace(pk=77)
class AuditLog:
    objects=Manager()
mod._auditlog_model=lambda: AuditLog

service=mod.service_audit_actor(module_id='core', service='scheduler', identity='core.scheduler')
res=mod.record(actor=service,module_id='core',action='run',object_type='scheduled_job',operation_context={'source_module':'core','source_action':'tick','source_run_id':'run-1','correlation_id':'corr-1'})
assert res['recorded'] is True and res['username']=='service:core.scheduler'
assert created[-1]['debug_info']['actor_kind']=='service'
assert created[-1]['debug_info']['operation_context']['source_run_id']=='run-1'
assert created[-1]['debug_info']['correlation_id']=='corr-1'

device=mod.device_audit_actor(module_id='core',device_id='probe-1',identity='probe:branch-1',service='callback')
res=mod.record(actor=device,module_id='core',action='sync',object_type='probe_result')
assert res['username']=='device:probe:branch-1'
assert created[-1]['debug_info']['actor_kind']=='device'
assert created[-1]['debug_info']['actor_device_id']=='probe-1'

try:
    mod.record(actor=mod.AuditActor(kind='service',module_id='other',identity='x'), module_id='core', action='run', object_type='job')
except mod.AuditContractError:
    pass
else:
    raise AssertionError('cross-module non-human actor was accepted')

print('[TEST] PASS networkprobe public contract requests 1.15.179')
