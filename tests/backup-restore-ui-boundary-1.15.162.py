#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, pathlib, sys, types
ROOT=pathlib.Path(__file__).resolve().parents[1]
pkg=types.ModuleType('tec_tac'); pkg.__path__=[str(ROOT/'framwork'/'tec_tac')]; sys.modules['tec_tac']=pkg
rf=types.ModuleType('rest_framework'); rf.status=types.SimpleNamespace(HTTP_202_ACCEPTED=202); sys.modules['rest_framework']=rf
exc=types.ModuleType('rest_framework.exceptions')
class PermissionDenied(Exception): pass
class ValidationError(Exception): pass
exc.PermissionDenied=PermissionDenied; exc.ValidationError=ValidationError; sys.modules['rest_framework.exceptions']=exc
resp=types.ModuleType('rest_framework.response')
class Response:
    def __init__(self,data,status=200): self.data=data; self.status_code=status
resp.Response=Response; sys.modules['rest_framework.response']=resp
views=types.ModuleType('rest_framework.views')
class APIView: pass
views.APIView=APIView; sys.modules['rest_framework.views']=views

audit=types.ModuleType('tec_tac.audit')
class AuditContractError(Exception): pass
class AuditWriteError(Exception): pass
audit.AuditContractError=AuditContractError; audit.AuditWriteError=AuditWriteError; audit.record=lambda **kw: None; sys.modules['tec_tac.audit']=audit
caps=types.ModuleType('tec_tac.capabilities'); caps.build_operation_context=lambda **kw: kw; sys.modules['tec_tac.capabilities']=caps
ss=types.ModuleType('tec_tac.session_security')
class SessionAuthenticated: pass
ss.SessionAuthenticated=SessionAuthenticated; sys.modules['tec_tac.session_security']=ss

calls={'dest':0,'list':[],'validate':[],'restore':[],'jobs':[]}
sb=types.ModuleType('tec_tac.server_backup')
class ServerBackupError(Exception): pass
sb.ServerBackupError=ServerBackupError
sb.recovery_identity_core=lambda **kw: {}
sb.recovery_trust_job_status_core=lambda **kw: {}
sb.trust_recovery_signer_core=lambda **kw: {}
sb.list_registered_destinations_core=lambda **kw: calls.__setitem__('dest',calls['dest']+1) or [{'id':'remote-a','type':'s3','location':'bucket-a'}]
def list_core(**kw): calls['list'].append(kw); return {'job_id':'11111111-1111-4111-8111-111111111111','status':'queued','action':'list_registered_backups'}
def val_core(**kw): calls['validate'].append(kw); return {'job_id':'22222222-2222-4222-8222-222222222222','status':'queued','action':'validate_registered_restore'}
def restore_core(**kw): calls['restore'].append(kw); return {'job_id':'33333333-3333-4333-8333-333333333333','status':'queued','action':'restore_registered_backup'}
sb.list_registered_backups_core=list_core; sb.validate_registered_restore_core=val_core; sb.restore_registered_backup_core=restore_core
validation_checks=[]
def require_validation(**kw): validation_checks.append(kw); return {'ok':True}
sb.require_successful_restore_validation_core=require_validation
class Provider:
    def get_job_status(self, **kw): calls['jobs'].append(kw); return {'job_id':kw['job_id'],'action':'validate_registered_restore','status':'succeeded','result':{'ok':True,'recovery_signer':{'installation_id':'source-a','server_name':'old-rmm','public_key_sha256':'abcd'},'version_transition':{'current_core_version':'1.15.162','restored_core_version':'1.15.83','is_core_downgrade':True,'notice':'This restore puts Core back to 1.15.83.'}}}
sb.get_server_backup_provider=lambda: Provider()
sys.modules['tec_tac.server_backup']=sb

spec=importlib.util.spec_from_file_location('tec_tac.server_backup_views',ROOT/'framwork'/'tec_tac'/'server_backup_views.py')
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
class User:
    def __init__(self,name,superuser=False): self.username=name; self.is_superuser=superuser; self.role=None
    def get_and_set_role_cache(self): return self.role
class Req:
    def __init__(self,user,data=None): self.user=user; self.data=data or {}; self.query_params={}

view=mod.BackupRestoreView()
try: view.get(Req(User('normal')))
except PermissionDenied: pass
else: raise AssertionError('non-superuser listed backup destinations')
admin=User('admin',True)
out=view.get(Req(admin)); assert out.data['destinations'][0]['id']=='remote-a' and calls['dest']==1
q=view.post(Req(admin,{'action':'list','destination_ids':['remote-a']})); assert q.status_code==202 and calls['list'][0]['destination_ids']==['remote-a']
q=view.post(Req(admin,{'action':'validate','backup_ref':'destination:remote-a:a.tectac-recovery.tar.gz','destination_id':'remote-a','restore_mode':'full'})); assert q.status_code==202 and calls['validate']
try: view.post(Req(admin,{'action':'restore','backup_ref':'destination:remote-a:a.tectac-recovery.tar.gz','destination_id':'remote-a','restore_mode':'full'}))
except ValidationError: pass
else: raise AssertionError('restore started without explicit confirmation')
assert not calls['restore']
try: view.post(Req(admin,{'action':'restore','backup_ref':'destination:remote-a:a.tectac-recovery.tar.gz','destination_id':'remote-a','restore_mode':'full','confirmed':True}))
except ValidationError: pass
else: raise AssertionError('restore started without validation job id')
q=view.post(Req(admin,{'action':'restore','backup_ref':'destination:remote-a:a.tectac-recovery.tar.gz','destination_id':'remote-a','restore_mode':'full','confirmed':True,'validation_job_id':'22222222-2222-4222-8222-222222222222'})); assert q.status_code==202 and calls['restore'] and validation_checks
job=mod.BackupRestoreJobView().get(Req(admin), '22222222-2222-4222-8222-222222222222')
assert job.data['job']['result']['version_transition']['restored_core_version']=='1.15.83'
assert job.data['job']['result']['recovery_signer']['installation_id']=='source-a'
print('backup restore UI HTTP boundary 1.15.162: PASS')
