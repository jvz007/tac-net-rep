#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, pathlib, sys, types
ROOT=pathlib.Path(__file__).resolve().parents[1]
pkg=types.ModuleType('tec_tac'); pkg.__path__=[str(ROOT/'framwork'/'tec_tac')]; sys.modules['tec_tac']=pkg
safe=types.ModuleType('tec_tac.safe_files'); safe.atomic_json=lambda *a,**k: None; sys.modules['tec_tac.safe_files']=safe
caps=types.ModuleType('tec_tac.capabilities'); caps.register_capability=lambda **k:k; sys.modules['tec_tac.capabilities']=caps
conf=types.ModuleType('tec_tac.config'); conf.load_layout=lambda:{}; sys.modules['tec_tac.config']=conf
spec=importlib.util.spec_from_file_location('tec_tac.server_backup',ROOT/'framwork'/'tec_tac'/'server_backup.py'); mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
starts=[]; runs=[]
mod._start=lambda action,request,context=None: starts.append((action,request,context)) or {'job_id':'j','status':'queued','action':action}
mod._run=lambda action,request,context=None,timeout=None: runs.append((action,request,context)) or {'destinations':[{'id':'remote-a','type':'s3'}]}
assert mod.list_registered_destinations_core(context={'source_module':'core'})[0]['id']=='remote-a'
mod.list_registered_backups_core(destination_ids=['remote-a'],context={})
assert starts[-1][0]=='list_registered_backups' and starts[-1][1]=={'destination_ids':['remote-a']}
mod.validate_registered_restore_core(backup_ref='destination:remote-a:a.tectac-recovery.tar.gz',destination_id='remote-a',restore_mode='full',overrides=[],context={})
assert starts[-1][0]=='validate_registered_restore' and starts[-1][1]['destination_id']=='remote-a'
mod.restore_registered_backup_core(backup_ref='destination:remote-a:a.tectac-recovery.tar.gz',destination_id='remote-a',restore_mode='tec_tac',overrides={},context={})
assert starts[-1][0]=='restore_registered_backup' and starts[-1][1]['restore_mode']=='tec_tac'

mod._read_job=lambda job_id:{'id':job_id,'action':'validate_registered_restore','status':'succeeded','request':{'backup_ref':'destination:remote-a:a.tectac-recovery.tar.gz','destination_id':'remote-a','restore_mode':'full','overrides':[]},'result':{'ok':True,'version_transition':{'restored_core_version':'1.15.83'}}}
auth=mod.require_successful_restore_validation_core(validation_job_id='v1',backup_ref='destination:remote-a:a.tectac-recovery.tar.gz',destination_id='remote-a',restore_mode='full')
assert auth['ok'] is True
try:
    mod.require_successful_restore_validation_core(validation_job_id='v1',backup_ref='destination:remote-a:other.tar.gz',destination_id='remote-a',restore_mode='full')
except mod.ServerBackupError: pass
else: raise AssertionError('mismatched restore bypassed validation binding')

print('server backup registered restore 1.15.162: PASS')
