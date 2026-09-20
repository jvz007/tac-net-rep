from __future__ import annotations
import json, subprocess, uuid
from pathlib import Path

ROOT=Path('/var/lib/tec-tac/housekeeping')
REQUESTS=ROOT/'requests'; RESULTS=ROOT/'results'; CONFIG=ROOT/'config.json'; HELPER=Path('/usr/local/sbin/tec-tac-housekeeping')
DEFAULT_POLICIES={
 'local_settings_backups': {'mode':'keep_count','keep':10}, 'module_staging': {'mode':'age_days','days':7},
 'module_history': {'mode':'age_days','days':30}, 'system_update_staging': {'mode':'age_days','days':7},
 'system_update_backups': {'mode':'keep_count','keep':3}, 'system_update_history': {'mode':'age_days','days':30},
 'server_backup_staging': {'mode':'age_days','days':7}, 'server_backup_history': {'mode':'age_days','days':30},
 'server_backup_pre_restore': {'mode':'age_days','days':14},
}
LABELS={
 'local_settings_backups':'local_settings.py backups','module_staging':'Module installer staging','module_history':'Module jobs and logs',
 'system_update_staging':'System Update installers','system_update_backups':'System Update rollback backups','system_update_history':'System Update jobs/logs/history',
 'server_backup_staging':'Server Backup staging','server_backup_history':'Server Backup jobs and logs','server_backup_pre_restore':'Pre-restore Tactical snapshots',
}
class HousekeepingError(RuntimeError): pass

def _load_config():
    if not CONFIG.is_file(): return {'policies':DEFAULT_POLICIES}
    try: raw=json.loads(CONFIG.read_text())
    except Exception: return {'policies':DEFAULT_POLICIES}
    policies={k:{**v,**((raw.get('policies') or {}).get(k) or {})} for k,v in DEFAULT_POLICIES.items()}
    return {'policies':policies}

def save_config(payload):
    incoming=payload.get('policies') if isinstance(payload,dict) else None
    if not isinstance(incoming,dict): raise HousekeepingError('policies must be an object')
    policies={}
    for k,default in DEFAULT_POLICIES.items():
        raw=incoming.get(k,default)
        if not isinstance(raw,dict) or raw.get('mode',default['mode'])!=default['mode']: raise HousekeepingError(f'invalid policy for {k}')
        item={**default,**raw}
        field='days' if item['mode']=='age_days' else 'keep'; value=int(item[field])
        if value<0 or value>3650: raise HousekeepingError(f'{k}.{field} is outside allowed range')
        item[field]=value; policies[k]=item
    ROOT.mkdir(parents=True,exist_ok=True); CONFIG.write_text(json.dumps({'policies':policies},indent=2)); CONFIG.chmod(0o640)
    return {'policies':policies}

def _run(action, *, dry_run=True, categories=None):
    if not HELPER.is_file(): raise HousekeepingError(f'housekeeping helper missing: {HELPER}')
    cfg=_load_config(); reqid=str(uuid.uuid4()); REQUESTS.mkdir(parents=True,exist_ok=True); RESULTS.mkdir(parents=True,exist_ok=True)
    req=REQUESTS/f'{reqid}.json'; result=RESULTS/f'{reqid}.json'
    data={'dry_run':bool(dry_run),'categories':categories or list(DEFAULT_POLICIES),'policies':cfg['policies']}; req.write_text(json.dumps(data)); req.chmod(0o660)
    try:
        cp=subprocess.run(['sudo','-n',str(HELPER),action,str(req)],capture_output=True,text=True,timeout=180)
        if cp.returncode: raise HousekeepingError((cp.stderr or cp.stdout or 'housekeeping helper failed').strip())
        report=json.loads(result.read_text())
    finally:
        req.unlink(missing_ok=True)
        result.unlink(missing_ok=True)
    report['categories']=[{**row,'label':LABELS.get(row.get('id'),row.get('id'))} for row in report.get('categories',[])]
    report['policies']=cfg['policies']; report['protected']=['/var/lib/tec-tac/ui','/var/lib/tec-tac/module-manager/module-state.json','/var/lib/tec-tac/module-manager/repositories','/var/lib/tec-tac/server-backup/secrets','configured backup destinations','/opt/tec-tac','/opt/tec-tac-src']
    return report

def status(): return _run('--scan',dry_run=True)
def purge(categories=None): return _run('--purge',dry_run=False,categories=categories)
def dry_run(categories=None): return _run('--scan',dry_run=True,categories=categories)
def config(): return _load_config()
