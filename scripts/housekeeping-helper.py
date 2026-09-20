#!/usr/bin/env python3
from __future__ import annotations
import json, os, shutil, sys, time
from pathlib import Path

STATE = Path('/var/lib/tec-tac')
ROOT = STATE / 'housekeeping'
RESULTS = ROOT / 'results'
DEFAULTS = {
  'local_settings_backups': {'mode':'keep_count','keep':10},
  'module_staging': {'mode':'age_days','days':7},
  'module_history': {'mode':'age_days','days':30},
  'system_update_staging': {'mode':'age_days','days':7},
  'system_update_backups': {'mode':'keep_count','keep':3},
  'system_update_history': {'mode':'age_days','days':30},
  'server_backup_staging': {'mode':'age_days','days':7},
  'server_backup_history': {'mode':'age_days','days':30},
  'server_backup_pre_restore': {'mode':'age_days','days':14},
}
CATEGORY_PATHS = {
  'local_settings_backups': [(STATE/'backups', 'files', 'local_settings.py.*.bak')],
  'module_staging': [(STATE/'module-manager'/'staged', 'files', '*'), (STATE/'module-manager'/'staged'/'bundles', 'files', '*'), (STATE/'module-manager'/'staged'/'batches', 'files', '*')],
  'module_history': [(STATE/'module-manager'/'jobs', 'files', '*.json'), (STATE/'module-manager'/'logs', 'files', '*.log')],
  'system_update_staging': [(STATE/'system-updates'/'staged', 'children', None)],
  'system_update_backups': [(STATE/'system-updates'/'backups', 'files', '*')],
  'system_update_history': [(STATE/'system-updates'/'jobs', 'files', '*.json'), (STATE/'system-updates'/'logs', 'files', '*.log'), (STATE/'system-updates'/'history', 'files', '*.json')],
  'server_backup_staging': [(STATE/'server-backup'/'staging', 'children', None)],
  'server_backup_history': [(STATE/'server-backup'/'jobs', 'files', '*.json'), (STATE/'server-backup'/'logs', 'files', '*.log')],
  'server_backup_pre_restore': [(STATE/'server-backup'/'pre-restore', 'children', None)],
}

def safe_child(p: Path):
    try: p.resolve(strict=False).relative_to(STATE.resolve())
    except ValueError: raise RuntimeError(f'unsafe housekeeping path: {p}')

def size_of(p: Path):
    try:
        if p.is_symlink(): return p.lstat().st_size
        if p.is_file(): return p.stat().st_size
        total=0
        for root, dirs, files in os.walk(p, followlinks=False):
            for n in files:
                q=Path(root)/n
                try: total += q.lstat().st_size
                except OSError: pass
        return total
    except OSError: return 0

def candidates(category):
    out=[]
    for base, kind, pattern in CATEGORY_PATHS[category]:
        safe_child(base)
        if not base.exists(): continue
        if kind=='children': items=list(base.iterdir())
        else: items=list(base.glob(pattern or '*'))
        for p in items:
            if kind == 'files' and not (p.is_file() or p.is_symlink()):
                continue
            safe_child(p)
            try: st=p.lstat()
            except OSError: continue
            out.append({'path':p,'mtime':st.st_mtime,'bytes':size_of(p)})
    return out

def select(category, policy):
    items=candidates(category)
    mode=policy.get('mode')
    purge=[]
    if mode=='age_days':
        days=max(0,int(policy.get('days',0))); cutoff=time.time()-days*86400
        purge=[x for x in items if x['mtime'] < cutoff]
    elif mode=='keep_count':
        keep=max(0,int(policy.get('keep',0))); ordered=sorted(items,key=lambda x:x['mtime'],reverse=True); purge=ordered[keep:]
    else: raise RuntimeError(f'unsupported policy mode for {category}')
    return items,purge

def remove_path(p: Path):
    safe_child(p)
    if p.is_symlink() or p.is_file(): p.unlink(missing_ok=True)
    elif p.is_dir(): shutil.rmtree(p)

def main():
    if len(sys.argv)!=3 or sys.argv[1] not in {'--scan','--purge'}: raise SystemExit('usage: tec-tac-housekeeping --scan|--purge <request-json>')
    req=Path(sys.argv[2]); safe_child(req)
    if req.parent != ROOT/'requests' or not req.name.endswith('.json') or req.is_symlink() or not req.is_file(): raise SystemExit('invalid request path')
    payload=json.loads(req.read_text())
    selected=payload.get('categories') or list(DEFAULTS)
    if any(c not in DEFAULTS for c in selected): raise SystemExit('unknown housekeeping category')
    policies=dict(DEFAULTS)
    for c,v in (payload.get('policies') or {}).items():
        if c not in DEFAULTS or not isinstance(v,dict): raise SystemExit('invalid housekeeping policy')
        policies[c]={**DEFAULTS[c],**v}
    dry = sys.argv[1]=='--scan' or bool(payload.get('dry_run',False))
    rows=[]; reclaimed=0; deleted=0; scanned=0
    for c in selected:
        items,purge=select(c,policies[c]); scanned += sum(x['bytes'] for x in items)
        row={'id':c,'policy':policies[c],'total_items':len(items),'total_bytes':sum(x['bytes'] for x in items),'purge_items':len(purge),'purge_bytes':sum(x['bytes'] for x in purge)}
        if not dry:
            for x in purge:
                remove_path(x['path']); reclaimed+=x['bytes']; deleted+=1
        rows.append(row)
    result={'ok':True,'dry_run':dry,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'categories':rows,'scanned_bytes':scanned,'deleted_items':deleted,'reclaimed_bytes':reclaimed}
    RESULTS.mkdir(parents=True,exist_ok=True)
    out=RESULTS/(req.stem+'.json'); tmp=out.with_suffix('.tmp'); tmp.write_text(json.dumps(result,indent=2)); os.replace(tmp,out); os.chmod(out,0o644)

if __name__=='__main__': main()
