#!/usr/bin/python3
from __future__ import annotations
import json, os, shutil, stat, sys, tempfile, time, uuid
from pathlib import Path

STATE = Path('/var/lib/tec-tac')
ROOT = STATE / 'housekeeping'
RESULTS = ROOT / 'results'
RUNNING = ROOT / 'running'
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
JOB_ROOTS = {
  'module_staging': STATE/'module-manager'/'jobs', 'module_history': STATE/'module-manager'/'jobs',
  'system_update_staging': STATE/'system-updates'/'jobs', 'system_update_backups': STATE/'system-updates'/'jobs', 'system_update_history': STATE/'system-updates'/'jobs',
  'server_backup_staging': STATE/'server-backup'/'jobs', 'server_backup_history': STATE/'server-backup'/'jobs',
  'server_backup_pre_restore': STATE/'server-backup'/'jobs',
}
STAGING_CATEGORIES = {'module_staging','system_update_staging','server_backup_staging'}
HISTORY_CATEGORIES = {'module_history','system_update_history','server_backup_history'}
ACTIVE_GUARD_CATEGORIES = STAGING_CATEGORIES | HISTORY_CATEGORIES | {'system_update_backups','server_backup_pre_restore'}
TERMINAL_STATUSES = {'succeeded','failed','cancelled','canceled','complete','completed','skipped','expired','rolled-back','rollback-failed'}



def _read_request_nofollow(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError('housekeeping request is not a regular file')
        if st.st_size > 256 * 1024:
            raise RuntimeError('housekeeping request exceeds the size limit')
        chunks=[]
        remaining=256 * 1024 + 1
        while remaining > 0:
            chunk=os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk); remaining -= len(chunk)
        data=b''.join(chunks)
        if len(data) > 256 * 1024:
            raise RuntimeError('housekeeping request exceeds the size limit')
        return data
    finally:
        os.close(fd)


def _require_trusted_directory(path: Path, *, private: bool = False) -> os.stat_result:
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f'trusted housekeeping directory is missing: {path}') from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f'trusted housekeeping path is not a real directory: {path}')
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    if st.st_uid != expected_uid:
        raise RuntimeError(f'trusted housekeeping directory has the wrong owner: {path}')
    mode = stat.S_IMODE(st.st_mode)
    if private and mode != 0o700:
        raise RuntimeError(f'private housekeeping directory must be mode 0700: {path}')
    if not private and (mode & 0o002):
        raise RuntimeError(f'trusted housekeeping directory may not be world-writable: {path}')
    return st


def _ensure_running_directory() -> None:
    # ROOT is installed root:root 0755, so Tactical cannot replace entries below
    # it. Never chmod/chown RUNNING here: validate before use and fail closed.
    _require_trusted_directory(ROOT)
    try:
        RUNNING.mkdir(mode=0o700, exist_ok=True)
    except FileExistsError:
        pass
    _require_trusted_directory(RUNNING, private=True)


def _write_result(request_id: str, payload: dict) -> Path:
    _require_trusted_directory(ROOT)
    result_dir = _require_trusted_directory(RESULTS)
    target = RESULTS / f'{request_id}.json'
    fd, tmp_name = tempfile.mkstemp(prefix=f'.{request_id}.', suffix='.tmp', dir=str(RESULTS))
    tmp = Path(tmp_name)
    try:
        data = (json.dumps(payload, indent=2) + '\n').encode('utf-8')
        with os.fdopen(fd, 'wb', closefd=False) as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.fchmod(fd, 0o640)
        try:
            os.fchown(fd, 0 if os.geteuid() == 0 else os.geteuid(), result_dir.st_gid)
        except PermissionError:
            pass
        os.close(fd); fd = -1
        os.replace(tmp, target)
    finally:
        if fd >= 0:
            os.close(fd)
        tmp.unlink(missing_ok=True)
    return target


def claim_request(req: Path) -> Path:
    try:
        request_id=str(uuid.UUID(req.stem))
    except (ValueError, TypeError) as exc:
        raise RuntimeError('housekeeping request filename must be a UUID') from exc
    expected=(ROOT/'requests'/f'{request_id}.json')
    if req != expected:
        raise RuntimeError('invalid request path')
    data=_read_request_nofollow(req)
    _ensure_running_directory()
    fd,tmp_name=tempfile.mkstemp(prefix=f'.{request_id}.',suffix='.tmp',dir=str(RUNNING))
    tmp=Path(tmp_name); target=RUNNING/f'{request_id}.json'
    try:
        with os.fdopen(fd,'wb',closefd=False) as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.fchmod(fd,0o600)
        try:
            os.fchown(fd,0,0)
        except PermissionError:
            pass
        os.close(fd); fd=-1
        os.replace(tmp,target)
    finally:
        if fd >= 0:
            os.close(fd)
        tmp.unlink(missing_ok=True)
    return target

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

def active_jobs(category):
    root = JOB_ROOTS.get(category)
    if root is None or not root.exists(): return set(), False
    ids=set(); unreadable=False
    for path in root.glob('*.json'):
        try:
            payload=json.loads(path.read_text(encoding='utf-8'))
            status=str(payload.get('status') or '').strip().lower()
            if not status or status not in TERMINAL_STATUSES:
                ids.add(str(payload.get('id') or path.stem))
        except Exception:
            unreadable=True
    return ids, unreadable

def candidates(category):
    out=[]
    for base, kind, pattern in CATEGORY_PATHS[category]:
        safe_child(base)
        if not base.exists(): continue
        if kind=='children': items=list(base.iterdir())
        else: items=list(base.glob(pattern or '*'))
        for p in items:
            if kind == 'files' and not (p.is_file() or p.is_symlink()): continue
            safe_child(p)
            try: st=p.lstat()
            except OSError: continue
            out.append({'path':p,'mtime':st.st_mtime,'bytes':size_of(p)})
    return out

def protected_for_active_job(category, item, active_ids, unreadable):
    if category in {'system_update_backups','server_backup_pre_restore'}:
        return bool(active_ids or unreadable)
    if category in STAGING_CATEGORIES:
        # Staging paths are mutable request/work areas. If any job is active (or
        # a job record is unreadable), preserve the whole staging category rather
        # than risk deleting bytes a privileged worker is about to consume.
        return bool(active_ids or unreadable)
    if category in HISTORY_CATEGORIES:
        if unreadable: return True
        name=item['path'].name
        return any(job_id and job_id in name for job_id in active_ids)
    return False

def select(category, policy, *, allow_zero=False, dry_run=False):
    items=candidates(category)
    mode=policy.get('mode')
    zero_blocked=False; zero_reason=None
    if mode=='age_days':
        days=int(policy.get('days',0))
        if days < 1:
            raise RuntimeError(f'{category}.days must be at least 1')
        cutoff=time.time()-days*86400
        purge=[x for x in items if x['mtime'] < cutoff]
    elif mode=='keep_count':
        keep=int(policy.get('keep',0))
        if keep < 1:
            raise RuntimeError(f'{category}.keep must be at least 1')
        ordered=sorted(items,key=lambda x:x['mtime'],reverse=True); purge=ordered[keep:]
    else: raise RuntimeError(f'unsupported policy mode for {category}')
    active_ids, unreadable = active_jobs(category)
    protected=[x for x in purge if protected_for_active_job(category,x,active_ids,unreadable)]
    purge=[x for x in purge if x not in protected]
    return items,purge,protected,active_ids,unreadable,zero_blocked,zero_reason

def remove_path(p: Path):
    safe_child(p)
    if p.is_symlink() or p.is_file(): p.unlink(missing_ok=True)
    elif p.is_dir(): shutil.rmtree(p)

def main():
    if len(sys.argv)!=3 or sys.argv[1] not in {'--scan','--purge'}: raise SystemExit('usage: tec-tac-housekeeping --scan|--purge <request-json>')
    req=Path(sys.argv[2]); safe_child(req)
    if req.parent != ROOT/'requests' or not req.name.endswith('.json'): raise SystemExit('invalid request path')
    claimed=None
    try:
        claimed=claim_request(req)
        payload=json.loads(claimed.read_text(encoding='utf-8'))
        if not isinstance(payload,dict): raise SystemExit('housekeeping request must be an object')
        selected=payload.get('categories') or list(DEFAULTS)
        if not isinstance(selected,list) or any(c not in DEFAULTS for c in selected): raise SystemExit('unknown housekeeping category')
        policies=dict(DEFAULTS)
        for c,v in (payload.get('policies') or {}).items():
            if c not in DEFAULTS or not isinstance(v,dict): raise SystemExit('invalid housekeeping policy')
            policies[c]={**DEFAULTS[c],**v}
        allow_zero = payload.get('allow_zero_destructive') is True
        dry = sys.argv[1]=='--scan' or bool(payload.get('dry_run',False))
        rows=[]; reclaimed=0; deleted=0; scanned=0
        for c in selected:
            items,purge,protected,active_ids,unreadable,zero_blocked,zero_reason=select(c,policies[c],allow_zero=allow_zero,dry_run=dry); scanned += sum(x['bytes'] for x in items)
            row={'id':c,'policy':policies[c],'total_items':len(items),'total_bytes':sum(x['bytes'] for x in items),'purge_items':len(purge),'purge_bytes':sum(x['bytes'] for x in purge),'protected_active_items':len(protected),'active_jobs':len(active_ids),'unreadable_job_state':bool(unreadable),'blocked_zero_destructive':zero_blocked,'blocked_reason':zero_reason}
            if not dry:
                for x in purge:
                    remove_path(x['path']); reclaimed+=x['bytes']; deleted+=1
            rows.append(row)
        result={'ok':True,'dry_run':dry,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'categories':rows,'scanned_bytes':scanned,'deleted_items':deleted,'reclaimed_bytes':reclaimed,'allow_zero_destructive':allow_zero}
        _write_result(req.stem, result)
    finally:
        if claimed is not None:
            claimed.unlink(missing_ok=True)

if __name__=='__main__': main()
