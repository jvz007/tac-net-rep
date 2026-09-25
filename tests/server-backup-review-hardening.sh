#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
HELPER="${ROOT}/scripts/server-backup-helper.py"

grep -q 'rollback_failed_restore' "${HELPER}" || fail "restore rollback helper missing"
grep -q 'create_pre_restore_snapshot' "${HELPER}" || fail "pre-restore database snapshot missing"
grep -q 'rollback_performed' "${HELPER}" || fail "rollback result marker missing"
grep -q 'pg_dump' "${HELPER}" || fail "pre-restore pg_dump missing"
grep -q 'tec-tac-backup-\*\.tgz' "${HELPER}" || fail "SCP list does not include Tec-Tac bundles"
grep -q '\.partial' "${HELPER}" || fail "partial remote publishing missing"
grep -q 'filter="data"' "${HELPER}" || fail "safe TAR data filter missing"
grep -q 'except BaseException as exc' "${HELPER}" || fail "final job status does not catch BaseException"
grep -q 'module-state.json' "${HELPER}" || fail "durable module state is not backed up"
grep -q 'repositories.json' "${HELPER}" || fail "durable repository configuration is not backed up"
grep -q 'keep_unclassified must be set explicitly' "${ROOT}/framwork/tec_tac/server_backup.py" || fail "retention still silently defaults unclassified backups to zero"
grep -q 'filter="data"' "${ROOT}/framwork/tec_tac/system_update.py" || fail "system update TAR extraction lacks data filter"

python3 - "${ROOT}" <<'PY'
import importlib.util, io, pathlib, tarfile, tempfile, time, sys
root=pathlib.Path(sys.argv[1]); path=root/'scripts/server-backup-helper.py'
spec=importlib.util.spec_from_file_location('backup_hardening',path); h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
assert h.remote_base({'type':'sftp','remote_path':'relative/path'}) == 'tectac:relative/path'
assert h.remote_base({'type':'webdav','remote_path':'/absolute/path'}) == 'tectac:/absolute/path'
with tempfile.TemporaryDirectory() as td:
    log=h.LimitedLog(pathlib.Path(td)/'timeout.log'); started=time.monotonic()
    try:
        h.run_logged(['python3','-c','import time; time.sleep(5)'],log,timeout=0.3)
    except RuntimeError as exc:
        assert 'exceeded' in str(exc)
    else:
        raise AssertionError('silent helper hang did not time out')
    finally:
        log.close()
    assert time.monotonic()-started < 2.5
with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td); archive=td/'bad.tgz'; dest=td/'dest'; dest.mkdir()
    with tarfile.open(archive,'w:gz') as tf:
        link=tarfile.TarInfo('link'); link.type=tarfile.SYMTYPE; link.linkname='target'; tf.addfile(link)
        child=tarfile.TarInfo('link/child'); child.size=1; tf.addfile(child,io.BytesIO(b'x'))
    try: h.safe_extract_payload_tar(archive,dest)
    except RuntimeError as exc: assert 'beneath a symlink' in str(exc)
    else: raise AssertionError('member below archive symlink was accepted')
# Retention must protect unreadable metadata regardless of keep_unclassified=0.
class Lock:
    def close(self): pass
old_lock, old_list, old_delete = h.acquire_lock, h.list_destination, h.delete_destination
removed=[]
try:
    h.acquire_lock=lambda config: Lock()
    h.list_destination=lambda config,destination,log:[
        {'archive_name':'tec-tac-backup-safe.tgz','backup_class':'unclassified','sidecar_status':'unreadable','modified_at':'2026-09-25T00:00:00Z'},
        {'archive_name':'tec-tac-backup-old.tgz','backup_class':'unclassified','sidecar_status':'missing','modified_at':'2026-09-24T00:00:00Z'},
    ]
    h.delete_destination=lambda config,destination,name,log: removed.append(name)
    result=h.operation_apply_retention({'TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS':'/tmp'}, {'request':{'policies':[{'destination':{'id':'x','type':'local','name':'x','path':'/tmp'},'keep_daily':0,'keep_weekly':0,'keep_monthly':0,'keep_unclassified':0}]}}, None)
    assert removed == ['tec-tac-backup-old.tgz'], removed
    assert result['protected_unreadable'][0]['archive_name']=='tec-tac-backup-safe.tgz'
finally:
    h.acquire_lock, h.list_destination, h.delete_destination = old_lock, old_list, old_delete
print('[TEST] PASS backup review hardening')
PY
