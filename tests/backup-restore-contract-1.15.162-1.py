#!/usr/bin/env python3
from __future__ import annotations
import ast
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
contracts=ROOT/'framwork/tec_tac/contracts.py'
urls=ROOT/'framwork/tec_tac/urls.py'
tree=ast.parse(contracts.read_text(encoding='utf-8'))
assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='HTTP_CONTRACT_DETAILS' for t in n.targets))
details=ast.literal_eval(assignment.value)
base='/api/tfd/system/backups/restore/'
job='/api/tfd/system/backups/restore/jobs/<uuid:job_id>/'
assert base in details and job in details
assert set(details[base])=={'GET','POST'}
assert details[base]['GET']['authorization'].startswith('effective Tactical superuser')
post=details[base]['POST']
for key in ('action','destination_id','backup_ref','restore_mode','validation_job_id','confirmed'):
    assert key in post['request'], key
assert 'registered destination' in post['request']['destination_id']
assert post['request']['validation_job_id'].startswith('restore only')
assert 'explicit confirmation' in post['errors']['400']
assert details[job]['GET']['authorization'].startswith('effective Tactical superuser')
source=urls.read_text(encoding='utf-8')
assert 'path("system/backups/restore/", BackupRestoreView.as_view()' in source
assert 'path("system/backups/restore/jobs/<uuid:job_id>/", BackupRestoreJobView.as_view()' in source
print('backup-restore-contract-1.15.162-1: PASS')
