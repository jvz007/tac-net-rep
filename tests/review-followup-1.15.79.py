#!/usr/bin/python3
from __future__ import annotations
import importlib.util
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

def text(rel):
    return (ROOT / rel).read_text(encoding='utf-8')

def require(condition, message):
    if not condition:
        raise AssertionError(message)

# C4 scheduler list: latest status is a scalar subquery, not an unbounded runs prefetch.
sv = text('framwork/tec_tac/scheduler_views.py')
require('Subquery(latest_status)' in sv, 'scheduler list must annotate latest run status')
require('.prefetch_related("runs")' not in sv, 'scheduler list must not prefetch all retained runs')

# C7/B5 runtime authorization and per-schedule exception containment.
sc = text('framwork/tec_tac/scheduler.py')
require('def _runtime_authorization_error' in sc and 'AuthorizationRevoked' in sc, 'runtime schedule authorization missing')
require('dispatch_failed.append(f"schedule:{schedule_id}")' in sc and 'except TecTacSchedule.DoesNotExist' in sc, 'scheduler tick lacks per-schedule containment')

# C8 dedicated authenticated audit throttles and browser provenance restrictions.
av = text('framwork/tec_tac/audit_views.py')
aud = text('framwork/tec_tac/audit.py')
require('AuditWriteMinThrottle' in av and 'AuditWriteDayThrottle' in av, 'audit writer lacks dedicated throttles')
require('module.get("id") == "core" or not tuple(module.get("permissions") or ())' in aud, 'browser audit must reject Core and permissionless modules')

# MFA-1 proof attempts use a dedicated authenticated throttle.
mfa = text('framwork/tec_tac/mfa_backup_views.py')
require('MfaBackupProofMinThrottle' in mfa and 'MfaBackupProofDayThrottle' in mfa, 'MFA backup generation lacks dedicated proof throttle')

# C9 superuser-only session policy management + conservative private proxy ranges.
ss = text('framwork/tec_tac/session_security.py')
require('can_do_server_maint' not in ss[ss.index('def can_manage_session_security'):ss.index('def _is_effective_superuser')], 'server-maint permission must not manage session security')
require('network.prefixlen < min_prefix' in ss and 'network.is_private or network.is_loopback or network.is_link_local' in ss, 'trusted proxy validation is not restrictive enough')
require('force=True' in ss[ss.index('def update_global_policy'):ss.index('def _credential_identity')], 'session policy changes must always be audited')

# C10 revoked session fingerprints are preserved as security tombstones.
require('revoked_tombstones_preserved' in ss and 'Q(revoked=False' in ss, 'revoked session tombstones are not preserved')

# C11 repository URLs/errors are redacted from ordinary users.
rv = text('framwork/tec_tac/module_repository_views.py')
require('_redact_repository_urls' in rv and 'Repository operation failed.' in rv, 'repository redaction/generic error boundary missing')

# C14 mutation lock cannot be held by Tactical; both helpers use unique temp JSON.
inst = text('install.sh')
require(inst.count('chown root:root "${MODULE_STATE_LOCK}"') >= 2 and inst.count('chmod 0600 "${MODULE_STATE_LOCK}"') >= 2, 'module-state lock must remain root-only')
for rel in ('scripts/module-job-helper.py','scripts/module-v2-job-helper.py'):
    src=text(rel)
    require('tempfile.mkstemp' in src, f'{rel} must use unique temporary JSON files')
require('fcntl.LOCK_EX' in text('scripts/module-job-helper.py'), 'v1 module state mutation must be flock protected')

# C16 rollback/recovery extraction uses explicit validation + data filter.
su=text('scripts/system-update-helper.py')
rec=text('scripts/recovery/tec-tac-recover-modules-from-backup.sh')
require('tf.extractall(parent, members=members, filter="data")' in su, 'system update rollback extraction not hardened')
require("filter='data'" in rec and 'member.issym() or member.islnk()' in rec, 'module recovery extraction not hardened')

# C2 privileged archives are staged under the server-backup state root rather than /tmp.
sb=text('scripts/server-backup-helper.py')
require('_archive_fixed_tree(source, roots(config)["staging"])' in sb, 'privileged backup archive still uses global temp storage')
require('TemporaryDirectory(prefix="tectac-scp-", dir=str(roots(config)["staging"]))' in sb, 'SCP verification still uses global temp storage')
require('removed verified local staging bundle after destination upload' in sb, 'verified remote backups must clean local staging')

# C5: helper rejects destructive zero retention and protects active staging.
spec=importlib.util.spec_from_file_location('hk179', ROOT/'scripts/housekeeping-helper.py')
hk=importlib.util.module_from_spec(spec); spec.loader.exec_module(hk)
with tempfile.TemporaryDirectory() as td:
    base=pathlib.Path(td)
    hk.STATE=base
    hk.CATEGORY_PATHS={'x': [(base/'x','children',None)]}
    (base/'x').mkdir()
    try:
        hk.select('x', {'mode':'age_days','days':0})
    except RuntimeError:
        pass
    else:
        raise AssertionError('age_days=0 must be rejected')
    try:
        hk.select('x', {'mode':'keep_count','keep':0})
    except RuntimeError:
        pass
    else:
        raise AssertionError('keep_count=0 must be rejected')

# Low review tail.
sysup=text('framwork/tec_tac/system_update.py')
for token in ('"requested_by"', '"version"', '"operation"'):
    require(token in sysup[sysup.index('def queue_install'):sysup.index('def public_job')], f'queue_install missing {token}')
require('OpenApiParameter(name="ui_url"' in text('framwork/tec_tac/views.py'), 'ui_url missing from OpenAPI contract')
require('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683' in text('.github/workflows/release.yml'), 'checkout action is not SHA pinned')
require("config values may not contain CR/LF" in inst, 'installer config line-injection guard missing')

print('[TEST] PASS review follow-up 1.15.79')
