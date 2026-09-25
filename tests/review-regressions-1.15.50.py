#!/usr/bin/env python3
import importlib.util
import io
import json
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

# Scheduler retry fix must remain intact.
scheduler = (ROOT / 'framwork/tec_tac/scheduler.py').read_text(encoding='utf-8')
tasks = (ROOT / 'framwork/tec_tac/tasks.py').read_text(encoding='utf-8')
models = (ROOT / 'framwork/tec_tac/models.py').read_text(encoding='utf-8')
assert 'last_queued_at = models.DateTimeField' in models
assert 'Q(last_queued_at__lt=queued_cutoff)' in scheduler
assert 'current.last_queued_at = timezone.now()' in tasks
assert (ROOT / 'framwork/tec_tac/migrations/0014_scheduler_last_queued_at.py').is_file()

# Tactical DB / Knox / TOTP must not participate in root trust decisions.
privileged = (ROOT / 'scripts/privileged-trust.py').read_text(encoding='utf-8')
helper = (ROOT / 'scripts/system-update-helper.py').read_text(encoding='utf-8')
installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
views = (ROOT / 'framwork/tec_tac/views.py').read_text(encoding='utf-8')
assert 'knox_authtoken' not in privileged
assert 'set-policy-authorized' not in privileged
assert '--set-trust-policy-auth' not in helper
assert '--set-trust-policy-auth *' not in installer
assert 'console_change_requested' in views
assert 'trust_policy_console_guidance' in views

# Root-console tool: test a temporary lowering with timer scheduling stubbed.
path = ROOT / 'scripts/trust-policy-cli.py'
spec = importlib.util.spec_from_file_location('trust_policy_cli_review', path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    mod.POLICY_ROOT = td / 'policy'
    mod.POLICY_FILE = mod.POLICY_ROOT / 'update-trust-policy.json'
    mod.PENDING_FILE = mod.POLICY_ROOT / 'pending.json'
    mod.AUDIT_DIR = td / 'log'
    mod.AUDIT_FILE = mod.AUDIT_DIR / 'audit.jsonl'
    mod.POLICY_ROOT.mkdir(parents=True)
    mod.POLICY_FILE.write_text(json.dumps({'schema':1,'minimum_level':'signed_production','updated_at':None,'updated_by':'test'})+'\n')
    scheduled = {}
    def fake_schedule(change_id, expires):
        scheduled['id'] = change_id
        scheduled['expires'] = expires
    with mock.patch.object(mod, 'confirm', return_value=None), mock.patch.object(mod, 'schedule_revert', side_effect=fake_schedule), mock.patch.object(mod, 'stop_timer', return_value=None), mock.patch.object(mod, 'actor', return_value='tester'):
        result = mod.set_level('signed_development', reason='review test', hours=8)
    assert result['temporary'] is True
    assert result['revert_level'] == 'signed_production'
    assert scheduled['id'] == result['change_id']
    assert mod.read_policy()['minimum_level'] == 'signed_development'
    pending = mod.read_pending(); assert pending['previous_level'] == 'signed_production'
    with mock.patch.object(mod, 'actor', return_value='root'):
        reverted = mod.revert_due(result['change_id'])
    assert reverted['status'] == 'reverted'
    assert mod.read_policy()['minimum_level'] == 'signed_production'
    audit = mod.AUDIT_FILE.read_text(encoding='utf-8')
    assert 'policy_changed_console' in audit and 'policy_auto_reverted' in audit

print('[TEST] PASS scheduler retry timestamp + root-console trust-policy lowering')
