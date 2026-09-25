#!/usr/bin/env python3
import importlib.util
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

# 1) Persistent trust-policy revert architecture: no transient systemd-run.
cli_source = (ROOT / 'scripts/trust-policy-cli.py').read_text(encoding='utf-8')
installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
assert 'systemd-run' not in cli_source
assert 'check-revert' in cli_source
assert 'tec-tac-trust-policy-revert.service' in installer
assert 'tec-tac-trust-policy-revert.timer' in installer
assert 'WantedBy=multi-user.target' in installer
assert 'OnBootSec=2min' in installer
assert 'OnUnitActiveSec=2min' in installer
assert '${TRUST_POLICY_CLI} check-revert >/dev/null' in installer

# Exercise an expired pending revert as the static service would after reboot.
path = ROOT / 'scripts/trust-policy-cli.py'
spec = importlib.util.spec_from_file_location('trust_policy_cli_review_151', path)
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
    mod.POLICY_FILE.write_text(json.dumps({'schema':1,'minimum_level':'signed_development','updated_at':None,'updated_by':'test'})+'\n')
    expired = datetime.now(timezone.utc) - timedelta(minutes=5)
    mod.write_pending({
        'schema': 1,
        'change_id': 'reboot-test',
        'previous_level': 'signed_production',
        'temporary_level': 'signed_development',
        'created_at': mod.iso(expired - timedelta(hours=8)),
        'expires_at': mod.iso(expired),
        'reason': 'test reboot persistence',
        'actor': 'tester',
    })
    with mock.patch.object(mod, 'actor', return_value='root'):
        result = mod.check_revert_due()
    assert result['status'] == 'reverted', result
    assert mod.read_policy()['minimum_level'] == 'signed_production'
    assert mod.read_pending() is None

# 2) console_change_requested is accepted by Core's audit vocabulary.
audit_source = (ROOT / 'framwork/tec_tac/audit.py').read_text(encoding='utf-8')
assert '"console_change_requested"' in audit_source
spec = importlib.util.spec_from_file_location('tec_tac_audit_review_151', ROOT / 'framwork/tec_tac/audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
assert audit._normalize_action('console_change_requested') == 'console_change_requested'

# 3) B4: long retry countdown gets its countdown plus the stale grace window.
spec = importlib.util.spec_from_file_location('scheduler_timing_review_151', ROOT / 'framwork/tec_tac/scheduler_timing.py')
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)
queued_at = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
initial_deadline = timing.queued_stale_deadline(queued_at=queued_at, queued_stale_minutes=10, attempt=0, retry_delay_seconds=3600)
retry_deadline = timing.queued_stale_deadline(queued_at=queued_at, queued_stale_minutes=10, attempt=1, retry_delay_seconds=3600)
assert initial_deadline == queued_at + timedelta(minutes=10)
assert retry_deadline == queued_at + timedelta(minutes=70)
assert retry_deadline > queued_at + timedelta(hours=1)

scheduler_source = (ROOT / 'framwork/tec_tac/scheduler.py').read_text(encoding='utf-8')
assert 'queued_stale_deadline(' in scheduler_source
assert 'retry_delay_seconds=int(run.retry_delay_seconds_snapshot or 0)' in scheduler_source
assert 'attempt=int(run.attempt or 0)' in scheduler_source

print('[TEST] PASS 1.15.51 persistent trust revert + audit + retry-aware B4')
