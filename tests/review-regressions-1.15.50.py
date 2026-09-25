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
assert 'queued_stale_deadline(' in scheduler
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

# Root-console lifecycle is covered by review-regressions-1.15.51.py.
print('[TEST] PASS 1.15.50 scheduler timestamp + console trust-policy baseline')
