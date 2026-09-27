#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'framwork' / 'tec_tac' / 'throttles.py'

class FakeCache:
    def __init__(self): self.data = {}
    def get(self, key, default=None): return self.data.get(key, default)
    def set(self, key, value, timeout=None): self.data[key] = value; return True
    def add(self, key, value, timeout=None):
        if key in self.data: return False
        self.data[key] = value; return True
    def incr(self, key, delta=1):
        if key not in self.data: raise ValueError('missing')
        self.data[key] += delta; return self.data[key]
    def delete_many(self, keys):
        for key in keys: self.data.pop(key, None)

cache = FakeCache()
django = types.ModuleType('django')
django_core = types.ModuleType('django.core')
django_cache = types.ModuleType('django.core.cache')
django_cache.cache = cache
sys.modules.update({'django': django, 'django.core': django_core, 'django.core.cache': django_cache})
rf = types.ModuleType('rest_framework')
rf_thr = types.ModuleType('rest_framework.throttling')
class SimpleRateThrottle: pass
rf_thr.SimpleRateThrottle = SimpleRateThrottle
sys.modules.update({'rest_framework': rf, 'rest_framework.throttling': rf_thr})

spec = importlib.util.spec_from_file_location('mfa_throttles_test', MODULE)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
now = [1_000_000.0]
mod.time.time = lambda: now[0]

class User:
    def __init__(self, pk, username): self.pk=pk; self.username=username
u = User(7, 'Alice')

# Proof failure budget: account only, 5 failures in 15 minutes, next attempt blocked.
assert mod.mfa_backup_proof_failure_retry_after(u) is None
for _ in range(5): mod.record_mfa_backup_proof_failure(u)
wait = mod.mfa_backup_proof_failure_retry_after(u)
assert 899 <= wait <= 900, wait
mod.reset_mfa_backup_proof_failures(u)
assert mod.mfa_backup_proof_failure_retry_after(u) is None

# Successful generation uses an independent bucket and does not consume failures.
for _ in range(mod.MFA_BACKUP_SUCCESS_LIMIT): mod.record_mfa_backup_proof_success(u)
wait = mod.mfa_backup_proof_success_retry_after(u)
assert 86399 <= wait <= 86400, wait
assert mod.mfa_backup_proof_failure_retry_after(u) is None

# Tight backup-code budget is reserved before verification. Five concurrent-like
# admissions are allowed; the sixth is rejected before it can verify a code.
for _ in range(mod.MFA_BACKUP_FAILURE_LIMIT):
    assert mod.claim_backup_code_login_attempt('Alice') is None
wait = mod.claim_backup_code_login_attempt('  ALICE  ')
assert 899 <= wait <= 900, wait
assert mod.backup_code_login_failure_retry_after('ALICE') is not None
mod.reset_backup_code_login_failures('alice')
assert mod.backup_code_login_failure_retry_after('ALICE') is None

# Wrong passwords use a distinct, looser per-username budget and do not consume
# the tight backup-code verification allowance.
assert mod.MFA_BACKUP_PASSWORD_FAILURE_LIMIT > mod.MFA_BACKUP_FAILURE_LIMIT
for _ in range(mod.MFA_BACKUP_PASSWORD_FAILURE_LIMIT):
    mod.record_backup_code_password_failure('Bob')
assert mod.backup_code_password_failure_retry_after(' bob ') is not None
assert mod.backup_code_login_failure_retry_after('bob') is None

# Window expiry clears both kinds of block.
now[0] += 901
assert mod.backup_code_password_failure_retry_after('bob') is None

view = (ROOT/'framwork/tec_tac/mfa_backup_views.py').read_text()
assert 'response["Retry-After"]' in view
assert 'record_mfa_backup_proof_failure(request.user)' in view
assert 'reset_mfa_backup_proof_failures(request.user)' in view
assert 'record_mfa_backup_proof_success(request.user)' in view
assert 'backup_code_login_failure_retry_after(username)' in view
assert 'claim_backup_code_login_attempt(username)' in view
assert 'record_backup_code_password_failure(username)' in view
assert 'record_backup_code_login_failure(username)' not in view
assert 'reset_backup_code_login_failures(username)' in view
assert 'reset_backup_code_password_failures(username)' in view
print('mfa backup throttling regression: PASS')
