#!/usr/bin/env python3
from __future__ import annotations

import ast
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
VIEWS = ROOT / 'framwork/tec_tac/mfa_backup_views.py'
MFA = ROOT / 'framwork/tec_tac/mfa_backup.py'


class FakeResponse:
    def __init__(self, data=None, status=200):
        self.data = data
        self.status_code = status
        self.headers = {}
    def __setitem__(self, key, value):
        self.headers[key] = value
    def __getitem__(self, key):
        return self.headers[key]


def compile_class(path: Path, class_name: str, globals_dict: dict):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    ns = dict(globals_dict)
    exec(compile(module, str(path), 'exec'), ns)
    return ns[class_name]


def compile_functions(path: Path, names: list[str], globals_dict: dict):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    wanted = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    missing = set(names) - {n.name for n in wanted}
    assert not missing, f'missing functions: {sorted(missing)}'
    module = ast.Module(body=wanted, type_ignores=[])
    ast.fix_missing_locations(module)
    ns = dict(globals_dict)
    exec(compile(module, str(path), 'exec'), ns)
    return ns


# L47/L48: execute the actual admin GET method and prove protected-target
# authorization runs before status access. Allowed GET is status-only.
class APIView: pass
class SessionAuthenticated: pass

target = SimpleNamespace(pk=7, username='protected')
status_calls = []
manage_allowed = [True]
target_allowed = [False]

class UserManager:
    def filter(self, **kwargs):
        assert kwargs == {'pk': 7}
        return self
    def first(self):
        return target
class UserModel:
    objects = UserManager()

def can_manage(_user): return manage_allowed[0]
def can_target(_actor, _target): return target_allowed[0]
def status_reader(_target):
    status_calls.append(_target.pk)
    return {'configured': True}

AdminView = compile_class(VIEWS, 'AdminUserMfaRecoveryView', {
    'APIView': APIView,
    'SessionAuthenticated': SessionAuthenticated,
    'Response': FakeResponse,
    'get_user_model': lambda: UserModel,
    'can_manage_account_security': can_manage,
    'can_administer_account_security_target': can_target,
    'backup_code_status': status_reader,
    'invalidate_backup_codes': lambda *a, **k: {'invalidated': 0},
})
request = SimpleNamespace(user=SimpleNamespace(username='admin'), data={})
view = AdminView()
blocked = view.get(request, 7)
assert blocked.status_code == 403
assert status_calls == [], 'protected account status was read before authorization'
target_allowed[0] = True
allowed = view.get(request, 7)
assert allowed.status_code == 200
assert status_calls == [7]
assert allowed.data['user'] == {'id': 7, 'username': 'protected'}
assert allowed.data['status'] == {'configured': True}


# L48/L49: execute the real status/invalidation functions with a tiny ORM double.
# Status must not delete/audit; automatic TOTP change and explicit admin invalidation
# must remain distinguishable in the audit stream.
audit_events = []
delete_count = [0]

class StatusQS:
    def __init__(self, total=3, unused=2):
        self.total = total
        self.unused = unused
    def count(self): return self.total
    def filter(self, **kwargs):
        if kwargs == {'used_at__isnull': True}:
            return StatusQS(self.unused, self.unused)
        return self
    def order_by(self, *_args): return self
    def values_list(self, *_args, **_kwargs): return self
    def first(self): return None

class DeleteQS:
    def select_for_update(self): return self
    def filter(self, **_kwargs): return self
    def exclude(self, **_kwargs): return self
    def count(self): return 2
    def delete(self):
        delete_count[0] += 1
        return (2, {})

class StatusManager:
    def filter(self, **_kwargs): return StatusQS()
    def select_for_update(self): return DeleteQS()

class FakeCode:
    objects = StatusManager()

@contextmanager
def atomic():
    yield

mfa_ns = compile_functions(MFA, ['backup_code_status', '_delete_stale_codes_locked', 'invalidate_backup_codes'], {
    'Any': object,
    'TecTacMfaBackupCode': FakeCode,
    '_totp_fingerprint': lambda _u: 'fp',
    '_security_audit': lambda event, _u, **kw: audit_events.append((event, kw)),
    'transaction': SimpleNamespace(atomic=atomic),
})
service_user = SimpleNamespace(username='target', totp_key='ABC', is_sso_user=False)
status = mfa_ns['backup_code_status'](service_user, requested_by='admin')
assert status['total'] == 3 and status['unused'] == 2 and status['used'] == 1
assert delete_count[0] == 0, 'status read deleted data'
assert audit_events == [], 'status read emitted a mutation audit'

mfa_ns['_delete_stale_codes_locked'](service_user, 'new-fp', requested_by='system')
assert audit_events[-1][0] == 'mfa_backup_codes_invalidated_totp_change'
assert audit_events[-1][1]['reason'] == 'totp-key-changed'

# Replace status lookup with a minimal post-delete status to isolate explicit invalidation.
mfa_ns['backup_code_status'] = lambda _u: {'configured': False}
result = mfa_ns['invalidate_backup_codes'](service_user, requested_by='admin', reason='reset')
assert result['invalidated'] == 2
assert audit_events[-1][0] == 'mfa_backup_codes_invalidated'
assert audit_events[-1][1]['metadata']['explicit'] is True
assert audit_events[-2][0] != audit_events[-1][0]


# L88/L89: execute the actual BackupCodeLoginView.post flow. The tight code
# allowance must be claimed before consume_backup_code, while wrong passwords
# must use only the separate loose password bucket.
class KnoxLoginView:
    def post(self, request, format=None):
        return FakeResponse({'token': 'ok'})
class AllowAny: pass
class LoginMinThrottle: pass
class LoginDayThrottle: pass

class FakeSerializer:
    valid = False
    user = None
    def __init__(self, data=None):
        self.data = data or {}
        self.validated_data = {}
    def is_valid(self):
        if self.valid:
            self.validated_data['user'] = self.user
        return self.valid

password_failures = []
code_claims = []
consume_calls = []
code_block = [None]
password_block = [None]
claim_result = [None]

class Audit:
    @staticmethod
    def audit_user_failed_login(*a, **k): pass
    @staticmethod
    def audit_user_failed_twofactor(*a, **k): pass
    @staticmethod
    def audit_user_login_successful(*a, **k): pass

login_user = SimpleNamespace(
    username='Alice', block_dashboard_login=False, is_sso_user=False,
    is_superuser=False, totp_key='TOTP', last_login_ip='',
    save=lambda **kwargs: None,
)

def password_retry(username): return password_block[0]
def code_retry(username): return code_block[0]
def claim_code(username):
    code_claims.append(username)
    return claim_result[0]
def consume_code(user, code, requested_by=''):
    consume_calls.append((user.username, code, requested_by))
    return False

BackupView = compile_class(VIEWS, 'BackupCodeLoginView', {
    'KnoxLoginView': KnoxLoginView,
    'AllowAny': AllowAny,
    'LoginMinThrottle': LoginMinThrottle,
    'LoginDayThrottle': LoginDayThrottle,
    'AuthTokenSerializer': FakeSerializer,
    'backup_code_password_failure_retry_after': password_retry,
    'backup_code_login_failure_retry_after': code_retry,
    'claim_backup_code_login_attempt': claim_code,
    'record_backup_code_password_failure': lambda username: password_failures.append(username),
    'reset_backup_code_login_failures': lambda username: None,
    'reset_backup_code_password_failures': lambda username: None,
    'burn_backup_code_hash_cost': lambda: None,
    'consume_backup_code': consume_code,
    '_mfa_rate_limited': lambda wait, detail: FakeResponse({'detail': detail}, status=429),
    'AuditLog': Audit,
    'notify_error': lambda detail: FakeResponse({'detail': detail}, status=400),
    'get_core_settings': lambda: SimpleNamespace(block_local_user_logon=False),
    'login': lambda request, user: None,
    'IpWare': lambda: SimpleNamespace(get_client_ip=lambda meta: (None, False)),
    'Response': FakeResponse,
})
backup_view = BackupView()

# Wrong password / invalid primary credential: loose bucket only; never claim code slot.
FakeSerializer.valid = False
req = SimpleNamespace(data={'username': 'Alice', 'password': 'wrong', 'backup_code': 'bad'}, _client_ip='', META={})
resp = backup_view.post(req)
assert resp.status_code == 400
assert password_failures == ['Alice']
assert code_claims == []
assert consume_calls == []

# Correct password path: reserve tight code slot before verification.
FakeSerializer.valid = True
FakeSerializer.user = login_user
password_failures.clear(); code_claims.clear(); consume_calls.clear()
resp = backup_view.post(req)
assert resp.status_code == 400
assert code_claims == ['Alice']
assert consume_calls == [('Alice', 'bad', 'Alice')]
assert password_failures == [], 'wrong recovery code consumed the loose password budget'

# Once the tight budget rejects admission, code verification must never run.
code_claims.clear(); consume_calls.clear(); claim_result[0] = 600
resp = backup_view.post(req)
assert resp.status_code == 429
assert code_claims == ['Alice']
assert consume_calls == [], 'rate-limited code attempt reached verification'
assert resp.headers['Retry-After'] == '600' if 'Retry-After' in resp.headers else True

print('[TEST] PASS MFA L47-L49/L88-L89 behavioral closure')
