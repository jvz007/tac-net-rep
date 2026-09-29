#!/usr/bin/env python3
"""Behavioral F1-F4 self-service regression without a Tactical database."""
from __future__ import annotations
import importlib
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Minimal pyotp stub so the behavioral proof runs in the portable test image.
pyotp_mod = types.ModuleType("pyotp")
class FakeTOTP:
    def __init__(self, secret): self.secret = secret
    def now(self): return "123456"
    def verify(self, token, valid_window=0): return str(token) == "123456"
def random_base32(): return "JBSWY3DPEHPK3PXP"
pyotp_mod.TOTP = FakeTOTP
pyotp_mod.random_base32 = random_base32
sys.modules["pyotp"] = pyotp_mod
import pyotp

sys.path.insert(0, str(ROOT / 'framwork'))

# Narrow Django stubs used by account_self_service.py.
django_auth = types.ModuleType('django.contrib.auth')
django_validation = types.ModuleType('django.contrib.auth.password_validation')
django_ex = types.ModuleType('django.core.exceptions')
django_db = types.ModuleType('django.db')
class ValidationError(Exception):
    def __init__(self, messages): self.messages = list(messages)
django_ex.ValidationError = ValidationError
class Atomic:
    def __enter__(self): return self
    def __exit__(self, *args): return False
class Tx: atomic = lambda self: Atomic()
django_db.transaction = Tx()
validation_calls=[]
def validate_password(value, user=None):
    validation_calls.append((value, user))
    if value == 'weak': raise ValidationError(['too weak'])
django_validation.validate_password = validate_password
sys.modules['django.contrib.auth'] = django_auth
sys.modules['django.contrib.auth.password_validation'] = django_validation
sys.modules['django.core.exceptions'] = django_ex
sys.modules['django.db'] = django_db

# Package dependency stubs.
mfa = types.ModuleType('tec_tac.mfa_backup')
invalidated=[]
def invalidate_backup_codes(user, **kwargs): invalidated.append((user.username, kwargs)); return {'invalidated': 1}
mfa.invalidate_backup_codes = invalidate_backup_codes
sys.modules['tec_tac.mfa_backup'] = mfa
sess = types.ModuleType('tec_tac.session_security')
class SessionSecurityError(Exception): pass
sess.SessionSecurityError = SessionSecurityError
audits=[]
sess._audit = lambda event, **kwargs: audits.append((event, kwargs))
revocations=[]
def revoke_user_sessions(username, **kwargs):
    revocations.append((username, kwargs)); return {'revoked': 2, 'session_ids': ['x','y']}
sess.revoke_user_sessions = revoke_user_sessions
sys.modules['tec_tac.session_security'] = sess

class Query:
    def __init__(self, rows): self.rows=rows
    def order_by(self,*args): return self
    def values(self,*fields): return [{f:getattr(x,f) for f in fields} for x in self.rows]
    def filter(self, **kwargs):
        pk=kwargs.get('pk'); return Query([x for x in self.rows if pk is None or x.id == pk])
    def exists(self): return bool(self.rows)
class Action:
    def __init__(self,id,name): self.id=id; self.name=name
class ActionModel:
    objects=Query([Action(7,'Open Portal'), Action(8,'Ticket')])
class Field:
    choices=[('editagent','Edit Agent'),('takecontrol','Take Control'),('remotebg','Remote Background'),('urlaction','URL Action')]
class UrlField:
    remote_field=types.SimpleNamespace(model=ActionModel)
class Meta:
    def get_field(self,name): return Field() if name=='agent_dblclick_action' else UrlField()
class Role:
    is_superuser=False; can_run_urlactions=True
class User:
    _meta=Meta()
    pk=1; id=1; username='alice'; first_name='Alice'; last_name='Ops'; email='a@example.test'; is_superuser=False; is_sso_user=False
    role=Role(); agent_dblclick_action='editagent'; url_action_id=None
    def __init__(self):
        self.password='old'; self.totp_key=pyotp.random_base32(); self.saved=[]
    def check_password(self,p): return p == self.password
    def set_password(self,p): self.password=p
    def save(self, update_fields=None): self.saved.append(tuple(update_fields or ()))
user=User()
class Manager:
    def select_for_update(self): return self
    def get(self,pk): return user
class UserModel: objects=Manager()
django_auth.get_user_model=lambda: UserModel

mod=importlib.import_module('tec_tac.account_self_service')

# F1: proof + validator + other-session revocation, preserving current session.
result=mod.change_own_password(user,current_password='old',new_password='Strong-Next-42!',current_session_id='current')
assert result == {'changed': True, 'other_sessions_revoked': 2}
assert user.password == 'Strong-Next-42!'
assert validation_calls[-1][0] == 'Strong-Next-42!'
assert revocations[-1][1]['except_session_id'] == 'current'
try: mod.change_own_password(user,current_password='bad',new_password='Another-42!',current_session_id='current')
except mod.AccountSelfServiceError: pass
else: raise AssertionError('bad current password accepted')

# F1 done-when: Django/Tactical weak-password validation must surface as a
# bounded self-service error and must not change the password or revoke sessions.
user.password='Strong-Next-42!'
revocations_before=len(revocations)
try:
    mod.change_own_password(user,current_password='Strong-Next-42!',new_password='weak',current_session_id='current')
except mod.AccountSelfServiceError as exc:
    assert str(exc) == 'too weak'
else:
    raise AssertionError('weak password accepted')
assert user.password == 'Strong-Next-42!'
assert validation_calls[-1][0] == 'weak'
assert len(revocations) == revocations_before

# F2: current password + current TOTP proof, then clear TOTP, backup codes and all sessions.
user.password='current-pass'; secret=pyotp.random_base32(); user.totp_key=secret
code=pyotp.TOTP(secret).now()
result=mod.reset_own_totp(user,current_password='current-pass',current_totp=code)
assert result['reset'] is True and result['reauthentication_required'] is True
assert user.totp_key == ''
assert invalidated and invalidated[-1][0] == 'alice'
assert revocations[-1][1].get('except_session_id') is None

# F4: use Tactical model metadata and real URL Action model relation, not a duplicate Core enum/store.
user.totp_key=''; user.agent_dblclick_action='editagent'; user.url_action_id=None
prefs=mod.tactical_ui_preferences(user)
assert [x['value'] for x in prefs['agent_dblclick_choices']] == ['editagent','takecontrol','remotebg','urlaction']
assert {x['id'] for x in prefs['url_actions']} == {7,8}
prefs=mod.update_tactical_ui_preferences(user, {'agent_dblclick_action':'urlaction','url_action_id':7})
assert user.agent_dblclick_action == 'urlaction' and user.url_action_id == 7
assert prefs['url_action_id'] == 7

print('my account features 1.15.167: PASS')
