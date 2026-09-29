#!/usr/bin/env python3
from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'framwork'))

# ---------------------------------------------------------------------------
# Minimal DRF/drf-spectacular stubs. The test imports and executes the real
# Tec-Tac view classes; only framework plumbing is replaced for portability.
# ---------------------------------------------------------------------------
rf = types.ModuleType('rest_framework')
rf_response = types.ModuleType('rest_framework.response')
rf_views = types.ModuleType('rest_framework.views')

class Response:
    def __init__(self, data=None, status=200):
        self.data = data
        self.status_code = status

class APIView: pass
rf_response.Response = Response
rf_views.APIView = APIView
sys.modules['rest_framework'] = rf
sys.modules['rest_framework.response'] = rf_response
sys.modules['rest_framework.views'] = rf_views

spectacular = types.ModuleType('drf_spectacular')
spectacular_utils = types.ModuleType('drf_spectacular.utils')
def extend_schema(*_args, **_kwargs):
    return lambda fn: fn
spectacular_utils.extend_schema = extend_schema
sys.modules['drf_spectacular'] = spectacular
sys.modules['drf_spectacular.utils'] = spectacular_utils

session = types.ModuleType('tec_tac.session_security')
class SessionAuthenticated: pass
session.SessionAuthenticated = SessionAuthenticated
sys.modules['tec_tac.session_security'] = session

throttles = types.ModuleType('tec_tac.throttles')
class TotpEnrollmentDayThrottle: pass
class TotpEnrollmentMinThrottle: pass
throttles.TotpEnrollmentDayThrottle = TotpEnrollmentDayThrottle
throttles.TotpEnrollmentMinThrottle = TotpEnrollmentMinThrottle
sys.modules['tec_tac.throttles'] = throttles

# ---------------------------------------------------------------------------
# F1/F2: actual My Account DRF views -> self-service operations.
# ---------------------------------------------------------------------------
account = types.ModuleType('tec_tac.account_self_service')
class AccountSelfServiceError(RuntimeError): pass
account.AccountSelfServiceError = AccountSelfServiceError
account.account_summary = lambda user: {'username': user.username}
account.tactical_ui_preferences = lambda user: {'agent_dblclick_action': 'editagent'}
account.update_tactical_ui_preferences = lambda user, payload, request=None: dict(payload)
account_calls = []
def change_own_password(user, **kwargs):
    account_calls.append(('password', user.username, kwargs))
    return {'changed': True, 'other_sessions_revoked': 2}
def reset_own_totp(user, **kwargs):
    account_calls.append(('totp', user.username, kwargs))
    return {'reset': True, 'reauthentication_required': True}
account.change_own_password = change_own_password
account.reset_own_totp = reset_own_totp
sys.modules['tec_tac.account_self_service'] = account

mfa = types.ModuleType('tec_tac.mfa_backup')
mfa.backup_code_status = lambda user: {'totp_configured': True}
sys.modules['tec_tac.mfa_backup'] = mfa

account_views = importlib.import_module('tec_tac.account_self_service_views')
user = SimpleNamespace(username='alice')
request = SimpleNamespace(
    user=user,
    data={'current_password': 'old-pass', 'new_password': 'Strong-Next-42!'},
    tec_tac_session=SimpleNamespace(id='current-session'),
)
response = account_views.MyAccountPasswordView().put(request)
assert response.status_code == 200 and response.data['changed'] is True
kind, username, kwargs = account_calls[-1]
assert kind == 'password' and username == 'alice'
assert kwargs['current_password'] == 'old-pass'
assert kwargs['new_password'] == 'Strong-Next-42!'
assert kwargs['current_session_id'] == 'current-session'
assert kwargs['request'] is request

request.data = {'current_password': 'Strong-Next-42!', 'current_totp': '123456'}
response = account_views.MyAccountTotpResetView().post(request)
assert response.status_code == 200 and response.data['reauthentication_required'] is True
kind, username, kwargs = account_calls[-1]
assert kind == 'totp' and username == 'alice'
assert kwargs['current_password'] == 'Strong-Next-42!'
assert kwargs['current_totp'] == '123456'
assert kwargs['request'] is request

# Error translation is part of the browser contract: proof/validation failures
# must remain a bounded 400 rather than becoming a 500.
def rejected(*_args, **_kwargs):
    raise AccountSelfServiceError('current password is incorrect')
account_views.change_own_password = rejected
response = account_views.MyAccountPasswordView().put(request)
assert response.status_code == 400
assert response.data == {'detail': 'current password is incorrect'}

# ---------------------------------------------------------------------------
# F5/F6/F7: actual Resource Directory DRF views -> delete/relocate/custom fields.
# ---------------------------------------------------------------------------
resources = types.ModuleType('tec_tac.resources')
class ResourceDirectoryError(RuntimeError):
    code = 'resource_error'
class ResourcePermissionDenied(ResourceDirectoryError): code = 'resource_permission_denied'
class ResourceNotFound(ResourceDirectoryError): code = 'resource_not_found'
class ResourceConflict(ResourceDirectoryError): code = 'resource_conflict'
class ResourceValidationError(ResourceDirectoryError): code = 'invalid_resource_request'
for cls in (ResourceDirectoryError, ResourcePermissionDenied, ResourceNotFound, ResourceConflict, ResourceValidationError):
    setattr(resources, cls.__name__, cls)
resource_calls = []
resources.user_context = lambda user: SimpleNamespace(actor=user.username)
resources.list_clients = lambda **kwargs: {'items': []}
resources.list_sites = lambda **kwargs: {'items': []}
resources.list_agents = lambda **kwargs: {'items': []}
resources.get_client = lambda *args, **kwargs: {}
resources.get_site = lambda *args, **kwargs: {}
resources.get_agent = lambda *args, **kwargs: {}
resources.create_client = lambda **kwargs: {}
resources.create_site = lambda **kwargs: {}
resources.update_client = lambda *args, **kwargs: {}
resources.update_site = lambda *args, **kwargs: {}

def delete_site(resource_id, *, move_to_site_id=None, context=None):
    resource_calls.append(('delete_site', resource_id, move_to_site_id, context.actor))
    return {'deleted_site_id': resource_id, 'moved_agents': 3}
def delete_client(resource_id, *, move_to_site_id=None, context=None):
    resource_calls.append(('delete_client', resource_id, move_to_site_id, context.actor))
    return {'deleted_client_id': resource_id, 'moved_agents': 4}
def list_custom_fields(resource_type, resource_id, *, context=None):
    resource_calls.append(('list_fields', resource_type, resource_id, context.actor))
    return {'resource_type': resource_type, 'resource_id': resource_id, 'fields': [{'field_id': 7, 'value': 'OLD'}]}
def update_custom_fields(resource_type, resource_id, *, values, context=None):
    resource_calls.append(('update_fields', resource_type, resource_id, values, context.actor))
    return {'resource_type': resource_type, 'resource_id': resource_id, 'fields': values}
resources.delete_site = delete_site
resources.delete_client = delete_client
resources.list_custom_fields = list_custom_fields
resources.update_custom_fields = update_custom_fields
sys.modules['tec_tac.resources'] = resources

resources_views = importlib.import_module('tec_tac.resource_views')

site_view = resources_views.ResourceMutableDetailView()
site_view.resource_type = 'site'
request = SimpleNamespace(user=user, data={'move_to_site_id': 21}, query_params={})
response = site_view.delete(request, 11)
assert response.status_code == 200 and response.data['moved_agents'] == 3
assert resource_calls[-1] == ('delete_site', 11, 21, 'alice')

client_view = resources_views.ResourceMutableDetailView()
client_view.resource_type = 'client'
request.data = {'move_to_site_id': 22}
response = client_view.delete(request, 2)
assert response.status_code == 200 and response.data['moved_agents'] == 4
assert resource_calls[-1] == ('delete_client', 2, 22, 'alice')

fields_view = resources_views.ResourceCustomFieldsView()
fields_view.resource_type = 'client'
request.data = {}
response = fields_view.get(request, 1)
assert response.status_code == 200 and response.data['fields'][0]['field_id'] == 7
assert resource_calls[-1] == ('list_fields', 'client', 1, 'alice')
request.data = {'values': [{'field_id': 7, 'value': 'NEW'}]}
response = fields_view.patch(request, 1)
assert response.status_code == 200
assert resource_calls[-1] == ('update_fields', 'client', 1, [{'field_id': 7, 'value': 'NEW'}], 'alice')

# Unknown request fields fail at the real HTTP boundary before mutation.
request.data = {'move_to_site_id': 21, 'unexpected': True}
response = site_view.delete(request, 11)
assert response.status_code == 400
assert response.data['code'] == 'invalid_resource_request'

print('[TEST] PASS F1/F2/F5/F6/F7 actual DRF endpoint dispatch and error boundary')
