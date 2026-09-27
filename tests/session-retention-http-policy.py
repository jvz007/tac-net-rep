#!/usr/bin/env python3
"""D4 closure regression: retention is a Core session-policy HTTP setting."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "session_security_views.py"

# Minimal Django/DRF surface required by the view module.
django = types.ModuleType("django")
django_shortcuts = types.ModuleType("django.shortcuts")
django_shortcuts.get_object_or_404 = lambda *args, **kwargs: None
sys.modules.update({"django": django, "django.shortcuts": django_shortcuts})

rf = types.ModuleType("rest_framework")
rf_response = types.ModuleType("rest_framework.response")
class Response:
    def __init__(self, data=None, status=200):
        self.data = data
        self.status_code = status
rf_response.Response = Response
rf_views = types.ModuleType("rest_framework.views")
class APIView: pass
rf_views.APIView = APIView
sys.modules.update({
    "rest_framework": rf,
    "rest_framework.response": rf_response,
    "rest_framework.views": rf_views,
})

pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg
models = types.ModuleType("tec_tac.models")
models.TecTacSessionTrust = object
sys.modules["tec_tac.models"] = models

calls = []
policy = {
    "idle_timeout_minutes": 30,
    "absolute_lifetime_minutes": 480,
    "ip_change_policy": "reauthenticate",
    "session_audit_enabled": True,
    "activity_heartbeat_seconds": 60,
    "history_retention_days": 30,
    "trusted_proxies": [],
}

security = types.ModuleType("tec_tac.session_security")
class SessionAuthenticated: pass
class SessionSecurityError(RuntimeError): pass
security.SessionAuthenticated = SessionAuthenticated
security.SessionSecurityError = SessionSecurityError
security.can_manage_session_security = lambda user: bool(getattr(user, "is_superuser", False))
security.can_manage_login_sessions = lambda user: False
security.diagnostics = lambda: {}
security.get_current_session = lambda request: {}
security.get_effective_policy = lambda user=None, request=None: dict(policy)
security.list_audit_events = lambda **kwargs: []
security.page_audit_events = lambda **kwargs: {"items": [], "total": 0, "page": 1, "page_size": 50, "pages": 0, "next_page": None, "previous_page": None}
security.list_active_login_sessions = lambda **kwargs: []
security.page_active_login_sessions = lambda **kwargs: {"items": []}
security.list_sessions = lambda **kwargs: []
security.record_activity = lambda request: {}
security.revoke_active_login_session = lambda *args, **kwargs: {}
security.revoke_session = lambda *args, **kwargs: {}
security.revoke_user_login_sessions = lambda *args, **kwargs: {}
security.revoke_user_sessions = lambda *args, **kwargs: {}
def update_global_policy(payload, *, requested_by=""):
    calls.append((dict(payload), requested_by))
    if "history_retention_days" in payload:
        value = int(payload["history_retention_days"])
        if value < 1 or value > 3650:
            raise SessionSecurityError("history_retention_days must be between 1 and 3650.")
        policy["history_retention_days"] = value
    return dict(policy)
security._update_global_policy = update_global_policy
sys.modules["tec_tac.session_security"] = security

spec = importlib.util.spec_from_file_location("tec_tac.session_security_views", MODULE)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

class User:
    def __init__(self, username, is_superuser):
        self.username = username
        self.is_superuser = is_superuser
        self.is_authenticated = True
class Request:
    def __init__(self, user, data=None):
        self.user = user
        self.data = data or {}
        self.query_params = {}

view = mod.SessionPolicyView()
admin = Request(User("root", True))
reader = Request(User("reader", False))

# The administrator policy surface must expose retention as part of Core policy.
resp = view.get(admin)
assert resp.status_code == 200
assert resp.data["policy"]["history_retention_days"] == 30

# PUT must round-trip the policy field through Core's policy mutation boundary.
resp = view.put(Request(admin.user, {"policy": {"history_retention_days": 45}}))
assert resp.status_code == 200
assert resp.data["policy"]["history_retention_days"] == 45
assert calls[-1] == ({"history_retention_days": 45}, "root")

# Invalid retention remains a stable 400, not an unhandled conversion error.
resp = view.put(Request(admin.user, {"history_retention_days": 0}))
assert resp.status_code == 400
assert "between 1 and 3650" in resp.data["detail"]

# Non-superusers cannot read or mutate the global security policy.
assert view.get(reader).status_code == 403
assert view.put(Request(reader.user, {"history_retention_days": 45})).status_code == 403

print("[TEST] PASS D4 retention is a Core session-policy HTTP setting")
