#!/usr/bin/env python3
"""Regression for C8/L05 browser-audit provenance hardening.

Uses the real tec_tac.audit._actor_can_use_module and can_record_from_browser
against a registry containing one permissionless extension and one legacy plugin.
It also executes the real AuditRecordView.post path with lightweight framework
stubs because the release-test container intentionally does not ship Django/DRF.
"""
from __future__ import annotations

import io
import logging
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))

from tec_tac import audit, registry

permissionless = registry.PluginSpec(
    plugin_id="permissionless-demo",
    plugin_type="extension",
    root=ROOT,
    version="1.0.0",
    permission_groups=(),
)
legacy = registry.PluginSpec(
    plugin_id="legacy-demo",
    plugin_type="legacy",
    root=ROOT,
    version="0.5.x",
    permission_groups=(),
    legacy=True,
)
permissioned = registry.PluginSpec(
    plugin_id="permissioned-demo",
    plugin_type="extension",
    root=ROOT,
    version="1.0.0",
    permission_groups=(("Use", ("permissioned-demo.use",)),),
)

registry.get_plugins = lambda: (permissionless, legacy, permissioned)

import tec_tac.module_state as module_state
module_state.load_state = lambda: {}
module_state.is_enabled = lambda module_id, state: True

class Actor:
    is_authenticated = True
    is_superuser = False
    username = "operator"
    role = None

    def get_and_set_role_cache(self):
        return None

actor = Actor()

# Real _actor_can_use_module intentionally allows backend use of permissionless
# modules; the browser boundary must override that and reject their provenance.
assert audit._actor_can_use_module(actor, {"id": "permissionless-demo", "permissions": ()}) is True
assert audit.can_record_from_browser(actor, "permissionless-demo") is False
assert audit.can_record_from_browser(actor, "legacy-demo") is False

# Permission-bearing browser modules still require an effective grant. Keep the
# real _actor_can_use_module path and stub only its external RBAC dependency.
rbac = types.ModuleType("tec_tac.rbac")
rbac.effective_permissions = lambda actor: set()
sys.modules["tec_tac.rbac"] = rbac
assert audit.can_record_from_browser(actor, "permissioned-demo") is False
rbac.effective_permissions = lambda actor: {"permissioned-demo.use"}
assert audit.can_record_from_browser(actor, "permissioned-demo") is True

# Minimal DRF/spectacular/session stubs so the real HTTP view can be exercised.
rf = types.ModuleType("rest_framework")
rf_response = types.ModuleType("rest_framework.response")
rf_views = types.ModuleType("rest_framework.views")

class Response:
    def __init__(self, data, status=200):
        self.data = data
        self.status_code = status

class APIView:
    pass

rf_response.Response = Response
rf_views.APIView = APIView
sys.modules["rest_framework"] = rf
sys.modules["rest_framework.response"] = rf_response
sys.modules["rest_framework.views"] = rf_views

spectacular = types.ModuleType("drf_spectacular")
spectacular_utils = types.ModuleType("drf_spectacular.utils")
def passthrough(*args, **kwargs):
    return lambda obj: obj
spectacular_utils.extend_schema = passthrough
spectacular_utils.extend_schema_view = passthrough
sys.modules["drf_spectacular"] = spectacular
sys.modules["drf_spectacular.utils"] = spectacular_utils

fake_session = types.ModuleType("tec_tac.session_security")
fake_session.SessionAuthenticated = object
sys.modules["tec_tac.session_security"] = fake_session
fake_throttles = types.ModuleType("tec_tac.throttles")
fake_throttles.AuditWriteDayThrottle = object
fake_throttles.AuditWriteMinThrottle = object
sys.modules["tec_tac.throttles"] = fake_throttles

# Reload the view after stubs are installed.
import importlib
sys.modules.pop("tec_tac.audit_views", None)
audit_views = importlib.import_module("tec_tac.audit_views")

class Request:
    user = actor
    def __init__(self, module_id):
        self.data = {"module_id": module_id, "action": "view", "object_type": "thing"}

view = audit_views.AuditRecordView()
for module_id in ("permissionless-demo", "legacy-demo"):
    response = view.post(Request(module_id))
    assert response.status_code == 403, (module_id, response.status_code, response.data)

# Browser runtime discovery must warn operators/developers when an enabled
# permissionless module is exposed to the browser but cannot use browser audit.
import tec_tac.module_runtime as runtime
runtime.get_plugins = lambda: (permissionless, legacy, permissioned)
runtime.load_state = lambda: {}
runtime.is_enabled = lambda module_id, state: True
stream = io.StringIO()
handler = logging.StreamHandler(stream)
runtime.logger.addHandler(handler)
runtime.logger.setLevel(logging.WARNING)
try:
    rows = runtime.module_runtime_snapshot()
finally:
    runtime.logger.removeHandler(handler)
warning_text = stream.getvalue()
assert {row["id"] for row in rows} == {"permissionless-demo", "legacy-demo", "permissioned-demo"}
assert "permissionless-demo has no declared permissions" in warning_text
assert "legacy-demo has no declared permissions" in warning_text
assert "HTTP 403" in warning_text

print("[TEST] PASS browser audit provenance hardening")
