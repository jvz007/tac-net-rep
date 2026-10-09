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
    def __init__(self, data, status=200, headers=None):
        self.data = data
        self.status_code = status
        self.headers = dict(headers or {})

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
declaring = registry.PluginSpec(
    plugin_id="declaring-demo",
    plugin_type="extension",
    root=ROOT,
    version="1.0.0",
    permission_groups=(),
    audit_events=(("agent", ("view",)),),
)
runtime.get_plugins = lambda: (permissionless, legacy, permissioned, declaring)
runtime._WARNED_MODULES.clear()
stream = io.StringIO()
handler = logging.StreamHandler(stream)
runtime.logger.addHandler(handler)
runtime.logger.setLevel(logging.WARNING)
try:
    rows = runtime.module_runtime_snapshot()
    runtime.module_runtime_snapshot()  # a second UI-context request must not warn again
finally:
    runtime.logger.removeHandler(handler)
warning_text = stream.getvalue()
assert {row["id"] for row in rows} == {"permissionless-demo", "legacy-demo", "permissioned-demo", "declaring-demo"}
assert "permissionless-demo has no declared permissions" in warning_text
assert "legacy-demo has no declared permissions" in warning_text
assert "HTTP 403" in warning_text
# Once per module per process; a module that declares audit_events, or permissions, never warns.
assert warning_text.count("permissionless-demo has no declared permissions") == 1
assert warning_text.count("legacy-demo has no declared permissions") == 1
assert "declaring-demo" not in warning_text and "permissioned-demo" not in warning_text

# Core 1.17.0 (1.16.0 review Low): _fit_debug_info replaces only keys that are present, the larger of
# metadata and operation_context first, and a replaced operation_context keeps Core's own keys.
saved_limit = audit._max_value_bytes
audit._max_value_bytes = lambda: 1000
try:
    base = {"source": "tec-tac", "module_id": "m", "module_version": "1", "correlation_id": "c"}
    fitted = audit._fit_debug_info({**base, "metadata": {"blob": "m" * 2000}})
    assert "operation_context" not in fitted and "error" in fitted["metadata"], fitted
    fitted = audit._fit_debug_info({**base, "metadata": {"blob": "m" * 600}, "operation_context": {"blob": "o" * 900, "browser_provenance": audit.BROWSER_PROVENANCE_MARKER, "core_refusal": True}})
    assert fitted["operation_context"]["browser_provenance"] == audit.BROWSER_PROVENANCE_MARKER, fitted
    assert fitted["operation_context"]["core_refusal"] is True and "error" in fitted["operation_context"], fitted
    assert fitted["metadata"]["blob"] == "m" * 600, "the larger piece goes first; the smaller one survives"
    assert audit.SCOPE_CHECKED_OBJECT_TYPES == ("client", "site", "agent")
finally:
    audit._max_value_bytes = saved_limit

print("[TEST] PASS browser audit provenance hardening")
