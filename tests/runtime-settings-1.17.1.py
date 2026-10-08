#!/usr/bin/env python3
"""1.17.1 UI Q3 regression: Core setting for the module register() time limit.

Django is not installed on the development PC, so the module is loaded against stubs.
The migration and the HTTP wiring are checked with the same stubs and by source.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------ stubs
class PermissionDenied(Exception):
    pass


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


class APIView:
    pass


class AtomicCtx:
    entered = 0
    exited_with_error = 0

    def __enter__(self):
        AtomicCtx.entered += 1
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            AtomicCtx.exited_with_error += 1
        return False


def passthrough(*a, **k):
    return (lambda fn: fn)


mods = {n: types.ModuleType(n) for n in (
    "django", "django.db", "drf_spectacular", "drf_spectacular.utils", "rest_framework",
    "rest_framework.exceptions", "rest_framework.response", "rest_framework.views",
    "tec_tac.models", "tec_tac.rbac", "tec_tac.session_security", "tec_tac.throttles", "tec_tac.audit")}
mods["django.db"].transaction = types.SimpleNamespace(atomic=lambda: AtomicCtx())
mods["drf_spectacular.utils"].extend_schema = passthrough
mods["drf_spectacular.utils"].extend_schema_view = passthrough
mods["rest_framework.exceptions"].PermissionDenied = PermissionDenied
mods["rest_framework.response"].Response = Response
mods["rest_framework.views"].APIView = APIView
mods["tec_tac.session_security"].SessionAuthenticated = type("SessionAuthenticated", (), {})
mods["tec_tac.throttles"].RuntimeSettingsWriteMinThrottle = type("Min", (), {})
mods["tec_tac.throttles"].RuntimeSettingsWriteDayThrottle = type("Day", (), {})
PRIVILEGED = {"ok": False}
mods["tec_tac.rbac"].can_manage_privileged_operations = lambda user: PRIVILEGED["ok"]
AUDITS = []
AUDIT_FAIL = {"on": False}


def record(**kwargs):
    if AUDIT_FAIL["on"]:
        raise RuntimeError("audit store down")
    AUDITS.append(kwargs)
    return {"recorded": True}


mods["tec_tac.audit"].record = record


class Config:
    pk = 1
    module_register_timeout_seconds = 30
    updated_at = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    updated_by = None
    saved = []

    def save(self, update_fields=None):
        Config.saved.append(tuple(update_fields or ()))


CONFIG = Config()
CURRENT_FAILS = {"on": False}


class TecTacRuntimeConfig:
    @classmethod
    def current(cls):
        if CURRENT_FAILS["on"]:
            raise RuntimeError("database unavailable")
        return CONFIG

    class objects:
        @staticmethod
        def select_for_update():
            return types.SimpleNamespace(get=lambda pk: CONFIG)


mods["tec_tac.models"].TecTacRuntimeConfig = TecTacRuntimeConfig
pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(APP)]
sys.modules.update(mods)
sys.modules["tec_tac"] = pkg

spec = importlib.util.spec_from_file_location("tec_tac.runtime_settings", APP / "runtime_settings.py")
rs = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = rs
spec.loader.exec_module(rs)

# ------------------------------------------------------------------ default and range
must(rs.DEFAULT_MODULE_REGISTER_TIMEOUT_SECONDS == 30, "default must be 30 seconds")
must(rs.get_module_register_timeout_seconds() == 30, "helper must return 30 by default")
must((rs.MIN_MODULE_REGISTER_TIMEOUT_SECONDS, rs.MAX_MODULE_REGISTER_TIMEOUT_SECONDS) == (5, 300), "range must be 5 to 300")
for ok in (5, 300, 30, 120):
    must(rs.validate_module_register_timeout_seconds(ok) == ok, f"{ok} must be accepted")
for bad in (4, 301, 0, -1, True, False, 30.5, 30.0, "30", None, [30], {"v": 30}):
    try:
        rs.validate_module_register_timeout_seconds(bad)
    except rs.RuntimeSettingsError:
        continue
    raise AssertionError(f"{bad!r} must be rejected")

# ------------------------------------------------------------------ the helper never raises
CURRENT_FAILS["on"] = True
must(rs.get_module_register_timeout_seconds() == 30, "helper must return 30 when current() raises")
CURRENT_FAILS["on"] = False
CONFIG.module_register_timeout_seconds = 9999
must(rs.get_module_register_timeout_seconds() == 30, "a stored value outside the range must fall back to 30")
CONFIG.module_register_timeout_seconds = 45
must(rs.get_module_register_timeout_seconds() == 45, "helper must return the stored value")
CONFIG.module_register_timeout_seconds = 30

# ------------------------------------------------------------------ GET (any signed-in user)
view = rs.RuntimeSettingsView()
PRIVILEGED["ok"] = False
payload = view.get(types.SimpleNamespace(user=object())).data
must(payload["module_register_timeout_seconds"] == {"value": 30, "minimum": 5, "maximum": 300, "default": 30}, payload)
must(payload["updated_at"] == "2026-10-08T12:00:00+00:00" and payload["updated_by"] is None, payload)

# ------------------------------------------------------------------ PATCH
req = types.SimpleNamespace(user=types.SimpleNamespace(username="alice"), data={"module_register_timeout_seconds": 60})
try:
    view.patch(req)
except PermissionDenied:
    pass
else:
    raise AssertionError("PATCH must be refused without privileged authority")
must(CONFIG.module_register_timeout_seconds == 30 and not AUDITS, "a refused PATCH must change and audit nothing")

PRIVILEGED["ok"] = True
for body, why in (
    ({"module_register_timeout_seconds": 301}, "out of range"),
    ({"module_register_timeout_seconds": "60"}, "string"),
    ({"module_register_timeout_seconds": True}, "bool"),
    ({"module_register_timeout_seconds": None}, "null"),
    ({"module_register_timeout_seconds": 60.5}, "float"),
    ({}, "missing"),
    ({"module_register_timeout_seconds": 60, "other": 1}, "unknown field"),
    ([60], "not an object"),
):
    resp = view.patch(types.SimpleNamespace(user=req.user, data=body))
    must(resp.status_code == 400, f"{why} must give 400, gave {resp.status_code}")
must(CONFIG.module_register_timeout_seconds == 30 and not AUDITS, "rejected values must change and audit nothing")

resp = view.patch(req)
must(resp.status_code == 200 and CONFIG.module_register_timeout_seconds == 60, "a valid PATCH must store the value")
must(resp.data["module_register_timeout_seconds"]["value"] == 60, "PATCH must return the new state")
must(Config.saved[-1] == ("module_register_timeout_seconds", "updated_by", "updated_at"), Config.saved)
must(len(AUDITS) == 1, "exactly one audit row")
row = AUDITS[0]
must(row["module_id"] == "core" and row["object_type"] == "runtime_settings" and row["action"] == "modify", row)
must(row["strict"] is True, "the audit write must be strict")
must(row["before"] == {"module_register_timeout_seconds": 30} and row["after"] == {"module_register_timeout_seconds": 60}, row)
must(row["actor"] is req.user, "the signed-in user is the actor")

# An unchanged value is not a change: no audit row.
AUDITS.clear()
view.patch(req)
must(not AUDITS, "an unchanged value must not write an audit row")

# A failed audit write surfaces (the transaction then rolls the change back).
AUDIT_FAIL["on"] = True
before_errors = AtomicCtx.exited_with_error
try:
    view.patch(types.SimpleNamespace(user=req.user, data={"module_register_timeout_seconds": 90}))
except RuntimeError:
    pass
else:
    raise AssertionError("a failed audit write must not be swallowed")
must(AtomicCtx.exited_with_error == before_errors + 1, "the change and the audit row must share one transaction")
AUDIT_FAIL["on"] = False

# ------------------------------------------------------------------ source wiring
views_src = (APP / "views.py").read_text(encoding="utf-8")
ui = next(n for n in ast.parse(views_src).body if isinstance(n, ast.ClassDef) and n.name == "UiContextView")
ui_src = ast.get_source_segment(views_src, ui)
must('"module_register_timeout_seconds": get_module_register_timeout_seconds()' in ui_src, "UiContextView must put module_register_timeout_seconds in the payload")
must("from .runtime_settings import get_module_register_timeout_seconds" in views_src, "views.py must import the helper")
urls = (APP / "urls.py").read_text(encoding="utf-8")
must('path("system/runtime-settings/", RuntimeSettingsView.as_view(), name="tec-tac-runtime-settings")' in urls, "route missing")
openapi = (APP / "openapi.py").read_text(encoding="utf-8")
must(openapi.count("Tec-Tac · Runtime Settings") == 2, "Swagger group missing from callback and path tables")
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
must('"module_register_timeout_seconds"' in contracts and '"/api/tfd/system/runtime-settings/"' in contracts, "contracts.py must list the key and the endpoint")
must('"/api/tfd/ui/context/"' in contracts, "contracts.py must describe the ui/context addition")
must("The UI, not modules, applies the module register() time limit." in contracts, "contracts.py must say the UI applies the limit")
must("get_module_register_timeout_seconds" in contracts, "contracts.py python row missing")
for needle in ('"PATCH"', "core.privileged_operations", "strict Core audit row"):
    must(needle in contracts, f"endpoint contract lacks {needle}")
install = (ROOT / "install.sh").read_text(encoding="utf-8")
must("/api/tfd/system/runtime-settings/" in install and "tec_tac/runtime_settings.py" in install, "install.sh must verify the route and require the file")
must(AtomicCtx.entered > 0, "the PATCH must run inside a transaction")
rs_src = (APP / "runtime_settings.py").read_text(encoding="utf-8")
must("strict=True" in rs_src, "audit must be strict")
throttle_src = (APP / "throttles.py").read_text(encoding="utf-8")
must("RuntimeSettingsWriteMinThrottle" in throttle_src and "RuntimeSettingsWriteDayThrottle" in throttle_src, "write throttles missing")

# ------------------------------------------------------------------ migration 0022 and model
model_src = (APP / "models.py").read_text(encoding="utf-8")
cls = next(n for n in ast.parse(model_src).body if isinstance(n, ast.ClassDef) and n.name == "TecTacRuntimeConfig")
cls_src = ast.unparse(cls)
must("module_register_timeout_seconds = models.PositiveIntegerField(default=30)" in cls_src, "model field/default wrong")
must("def current(cls)" in cls_src and "get_or_create(singleton=1)" in cls_src, "model needs a current() classmethod like the other singletons")

created = []


class Rec:
    def __init__(self, *a, **k):
        self.a, self.k = a, k


class Migration:
    pass


dj = types.ModuleType("django")
dconf = types.ModuleType("django.conf")
dconf.settings = types.SimpleNamespace(AUTH_USER_MODEL="accounts.User")
ddb = types.ModuleType("django.db")
dmig = types.ModuleType("django.db.migrations")
dmig.Migration = Migration
dmig.CreateModel = Rec
dmig.swappable_dependency = lambda x: ("swappable", x)


class M(types.ModuleType):
    def __getattr__(self, n):
        if n.startswith("__"):
            raise AttributeError(n)
        return type(n, (Rec,), {})


dmodels = M("django.db.models")
dd = types.ModuleType("django.db.models.deletion")
dd.SET_NULL = "SET_NULL"
ddb.migrations, ddb.models = dmig, dmodels
dmodels.deletion = dd
dj.db = ddb
sys.modules.update({"django": dj, "django.conf": dconf, "django.db": ddb, "django.db.migrations": dmig,
                    "django.db.models": dmodels, "django.db.models.deletion": dd})
sys.modules.pop("django.db.models.deletion", None)
sys.modules["django.db.models.deletion"] = dd
spec = importlib.util.spec_from_file_location("mig0022", APP / "migrations" / "0022_runtime_config.py")
m22 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m22)
must(("tec_tac", "0021_saved_views") in m22.Migration.dependencies, "0022 must follow 0021")
op = m22.Migration.operations[0]
must(isinstance(op, Rec) and op.k["name"] == "TecTacRuntimeConfig", "0022 must create TecTacRuntimeConfig")
names = [f[0] for f in op.k["fields"]]
must(names == ["singleton", "module_register_timeout_seconds", "updated_at", "updated_by"], names)
default = dict(op.k["fields"])["module_register_timeout_seconds"]
must(default.k.get("default") == 30, "0022 default must be 30")
must(len(m22.Migration.operations) == 1, "0022 creates only the model")

print("[TEST] PASS 1.17.1 runtime settings: module register() time limit")
