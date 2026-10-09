#!/usr/bin/env python3
"""1.17.4 regression: tec_tac.reporting is a forwarding shim over reportmanager.registry (AD-15).

Django is not installed on the development PC, so the real reporting.py (and the real module_state.version_satisfies)
are loaded against stubs for django, tec_tac.registry, tec_tac.capabilities and a fake ee.reporting package, as
tests/update-source-1.17.3.py does for system_update.py. Every scenario loads a fresh copy of reporting.py, because
the handover state is module state. contracts.py and install.sh are read as text.
"""
from __future__ import annotations

import ast
import importlib.util
import logging
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
logging.disable(logging.CRITICAL)


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


class RegistryError(ValueError):
    """Stand-in for Report Manager's RegistryError: ``state`` says why."""

    def __init__(self, message, state="invalid"):
        super().__init__(message)
        self.state = state


class FakeProvider:
    """Stand-in for the reportmanager.registry capability provider."""

    def __init__(self):
        self.registered = []
        self.unregistered = []
        self.rows = {}
        self.raise_with = None  # an exception instance to raise from register_model

    def register_model(self, **kw):
        if self.raise_with is not None:
            raise self.raise_with
        self.registered.append(kw)
        row = {"id": kw["reporting_id"], "module_id": kw["module_id"], "app_label": kw["app_label"], "model": kw["model"],
               "hidden_fields": list(kw["hidden_fields"] or []), "available": True, "state": "available", "reason": None}
        self.rows[kw["reporting_id"]] = row
        return row

    def unregister_model(self, reporting_id=None, **kw):
        self.unregistered.append((reporting_id, kw.get("context")))
        self.rows.pop(reporting_id, None)
        return True

    def list_models(self, *, include_unavailable=True, context=None):
        return [dict(row) for row in self.rows.values()]

    def model_status(self, reporting_id, context=None):
        return dict(self.rows.get(reporting_id) or {"id": reporting_id, "available": False, "state": "missing"})


class FakeModel:
    def __init__(self, app, name):
        self.app, self.__name__ = app, name
        self._meta = SimpleNamespace(get_fields=lambda: [SimpleNamespace(name="id", many_to_many=False, one_to_many=False)])


MODELS = {
    ("tec_tac_alerts", "modulealert"): FakeModel("tec_tac_alerts", "ModuleAlert"),
    ("tec_tac_alerts", "modulealertevent"): FakeModel("tec_tac_alerts", "ModuleAlertEvent"),
    ("tec_tac_checks", "checkreport"): FakeModel("tec_tac_checks", "CheckReport"),
}
NATIVE = (("Agent", "agents"), ("Client", "clients"))


def fresh(*, report_manager=None, rm_enabled=True, cap_state=None, health=None):
    """Load a fresh reporting.py. ``report_manager`` is the installed Report Manager version, or None.

    Returns an env with the module, the capability stub state and the fake ee.reporting modules.
    """
    env = SimpleNamespace(provider=FakeProvider(), cap={"available": False, "state": "capability-unavailable", "health": {}, "reason": "not registered"})
    if cap_state:
        env.cap.update(cap_state)
    if health is not None:
        env.cap["health"] = health
    plugins = [SimpleNamespace(plugin_id=name, plugin_type="extension", version="1.0.0") for name in ("alerts", "checks", "scriptexecution")]
    if report_manager:
        plugins.append(SimpleNamespace(plugin_id="reportmanager", plugin_type="extension", version=report_manager))
    enabled = {"reportmanager": rm_enabled}

    mods = {}

    def mod(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        mods[name] = m
        return m

    class FakeApps:
        @staticmethod
        def get_model(app_label=None, model_name=None):
            try:
                return MODELS[(app_label.lower(), model_name.lower())]
            except KeyError:
                raise LookupError(model_name) from None

    mod("django")
    mod("django.apps", apps=FakeApps)
    mod("django.http", JsonResponse=lambda payload: SimpleNamespace(payload=payload, status_code=200))
    tmp_root = Path(tempfile.mkdtemp(prefix="reporting-1174-"))
    (tmp_root / "VERSION").write_text("1.17.4\n", encoding="utf-8")
    pkg = mod("tec_tac")
    pkg.__path__ = [str(APP)]
    mod("tec_tac.registry", get_plugins=lambda: plugins, TEC_TAC_ROOT=tmp_root)
    mod("fcntl")
    mod("tec_tac.safe_files", atomic_json=lambda *a, **k: None)
    spec = importlib.util.spec_from_file_location("tec_tac.module_state", APP / "module_state.py")
    state_mod = importlib.util.module_from_spec(spec)
    mods["tec_tac.module_state"] = state_mod
    sys.modules.update({k: v for k, v in mods.items() if k != "tec_tac.module_state"})
    sys.modules["tec_tac.module_state"] = state_mod
    spec.loader.exec_module(state_mod)
    state_mod.is_enabled = lambda module_id, state=None: enabled.get(module_id, True)
    state_mod.load_state = dict

    def capability_status(capability_id, **kw):
        row = dict(env.cap)
        row.setdefault("id", capability_id)
        return row

    def get_capability(capability_id, *, version=None, required=True, module_id=None):
        if env.cap.get("available"):
            return env.provider
        if required:
            raise RuntimeError("unavailable")
        return None

    def build_operation_context(*, source_module, source_action, source_run_id=None, requested_by=None, **extra):
        return {"source_module": source_module, "source_action": source_action, "source_run_id": source_run_id,
                "requested_by": requested_by, **extra}

    mods["tec_tac.capabilities"] = mod("tec_tac.capabilities", capability_status=capability_status, get_capability=get_capability,
                                       build_operation_context=build_operation_context)

    class QuerySchema:
        def get(self, request):
            return SimpleNamespace(status_code=200, content=b"{}")

    def resolve_model(*, data_source):
        return {"model": data_source.get("model")}

    constants = mod("ee.reporting.constants", REPORTING_MODELS=NATIVE)
    utils = mod("ee.reporting.utils", REPORTING_MODELS=NATIVE, resolve_model=resolve_model, ResolveModelException=type("ResolveModelException", (Exception,), {}))
    views = mod("ee.reporting.views", QuerySchema=QuerySchema)
    ee = mod("ee")
    ee.__path__ = []
    reporting_pkg = mod("ee.reporting", constants=constants, utils=utils, views=views)
    reporting_pkg.__path__ = []
    sys.modules.update(mods)

    spec = importlib.util.spec_from_file_location("tec_tac.reporting", APP / "reporting.py")
    rep = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = rep
    spec.loader.exec_module(rep)
    env.rep, env.constants, env.utils, env.views = rep, constants, utils, views
    env.mods = mods
    return env


def marked(env):
    return (getattr(env.views.QuerySchema.get, "_tec_tac_reporting_bridge", False),
            getattr(env.utils.resolve_model, "_tec_tac_reporting_bridge", False))


def reg(env, model="ModuleAlert", module="alerts", app="tec_tac_alerts", **kw):
    return env.rep.register_reporting_model(module_id=module, app_label=app, model=model, **kw)


def healthy(env):
    env.cap.update(available=True, state="available", reason=None, health={"healthy": True, "mode": "report-manager"})


OLD_KEYS = {"available", "installed", "error", "native_models", "tec_tac_models", "total_models", "dynamic_schema"}
NEW_KEYS = {"owner", "handover", "fallback", "forwarded_models", "pending_models", "row_scope_enforced", "row_scope_models"}
# 1.17.5: two additive keys; `error` is unchanged and is their combination.
NEW_KEYS |= {"bridge_error", "handover_error"}

# ------------------------------------------------------------------ (a) Report Manager absent, disabled or older: today's bridge
for label, kw in (("absent", {}), ("disabled", {"report_manager": "0.3.0", "rm_enabled": False}),
                  ("older", {"report_manager": "0.2.9"})):
    env = fresh(**kw)
    status = env.rep.install_tactical_reporting_bridge()
    must(status["installed"] is True and status["available"] is True and marked(env) == (True, True), (label, status))
    must(status["handover"] is False and status["fallback"] is False and status["owner"] == "core", (label, status))
    row = reg(env)
    must(row["available"] is True and row["state"] == "available" and row["forwarded"] is False, (label, row))
    must(("ModuleAlert", "tec_tac_alerts") in env.constants.REPORTING_MODELS, label)
    must(env.constants.REPORTING_MODELS == env.utils.REPORTING_MODELS, label)
    must(env.rep.settle_reporting_bridge()["owner"] == "core", label)
    must(env.provider.registered == [], f"{label}: nothing is forwarded")
    must(env.rep.unregister_reporting_model("alerts.modulealert") is True and ("ModuleAlert", "tec_tac_alerts") not in env.constants.REPORTING_MODELS, label)

# a provider-state error is not a takeover
env = fresh(report_manager="0.3.0")
env.rep._provider_status = lambda module_id: {"installed": False, "enabled": False, "version": None, "state": "provider-state-error"} \
    if module_id == "reportmanager" else {"installed": True, "enabled": True, "version": "1.0.0", "state": "available"}
must(env.rep.install_tactical_reporting_bridge()["installed"] is True, "an unreadable Report Manager state keeps Core's bridge")

# ------------------------------------------------------------------ (b) Report Manager 0.3.0 enabled: Core stands down
for version in ("0.3.0", "0.3.0-1", "0.10.2", "1.0.0"):
    env = fresh(report_manager=version)
    status = env.rep.install_tactical_reporting_bridge()
    must(status["installed"] is False and status["available"] is False and status["handover"] is True, (version, status))
    must(marked(env) == (False, False), f"{version}: no marker may be set")
    must(env.constants.REPORTING_MODELS is NATIVE and env.utils.REPORTING_MODELS is NATIVE, f"{version}: no patching")
    must(status["owner"] == "pending" and status["fallback"] is False and status["error"] is None, status)

# ------------------------------------------------------------------ (c) pending, then settle forwards in id order
env = fresh(report_manager="0.3.0")
env.rep.install_tactical_reporting_bridge()
row_b = reg(env, "CheckReport", "checks", "tec_tac_checks", hidden_fields=["secret", "token"])
row_a = reg(env, "ModuleAlert", "alerts", "tec_tac_alerts")
for row in (row_a, row_b):
    must(row["available"] is False and row["state"] == "pending-report-manager" and row["forwarded"] is False, row)
must(row_b["hidden_fields"] == ["secret", "token"] and row_a["hidden_fields"] == [], (row_a, row_b))
must(env.provider.registered == [] and env.constants.REPORTING_MODELS is NATIVE, "pending registrations are neither forwarded nor synced")
must(env.rep.reporting_bridge_status()["pending_models"] == 2, env.rep.reporting_bridge_status())
healthy(env)
status = env.rep.settle_reporting_bridge()
must([call["reporting_id"] for call in env.provider.registered] == ["alerts.modulealert", "checks.checkreport"], env.provider.registered)
alert_call, check_call = env.provider.registered
must(alert_call["context"]["source_module"] == "alerts" and check_call["context"]["source_module"] == "checks", "context names the registering module")
must(alert_call["context"]["source_action"] == "reporting-shim", alert_call["context"])
must(check_call["hidden_fields"] == ["secret", "token"] and alert_call["hidden_fields"] is None, (alert_call, check_call))
must(alert_call["app_label"] == "tec_tac_alerts" and alert_call["model"] == "ModuleAlert" and alert_call["module_id"] == "alerts", alert_call)
must(status["owner"] == "reportmanager" and status["forwarded_models"] == 2 and status["pending_models"] == 0, status)
must(status["installed"] is False and marked(env) == (False, False) and env.constants.REPORTING_MODELS is NATIVE, "Core still patches nothing")
rows = env.rep.list_reporting_models()
must([r["id"] for r in rows] == ["alerts.modulealert", "checks.checkreport"] and all(r["forwarded"] for r in rows), rows)
must(all("row_scope" in r and "hidden_fields" in r for r in rows), rows)
must(env.rep.reporting_model_status("checks.checkreport")["hidden_fields"] == ["secret", "token"], "the live Report Manager row is returned")
must(status["tec_tac_models"] == 2 and status["total_models"] == len(NATIVE) + 2, status)
before = list(env.provider.registered)
env.rep.settle_reporting_bridge()
must(env.provider.registered == before, "settle runs once")

# ------------------------------------------------------------------ (i) a late call after settle forwards at once
row = reg(env, "ModuleAlertEvent")
must(row["available"] is True and row["forwarded"] is True and env.provider.registered[-1]["reporting_id"] == "alerts.modulealertevent", row)
# an older pending registration is replayed by a later call once the capability appears
env = fresh(report_manager="0.3.0")
env.rep.install_tactical_reporting_bridge()
env.rep.settle_reporting_bridge()  # capability absent -> fallback, so use the unhealthy-report-manager path below instead
must(env.rep.reporting_bridge_status()["fallback"] is True, "an absent capability at settle takes the bridge back")
env = fresh(report_manager="0.3.0", cap_state={"state": "unhealthy", "reason": "bridge not installed", "health": {"healthy": False, "mode": "report-manager"}})
env.rep.install_tactical_reporting_bridge()
reg(env, "ModuleAlert")
env.rep.settle_reporting_bridge()
must(env.provider.registered == [], "nothing forwarded while the capability is unhealthy")
healthy(env)
reg(env, "CheckReport", "checks", "tec_tac_checks")
must([c["reporting_id"] for c in env.provider.registered] == ["alerts.modulealert", "checks.checkreport"], "a late call replays older pending registrations in id order")

# ------------------------------------------------------------------ (d) fallback: the capability is absent or not the owner
for label, cap in (("absent", None),
                   ("core-bridge-active", {"state": "unhealthy", "reason": "core", "health": {"healthy": False, "mode": "core-bridge-active"}}),
                   ("unavailable", {"state": "unhealthy", "reason": "x", "health": {"healthy": False, "mode": "unavailable"}}),
                   ("no mode", {"state": "unhealthy", "reason": "raised", "health": {"error_type": "RuntimeError"}}),
                   ("disabled", {"state": "disabled", "reason": "off", "health": {}})):
    env = fresh(report_manager="0.3.0", cap_state=cap)
    env.rep.install_tactical_reporting_bridge()
    plain = reg(env, "ModuleAlert")
    hidden = reg(env, "CheckReport", "checks", "tec_tac_checks", hidden_fields=["secret"])
    must(plain["state"] == "pending-report-manager" and hidden["state"] == "pending-report-manager", label)
    status = env.rep.settle_reporting_bridge()
    must(status["fallback"] is True and status["installed"] is True and status["available"] is True and status["owner"] == "core", (label, status))
    must(marked(env) == (True, True), f"{label}: Core's bridge is installed again")
    must(("ModuleAlert", "tec_tac_alerts") in env.constants.REPORTING_MODELS, f"{label}: the pending registration is synced")
    must(("CheckReport", "tec_tac_checks") not in env.constants.REPORTING_MODELS, f"{label}: hidden_fields are never exposed")
    row = env.rep.reporting_model_status("checks.checkreport")
    must(row["available"] is False and row["state"] == "hidden-fields-unavailable", (label, row))
    must(env.rep.reporting_model_status("alerts.modulealert")["available"] is True, label)
    must(status["pending_models"] == 0 and status["handover"] is True, (label, status))
    must(env.provider.registered == [], f"{label}: nothing reaches Report Manager")
    # a late call after the fallback is served by Core, and still refuses hidden columns
    late = reg(env, "ModuleAlertEvent", hidden_fields=["x"])
    must(late["state"] == "hidden-fields-unavailable" and late["available"] is False, (label, late))
    must(("ModuleAlertEvent", "tec_tac_alerts") not in env.constants.REPORTING_MODELS, label)

# ------------------------------------------------------------------ (e) unhealthy but mode report-manager: nothing changes
env = fresh(report_manager="0.3.0", cap_state={"state": "unhealthy", "reason": "Report Manager's patch failed", "health": {"healthy": False, "mode": "report-manager"}})
env.rep.install_tactical_reporting_bridge()
reg(env, "ModuleAlert")
status = env.rep.settle_reporting_bridge()
must(status["fallback"] is False and status["installed"] is False and marked(env) == (False, False), status)
must("patch failed" in status["error"] and status["pending_models"] == 1 and status["owner"] == "pending", status)
must(env.constants.REPORTING_MODELS is NATIVE and env.provider.registered == [], "two bridges never patch the same names")
must(env.rep.reporting_model_status("alerts.modulealert")["state"] == "pending-report-manager", "the registration stays pending")

# ------------------------------------------------------------------ (f) refusal mapping
VALIDATION = ("invalid", "duplicate", "not-owner", "native-model-clash", "unknown-provider", "provider-disabled", "model-unavailable")
AVAILABILITY = ("row-scope-unavailable", "bridge-unavailable", "core-bridge-active", "hidden-fields-unavailable")
env = fresh(report_manager="0.3.0")
env.rep.install_tactical_reporting_bridge()
healthy(env)
env.rep.settle_reporting_bridge()
for state in VALIDATION:
    env.provider.raise_with = RegistryError(f"refused {state}", state)
    try:
        reg(env, "ModuleAlert")
    except env.rep.ReportingRegistrationError as exc:
        must(exc.state == state and isinstance(exc, ValueError) and f"refused {state}" in str(exc), (state, exc))
    else:
        raise AssertionError(f"{state} must raise")
    must(env.rep.reporting_model_status("alerts.modulealert")["state"] == "missing", f"{state}: the registration is removed")
    must(env.rep.list_reporting_models() == [], state)
for state in AVAILABILITY:
    env.provider.raise_with = RegistryError(f"refused {state}", state)
    row = reg(env, "ModuleAlert")  # must not raise, so the caller's ready() never aborts
    must(row["available"] is False and row["state"] == state and "refused" in row["reason"], (state, row))
    must([r["id"] for r in env.rep.list_reporting_models()] == ["alerts.modulealert"], f"{state}: the registration is kept")
    env.provider.raise_with = None
    healthy(env)
    must(env.rep.unregister_reporting_model("alerts.modulealert") is True, state)
# an unexpected failure keeps the registration too
env.provider.raise_with = RuntimeError("boom")
row = reg(env, "ModuleAlert")
must(row["state"] == "report-manager-error" and row["available"] is False, row)
env.provider.raise_with = None
env.rep.unregister_reporting_model("alerts.modulealert")

# ------------------------------------------------------------------ (g) unregister forwards
env = fresh(report_manager="0.3.0")
env.rep.install_tactical_reporting_bridge()
reg(env, "CheckReport", "checks", "tec_tac_checks")  # pending, never forwarded
must(env.rep.unregister_reporting_model("checks.checkreport") is True and env.provider.unregistered == [], "a pending registration is dropped without a call")
healthy(env)
reg(env, "ModuleAlert")
must(env.rep.unregister_reporting_model(module_id="alerts", app_label="tec_tac_alerts", model="ModuleAlert") is True, "by module, app and model")
must(len(env.provider.unregistered) == 1 and env.provider.unregistered[0][0] == "alerts.modulealert", env.provider.unregistered)
must(env.provider.unregistered[0][1]["source_module"] == "alerts" and env.provider.unregistered[0][1]["source_action"] == "reporting-shim", env.provider.unregistered)
must(env.rep.unregister_reporting_model("alerts.modulealert") is False and env.rep.list_reporting_models() == [], "gone from Core's record")
must(env.constants.REPORTING_MODELS is NATIVE, "an unregister in handover never touches Tactical's allow-list")

# ------------------------------------------------------------------ (h) status keys, validation and contract entries
env = fresh()
status = env.rep.install_tactical_reporting_bridge()
must(set(status) == OLD_KEYS | NEW_KEYS, set(status) ^ (OLD_KEYS | NEW_KEYS))
must(status["row_scope_enforced"] is True and set(status["row_scope_models"]) == {"enforced", "unscoped"}, status)
env.rep._provider_status = lambda module_id: {"installed": True, "enabled": True, "version": "1.0.0", "state": "available"}
must(set(reg(env)) >= {"id", "module_id", "module_version", "app_label", "model", "display_name", "description", "field_metadata", "fields",
                       "queryable_fields", "available", "state", "reason", "hidden_fields", "forwarded", "row_scope"}, "status row keys")
must(reg(env, "ModuleAlertEvent")["row_scope"] == {"enforced": False, "source": None, "client_field": None, "site_field": None, "include_unassigned": False},
     "a plain manager is not row scoped")
must("ModuleAlertEvent" in dict(env.constants.REPORTING_MODELS), "a model that does not adopt the manager stays registered with Core's bridge")
for bad in ("secret", ["bad name"], [1], [""], {"a": 1}, ["a.b"]):
    try:
        reg(env, "CheckReport", "checks", "tec_tac_checks", hidden_fields=bad)
    except env.rep.ReportingRegistrationError as exc:
        must(exc.state == "invalid", (bad, exc.state))
    else:
        raise AssertionError(f"hidden_fields {bad!r} must be refused")
# Core's own refusals keep their messages and gain a state
for kwargs, state, text in (({"model": "ModuleAlert"}, "duplicate", "Duplicate public reporting ID"),
                            ({"model": "Agent", "module": "alerts"}, "model-unavailable", "is not loaded"),
                            ({"module": "nope"}, "unknown-provider", "Unknown Tec-Tac provider module")):
    env.rep._provider_status = lambda module_id: {"installed": module_id != "nope", "enabled": True, "version": "1.0.0", "state": "available"}
    try:
        reg(env, **kwargs)
    except env.rep.ReportingRegistrationError as exc:
        must(exc.state == state and text in str(exc), (kwargs, exc.state, str(exc)))
    else:
        raise AssertionError(f"{kwargs} must be refused")
env.rep._clear_reporting_registry_for_tests()
must(env.rep.list_reporting_models() == [], "test helper clears the registry")

tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
contracts = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
reporting = {row["name"]: row for row in contracts if row["area"] == "reporting"}
for name in ("register_reporting_model", "unregister_reporting_model", "list_reporting_models", "reporting_model_status",
             "reporting_bridge_status", "ReportingRegistrationError", "scoped_report_manager", "model_row_scope"):
    must(name in reporting and reporting[name]["import_path"] == "tec_tac.reporting" and reporting[name]["kind"] == "python", f"contract entry {name}")
    must(hasattr(env.rep, name), f"{name} exists in reporting.py")
text = reporting["register_reporting_model"]["purpose"]
for word in ("hidden_fields", "pending-report-manager", "ReportingRegistrationError", "reportmanager.registry", "no date"):
    must(word in text, f"register contract mentions {word}")
bridge_text = reporting["reporting_bridge_status"]["purpose"]
for key in NEW_KEYS | OLD_KEYS:
    must(key in bridge_text, f"reporting_bridge_status contract lists {key}")
rules = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "RULES" for t in n.targets))
must(any("reportmanager.registry" in rule and "modules must not import or mutate ee.reporting internals" in rule for rule in rules), "guideline names reportmanager.registry")

# ------------------------------------------------------------------ install.sh self-check accepts handover and fallback
script = (ROOT / "install.sh").read_text(encoding="utf-8")
line = next(item for item in script.splitlines() if item.startswith("VERIFY_REPORTING_CODE="))
code = line[len('VERIFY_REPORTING_CODE="'):-1]


def verify(env):
    sys.modules.update(env.mods)
    sys.modules["tec_tac.reporting"] = env.rep
    sys.modules["tec_tac"].reporting = env.rep
    exec(compile(code, "VERIFY_REPORTING_CODE", "exec"), {})


env = fresh()
env.rep.install_tactical_reporting_bridge()
verify(env)  # normal: markers are asserted and present
env = fresh(report_manager="0.3.0")
env.rep.install_tactical_reporting_bridge()
verify(env)  # handover: no markers, no failure
env.rep.settle_reporting_bridge()
verify(env)  # fallback: Core's bridge is installed again
env = fresh(report_manager="0.3.0", cap_state={"available": False, "state": "unhealthy", "reason": "bridge not owned", "health": {"mode": "report-manager"}})
env.rep.install_tactical_reporting_bridge()
env.rep.settle_reporting_bridge()
verify(env)  # 1.17.5: Report Manager owns the bridge but is unhealthy; a healthy Core must not fail the install
env = fresh()
env.rep.install_tactical_reporting_bridge()
env.views.QuerySchema.get = lambda self, request: None  # a lost marker still fails the installer when Core claims installed
try:
    verify(env)
except AssertionError:
    pass
else:
    raise AssertionError("a missing marker must fail the install check when the bridge is installed")
env = fresh()
env.rep._BRIDGE_ERROR = "broken"
try:
    verify(env)
except AssertionError:
    pass
else:
    raise AssertionError("a bridge error must fail the install check")

print("reporting handover 1.17.4: ok")
