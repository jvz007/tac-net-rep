#!/usr/bin/env python3
"""Regression for Core 1.17.0: Core-owned deny rows, any declared object type, and the browser provenance marker.

Q34: denials of Tactical-guarded actions reach the audit log as Core-owned rows (core_refusal).
Q35: a permissionless module may declare audit events for any lowercase object type; only client,
site and agent are scope-checked.
Q36: browser_provenance is on every row the declared path writes, also when a value is too large.

Runs the real registry, audit, audit_views and resources code. Only the Tactical ORM boundary is faked.
DRF, session and throttle classes are stubs because the release-test container does not ship Django/DRF.
"""
from __future__ import annotations

import importlib
import json
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"

pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(PKG)]
sys.modules["tec_tac"] = pkg

# --- Tactical / framework boundary stubs -------------------------------------------------
capabilities = types.ModuleType("tec_tac.capabilities")
capabilities.register_capability = lambda **kwargs: kwargs
capabilities.list_capabilities = lambda check_health=False: []
sys.modules["tec_tac.capabilities"] = capabilities

module_state = types.ModuleType("tec_tac.module_state")
ENABLED = {"disabled-demo": False}
module_state.load_state = lambda: {}
module_state.is_enabled = lambda module_id, state: ENABLED.get(module_id, True)
sys.modules["tec_tac.module_state"] = module_state

GRANTED: set[str] = set()
rbac_stub = types.ModuleType("tec_tac.rbac")
rbac_stub.effective_permissions = lambda actor: set(GRANTED)
sys.modules["tec_tac.rbac"] = rbac_stub

SCOPE_CALLS = []
DATA = {
    "agents": [
        {"type": "agent", "id": "a-1", "hostname": "ALPHA-PC", "client_id": 1, "site_id": 11, "active": True},
        {"type": "agent", "id": "a-2", "hostname": "BETA-SRV", "client_id": 2, "site_id": 21, "active": True},
    ],
}


class FakeQS:
    def __init__(self, rows):
        self.rows = list(rows)


adapter = types.ModuleType("tec_tac.resources_adapter")
for name in ("TacticalResourceAdapterError", "TacticalResourceConflictError", "TacticalResourceValidationError"):
    setattr(adapter, name, type(name, (RuntimeError,), {}))


def agents_queryset(*, user=None, trusted=False, client_id=None, site_id=None, search=None, active=None):
    SCOPE_CALLS.append(("agents", getattr(user, "username", None)))
    allowed = getattr(user, "allowed_agents", set())
    return FakeQS([row for row in DATA["agents"] if trusted or row["id"] in allowed])


def clients_queryset(*, user=None, trusted=False, search=None, active=None):
    SCOPE_CALLS.append(("clients", getattr(user, "username", None)))
    return FakeQS([])


adapter.agents_queryset = agents_queryset
adapter.clients_queryset = clients_queryset
adapter.sites_queryset = lambda **kwargs: FakeQS([])
adapter.get_agent_row = lambda qs, rid: next((dict(r) for r in qs.rows if r["id"] == rid), None)
adapter.get_client_row = lambda qs, rid: None
adapter.get_site_row = lambda qs, rid: None
sys.modules["tec_tac.resources_adapter"] = adapter

# DRF, spectacular, session and throttle stubs so the real view runs.
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
sys.modules.update({"rest_framework": rf, "rest_framework.response": rf_response, "rest_framework.views": rf_views})
spectacular = types.ModuleType("drf_spectacular")
spectacular_utils = types.ModuleType("drf_spectacular.utils")
spectacular_utils.extend_schema = lambda *a, **k: (lambda obj: obj)
spectacular_utils.extend_schema_view = lambda *a, **k: (lambda obj: obj)
sys.modules.update({"drf_spectacular": spectacular, "drf_spectacular.utils": spectacular_utils})
fake_session = types.ModuleType("tec_tac.session_security")
fake_session.SessionAuthenticated = object
sys.modules["tec_tac.session_security"] = fake_session


class MinThrottle:
    pass


class DayThrottle:
    pass


fake_throttles = types.ModuleType("tec_tac.throttles")
fake_throttles.AuditWriteMinThrottle = MinThrottle
fake_throttles.AuditWriteDayThrottle = DayThrottle
sys.modules["tec_tac.throttles"] = fake_throttles

# --- Real code under test -----------------------------------------------------------------
from tec_tac import audit, registry  # noqa: E402

registry_ok = registry
audit_views = importlib.import_module("tec_tac.audit_views")


class FakeRow:
    pk = 1


class Manager:
    def __init__(self):
        self.rows = []
        self.fail = False

    def create(self, **kwargs):
        if self.fail:
            raise RuntimeError("db down")
        self.rows.append(kwargs)
        return FakeRow()


class FakeAuditLog:
    objects = Manager()


audit._auditlog_model = lambda: FakeAuditLog
ROWS = FakeAuditLog.objects.rows


def spec(plugin_id, **kwargs):
    return registry.PluginSpec(plugin_id=plugin_id, plugin_type=kwargs.pop("plugin_type", "extension"), root=ROOT, version="2.0.0", **kwargs)


declaring = spec("declaring-demo", audit_events=(("agent", ("view", "run", "custom:remote-session")),))
no_events = spec("noevents-demo")
legacy = spec("legacy-demo", plugin_type="legacy", legacy=True, audit_events=(("agent", ("view",)),))
disabled = spec("disabled-demo", audit_events=(("agent", ("view",)),))
both = spec(
    "both-demo",
    permission_groups=(("Use", ("both-demo.use",)),),
    audit_events=(("agent", ("view",)),),
)
registry.get_plugins = lambda: (declaring, no_events, legacy, disabled, both)


class Role:
    def __init__(self, can_list_agents=True):
        self.can_list_agents = can_list_agents
        self.can_list_clients = True
        self.can_list_sites = True
        self.is_superuser = False


class User:
    is_authenticated = True
    is_superuser = False

    def __init__(self, username, allowed_agents=(), can_list_agents=True):
        self.username = username
        self.allowed_agents = set(allowed_agents)
        self.role = Role(can_list_agents)

    def get_and_set_role_cache(self):
        return self.role


tech = User("tech", {"a-1"})
no_list_role = User("norole", {"a-1"}, can_list_agents=False)


class Request:
    def __init__(self, user, data):
        self.user = user
        self.data = data


def base_event(**overrides):
    event = {"module_id": "declaring-demo", "action": "view", "object_type": "agent", "object_id": "a-1"}
    event.update(overrides)
    return event


view = audit_views.AuditRecordView()


def post(_user, **overrides):
    data = base_event(**overrides)
    data = {k: v for k, v in data.items() if v is not ...}
    return view.post(Request(_user, data))


def reset():
    del ROWS[:]
    del SCOPE_CALLS[:]
    GRANTED.clear()


# --- 1.17.0 fixtures ---------------------------------------------------------------------------
# licence-demo declares a non-scope-checked type. multi-demo declares 'deny' on agents (a 403 Tactical itself returned).
licence = spec("licence-demo", audit_events=(("licence_key", ("view", "run")),))
multi = spec("multi-demo", audit_events=(("agent", ("view", "deny")), ("licence_key", ("view",)), ("deny", ("view",))))
permissioned_typed = spec(
    "permissioned-typed-demo",
    permission_groups=(("Use", ("permissioned-typed-demo.use",)),),
    audit_events=(("licence_key", ("view",)),),
)
registry.get_plugins = lambda: (declaring, no_events, legacy, disabled, both, licence, multi, permissioned_typed)


def marker(row):
    return row["debug_info"].get("operation_context", {}).get("browser_provenance") == audit.BROWSER_PROVENANCE_MARKER


def assert_all_marked(label):
    assert ROWS, label
    for row in ROWS:
        assert marker(row), (label, row)


# === Q34: denials reach the audit log as Core-owned rows =========================================
reset()
response = post(tech, object_id="a-2", message="MODULE-SECRET-TEXT", metadata={"note": "MODULE-SECRET-TEXT"})
assert response.status_code == 404 and response.data["recorded"] is False
assert len(ROWS) == 1, ROWS
deny = ROWS[0]
assert deny["action"] == "deny" and deny["username"] == "tech" and deny["object_type"] == "agent"
assert deny["message"] == audit_views._DENY_MESSAGES["not_found"]
assert "missing or outside" in deny["message"]
info = deny["debug_info"]
assert info["operation_context"] == {"browser_provenance": "module-declared-event", "core_refusal": True}
assert info["metadata"] == {"refused_action": "view", "reason": "not_found", "status": 404}
assert info["module_id"] == "declaring-demo" and info["object_id"] == "a-2"
assert "MODULE-SECRET-TEXT" not in json.dumps(deny, default=str)

# Missing object: same answer, same row shape.
reset()
assert post(tech, object_id="a-99").status_code == 404
assert len(ROWS) == 1 and ROWS[0]["debug_info"]["operation_context"]["core_refusal"] is True

# A role without Tactical's can_list_agents gets 403 and its own, accurate message.
reset()
response = post(no_list_role, message="MODULE-SECRET-TEXT")
assert response.status_code == 403 and response.data["recorded"] is False
assert len(ROWS) == 1, ROWS
deny = ROWS[0]
assert deny["action"] == "deny" and deny["username"] == "norole"
assert deny["message"] == audit_views._DENY_MESSAGES["permission_denied"]
assert "lacks Tactical's permission" in deny["message"] and "outside the signed-in user's scope" not in deny["message"]
assert deny["message"] != audit_views._DENY_MESSAGES["not_found"]
assert deny["debug_info"]["metadata"] == {"refused_action": "view", "reason": "permission_denied", "status": 403}
assert deny["debug_info"]["operation_context"]["core_refusal"] is True and marker(deny)
assert "MODULE-SECRET-TEXT" not in json.dumps(deny, default=str)

# A module-declared 'deny' event is an ordinary declared row: recorded once, no core_refusal flag.
reset()
response = post(tech, module_id="multi-demo", action="deny", message="Tactical returned 403 for can_use_mesh", metadata={"status": 403})
assert response.status_code == 201 and response.data["recorded"] is True, (response.status_code, response.data)
assert len(ROWS) == 1
mine = ROWS[0]
assert mine["action"] == "deny" and mine["message"] == "Tactical returned 403 for can_use_mesh"
assert mine["debug_info"]["operation_context"] == {"browser_provenance": "module-declared-event"}
assert "core_refusal" not in mine["debug_info"]["operation_context"]
assert mine["debug_info"]["metadata"] == {"status": 403}
# ...so it can be told apart from Core's own row.
reset()
post(tech, module_id="multi-demo", action="deny")
post(tech, module_id="multi-demo", action="view", object_id="a-2")
flags = [bool(row["debug_info"]["operation_context"].get("core_refusal")) for row in ROWS]
assert flags == [False, True], flags
# A declared 'deny' for an agent outside the user's scope is still refused by Core, with Core's own row.
reset()
assert post(tech, module_id="multi-demo", action="deny", object_id="a-2").status_code == 404
assert len(ROWS) == 1 and ROWS[0]["debug_info"]["operation_context"]["core_refusal"] is True

# The payload can never supply Core-owned context.
for extra in ({"core_refusal": True}, {"operation_context": {"core_refusal": True}},
              {"operation_context": {"browser_provenance": "x"}}):
    reset()
    response = post(tech, **extra)
    assert response.status_code == 400, (extra, response.status_code)
    assert not ROWS and not SCOPE_CALLS
# Metadata cannot forge it either: it stays under debug_info.metadata, not operation_context.
reset()
assert post(tech, metadata={"core_refusal": True}).status_code == 201
assert "core_refusal" not in ROWS[0]["debug_info"]["operation_context"]
# A backend caller of record() cannot set it, only Core's own helper can.
try:
    audit.record(actor=tech, module_id="declaring-demo", action="deny", object_type="agent", operation_context={"core_refusal": True})
    raise AssertionError("record() accepted core_refusal")
except audit.AuditContractError:
    pass
try:
    audit.get_audit_provider().record(actor=tech, module_id="declaring-demo", action="deny", object_type="agent",
                                      operation_context={"core_refusal": False})
    raise AssertionError("provider accepted core_refusal")
except audit.AuditContractError:
    pass

# An event the module did not declare is a wrong manifest, not a denied user: 403 and nothing written.
reset()
for overrides in (dict(action="deny"), dict(action="delete"), dict(module_id="licence-demo"),
                  dict(module_id="noevents-demo", action="deny")):
    response = post(tech, **overrides)
    assert response.status_code == 403, (overrides, response.status_code)
    assert not ROWS and not SCOPE_CALLS, overrides

# Deny rows go through the same view, so they count toward the 60/min and 1000/day throttles.
assert audit_views.AuditRecordView.throttle_classes == [MinThrottle, DayThrottle]
throttle_text = (PKG / "throttles.py").read_text(encoding="utf-8")
assert 'rate = "60/min"' in throttle_text and 'rate = "1000/day"' in throttle_text
view_source = (PKG / "audit_views.py").read_text(encoding="utf-8")
assert view_source.count("record_core_refusal(") == 1 and "strict=False" in view_source

# A failing deny write never turns the refusal into a 500, and Core's deny message stays fixed.
reset()
FakeAuditLog.objects.fail = True
assert post(tech, object_id="a-2").status_code == 404
assert post(no_list_role).status_code == 403
FakeAuditLog.objects.fail = False
assert not ROWS

# === Q35: any object type, scope check only for client, site and agent ===========================
assert audit.SCOPE_CHECKED_OBJECT_TYPES == ("client", "site", "agent") == registry.SCOPE_CHECKED_OBJECT_TYPES
assert audit.BROWSER_EVENT_OBJECT_TYPES is audit.SCOPE_CHECKED_OBJECT_TYPES
assert registry.AUDIT_EVENT_OBJECT_TYPES is registry.SCOPE_CHECKED_OBJECT_TYPES


def load(payload, plugin_type="extension", plugin_id="demo-ext"):
    with tempfile.TemporaryDirectory() as tmp:
        plugin_dir = Path(tmp) / plugin_id
        plugin_dir.mkdir()
        (plugin_dir / "tec_tac.json").write_text(json.dumps({"id": plugin_id, "type": plugin_type, **payload}), encoding="utf-8")
        return registry._load_manifest(plugin_type, plugin_dir)


assert load({"audit_events": [{"object_type": "licence_key", "actions": ["view", "run"]}]}).audit_events == (("licence_key", ("view", "run")),)
assert load({"audit_events": [{"object_type": "agent", "actions": ["view"]}, {"object_type": "site", "actions": ["run"]},
                              {"object_type": "client", "actions": ["view"]}]}).audit_events == (
    ("agent", ("view",)), ("site", ("run",)), ("client", ("view",)))
assert load({"audit_events": [{"object_type": "a", "actions": ["view"]}, {"object_type": "with-dash_1", "actions": ["view"]}]}).audit_events
assert load({"audit_events": [{"object_type": "x" * 100, "actions": ["view"]}]}).audit_events
for label, bad_type in {"uppercase/space": "Bad Type", "empty": "", "leading digit": "1type", "too long": "x" * 101,
                        "not a string": 7, "null": None, "slash": "a/b", "uppercase": "Agent"}.items():
    try:
        load({"audit_events": [{"object_type": bad_type, "actions": ["view"]}]})
        raise AssertionError(f"registry accepted object_type: {label}")
    except registry.RegistryError:
        pass
for label, payload in {
    "repeated object_type": {"audit_events": [{"object_type": "licence_key", "actions": ["view"]}, {"object_type": "licence_key", "actions": ["run"]}]},
    "21 entries": {"audit_events": [{"object_type": f"type-{i}", "actions": ["view"]} for i in range(21)]},
    "21 actions": {"audit_events": [{"object_type": "licence_key", "actions": [f"custom:a{i}" for i in range(21)]}]},
}.items():
    try:
        load(payload)
        raise AssertionError(f"registry accepted: {label}")
    except registry.RegistryError:
        pass
assert len(load({"audit_events": [{"object_type": f"type-{i}", "actions": ["view"]} for i in range(20)]}).audit_events) == 20
assert len(load({"audit_events": [{"object_type": "licence_key", "actions": [f"custom:a{i}" for i in range(20)]}]}).audit_events[0][1]) == 20

# A declared licence_key event records without any core.resources call, under the signed-in user, with the marker.
reset()
response = post(tech, module_id="licence-demo", object_type="licence_key", object_id="LIC-42", message="Revealed a key hint")
assert response.status_code == 201 and response.data["recorded"] is True, (response.status_code, response.data)
assert not SCOPE_CALLS, SCOPE_CALLS
assert len(ROWS) == 1
row = ROWS[0]
assert row["username"] == "tech" and row["object_type"] == "licence_key" and row["action"] == "view"
assert row["debug_info"]["object_id"] == "LIC-42" and row["debug_info"]["module_id"] == "licence-demo"
assert row["debug_info"]["operation_context"] == {"browser_provenance": "module-declared-event"}
# object_id is optional for this type.
reset()
response = post(tech, module_id="licence-demo", object_type="licence_key", object_id=..., action="run")
assert response.status_code == 201, (response.status_code, response.data)
assert "object_id" not in ROWS[0]["debug_info"] and marker(ROWS[0]) and not SCOPE_CALLS
reset()
assert post(tech, module_id="licence-demo", object_type="licence_key", object_id=None).status_code == 201
assert post(tech, module_id="licence-demo", object_type="licence_key", object_id=12).status_code == 201
assert post(tech, module_id="licence-demo", object_type="licence_key", object_id="x" * 255).status_code == 201
assert len(ROWS) == 3 and not SCOPE_CALLS
# Bad object_id values are a 400 and write nothing.
reset()
for bad in ("x" * 256, "   ", {"a": 1}, ["a"], True):
    assert post(tech, module_id="licence-demo", object_type="licence_key", object_id=bad).status_code == 400, bad
assert not ROWS and not SCOPE_CALLS
# A row is recorded for a non-scope-checked type even when the user would fail every agent scope check.
reset()
assert post(no_list_role, module_id="licence-demo", object_type="licence_key", object_id="LIC-1").status_code == 201
assert not SCOPE_CALLS and len(ROWS) == 1 and ROWS[0]["action"] == "view"
# The same event for an undeclared type, action or module gives 403 and no row.
reset()
for overrides in (
    dict(module_id="licence-demo", object_type="other_type", object_id="1"),
    dict(module_id="licence-demo", object_type="licence_key", action="delete"),
    dict(module_id="declaring-demo", object_type="licence_key", object_id="1"),
    dict(module_id="legacy-demo", object_type="licence_key"),
    dict(module_id="disabled-demo", object_type="licence_key"),
    dict(module_id="core", object_type="licence_key"),
    dict(module_id="licence-demo", object_type="Bad Type"),
):
    response = post(tech, **overrides)
    assert response.status_code == 403, (overrides, response.status_code, response.data)
    assert not ROWS and not SCOPE_CALLS, overrides
# A permissioned module keeps the grant path for any type it declares.
reset()
assert post(tech, module_id="permissioned-typed-demo", object_type="licence_key", object_id="1").status_code == 403
GRANTED.add("permissioned-typed-demo.use")
response = post(tech, module_id="permissioned-typed-demo", object_type="licence_key", object_id="1")
assert response.status_code == 201 and ROWS[0]["debug_info"]["operation_context"] == {}
GRANTED.clear()
assert not audit.declared_browser_event(tech, "permissioned-typed-demo", "view", "licence_key")
assert audit.declared_browser_event(tech, "licence-demo", "view", "licence_key")
assert audit.declared_browser_event(tech, "licence-demo", "VIEW", "Licence_Key")
assert not audit.declared_browser_event(tech, "licence-demo", "view", "Bad Type")
assert not audit.declared_browser_event(tech, "licence-demo", "view", "")

# client/site/agent keep their 1.16.0 behaviour: object_id required and a deny row out of scope.
reset()
assert post(tech, object_id=...).status_code == 400 and post(tech, object_id="  ").status_code == 400
assert not ROWS and not SCOPE_CALLS
assert post(tech, object_id="a-2").status_code == 404 and len(ROWS) == 1 and ROWS[0]["action"] == "deny"
reset()
assert post(tech).status_code == 201 and ("agents", "tech") in SCOPE_CALLS

# The manager rows, catalog and Markdown already list any declared type.
accounts = types.ModuleType("accounts")
accounts_models = types.ModuleType("accounts.models")
accounts_models.Role = object
sys.modules.update({"accounts": accounts, "accounts.models": accounts_models})
sys.modules.pop("tec_tac.rbac", None)
real_rbac = importlib.import_module("tec_tac.rbac")
rows = {row["id"]: row for row in real_rbac.permission_catalog((licence, multi))}
assert rows["licence-demo"]["audit_events"] == [{"object_type": "licence_key", "actions": ["view", "run"]}]
assert rows["multi-demo"]["audit_events"][1] == {"object_type": "licence_key", "actions": ["view"]}
sys.modules["tec_tac.rbac"] = rbac_stub

# === Q36: the marker is on every row the declared path writes ===================================
audit_limit = types.ModuleType("django.conf")


class _Settings:
    AUDIT_MAX_VALUE_BYTES = 512 * 2**10


audit_limit.settings = _Settings
saved_conf = sys.modules.get("django.conf")
sys.modules["django.conf"] = audit_limit
try:
    # normal; every new-path success row
    reset()
    post(tech, message="x")
    post(tech, module_id="licence-demo", object_type="licence_key", object_id="1")
    post(tech, module_id="multi-demo", action="deny")
    assert_all_marked("normal")

    # metadata over AUDIT_MAX_VALUE_BYTES (Core keeps the row and the marker)
    reset()
    response = post(tech, metadata={"blob": "m" * (600 * 1024)})
    assert response.status_code == 201
    assert "error" in ROWS[0]["debug_info"]["metadata"]
    assert_all_marked("metadata over the limit")
    reset()
    response = post(tech, module_id="licence-demo", object_type="licence_key", metadata={"blob": "漢" * 150000})
    assert response.status_code == 201
    assert_all_marked("non-ascii metadata over the limit")
    assert len(json.dumps(ROWS[0]["debug_info"]).encode()) <= _Settings.AUDIT_MAX_VALUE_BYTES

    # operation_context over the limit: only Core-side callers can reach this, so call the writer directly
    reset()
    audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1",
                 operation_context={"blob": "o" * (600 * 1024), "browser_provenance": "module-declared-event"})
    assert_all_marked("operation_context over the limit")
    assert "error" in ROWS[0]["debug_info"]["operation_context"]

    # both over the limit
    reset()
    audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1",
                 metadata={"blob": "m" * (400 * 1024)},
                 operation_context={"blob": "o" * (400 * 1024), "browser_provenance": "module-declared-event"})
    assert_all_marked("both over the limit")
    assert len(json.dumps(ROWS[0]["debug_info"]).encode()) <= _Settings.AUDIT_MAX_VALUE_BYTES

    # Core deny row with a huge operation_context keeps both Core-owned keys
    reset()
    audit._record_row(actor=tech, module_id="declaring-demo", action="deny", object_type="agent", object_id="a-2",
                      operation_context={"blob": "o" * (600 * 1024), "browser_provenance": "module-declared-event",
                                         "core_refusal": True})
    ctx = ROWS[0]["debug_info"]["operation_context"]
    assert ctx["browser_provenance"] == "module-declared-event" and ctx["core_refusal"] is True and "error" in ctx
    # a Core deny row on the normal route
    reset()
    post(tech, object_id="a-2")
    post(no_list_role)
    assert len(ROWS) == 2
    assert_all_marked("deny rows")

    # before/after over the limit is a contract error: 400, no row
    reset()
    for field in ("before", "after"):
        response = post(tech, **{field: {"blob": "b" * (600 * 1024)}})
        assert response.status_code == 400, (field, response.status_code)
    assert not ROWS

    # The persistence write failing gives 202, no row, no crash
    reset()
    FakeAuditLog.objects.fail = True
    response = post(tech)
    assert response.status_code == 202 and response.data["recorded"] is False
    response = post(tech, module_id="licence-demo", object_type="licence_key")
    assert response.status_code == 202
    FakeAuditLog.objects.fail = False
    assert not ROWS

    # _fit_debug_info: only present keys are replaced, nothing spurious is added.
    _Settings.AUDIT_MAX_VALUE_BYTES = 1000
    core_keys = {"source": "tec-tac", "module_id": "m", "module_version": "1", "correlation_id": "c"}
    fitted = audit._fit_debug_info({**core_keys, "metadata": {"blob": "m" * 2000}})
    assert "operation_context" not in fitted, fitted
    assert "error" in fitted["metadata"] and fitted["source"] == "tec-tac"
    fitted = audit._fit_debug_info({**core_keys, "operation_context": {"blob": "o" * 2000, "browser_provenance": "module-declared-event"}})
    assert "metadata" not in fitted, fitted
    assert fitted["operation_context"]["browser_provenance"] == "module-declared-event" and "error" in fitted["operation_context"]
    # A row that fits is returned untouched, even with an absent key.
    small = {**core_keys, "metadata": {"a": 1}}
    assert audit._fit_debug_info(small) is small
    # The larger of the two goes first: a small metadata survives a huge operation_context.
    fitted = audit._fit_debug_info({**core_keys, "metadata": {"keep": "me"},
                                    "operation_context": {"blob": "o" * 2000, "browser_provenance": "module-declared-event", "core_refusal": True}})
    assert fitted["metadata"] == {"keep": "me"}
    assert fitted["operation_context"]["core_refusal"] is True
    assert fitted["operation_context"]["browser_provenance"] == "module-declared-event"
    # ...and a small operation_context survives a huge metadata.
    fitted = audit._fit_debug_info({**core_keys, "metadata": {"blob": "m" * 2000},
                                    "operation_context": {"browser_provenance": "module-declared-event"}})
    assert fitted["operation_context"] == {"browser_provenance": "module-declared-event"} and "error" in fitted["metadata"]
    # An operation_context with no Core keys gets none added.
    fitted = audit._fit_debug_info({**core_keys, "operation_context": {"blob": "o" * 2000}})
    assert "browser_provenance" not in fitted["operation_context"] and "core_refusal" not in fitted["operation_context"]
    # core_refusal is carried only when it is literally true.
    marker_only = {}
    audit._keep_browser_provenance(marker_only, {"core_refusal": "yes", "browser_provenance": "x" * 101})
    assert marker_only == {}
finally:
    if saved_conf is None:
        sys.modules.pop("django.conf", None)
    else:
        sys.modules["django.conf"] = saved_conf

# === Public contract text =========================================================================
import ast  # noqa: E402

contracts_source = (PKG / "contracts.py").read_text(encoding="utf-8")
tree = ast.parse(contracts_source)


def literal(name):
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


details = literal("HTTP_CONTRACT_DETAILS")["/api/tfd/audit/record/"]["POST"]
text = json.dumps(details)
assert "core_refusal" in text and "fixed Core messages" in text and "deny" in text and "1.17.0" in text
assert "any other lowercase object_type" in text
rules = " ".join(literal("RULES"))
assert "lowercase slug" in rules and ">=1.17.0" in rules
assert "client, site or agent; each action" not in rules

docs = (ROOT / "docs" / "module-audit.md").read_text(encoding="utf-8")
assert "core_refusal" in docs and "licence_key" in docs and "1.17.0" in docs

print("[TEST] PASS declared browser audit events 1.17.0")
