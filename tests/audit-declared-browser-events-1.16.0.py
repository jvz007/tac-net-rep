#!/usr/bin/env python3
"""Regression for Core 1.16.0: declared browser audit events for permissionless modules.

Runs the real registry, audit, audit_views and resources code. Only the Tactical ORM
boundary is faked: an in-memory resources_adapter (the way resource-directory-foundation.py
does it) and an in-memory AuditLog model. DRF, session and throttle classes are stubs
because the release-test container does not ship Django/DRF.
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


# (a) ACCEPTED ----------------------------------------------------------------------------
reset()
response = post(tech, message="Opened a session", metadata={"ticket": 7})
assert response.status_code == 201, (response.status_code, response.data)
assert response.data["recorded"] is True and response.data["module_id"] == "declaring-demo"
assert len(ROWS) == 1
row = ROWS[0]
info = row["debug_info"]
assert row["username"] == "tech" and row["action"] == "view" and row["object_type"] == "agent"
assert info["source"] == "tec-tac" and info["module_id"] == "declaring-demo" and info["module_version"] == "2.0.0"
assert info["object_id"] == "a-1" and info["metadata"] == {"ticket": 7}
assert info["operation_context"]["browser_provenance"] == "module-declared-event"
assert info["actor_kind"] == "human" and info["actor_identity"] == "tech" and info["correlation_id"]
assert ("agents", "tech") in SCOPE_CALLS
# A custom: action the module declared is accepted, and the marker is set on every row.
reset()
assert post(tech, action="custom:remote-session").status_code == 201
assert ROWS[0]["debug_info"]["operation_context"]["browser_provenance"] == "module-declared-event"
# Persistence failure is a 202, as on the permissioned path.
reset()
FakeAuditLog.objects.fail = True
assert post(tech).status_code == 202
FakeAuditLog.objects.fail = False
# Actor/provenance and unknown fields are still 400 and write nothing.
reset()
for forbidden in ("username", "actor", "user", "module_version", "source", "correlation_id", "request_id"):
    assert post(tech, **{forbidden: "mallory"}).status_code == 400, forbidden
assert post(tech, surprise=1).status_code == 400
assert not ROWS
# Non-object payload.
assert view.post(Request(tech, ["not", "an", "object"])).status_code == 400
# object_id is required on this path; a client id must be a number.
assert post(tech, object_id=...).status_code == 400
assert post(tech, object_id="   ").status_code == 400
assert post(tech, object_id={"x": 1}).status_code == 400
assert not ROWS

# (b) UNDECLARED refused: 403, "not permitted", nothing written -----------------------------
reset()
cases = [
    dict(action="delete"),                       # undeclared action
    dict(object_type="site", object_id="11"),    # undeclared object type
    dict(object_type="client", object_id="1"),
    dict(object_type="thing", object_id="1"),
    dict(module_id="noevents-demo"),             # permissionless, no audit_events
    dict(module_id="legacy-demo"),               # legacy plugin
    dict(module_id="unknown-demo"),              # not installed
    dict(module_id="core"),                      # Core provenance
    dict(module_id=""),
]
for overrides in cases:
    response = post(tech, **overrides)
    assert response.status_code == 403, (overrides, response.status_code, response.data)
    assert not ROWS, overrides
    assert not SCOPE_CALLS, overrides
assert "not permitted" in post(tech, action="delete").data["detail"]
assert "audit_events" in post(tech, action="delete").data["detail"]

# (c) OUT OF SCOPE refused --------------------------------------------------------------------
for object_id in ("a-2", "a-99"):
    reset()
    response = post(tech, object_id=object_id, message="MODULE-SECRET-TEXT", metadata={"note": "MODULE-SECRET-TEXT"})
    assert response.status_code == 404, (object_id, response.status_code, response.data)
    assert response.data["recorded"] is False and "detail" in response.data
    assert len(ROWS) == 1, ROWS
    deny = ROWS[0]
    assert deny["action"] == "deny" and deny["username"] == "tech" and deny["object_type"] == "agent"
    assert deny["debug_info"]["module_id"] == "declaring-demo" and deny["debug_info"]["object_id"] == object_id
    assert deny["debug_info"]["metadata"] == {"refused_action": "view", "reason": "not_found"}
    assert deny["message"] == audit_views._DENY_MESSAGE
    assert "MODULE-SECRET-TEXT" not in json.dumps(deny, default=str)
    assert deny["debug_info"]["operation_context"]["browser_provenance"] == "module-declared-event"
# Missing and out-of-scope use the same message, so existence is not leaked.
assert post(tech, object_id="a-2").data["detail"] == post(tech, object_id="a-99").data["detail"]
# A role without Tactical's can_list_agents permission is a 403.
reset()
response = post(no_list_role)
assert response.status_code == 403 and response.data["recorded"] is False, (response.status_code, response.data)
assert len(ROWS) == 1 and ROWS[0]["action"] == "deny"
assert ROWS[0]["debug_info"]["metadata"]["reason"] == "permission_denied"
# A failing deny write never turns the refusal into a 500.
reset()
FakeAuditLog.objects.fail = True
assert post(tech, object_id="a-2").status_code == 404
FakeAuditLog.objects.fail = False
# A non-numeric client id is a validation error (400) and records nothing.
reset()
adapter.clients_queryset = clients_queryset
declaring_client = spec("declaring-demo", audit_events=(("client", ("view",)),))
registry.get_plugins = lambda: (declaring_client, no_events, legacy, disabled, both)
response = post(tech, object_type="client", object_id="abc")
assert response.status_code == 400 and response.data["recorded"] is False, (response.status_code, response.data)
assert not ROWS
registry.get_plugins = lambda: (declaring, no_events, legacy, disabled, both)

# (d) DISABLED module refused through the real _resolve_module ---------------------------------
reset()
try:
    audit._resolve_module("disabled-demo")
    raise AssertionError("disabled module resolved")
except audit.AuditContractError:
    pass
assert post(tech, module_id="disabled-demo").status_code == 403
assert not ROWS and not SCOPE_CALLS
ENABLED["declaring-demo"] = False
assert post(tech).status_code == 403 and not ROWS
ENABLED.pop("declaring-demo")
assert post(tech).status_code == 201

# A permissioned module that also declares audit_events keeps the permissioned path -----------
reset()
before_calls = len(SCOPE_CALLS)
response = post(tech, module_id="both-demo")           # no grant: refused, never scope-checked
assert response.status_code == 403 and not ROWS
assert len(SCOPE_CALLS) == before_calls
GRANTED.add("both-demo.use")
response = post(tech, module_id="both-demo", object_id="a-2")  # grant: untouched path, no core.resources
assert response.status_code == 201, (response.status_code, response.data)
assert len(SCOPE_CALLS) == before_calls
assert ROWS[0]["debug_info"]["operation_context"] == {}
assert not audit.declared_browser_event(tech, "both-demo", "view", "agent")
GRANTED.clear()

# Throttles are unchanged and the view keeps both.
assert audit_views.AuditRecordView.throttle_classes == [MinThrottle, DayThrottle]
throttle_text = (PKG / "throttles.py").read_text(encoding="utf-8")
assert 'rate = "60/min"' in throttle_text and 'rate = "1000/day"' in throttle_text

# --- Backlog core-1.15.179: whole debug_info stays inside the limit, Core keys survive ------------
audit_limit = types.ModuleType("django.conf")


class _Settings:
    AUDIT_MAX_VALUE_BYTES = 512 * 2**10


audit_limit.settings = _Settings
saved_conf = sys.modules.get("django.conf")
sys.modules["django.conf"] = audit_limit
CORE_KEYS = ("source", "module_id", "module_version", "correlation_id", "actor_identity")
try:
    # Each piece fits its own budget, together they do not.
    reset()
    result = audit.record(
        actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1",
        metadata={"blob": "m" * (300 * 1024)}, operation_context={"blob": "o" * (300 * 1024), "browser_provenance": "module-declared-event"},
    )
    assert result["recorded"] is True
    info = ROWS[-1]["debug_info"]
    assert len(json.dumps(info).encode()) <= _Settings.AUDIT_MAX_VALUE_BYTES
    for key in CORE_KEYS:
        assert info.get(key), key
    assert "error" in info["metadata"]
    assert info["operation_context"]["blob"].startswith("o")  # only as much as needed is dropped

    # Tiny limit: metadata and operation_context both have to go, Core keys and the marker stay.
    reset()
    _Settings.AUDIT_MAX_VALUE_BYTES = 1000
    audit.record(
        actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1",
        metadata={"blob": "m" * 1000}, operation_context={"blob": "o" * 1000, "browser_provenance": "module-declared-event"},
    )
    info = ROWS[-1]["debug_info"]
    assert len(json.dumps(info).encode()) <= 1000, len(json.dumps(info).encode())
    for key in CORE_KEYS:
        assert info.get(key), key
    assert "error" in info["metadata"] and "error" in info["operation_context"]
    assert info["operation_context"]["browser_provenance"] == "module-declared-event"

    # Non-ASCII: Tactical measures json.dumps (ensure_ascii=True), so CJK counts 6 bytes a character.
    reset()
    _Settings.AUDIT_MAX_VALUE_BYTES = 512 * 2**10
    result = audit.record(
        actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1",
        metadata={"blob": "漢" * 150000}, operation_context={"note": "x", "browser_provenance": "module-declared-event"},
    )
    info = ROWS[-1]["debug_info"]
    assert len(json.dumps(info).encode()) <= _Settings.AUDIT_MAX_VALUE_BYTES, len(json.dumps(info).encode())
    for key in CORE_KEYS:
        assert info.get(key), key
    assert info["operation_context"].get("browser_provenance") == "module-declared-event"
    assert "error" in info["metadata"]
    reset()
    audit.record(
        actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1",
        metadata={"a": 1}, operation_context={"blob": "漢" * 150000, "browser_provenance": "module-declared-event"},
    )
    info = ROWS[-1]["debug_info"]
    assert len(json.dumps(info).encode()) <= _Settings.AUDIT_MAX_VALUE_BYTES
    assert info["operation_context"].get("browser_provenance") == "module-declared-event"
    assert audit._debug_info_bytes({"t": "漢"}) == len(json.dumps({"t": "漢"}).encode())

    # Small input is unchanged.
    reset()
    _Settings.AUDIT_MAX_VALUE_BYTES = 512 * 2**10
    audit.record(
        actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1",
        metadata={"a": 1}, operation_context={"b": 2},
    )
    info = ROWS[-1]["debug_info"]
    assert info["metadata"] == {"a": 1} and info["operation_context"] == {"b": 2}
finally:
    if saved_conf is None:
        sys.modules.pop("django.conf", None)
    else:
        sys.modules["django.conf"] = saved_conf

# --- Registry parsing ---------------------------------------------------------------------------
assert "audit_events" in registry.SUPPORTED_KEYS
fields = list(registry.PluginSpec.__dataclass_fields__)
assert fields[-1] == "audit_events" and fields[-2] == "legacy"
assert registry.PluginSpec(plugin_id="x", plugin_type="extension", root=ROOT).audit_events == ()


def load(payload, plugin_type="extension", plugin_id="demo-ext"):
    with tempfile.TemporaryDirectory() as tmp:
        plugin_dir = Path(tmp) / plugin_id
        plugin_dir.mkdir()
        (plugin_dir / "tec_tac.json").write_text(json.dumps({"id": plugin_id, "type": plugin_type, **payload}), encoding="utf-8")
        return registry._load_manifest(plugin_type, plugin_dir)


assert load({}).audit_events == ()
parsed = load({"audit_events": [{"object_type": "agent", "actions": ["view", "custom:remote-session"]}, {"object_type": "site", "actions": ["run"]}]})
assert parsed.audit_events == (("agent", ("view", "custom:remote-session")), ("site", ("run",)))
assert load({"audit_events": []}).audit_events == ()

bad_shapes = {
    "not a list": {"audit_events": {"object_type": "agent"}},
    "entry not an object": {"audit_events": ["agent"]},
    "unknown entry key": {"audit_events": [{"object_type": "agent", "actions": ["view"], "extra": 1}]},
    "missing object_type": {"audit_events": [{"actions": ["view"]}]},
    "unsupported object_type": {"audit_events": [{"object_type": "policy", "actions": ["view"]}]},
    "duplicate object_type": {"audit_events": [{"object_type": "agent", "actions": ["view"]}, {"object_type": "agent", "actions": ["run"]}]},
    "empty actions": {"audit_events": [{"object_type": "agent", "actions": []}]},
    "missing actions": {"audit_events": [{"object_type": "agent"}]},
    "duplicate actions": {"audit_events": [{"object_type": "agent", "actions": ["view", "view"]}]},
    "unknown action": {"audit_events": [{"object_type": "agent", "actions": ["explode"]}]},
    "bad custom slug": {"audit_events": [{"object_type": "agent", "actions": ["custom:Bad Slug"]}]},
    "non-string action": {"audit_events": [{"object_type": "agent", "actions": [1]}]},
    "too many entries": {"audit_events": [{"object_type": "agent", "actions": ["view"]}] * 21},
    "too many actions": {"audit_events": [{"object_type": "agent", "actions": [f"custom:a{i}" for i in range(21)]}]},
}
for label, payload in bad_shapes.items():
    try:
        load(payload)
    except registry.RegistryError:
        continue
    raise AssertionError(f"registry accepted: {label}")
try:
    load({"audit_events": [{"object_type": "agent", "actions": ["view"]}]}, plugin_type="reportset")
    raise AssertionError("reportset declaring audit_events accepted")
except registry.RegistryError:
    pass

# --- Public contract ------------------------------------------------------------------------------
contracts_source = (PKG / "contracts.py").read_text(encoding="utf-8")
import ast  # noqa: E402

tree = ast.parse(contracts_source)


def literal(name):
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


details = literal("HTTP_CONTRACT_DETAILS")["/api/tfd/audit/record/"]["POST"]
for status in ("400", "403", "404", "429"):
    assert status in details["errors"], status
assert set(details["success"]) == {"201", "202"}
assert "module-declared-event" in json.dumps(details) and "audit_events" in json.dumps(details)
browser = next(row for row in literal("BROWSER_CONTRACTS") if row["id"] == "ui.authenticated.audit")
assert "audit_events" in browser["purpose"]
assert any("audit_events" in rule for rule in literal("RULES"))
assert 'path("audit/record/"' in (PKG / "urls.py").read_text(encoding="utf-8")

# permission_catalog / module manager rows / render_markdown show the declared events.
accounts = types.ModuleType("accounts")
accounts_models = types.ModuleType("accounts.models")
accounts_models.Role = object
sys.modules.update({"accounts": accounts, "accounts.models": accounts_models})
sys.modules.pop("tec_tac.rbac", None)
real_rbac = importlib.import_module("tec_tac.rbac")
catalog = real_rbac.permission_catalog((declaring, no_events, both))
by_id = {row["id"]: row for row in catalog}
assert by_id["declaring-demo"]["audit_events"] == [{"object_type": "agent", "actions": ["view", "run", "custom:remote-session"]}]
assert by_id["noevents-demo"]["audit_events"] == [] and by_id["core"]["audit_events"] == []
assert by_id["both-demo"]["audit_events"] == [{"object_type": "agent", "actions": ["view"]}]

django_utils = types.ModuleType("django.utils")
django_utils.timezone = types.SimpleNamespace(now=lambda: __import__('datetime').datetime(2026, 9, 30))
django = types.ModuleType("django")
sys.modules.update({"django": django, "django.utils": django_utils})
for name, attrs in {
    "tec_tac.reporting": {"list_reporting_models": lambda: []},
    "tec_tac.scheduler": {"scheduled_actions": lambda: [], "serialize_action": lambda action: action},
}.items():
    stub = types.ModuleType(name)
    stub.__dict__.update(attrs)
    sys.modules[name] = stub
sys.modules["tec_tac.rbac"] = real_rbac
contracts = importlib.import_module("tec_tac.contracts")
contracts._http_contracts = lambda: []
contracts.permission_catalog = lambda: catalog
data = contracts.build_contract_catalog()
markdown = contracts.render_markdown(data)
assert "## Extension permissions" in markdown
assert "Declared browser audit events" in markdown and "`custom:remote-session`" in markdown
assert "audit_events agent: view, run, custom:remote-session" in contracts.render_text(data)

print("[TEST] PASS declared browser audit events 1.16.0")
