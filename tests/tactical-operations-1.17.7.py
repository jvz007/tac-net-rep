#!/usr/bin/env python3
"""1.17.7 regression: typed Tactical operations that Core runs server-side and audits (CQ6, CQ7 mode a).

Django and Tactical are not installed on the development PC, so the real tactical_operations.py, tactical_operation_views.py,
audit.py, rbac.py and resources_adapter.py are loaded against stubs for django, DRF, accounts.models and Tactical's
URL resolver and views. The in-process dispatch itself (resolve, DRF ForcedAuthentication, Tactical's real views) can only be proven on the
dev server: see tests/tactical-operations-runtime-1.17.7.py (manage.py shell).
"""
from __future__ import annotations

import ast
import importlib.util
import json
import logging
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
logging.disable(logging.CRITICAL)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------------------------------------ stubs
mods = {}


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    mods[name] = m
    return m


class FieldDoesNotExist(Exception):
    pass


class _Field:
    def __init__(self, kind):
        self.kind = kind

    def get_internal_type(self):
        return self.kind


class Role:
    FIELDS = {
        "can_reboot_agents": "BooleanField", "can_send_wol": "BooleanField", "can_code_sign": "BooleanField",
        "can_manage_notes": "BooleanField", "can_manage_clients": "BooleanField", "can_list_agents": "BooleanField",
        "can_view_clients": "ManyToManyField", "name": "CharField", "is_superuser": "BooleanField",
    }

    class _meta:
        @staticmethod
        def get_field(name):
            if name not in Role.FIELDS:
                raise FieldDoesNotExist(name)
            return _Field(Role.FIELDS[name])


class Roleish:
    """A user's role: ``flags`` are the Tactical booleans, ``grants`` the Tec-Tac codenames."""

    _next = [1]

    def __init__(self, *flags, superuser=False, grants=()):
        self.id = Roleish._next[0]
        Roleish._next[0] += 1
        self.is_superuser = superuser
        for flag in flags:
            setattr(self, flag, True)
        GRANTS[self.id] = set(grants)


GRANTS: dict[int, set] = {}


class _Qs:
    def __init__(self, hit):
        self.hit = hit

    def exists(self):
        return self.hit


class Permission:
    class objects:
        @staticmethod
        def filter(role_id, codename, granted):
            return _Qs(codename in GRANTS.get(role_id, set()))


class User:
    def __init__(self, name="tech", role=None, *, superuser=False, installer=False, anonymous=False):
        self.username = name
        self.is_authenticated = not anonymous
        self.is_superuser = superuser
        self.is_installer_user = installer
        self.role = role

    def get_and_set_role_cache(self):
        return self.role


PLUGINS = {
    "agents": SimpleNamespace(plugin_id="agents", plugin_type="extension", version="0.1.2", permission_groups=(), legacy=False, audit_events=(), category="core"),
    "licensing": SimpleNamespace(plugin_id="licensing", plugin_type="extension", version="0.9.2", permission_groups=(("Manage", ("licensing.manage",)),), legacy=False, audit_events=(), category=""),
    "reportmanager": SimpleNamespace(plugin_id="reportmanager", plugin_type="extension", version="0.3.1", permission_groups=(), legacy=False, audit_events=(), category="core"),
    "premiumdemo": SimpleNamespace(plugin_id="premiumdemo", plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False, audit_events=(), category=""),
    "oldmod": SimpleNamespace(plugin_id="oldmod", plugin_type="legacy", version="1.0.0", permission_groups=(), legacy=True, audit_events=()),
    "offmod": SimpleNamespace(plugin_id="offmod", plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False, audit_events=()),
}
ENABLED = {"offmod": False}

mod("django")
mod("django.core")
mod("django.core.exceptions", ValidationError=Exception)
mod("django.db", IntegrityError=Exception, transaction=SimpleNamespace(atomic=lambda: None))
mod("django.db.models", Q=lambda *a, **k: None)


class HttpRequest:
    def __init__(self):
        self.META = {}


class HttpResponse:
    def __init__(self, content=b"", status=200, content_type=None):
        self.content, self.status_code, self.content_type, self.headers = content, status, content_type, {}

    def __setitem__(self, key, value):
        self.headers[key] = value


class Resolver404(Exception):
    pass


ROUTES: dict[str, tuple] = {}
RESOLVED: list[str] = []


def resolve(path):
    RESOLVED.append(path)
    if path not in ROUTES:
        raise Resolver404(path)
    func, args, kwargs = ROUTES[path]
    return SimpleNamespace(func=func, args=args, kwargs=kwargs, route=path)


mod("django.http", HttpRequest=HttpRequest, HttpResponse=HttpResponse)
mod("django.urls", resolve=resolve, Resolver404=Resolver404)
mod("accounts")
mod("accounts.models", Role=Role)


class DRFResponse:
    def __init__(self, data=None, status=200, headers=None):
        self.data, self.status_code, self.headers = data, status, dict(headers or {})


mod("rest_framework")
mod("rest_framework.response", Response=DRFResponse)
mod("rest_framework.views", APIView=type("APIView", (), {}))
mod("rest_framework.parsers", JSONParser=type("JSONParser", (), {}), MultiPartParser=type("MultiPartParser", (), {}))
mod("drf_spectacular")
mod("drf_spectacular.utils", extend_schema=lambda *a, **k: (lambda obj: obj), extend_schema_view=lambda *a, **k: (lambda obj: obj))
mod("tec_tac.session_security", SessionAuthenticated=type("SessionAuthenticated", (), {}))
mod("tec_tac.throttles", TacticalOperationMinThrottle=type("Min", (), {}), TacticalOperationDayThrottle=type("Day", (), {}))
mod("tec_tac.registry", get_plugins=lambda: tuple(PLUGINS.values()))
mod("tec_tac.module_state", load_state=dict, is_enabled=lambda module_id, state=None: ENABLED.get(module_id, True))
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
CAPS = []
mod("tec_tac.capabilities", register_capability=lambda **kw: CAPS.append(kw) or SimpleNamespace(**kw))
sys.modules.update(mods)


def load(name):
    spec = importlib.util.spec_from_file_location(f"tec_tac.{name}", APP / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


audit = load("audit")
rbac = load("rbac")
rbac._permission_model = lambda: Permission
adapter = load("resources_adapter")
ops = load("tactical_operations")
views = load("tactical_operation_views")


class Row:
    pk = 7


class Manager:
    def __init__(self):
        self.rows, self.fail = [], False

    def create(self, **kw):
        if self.fail:
            raise RuntimeError("db down")
        self.rows.append(kw)
        return Row()


class FakeAuditLog:
    objects = Manager()


audit._auditlog_model = lambda: FakeAuditLog
ROWS = FakeAuditLog.objects.rows


def _resolve_module(module_id):
    if module_id == "core":
        return {"id": "core", "version": "1.17.7", "permissions": (), "legacy": False}
    plugin = PLUGINS.get(module_id)
    if plugin is None:
        raise audit.AuditContractError(f"Unknown or ambiguous Tec-Tac module_id: {module_id}")
    if not ENABLED.get(module_id, True):
        raise audit.AuditContractError(f"Tec-Tac module {module_id!r} is disabled.")
    return {"id": module_id, "version": plugin.version, "permissions": tuple(c for _, v in plugin.permission_groups for c in v),
            "legacy": plugin.legacy, "audit_events": (), "category": getattr(plugin, "category", "")}


audit._resolve_module = _resolve_module

# the scope functions the real helper uses: one fake Tactical, with per-user visibility
WORLD = {"agents": {"a" * 21: 1, "b" * 21: 2, "c" * 21: 1}, "clients": {1, 2, 3}, "sites": {10, 11}}


def _visible(user):
    return getattr(user, "sees", None) or {"agents": set(WORLD["agents"]), "clients": set(WORLD["clients"]), "sites": set(WORLD["sites"])}


adapter.canonical_agent_target_ids_in_scope = lambda *, user, identifiers: [i for i in identifiers if i in _visible(user)["agents"] and i in WORLD["agents"]]
adapter.explicit_client_target_ids_in_scope = lambda *, user, client_ids: {c for c in client_ids if c in _visible(user)["clients"] and c in WORLD["clients"]}
adapter.site_target_ids_in_scope = lambda *, user, site_ids: {s for s in site_ids if s in _visible(user)["sites"] and s in WORLD["sites"]}
sys.modules["tec_tac.resources_adapter"] = adapter

AGENT = "a" * 21
OTHER = "b" * 21
HIDDEN = "z" * 21  # not in the world
tech_role = Roleish("can_reboot_agents", "can_send_wol", "can_manage_notes")
tech = User("tech", tech_role)
tech.sees = {"agents": {AGENT}, "clients": {1}, "sites": {10}}  # sees agent a only, client 1, site 10


class Request:
    def __init__(self, user, **extra):
        self.user = user
        self.META = {"HTTP_AUTHORIZATION": "Token SECRET-KNOX", "HTTP_COOKIE": "sid=1", "REMOTE_ADDR": "10.0.0.9", "HTTP_USER_AGENT": "ua"}
        self.tec_tac_request_id = "req-1"
        self.__dict__.update(extra)


# ------------------------------------------------------------------------------------------------ declarations
def declare(**over):
    spec = dict(
        id="reboot", module_id="agents", method="POST", route="agents/{agent_id:agent}/reboot/", permissions=["can_reboot_agents"],
        scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["mode", "datetime"],
        audit={"action": "run", "object_type": "agent", "audit_fields": ["mode"]}, module_permission=None, message=None,
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def refused(**over):
    try:
        declare(**over)
    except ops.TacticalOperationRegistrationError as exc:
        must(isinstance(exc, ValueError), "a registration refusal is a ValueError")
        return str(exc)
    raise AssertionError(f"registration was accepted: {over}")


def fresh():
    ops._clear_operations_for_tests()
    del ROWS[:]
    del RESOLVED[:]
    ROUTES.clear()
    FakeAuditLog.objects.fail = False
    ENABLED["offmod"] = False
    ENABLED["agents"] = True


fresh()
must(ops.list_operations() == [], "the registry is empty until a module declares an operation")

# ---- registration refusals
for route in ("accounts/ssoproviders/", "accounts/", "api/tfd/modules/", "api/v3/checkin/", "api/v4/checkrunner/", "_allauth/browser/v1/config", "logout/",
              "logoutall/", "logout", "v2/login/", "agents/installer/", "agents/installer", "agents/installer/{x}/", "ACCOUNTS/x/", "Agents/Installer/"):
    refused(route=route, id=re.sub(r"[^a-z]", "", route.lower())[:20] or "x")
must("Core's own" in refused(route="accounts/x/"), "the refusal names the reason")
for route in ("agents/../x/", "agents/{agent_id:agent}/..", "/agents/x/", "agents//x/", "agents/{agent id}/", "agents/%2e/x/", "agents/x?y=1", "{x}/reboot/",
              "api/{x}/reboot/", "agents/{agent_id:float}/", "agents/{Agent}/", "agents/{a}/{a}/", "", "agents/ /", "agents\\x/", "agents/x#y", "a/" * 13):
    refused(route=route, id="badroute")
refused(method="TRACE")
refused(method="")
refused(id="Bad Id")
refused(id="")
# unknown, core, legacy, disabled module
refused(module_id="nosuchmodule")
refused(module_id="core")
refused(module_id="oldmod")
refused(module_id="offmod")
# 1.17.7-1: only the core module that owns the Tactical group may declare in it (AD-19 condition 1)
must("not a core module" in refused(module_id="premiumdemo", id="premreboot"), "a premium module (category '') is refused")
refused(module_id="premiumdemo", id="premcmd", route="agents/{agent_id:agent}/cmd/")
refused(module_id="premiumdemo", id="premcodesign", method="PUT", route="core/codesign/", permissions=["can_code_sign"], scope=[], body_fields=["token"],
        audit={"action": "modify", "object_type": "code_signing_token", "audit_fields": []})  # the exception is Licensing's alone
must("does not own route" in refused(module_id="reportmanager", id="rmreboot"), "a core module outside its group is refused")
refused(module_id="reportmanager", id="rmcmd", route="accounts/x/")
refused(module_id="licensing", id="licreboot")  # Licensing owns core/codesign/ only
refused(module_id="licensing", id="licsettings", method="GET", route="core/settings/", permissions=["can_code_sign"], scope=[], body_fields=[],
        audit={"action": "view", "object_type": "agent"})
refused(module_id="agents", id="unknowngroup", route="beta/x/")  # a group no core module owns in Core's map
must(ops.list_operations() == [], "an ownership refusal left no trace")
# a bad Tactical flag
for flag in ("can_nothing", "name", "is_superuser", "can_view_clients", "reboot", "", None, 5):
    refused(permissions=[flag])
refused(permissions=[])
refused(permissions="can_reboot_agents")
refused(permissions=["can_reboot_agents", "can_reboot_agents"])
# scope
refused(scope=[{"type": "agent", "source": "path:nope"}])
refused(scope=[{"type": "agent", "source": "body:nope"}])
refused(scope=[{"type": "device", "source": "path:agent_id"}])
refused(scope=[{"type": "agent", "source": "query:agent_id"}])
refused(scope=[{"type": "agent", "source": "path:agent_id", "extra": 1}])
refused(scope=[{"type": "client", "source": "path:agent_id"}])  # a client path parameter must be int
refused(scope=[{"type": "agent", "source": "path:agent_id"}, {"type": "agent", "source": "path:agent_id"}])
refused(scope="agent")
refused(route="agents/{agent_id:int}/reboot/")  # an agent must not be an int parameter
# body
refused(method="GET", body_fields=["mode"])
refused(body_fields=["bad field"])
refused(body_fields=["mode", "mode"])
refused(body_fields="mode")
# audit
refused(audit={"action": "launch", "object_type": "agent", "audit_fields": []})
refused(audit={"action": "deny", "object_type": "agent", "audit_fields": []})
refused(audit={"action": "custom:outcome-unknown", "object_type": "agent", "audit_fields": []})
refused(audit={"action": "run", "object_type": "Bad Type", "audit_fields": []})
refused(audit={"action": "run", "object_type": "agent", "audit_fields": ["nope"]})
refused(audit={"action": "run", "object_type": "agent"} | {"other": 1})
refused(audit={"action": "run"})
refused(audit=None)
for secretive in ("password", "api_token", "secret_key", "auth_header", "cookie", "private_key"):
    refused(body_fields=[secretive], audit={"action": "run", "object_type": "agent", "audit_fields": [secretive]})
refused(module_permission="nosuch.permission")
refused(message="x\ny")
refused(message="y" * 300)
must(ops.list_operations() == [], "no refused declaration left a trace")

# ---- a good registration, idempotence and the one-caller rule
first = declare()
must(first.id == "reboot" and first.module_id == "agents" and first.method == "POST", first)
must(declare() is first, "the identical operation again is idempotent")
refused(id="reboot", route="agents/{agent_id:agent}/reboot-now/")  # same (module, id), different definition
refused(id="reboot2", route="agents/{other_name}/reboot/")  # same (method, route), another parameter name
refused(id="reboot3", module_id="reportmanager")  # a second module cannot take the same route (not its group, so it never gets that far)
refused(id="reboot4", module_id="premiumdemo")  # a premium module cannot take a route away from its owner
declare(id="reboot-get", method="GET", route="agents/{agent_id:agent}/reboot/", body_fields=[], audit={"action": "view", "object_type": "agent"})  # another method: fine
must([row["id"] for row in ops.list_operations("agents")] == ["reboot", "reboot-get"], ops.list_operations())
must(ops.get_operation("agents", "reboot")["permissions"] == ["can_reboot_agents"] and ops.get_operation("agents", "nope") is None, "lookup")
described = ops.get_operation("agents", "reboot")
must(described["route"] == "agents/{agent_id:agent}/reboot/" and described["params"] == {"agent_id": "agent"}, described)
must(described["scope"] == [{"type": "agent", "source": "path:agent_id"}] and described["audit"]["audit_fields"] == ["mode"], described)
json.dumps(described)
# a module_permission must be a registered Tec-Tac codename
declare(id="codesign", module_id="licensing", method="PUT", route="core/codesign/", permissions=["can_code_sign"], scope=[], body_fields=["token"],
        audit={"action": "modify", "object_type": "code_signing_token", "audit_fields": []}, module_permission="licensing.manage")


# ------------------------------------------------------------------------------------------------ execution helpers
class FakeResponse:
    def __init__(self, status=200, content=b'{"ok": true}', content_type="application/json", headers=None, streaming=False, rendered=True):
        self.status_code, self.content, self.streaming = status, content, streaming
        self.is_rendered = rendered
        self._headers = {"Content-Type": content_type, **(headers or {})}
        self.rendered_now = False

    def get(self, name, default=None):
        return self._headers.get(name, default)

    def render(self):
        self.rendered_now = True
        self.is_rendered = True


CALLS = []


def tactical_view(response=None, boom=None):
    def view(request, *args, **kwargs):
        CALLS.append(SimpleNamespace(request=request, args=args, kwargs=kwargs))
        if boom:
            raise boom
        return response if response is not None else FakeResponse()
    return view


def route(path, response=None, boom=None, args=(), kwargs=None):
    ROUTES[path] = (tactical_view(response, boom), args, kwargs or {})


def run(user=tech, params=None, body=None, module="agents", operation="reboot", **extra):
    del CALLS[:]
    return ops.run_tactical_operation(Request(user, **extra), module, operation, params, body)


def refusal(fn, status, code):
    try:
        fn()
    except ops.TacticalOperationError as exc:
        must(exc.status == status and exc.code == code, (exc.status, exc.code, exc.message))
        return exc
    raise AssertionError(f"expected {status} {code}")


PATH = f"/agents/{AGENT}/reboot/"
route(PATH)

# ------------------------------------------------------------------------------------------------ ordering and refusals
del ROWS[:]
refusal(lambda: run(module="agents", operation="nope"), 404, "tactical_operation_not_found")
refusal(lambda: run(module="reportmanager", operation="reboot"), 404, "tactical_operation_not_found")
ENABLED["agents"] = False
refusal(lambda: run(params={"agent_id": AGENT}), 404, "tactical_operation_not_found")
ENABLED["agents"] = True
must(not ROWS and not CALLS, "an unknown operation or a disabled module writes nothing")

exc = refusal(lambda: run(user=User(anonymous=True, role=tech_role), params={"agent_id": AGENT}), 401, "authentication_required")
must(not ROWS and not CALLS, "an unauthenticated caller writes no row and reaches nothing")
refusal(lambda: ops.run_tactical_operation(SimpleNamespace(), "agents", "reboot", {"agent_id": AGENT}, None), 401, "authentication_required")

# a missing Tactical flag: 403 and a Core deny row
weak = User("weak", Roleish("can_send_wol"))
weak.sees = tech.sees
exc = refusal(lambda: run(user=weak, params={"agent_id": AGENT}, body={"mode": "MODULE-WORDING"}), 403, "tactical_permission_denied")
must(not CALLS, "Tactical is never reached")
must(len(ROWS) == 1, ROWS)
deny = ROWS[0]
must(deny["action"] == "deny" and deny["username"] == "weak" and deny["object_type"] == "agent", deny)
info = deny["debug_info"]
must(info["module_id"] == "agents" and info["object_id"] == AGENT, info)
must(info["operation_context"] == {"server_provenance": "tactical-operation", "operation": "reboot", "tactical_status": None, "core_refusal": True}, info)
must(info["metadata"]["reason"] == "permission_denied" and info["metadata"]["status"] == 403 and info["metadata"]["refused_action"] == "run", info["metadata"])
must(deny["message"] == ops.DENY_MESSAGES["permission_denied"] and "MODULE-WORDING" not in json.dumps(deny, default=str), deny)
must(exc.audit == {"recorded": True, "id": 7, "action": "deny"}, exc.audit)
# no role, installer user
del ROWS[:]
refusal(lambda: run(user=User("norole", None), params={"agent_id": AGENT}), 403, "tactical_permission_denied")
refusal(lambda: run(user=User("inst", tech_role, installer=True), params={"agent_id": AGENT}), 403, "tactical_permission_denied")
must(len(ROWS) == 2 and all(r["action"] == "deny" for r in ROWS), ROWS)
# a superuser and a role superuser pass the flag check
for boss in (User("root", None, superuser=True), User("rolesu", Roleish(superuser=True))):
    result = run(user=boss, params={"agent_id": AGENT})
    must(result.status == 200, result)

# the deny row of a Core refusal is written for a Python caller that could not use the module under the public record()
del ROWS[:]
refusal(lambda: run(user=weak, params={"agent_id": AGENT}), 403, "tactical_permission_denied")
must(ROWS and ROWS[0]["username"] == "weak", "the actor is the signed-in user")

# ---- module_permission with AND semantics; a superuser passes
CODESIGN_PATH = "/core/codesign/"
route(CODESIGN_PATH, FakeResponse(200, b'{"token": "x"}'))
signer = User("signer", Roleish("can_code_sign"))
licensor = User("licensor", Roleish(grants=["licensing.manage"]))
both = User("both", Roleish("can_code_sign", grants=["licensing.manage"]))
del ROWS[:]
refusal(lambda: run(user=signer, module="licensing", operation="codesign", body={"token": "t"}), 403, "module_permission_denied")
must(ROWS[-1]["action"] == "deny" and ROWS[-1]["debug_info"]["metadata"]["reason"] == "module_permission_denied", ROWS[-1])
must(ROWS[-1]["message"] == ops.DENY_MESSAGES["module_permission_denied"], ROWS[-1])
refusal(lambda: run(user=licensor, module="licensing", operation="codesign", body={"token": "t"}), 403, "tactical_permission_denied")  # the codename alone is not enough
del ROWS[:]
must(run(user=both, module="licensing", operation="codesign", body={"token": "t"}).status == 200, "both pass")
must(run(user=User("su", None, superuser=True), module="licensing", operation="codesign", body={"token": "t"}).status == 200, "a superuser passes")
must(ROWS[0]["action"] == "modify" and ROWS[0]["debug_info"]["module_id"] == "licensing", ROWS[0])
must("token" not in json.dumps(ROWS[0], default=str).lower().replace("tactical", "").replace("code_signing_token", ""), "no secret in the row")
# a lookup error on the codename fails closed
saved = rbac.has_extension_permission
rbac.has_extension_permission = lambda user, codename: (_ for _ in ()).throw(RuntimeError("db down"))
refusal(lambda: run(user=both, module="licensing", operation="codesign", body={"token": "t"}), 403, "module_permission_denied")
rbac.has_extension_permission = saved

# ---- scope: the same 404 text for a missing and an out-of-scope object
del ROWS[:]
out = refusal(lambda: run(params={"agent_id": OTHER}), 404, "object_not_found")  # exists, outside the role's scope
gone = refusal(lambda: run(params={"agent_id": HIDDEN}), 404, "object_not_found")  # does not exist
must(out.message == gone.message == ops.MESSAGES["object_not_found"], (out.message, gone.message))
must(not CALLS, "Tactical is not reached for an out-of-scope object")
must(len(ROWS) == 2 and all(r["action"] == "deny" and r["debug_info"]["metadata"]["reason"] == "not_found" for r in ROWS), ROWS)
must(ROWS[0]["message"] == ROWS[1]["message"] == ops.DENY_MESSAGES["not_found"], ROWS)
must([r["debug_info"]["object_id"] for r in ROWS] == [OTHER, HIDDEN], ROWS)
# the scope check does not ask for can_list_agents (no second gate): the role has no such flag and the call still runs
must(not hasattr(tech_role, "can_list_agents"), "fixture")
must(run(params={"agent_id": AGENT}).status == 200, "in scope runs without can_list_agents")
# agents are matched by agent_id only, never by PK alias
must(adapter.objects_in_role_scope(user=tech, resource_type="agent", identifiers=["1"]) is False, "a PK alias is not an agent id")
must(adapter.objects_in_role_scope(user=tech, resource_type="agent", identifiers=[AGENT]) is True, "agent id")
must(adapter.objects_in_role_scope(user=tech, resource_type="agent", identifiers=[AGENT, OTHER]) is False, "one out of scope fails the set")
must(adapter.objects_in_role_scope(user=tech, resource_type="client", identifiers=["1"]) is True, "client")
must(adapter.objects_in_role_scope(user=tech, resource_type="client", identifiers=["1", "2"]) is False, "client 2 is out of scope")
must(adapter.objects_in_role_scope(user=tech, resource_type="client", identifiers=["x"]) is False, "malformed")
must(adapter.objects_in_role_scope(user=tech, resource_type="client", identifiers=["0"]) is False, "zero")
must(adapter.objects_in_role_scope(user=tech, resource_type="site", identifiers=["10"]) is True and adapter.objects_in_role_scope(user=tech, resource_type="site", identifiers=["11"]) is False, "site")
must(adapter.objects_in_role_scope(user=tech, resource_type="agent", identifiers=[]) is False, "nothing is not in scope")
must(adapter.objects_in_role_scope(user=tech, resource_type="device", identifiers=["1"]) is False, "unknown type")
adapter_saved = adapter.canonical_agent_target_ids_in_scope
adapter.canonical_agent_target_ids_in_scope = lambda **kw: (_ for _ in ()).throw(RuntimeError("ambiguous"))
must(adapter.objects_in_role_scope(user=tech, resource_type="agent", identifiers=[AGENT]) is False, "an adapter error fails closed")
adapter.canonical_agent_target_ids_in_scope = adapter_saved

# a list-valued body field is checked id by id
declare(id="maintenance", method="POST", route="agents/maintenance/bulk/", permissions=["can_manage_clients"], scope=[{"type": "client", "source": "body:client_ids"}],
        body_fields=["client_ids", "action"], audit={"action": "enable", "object_type": "client", "audit_fields": ["action"]})
route("/agents/maintenance/bulk/", FakeResponse(200, b'"ok"'))
manager = User("mgr", Roleish("can_manage_clients"))
manager.sees = {"agents": set(), "clients": {1, 2}, "sites": set()}
del ROWS[:]
result = run(user=manager, operation="maintenance", body={"client_ids": [1, 2], "action": "on"})
must(result.status == 200 and result.data == "ok", result)
must(ROWS[0]["debug_info"]["object_id"] == "1,2" and ROWS[0]["after_value"] == {"action": "on"}, ROWS[0])
refusal(lambda: run(user=manager, operation="maintenance", body={"client_ids": [1, 3], "action": "on"}), 404, "object_not_found")
refusal(lambda: run(user=manager, operation="maintenance", body={"client_ids": [1, 99], "action": "on"}), 404, "object_not_found")
must(not CALLS, "a partly out-of-scope list never reaches Tactical")
for bad in ({"action": "on"}, {"client_ids": [], "action": "on"}, {"client_ids": None}, {"client_ids": [True]}, {"client_ids": [{"a": 1}]}, {"client_ids": ["  "]}):
    refusal(lambda: run(user=manager, operation="maintenance", body=bad), 400, "scope_field_required")
refusal(lambda: run(user=manager, operation="maintenance", body={"client_ids": ["x"], "action": "on"}), 404, "object_not_found")

# ---- body and parameter whitelists
del ROWS[:]
refusal(lambda: run(params={"agent_id": AGENT}, body={"mode": "now", "command": "rm -rf /"}), 400, "body_field_not_allowed")
must(not CALLS and not ROWS, "a body key outside the whitelist never reaches Tactical and writes nothing")
refusal(lambda: run(params={"agent_id": AGENT}, body=["mode"]), 400, "invalid_body")
refusal(lambda: run(params={"agent_id": AGENT}, body={"mode": object()}), 400, "invalid_body")
refusal(lambda: run(params={"agent_id": AGENT}, body={"mode": "x" * (ops.MAX_BODY_BYTES + 1)}), 413, "body_too_large")
must(run(params={"agent_id": AGENT}, body={"mode": "x" * 1000}).status == 200, "a body inside the cap passes")
for bad in ({}, {"agent_id": None}, {"agent_id": "a/b"}, {"agent_id": ".."}, {"agent_id": AGENT, "extra": "1"}, {"agent_id": True}, {"agent_id": ["x"]}, {"agent_id": "x" * 300}):
    refusal(lambda: run(params=bad), 400, "invalid_params")
refusal(lambda: run(params="agent"), 400, "invalid_params")
must(not CALLS, "bad parameters never reach Tactical")
route(f"/agents/{AGENT}/reboot/")
refusal(lambda: run(operation="reboot-get", params={"agent_id": AGENT}, body={"mode": "x"}), 400, "body_field_not_allowed")  # a GET takes no body

# ------------------------------------------------------------------------------------------------ dispatch
del ROWS[:]
result = run(params={"agent_id": AGENT}, body={"mode": "now", "datetime": "2026-10-09"})
must(result.status == 200 and result.data == {"ok": True} and result.content_type == "application/json", result)
must(len(CALLS) == 1 and RESOLVED[-1] == PATH, (CALLS, RESOLVED))
forwarded = CALLS[0].request
must(forwarded._force_auth_user is tech, "DRF ForcedAuthentication reads the signed-in user")
must(forwarded.method == "POST" and forwarded.path == PATH and forwarded.path_info == PATH, (forwarded.method, forwarded.path))
must(json.loads(forwarded._body) == {"mode": "now", "datetime": "2026-10-09"} and forwarded._stream.read() == forwarded._body, "the body is replaced")
must(forwarded.META["CONTENT_TYPE"] == "application/json" and forwarded.META["CONTENT_LENGTH"] == str(len(forwarded._body)), forwarded.META)
must("HTTP_AUTHORIZATION" not in forwarded.META and "HTTP_COOKIE" not in forwarded.META, "no Authorization header or cookie is forwarded")
must("SECRET-KNOX" not in json.dumps(forwarded.META, default=str), forwarded.META)
must(forwarded.META["REMOTE_ADDR"] == "10.0.0.9" and forwarded.META["QUERY_STRING"] == "" and forwarded.META["REQUEST_METHOD"] == "POST", forwarded.META)
must(forwarded.resolver_match.route == PATH and forwarded._dont_enforce_csrf_checks is True, "resolver match and csrf flag")
must(not hasattr(forwarded, "user"), "no user attribute is copied from the incoming request")
# 1.17.7-1: Tactical views read request._client_ip, which only the outer request carries
def ip_view(request, *args, **kwargs):
    CALLS.append(SimpleNamespace(request=request, args=args, kwargs=kwargs, ip=request._client_ip))  # AttributeError if missing
    return FakeResponse()


ROUTES[PATH] = (ip_view, (), {})
run(params={"agent_id": AGENT}, body={"mode": "now"}, _client_ip="203.0.113.7")
must(CALLS[0].ip == "203.0.113.7", "the outer request's _client_ip is copied to the in-process request")
run(params={"agent_id": AGENT}, body={"mode": "now"})
must(isinstance(CALLS[0].ip, str) and CALLS[0].ip in ("10.0.0.9", ""), "without one it is worked out from META and never missing")
route(PATH)
del ROWS[:]
# the original request is untouched
must(Request(tech).META["HTTP_AUTHORIZATION"].startswith("Token"), "fixture")
# a GET forwards no body
route(PATH, FakeResponse(200, b'{"v": 1}'))
run(operation="reboot-get", params={"agent_id": AGENT})
must(CALLS[0].request.method == "GET" and CALLS[0].request._body == b"" and CALLS[0].request.META["CONTENT_LENGTH"] == "0", CALLS[0].request.META)
# a DRF response that is not rendered yet is rendered
unrendered = FakeResponse(200, b'{"r": 1}', rendered=False)
route(PATH, unrendered)
run(params={"agent_id": AGENT})
must(unrendered.rendered_now is True, "an unrendered response is rendered")
# a renamed route: 502, no fallback, nothing else called, no row
del ROWS[:]
ROUTES.clear()
route("/agents/other/reboot/")
del RESOLVED[:]
exc = refusal(lambda: run(params={"agent_id": AGENT}), 502, "tactical_route_changed")
must(RESOLVED == [PATH] and not CALLS and not ROWS, (RESOLVED, CALLS, ROWS))
must(exc.audit is None, "no audit row for a route Core could not reach")
route(PATH)
route(CODESIGN_PATH, FakeResponse(200, b'{"token": "x"}'))
route("/agents/maintenance/bulk/", FakeResponse(200, b'"ok"'))
route(f"/agents/{AGENT}/notes/", FakeResponse(200, b'"ok"'))
# a parameter value cannot steer a path into a forbidden route
# 1.17.9: an untyped parameter here is refused at registration now (it can hold a route word), so register past the owner check
# to prove the dispatch-time path check on its own.
_owner_check = ops._check_route_owner
ops._check_route_owner = lambda *args, **kwargs: None
declare(id="inspect", method="GET", route="agents/{name}/notes/", permissions=["can_reboot_agents"], scope=[], body_fields=[], audit={"action": "view", "object_type": "agent"})
ops._check_route_owner = _owner_check
for name in ("installer", "Installer"):
    refusal(lambda: run(operation="inspect", params={"name": name}), 404, "tactical_operation_not_found")
must(not CALLS, "the concrete path is checked again")

# ------------------------------------------------------------------------------------------------ audit rows
def rows_after(status=200, content=b'{"ok": true}', **kw):
    del ROWS[:]
    route(PATH, FakeResponse(status, content, **kw))
    result = run(params={"agent_id": AGENT}, body={"mode": "now", "datetime": "t"})
    return result


result = rows_after(200)
must(len(ROWS) == 1, ROWS)
row = ROWS[0]
must(row["action"] == "run" and row["object_type"] == "agent" and row["username"] == "tech", row)
must(row["after_value"] == {"mode": "now"}, "only audit_fields are copied into after")
info = row["debug_info"]
must(info["module_id"] == "agents" and info["module_version"] == "0.1.2" and info["object_id"] == AGENT, info)
must(info["operation_context"] == {"server_provenance": "tactical-operation", "operation": "reboot", "tactical_status": 200}, info)
must(info["metadata"] == {"operation": "reboot", "method": "POST", "route": "agents/{agent_id:agent}/reboot/", "tactical_status": 200}, info["metadata"])
must(info["actor_kind"] == "human" and info["correlation_id"] == "req-1", info)
must(result.audit == {"recorded": True, "id": 7, "action": "run"}, result.audit)
must(row["message"] == "Core ran Tactical operation reboot.", row)
# the actor needs no Tec-Tac module grant: licensing has permission groups and the user holds none, yet the row is written
del ROWS[:]
run(user=User("su", None, superuser=True), module="licensing", operation="codesign", body={"token": "t"})
signing_role_user = User("flagonly", Roleish("can_code_sign"))
declare(id="codesign-view", module_id="licensing", method="GET", route="core/codesign/status/", permissions=["can_code_sign"], scope=[], body_fields=[],
        audit={"action": "view", "object_type": "code_signing_token"})
route("/core/codesign/status/", FakeResponse(200, b'{"set": true}'))
del ROWS[:]
must(run(user=signing_role_user, module="licensing", operation="codesign-view").status == 200, "ran")
must(len(ROWS) == 1 and ROWS[0]["action"] == "view" and ROWS[0]["username"] == "flagonly", ROWS)  # GET with action view writes a row
# a custom message
declare(id="noted", method="POST", route="agents/{agent_id:agent}/notes/", permissions=["can_manage_notes"], scope=[{"type": "agent", "source": "path:agent_id"}],
        body_fields=["note"], audit={"action": "add", "object_type": "agent_note", "audit_fields": []}, message="Core added an agent note.")
route(f"/agents/{AGENT}/notes/", FakeResponse(200, b'"ok"'))
del ROWS[:]
run(operation="noted", params={"agent_id": AGENT}, body={"note": "SECRET NOTE"})
must(ROWS[0]["message"] == "Core added an agent note." and ROWS[0]["after_value"] is None and "SECRET NOTE" not in json.dumps(ROWS, default=str), ROWS)

# Tactical refuses: a Core deny row, and Tactical's answer is relayed
for status in (401, 403):
    result = rows_after(status, b'"You do not have permission to perform this action."')
    must(result.status == status and result.data == "You do not have permission to perform this action.", result)
    must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", ROWS)
    ctx = ROWS[0]["debug_info"]["operation_context"]
    must(ctx == {"server_provenance": "tactical-operation", "operation": "reboot", "tactical_status": status, "core_refusal": True}, ctx)
    must(ROWS[0]["debug_info"]["metadata"]["reason"] == "tactical_denied", ROWS[0])
    must(ROWS[0]["message"] == ops.DENY_MESSAGES["tactical_denied"] and "permission to perform" not in ROWS[0]["message"], ROWS[0]["message"])
# 5xx: unknown outcome for a change, nothing for a read
result = rows_after(500, b'"boom"')
must(result.status == 500 and len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown", ROWS)
must(ROWS[0]["debug_info"]["operation_context"]["tactical_status"] == 500 and ROWS[0]["message"] == ops.OUTCOME_UNKNOWN_MESSAGE, ROWS[0])
result = rows_after(503)
must(ROWS[0]["action"] == "custom:outcome-unknown", ROWS)
del ROWS[:]
route(PATH, FakeResponse(500, b'"boom"'))
must(run(operation="reboot-get", params={"agent_id": AGENT}).status == 500 and not ROWS, "a failed GET writes no row")
# other 4xx: nothing changed
for status in (400, 404, 409, 422, 405):
    result = rows_after(status, b'"nope"')
    must(result.status == status and not ROWS and result.audit == {}, (status, ROWS))
# an exception after dispatch
del ROWS[:]
route(PATH, boom=RuntimeError("tactical exploded SECRET"))
exc = refusal(lambda: run(params={"agent_id": AGENT}, body={"mode": "now"}), 502, "tactical_call_failed")
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown" and ROWS[0]["debug_info"]["operation_context"]["tactical_status"] is None, ROWS)
must("SECRET" not in exc.message and "SECRET" not in json.dumps(ROWS, default=str), "the exception text is not relayed or stored")
must(exc.audit["recorded"] is True, exc.audit)
del ROWS[:]
route(PATH, boom=RuntimeError("get exploded"))
refusal(lambda: run(operation="reboot-get", params={"agent_id": AGENT}), 502, "tactical_call_failed")
must(not ROWS, "an exception on a GET writes no row")
# a failed audit write still relays Tactical's answer, reported as not recorded
route(PATH, FakeResponse(200, b'{"done": 1}'))
FakeAuditLog.objects.fail = True
result = run(params={"agent_id": AGENT}, body={"mode": "now"})
must(result.status == 200 and result.data == {"done": 1} and result.audit["recorded"] is False, result)
FakeAuditLog.objects.fail = False
# a Core refusal whose deny row cannot be written is still a refusal
FakeAuditLog.objects.fail = True
exc = refusal(lambda: run(user=weak, params={"agent_id": AGENT}), 403, "tactical_permission_denied")
must(exc.audit["recorded"] is False, exc.audit)
FakeAuditLog.objects.fail = False

# ------------------------------------------------------------------------------------------------ responses
pdf = b"%PDF-1.4 " + b"x" * 5000
route(PATH, FakeResponse(200, pdf, "application/pdf", {"Content-Disposition": 'attachment; filename="report.pdf"', "Set-Cookie": "x=1", "X-Other": "no"}))
result = run(operation="reboot-get", params={"agent_id": AGENT})
must(result.content == pdf and result.data == pdf and result.content_type == "application/pdf", "binary relayed")
must(result.headers == {"Content-Type": "application/pdf", "Content-Disposition": 'attachment; filename="report.pdf"'}, result.headers)
big = FakeResponse(200, b"x" * (ops.MAX_RESPONSE_BYTES + 1), "application/pdf")
route(PATH, big)
del ROWS[:]
refusal(lambda: run(params={"agent_id": AGENT}, body={"mode": "now"}), 502, "tactical_response_refused")
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown", ROWS)
del ROWS[:]
refusal(lambda: run(operation="reboot-get", params={"agent_id": AGENT}), 502, "tactical_response_refused")
must(not ROWS, "an oversized answer to a GET writes no row")
exactly = FakeResponse(200, b"x" * ops.MAX_RESPONSE_BYTES, "application/pdf")
route(PATH, exactly)
must(len(run(operation="reboot-get", params={"agent_id": AGENT}).content) == ops.MAX_RESPONSE_BYTES, "25 MiB exactly is relayed")
stream = FakeResponse(200, b"", "text/csv", streaming=True)
del stream.content
route(PATH, stream)
del ROWS[:]
refusal(lambda: run(params={"agent_id": AGENT}, body={"mode": "now"}), 502, "tactical_response_refused")
must(ROWS and ROWS[0]["action"] == "custom:outcome-unknown", "a streaming answer to a change is refused and recorded as unknown")
# JSON content types parse, others stay bytes, broken JSON stays bytes
route(PATH, FakeResponse(200, b'[1, 2]', "application/json; charset=utf-8"))
must(run(operation="reboot-get", params={"agent_id": AGENT}).data == [1, 2], "json")
route(PATH, FakeResponse(200, b'{broken', "application/json"))
must(run(operation="reboot-get", params={"agent_id": AGENT}).data == b"{broken", "broken json stays bytes")
route(PATH, FakeResponse(204, b"", "application/json"))
must(run(operation="reboot-get", params={"agent_id": AGENT}).data is None, "an empty JSON body is None")

# ------------------------------------------------------------------------------------------------ the HTTP view
route(PATH, FakeResponse(200, b'{"ok": true}'))
view = views.TacticalOperationView()
del ROWS[:]
reply = view.post(SimpleNamespace(data={"params": {"agent_id": AGENT}, "body": {"mode": "now"}}, user=tech, META={}), "agents", "reboot")
must(isinstance(reply, HttpResponse) and reply.status_code == 200 and reply.content == b'{"ok": true}' and reply.content_type == "application/json", reply.__dict__)
must(reply.headers == {"Content-Type": "application/json", "X-Tec-Tac-Audit": "recorded"}, reply.headers)
FakeAuditLog.objects.fail = True
reply = view.post(SimpleNamespace(data={"params": {"agent_id": AGENT}}, user=tech, META={}), "agents", "reboot")
must(reply.status_code == 200 and reply.headers["X-Tec-Tac-Audit"] == "not-recorded", reply.headers)
FakeAuditLog.objects.fail = False
route(PATH, FakeResponse(404, b'"Not found."'))
reply = view.post(SimpleNamespace(data={"params": {"agent_id": AGENT}}, user=tech, META={}), "agents", "reboot")
must(reply.status_code == 404 and reply.content == b'"Not found."' and "X-Tec-Tac-Audit" not in reply.headers, "Tactical's own 404 is relayed, with no header when no row was due")
route(PATH, FakeResponse(200, b'{"ok": true}'))
reply = view.post(SimpleNamespace(data={"params": {"agent_id": AGENT}}, user=weak, META={}), "agents", "reboot")
must(isinstance(reply, DRFResponse) and reply.status_code == 403 and reply.data == {"detail": ops.MESSAGES["permission_denied"], "code": "tactical_permission_denied"}, reply.__dict__)
must(reply.headers == {"X-Tec-Tac-Audit": "recorded"}, reply.headers)
reply = view.post(SimpleNamespace(data={"params": {"agent_id": OTHER}}, user=tech, META={}), "agents", "reboot")
must(reply.status_code == 404 and reply.data["code"] == "object_not_found", reply.__dict__)
reply = view.post(SimpleNamespace(data={"params": {"agent_id": AGENT}}, user=tech, META={}), "agents", "nope")
must(reply.status_code == 404 and reply.data["code"] == "tactical_operation_not_found" and reply.headers == {}, reply.__dict__)
for data in (["x"], "x", None):
    reply = view.post(SimpleNamespace(data=data, user=tech, META={}), "agents", "reboot")
    must(reply.status_code == 400 and reply.data["code"] == "invalid_operation_request", reply.__dict__)
reply = view.post(SimpleNamespace(data={"params": {}, "path": "/accounts/"}, user=tech, META={}), "agents", "reboot")
must(reply.status_code == 400 and "path" in reply.data["detail"], reply.__dict__)
# a path in the payload is never read: only params and body exist
view_source = (APP / "tactical_operation_views.py").read_text(encoding="utf-8")
must('_ALLOWED_FIELDS = {"params", "body", "query"}' in view_source and "SessionAuthenticated" in view_source, "the route sits behind SessionAuthenticated and takes only params, body and query (1.17.13)")

# ------------------------------------------------------------------------------------------------ AD-19 conditions 3 and 5
# Condition 3: a failed audit write is logged at error level, never fatal, and the result and the header say so.
class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


capture = _Capture()
ops_logger = logging.getLogger(ops.__name__)
ops_logger.addHandler(capture)
logging.disable(logging.NOTSET)
try:
    route(PATH, FakeResponse(200, b'{"ok": true}'))
    FakeAuditLog.objects.fail = True
    result = run(params={"agent_id": AGENT}, body={"mode": "now"})
    FakeAuditLog.objects.fail = False
finally:
    logging.disable(logging.CRITICAL)
    ops_logger.removeHandler(capture)
must(result.status == 200 and result.audit["recorded"] is False, ("a failed audit write is not fatal", result.audit))
must(any(r.levelno >= logging.ERROR for r in capture.records), "a failed audit write is logged at error level")

# Condition 5: Tec-Tac's own functions and Tactical operations are audited by the same row schema. A backend action
# calls tec_tac.audit.record from its route; an operation row comes from the executor. An auditor reads both the same way.
route(PATH, FakeResponse(200, b'{"ok": true}'))
del ROWS[:]
run(params={"agent_id": AGENT}, body={"mode": "now"})
operation_row = ROWS[0]
del ROWS[:]
backend = audit.record(actor=tech, module_id="agents", action="run", object_type="agent", object_id=AGENT, message="Module backend action.")
must(backend["recorded"] is True, backend)
backend_row = ROWS[0]
must(set(operation_row) == set(backend_row), (sorted(operation_row), sorted(backend_row)))
operation_info, backend_info = operation_row["debug_info"], backend_row["debug_info"]
for key in ("actor_kind", "actor_identity", "module_id", "module_version", "object_id", "source", "operation_context", "metadata"):
    must(key in operation_info and key in backend_info, key)
must(operation_row["username"] == backend_row["username"] == "tech", "actor")
must(operation_info["module_id"] == backend_info["module_id"] == "agents", "module")
must(operation_row["action"] == backend_row["action"] and operation_row["object_type"] == backend_row["object_type"], "action and object")
must("server_provenance" in operation_info["operation_context"] and "server_provenance" not in backend_info["operation_context"], "provenance tells the two apart")
# The executor refuses Core's own functions: module 'core' and any api/tfd/ route. Those are audited by record().
refused(module_id="core")
refused(route="api/tfd/system/updates/")

# ------------------------------------------------------------------------------------------------ capability, urls, throttles, apps, docs, install.sh
cap = ops.register_core_tactical_operations_capability()
must(CAPS and CAPS[-1]["id"] == "core.tactical_operations" and CAPS[-1]["module_id"] == "core" and CAPS[-1]["version"] == "1.2.0", CAPS)  # 1.17.14: 1.2.0, still major 1
must(CAPS[-1]["operations"] == ("run", "list_operations", "get_operation"), CAPS[-1]["operations"])
provider = CAPS[-1]["provider"]
must(provider.run is ops.run_tactical_operation and provider.list_operations is ops.list_operations and provider.get_operation is ops.get_operation, "provider")
json.dumps(CAPS[-1]["metadata"])
must(CAPS[-1]["metadata"]["limits"]["body_bytes"] == 262144 and CAPS[-1]["metadata"]["limits"]["response_bytes"] == 26214400, CAPS[-1]["metadata"])  # 1.17.13 adds upload and query limits

urls = (APP / "urls.py").read_text(encoding="utf-8")
must('path("tactical-operations/<str:module_id>/<str:operation_id>/", TacticalOperationView.as_view(), name="tec-tac-tactical-operations")' in urls, "route")
throttles = ast.parse((APP / "throttles.py").read_text(encoding="utf-8"))
rates = {}
for node in throttles.body:
    if isinstance(node, ast.ClassDef) and node.name.startswith("TacticalOperation"):
        rates[node.name] = {t.targets[0].id: ast.literal_eval(t.value) for t in node.body if isinstance(t, ast.Assign)}
must(rates["TacticalOperationMinThrottle"]["rate"] == "120/min" and rates["TacticalOperationDayThrottle"]["rate"] == "5000/day", rates)
apps_source = (APP / "apps.py").read_text(encoding="utf-8")
must("register_core_tactical_operations_capability()" in apps_source, "apps.py registers the capability")
guard = apps_source.split("register_core_tactical_operations_capability()")[0].rsplit("try:", 1)[1]
must("except Exception" in apps_source.split("register_core_tactical_operations_capability()")[1].split("\n\n")[0], "the registration is guarded and never aborts start-up")
must(guard.strip().startswith("from .tactical_operations import"), guard)

tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


python_rows = {(r["import_path"], r["name"]): r for r in literal("CORE_CONTRACTS")}
for name in ("register_tactical_operation", "run_tactical_operation", "list_operations", "get_operation"):
    row = python_rows[("tec_tac.tactical_operations", name)]
    must(row["area"] == "tactical-operations" and row["kind"] == "python" and "1.17.7" in row["purpose"], row)
must("core.tactical_operations" in python_rows[("tec_tac.tactical_operations", "run_tactical_operation")]["purpose"], "capability named in the Python row")
http = literal("HTTP_CONTRACT_DETAILS")["/api/tfd/tactical-operations/<str:module_id>/<str:operation_id>/"]["POST"]
text = json.dumps(http)
for needle in ("120/min", "5000/day", "X-Tec-Tac-Audit", "custom:outcome-unknown", "tactical_route_changed", "server_provenance", "256 KiB", "25 MiB", "Core deny row"):
    must(needle in text, needle)
for code in ("401", "403", "404", "413", "429", "502"):
    must(code in http["errors"], code)
must(any("tactical-operations" in rule and "register_tactical_operation" in rule for rule in literal("RULES")), "rule text")
docs = (ROOT / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("register_tactical_operation", "core.tactical_operations", "X-Tec-Tac-Audit", "custom:outcome-unknown", "tactical_route_changed",
               "mode (b)", "has_tactical_permission", "256 KiB", "25 MiB", "one caller per Tactical route", "never names a path"):
    must(needle.lower() in docs.lower(), needle)
for needle in ("accounts/", "api/tfd/", "api/v3/", "api/v4/", "_allauth/", "logout", "logoutall", "v2/", "agents/installer"):
    must(needle in docs, needle)
install = (ROOT / "install.sh").read_text(encoding="utf-8")
must("VERIFY_TACTICAL_OPERATIONS_CODE=" in install and "core.tactical_operations" in install and "tec-tac-tactical-operations" in install, "install.sh verifies the capability and route")
must("Core Tactical operations capability verification failed or timed out." in install, "install.sh fails the install when it is missing")
# the executor reads no token and makes no HTTP call
source = (APP / "tactical_operations.py").read_text(encoding="utf-8")
for banned in ("requests", "urllib", "httpx", "http.client", "knox", "Authorization", "request_local", "api_key", "service_account"):
    code = "\n".join(line for line in source.splitlines() if not line.strip().startswith(("#", '"""')))
    must(banned not in re.sub(r'"[^"\n]*"', '""', code).replace("HTTP_AUTHORIZATION", ""), f"tactical_operations.py must not use {banned}")
# the dev-server script exists and names every step
runtime = (ROOT / "tests" / "tactical-operations-runtime-1.17.7.py").read_text(encoding="utf-8")
ast.parse(runtime)
for needle in ("manage.py shell", "sys.exit(1)", '"PASS"', "FAIL", "dispatch through Tactical's own view", "audit row names the user", "deny row",
               "installer user is denied", "tactical_route_changed", "typed refusal", "nothing is left behind", "set_rollback"):
    must(needle in runtime, needle)
print("[TEST] PASS tactical operations 1.17.7")
