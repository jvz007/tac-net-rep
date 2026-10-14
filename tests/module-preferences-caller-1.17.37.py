#!/usr/bin/env python3
"""1.17.37 regression (AD-26, CQ110 a): the Python functions of core.module_preferences verify the calling module.

The real tec_tac/module_preferences.py and tec_tac/caller_identity.py run against a temporary extensions folder (the style of
tests/caller-identity-core-provider-1.17.27.py). The model is a fake table with a read and write log, so a refused call is checked
against what was read or written, not only against the exception. Covered: a module calling for its own id works for get, set, delete
and list_for; the same module naming another id is refused 403 caller_not_allowed for all four, with no row read or written; a Core
frame, a library frame, a generated '<string>' frame, the standard library, a disabled module, a legacy module and the test file itself
(outside every module) are refused; the refusal comes before name and value validation and before the signed-in and module id checks;
a module's own bad name still gives invalid_name; the browser views keep working through the private functions with the path id (PUT,
GET, DELETE, the 50 names limit, 401, 404 module_not_found, 400 invalid_name and invalid_value, and the write throttle class); the capability
was 1.1.0 with requires_framework >=1.17.37 and a verified-caller note (1.2.0 with >=1.17.38 from Core 1.17.38, see tests/module-preferences-audit-1.17.38.py); the contract rows and the rule text say so; docs/module-preferences.md
names the verified caller and no longer says the module id is an unchecked claim.
"""
from __future__ import annotations

import ast
import importlib
import json
import logging
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
logging.disable(logging.CRITICAL)
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
sys.path.insert(0, str(ROOT / "framwork"))
SCHEDULER_FILE = str(APP / "scheduler.py")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


# ------------------------------------------------------------------------------------------------ installed modules (a temporary extensions folder)
TMP = Path(tempfile.mkdtemp(prefix="tectac-modpref-caller-"))
EXT = TMP / "extensions"
LIB = TMP / "lib"
EXT.mkdir()
LIB.mkdir()
PLUGINS: dict = {}
ENABLED: dict = {}


def plugin(plugin_id, version, *, enabled=True, legacy=False, plugin_type="extension"):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type=plugin_type, root=root, version=version, legacy=legacy,
                                         category="premium")
    ENABLED[plugin_id] = enabled


def discover_plugins():
    return tuple(PLUGINS.values())


def is_enabled(module_id, state=None):
    return bool(ENABLED.get(module_id, False))


plugin("remote-background", "1.0.0")
plugin("endpoints", "0.3.0")
plugin("modoff", "0.1.0", enabled=False)
plugin("oldmod", "0.1.0", legacy=True)


class NoticeError(ValueError):
    pass


def enabled_extension_id(module_id):
    name = module_id.strip() if isinstance(module_id, str) else ""
    if not name:
        raise NoticeError("module_id is required.")
    if name.lower() in {"core", "tec-tac"}:
        raise NoticeError("module_id may not be a Core source.")
    plug = PLUGINS.get(name)
    if plug is None or plug.plugin_type != "extension" or plug.legacy or not ENABLED.get(name):
        raise NoticeError(f"module_id {name!r} is not an installed, enabled module.")
    return name


# ------------------------------------------------------------------------------------------------ narrow stubs for Django and DRF
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.registry = mod("tec_tac.registry", discover_plugins=discover_plugins)
pkg.module_state = mod("tec_tac.module_state", is_enabled=is_enabled)
pkg.notices = mod("tec_tac.notices", NoticeError=NoticeError, enabled_extension_id=enabled_extension_id)

# the audit module (1.17.38): the person check and the audit row; every row the code asks for is kept
AUDIT_CALLS: list = []


class AuditContractError(ValueError):
    pass


class AuditWriteError(RuntimeError):
    pass


def _resolve_module(module_id):
    plug = PLUGINS.get(module_id)
    if plug is None or plug.plugin_type != "extension" or not ENABLED.get(module_id):
        raise AuditContractError(f"Unknown or ambiguous Tec-Tac module_id: {module_id}")
    return {"id": module_id, "version": "1.0.0", "permissions": ("view",), "legacy": bool(plug.legacy)}


mod("tec_tac.audit", AuditContractError=AuditContractError, AuditWriteError=AuditWriteError, _resolve_module=_resolve_module,
    _actor_can_use_module=lambda actor, module: getattr(actor, "allowed", True),
    record=lambda **kwargs: AUDIT_CALLS.append(kwargs) or {"recorded": True})
REGISTERED: list = []
pkg.capabilities = mod("tec_tac.capabilities", register_capability=lambda **kwargs: REGISTERED.append(kwargs) or "registered")
mod("tec_tac.mfa_backup")
mod("tec_tac.session_security", SessionAuthenticated=type("SessionAuthenticated", (), {}))
mod("tec_tac.throttles", ModulePreferenceWriteMinThrottle=type("ModulePreferenceWriteMinThrottle", (), {}))
mod("django")
mod("django.contrib")


class _Atomic:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


mod("django.db", transaction=types.SimpleNamespace(atomic=lambda: _Atomic()))
LOCKS: list = []


class _UserQuery:
    def get(self, pk):
        LOCKS.append(pk)


class _UserManager:
    def select_for_update(self):
        return _UserQuery()


mod("django.contrib.auth", get_user_model=lambda: types.SimpleNamespace(objects=_UserManager()))


class Response:
    def __init__(self, data=None, status=None):
        self.data = data
        self.status_code = 200 if status is None else status


mod("drf_spectacular")
mod("drf_spectacular.utils", extend_schema=lambda **kwargs: (lambda fn: fn), extend_schema_view=lambda **kwargs: (lambda cls: cls))
mod("rest_framework")
mod("rest_framework.response", Response=Response)
mod("rest_framework.views", APIView=type("APIView", (), {}))

# ------------------------------------------------------------------------------------------------ the fake model: every read and write is logged
OPS: list = []


class Row(SimpleNamespace):
    pass


class Query:
    def __init__(self, table, rows):
        self.table, self.rows = table, rows

    def filter(self, **kwargs):
        return Query(self.table, [r for r in self.rows if all(getattr(r, k) == v for k, v in kwargs.items())])

    def first(self):
        return self.rows[0] if self.rows else None

    def exists(self):
        return bool(self.rows)

    def count(self):
        return len(self.rows)

    def delete(self):
        OPS.append("write")
        gone = {id(r) for r in self.rows}
        self.table.rows = [r for r in self.table.rows if id(r) not in gone]
        return len(gone), {}

    def order_by(self, field):
        return Query(self.table, sorted(self.rows, key=lambda r: getattr(r, field)))

    def __iter__(self):
        return iter(self.rows)


class Manager:
    def __init__(self):
        self.rows: list = []

    def filter(self, **kwargs):
        OPS.append("read")
        return Query(self, self.rows).filter(**kwargs)

    def update_or_create(self, user_id, module_id, name, defaults):
        OPS.append("write")
        for row in self.rows:
            if (row.user_id, row.module_id, row.name) == (user_id, module_id, name):
                row.value = defaults["value"]
                return row, False
        row = Row(user_id=user_id, module_id=module_id, name=name, value=defaults["value"])
        self.rows.append(row)
        return row, True


class TecTacModulePreference:
    objects = Manager()


mod("tec_tac.models", TecTacModulePreference=TecTacModulePreference)

ci = importlib.import_module("tec_tac.caller_identity")
mp = importlib.import_module("tec_tac.module_preferences")
views = importlib.import_module("tec_tac.module_preference_views")

ALICE = SimpleNamespace(pk=1, is_authenticated=True)
ANON = SimpleNamespace(pk=None, is_authenticated=False)


def reset():
    OPS.clear()
    LOCKS.clear()
    TecTacModulePreference.objects.rows.clear()


def compile_as(filename, source):
    """Code whose frames carry ``filename`` as their code file (a stand-in for a module, Core or a library)."""
    ns: dict = {"__name__": "probe"}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test-only stand-ins with a chosen code file name
    return ns


CALL = "def call(fn, *args, **kwargs):\n    return fn(*args, **kwargs)\n"
RB = compile_as(str(EXT / "remote-background" / "service.py"), CALL)  # an enabled module, its own folder
EP = compile_as(str(EXT / "endpoints" / "service.py"), CALL)  # another enabled module
OFF = compile_as(str(EXT / "modoff" / "service.py"), CALL)  # a disabled module
OLD = compile_as(str(EXT / "oldmod" / "service.py"), CALL)  # a legacy module
CORE = compile_as(SCHEDULER_FILE, CALL)  # Core's own file name (tec_tac/scheduler.py)
LIBRARY = compile_as(str(LIB / "decorator.py"), CALL)  # a library outside every module
GENERATED = compile_as("<string>", CALL)  # a generated frame
STDLIB = compile_as(json.__file__, CALL)  # the standard library


def run(caller, fn, *args, **kwargs):
    """Call fn from the code of ``caller`` (a stand-in module frame), or straight from this test file when caller is None."""
    if caller is None:
        return fn(*args, **kwargs)
    return caller["call"](fn, *args, **kwargs)


def refused(caller, fn, *args, module_id, **kwargs):
    """The call must be refused as caller_not_allowed (403) with no row read or written, and the refusal must be the one given."""
    reset()
    try:
        run(caller, fn, *args, module_id=module_id, **kwargs)
    except mp.ModulePreferenceError as exc:
        must(exc.code == "caller_not_allowed", f"code {exc.code!r} for {fn.__name__} to {module_id!r}")
        must(exc.status_code == 403, f"status {exc.status_code}")
    else:
        raise AssertionError(f"{fn.__name__} was not refused for {module_id!r}")
    must(not OPS and not LOCKS and not TecTacModulePreference.objects.rows, f"nothing read or written for {fn.__name__}: {OPS} {LOCKS}")


def code_of(fn):
    try:
        fn()
    except mp.ModulePreferenceError as exc:
        return exc.code
    return None


# ------------------------------------------------------------------------------------------------ 1. a module calling for its own id works for all four functions
reset()
must(run(RB, mp.set, ALICE, "header-collapsed", True, module_id="remote-background") is True, "set for its own id")
must(run(RB, mp.get, ALICE, "header-collapsed", module_id="remote-background") is True, "get for its own id")
must(run(RB, mp.list_for, ALICE, module_id="remote-background") == {"header-collapsed": True}, "list_for for its own id")
must(run(RB, mp.delete, ALICE, "header-collapsed", module_id="remote-background") is True, "delete for its own id")
must(run(RB, mp.get, ALICE, "header-collapsed", module_id="remote-background", default="gone") == "gone", "and it is gone")

# ------------------------------------------------------------------------------------------------ 2. another module's id is refused for all four, nothing read or written
for fn, args in (
    (mp.get, ("a",)), (mp.set, ("a", 1)), (mp.delete, ("a",)), (mp.list_for, ()),
):
    refused(RB, fn, ALICE, *args, module_id="endpoints")
# the same refusal from a second enabled module, in both directions
refused(EP, mp.get, ALICE, "a", module_id="remote-background")
refused(EP, mp.list_for, ALICE, module_id="remote-background")
must(run(EP, mp.list_for, ALICE, module_id="endpoints") == {}, "endpoints may still read its own (empty) list")

# ------------------------------------------------------------------------------------------------ 3. Core, library, generated, stdlib, disabled, legacy and the test file are refused
for caller, module in ((CORE, "remote-background"), (LIBRARY, "remote-background"), (GENERATED, "remote-background"),
                       (STDLIB, "remote-background"), (OFF, "modoff"), (OLD, "oldmod"), (None, "remote-background")):
    refused(caller, mp.get, ALICE, "a", module_id=module)
    refused(caller, mp.set, ALICE, "a", 1, module_id=module)
    refused(caller, mp.delete, ALICE, "a", module_id=module)
    refused(caller, mp.list_for, ALICE, module_id=module)

# ------------------------------------------------------------------------------------------------ 4. the caller check runs before name, value, sign-in and module checks
reset()
for caller, args, module in (
    (RB, ("Bad Name!",), "endpoints"),
    (RB, ("a",), "core"),
    (RB, ("a",), "nope"),
):
    try:
        run(caller, mp.get, ALICE, *args, module_id=module)
    except mp.ModulePreferenceError as exc:
        must(exc.code == "caller_not_allowed", f"{module!r} with {args!r}: {exc.code}")
    else:
        raise AssertionError("refused call returned")
try:
    run(RB, mp.set, ALICE, "a", [[[[[[1]]]]]], module_id="endpoints")  # a 6 level value from the wrong module
except mp.ModulePreferenceError as exc:
    must(exc.code == "caller_not_allowed", f"a bad value from the wrong module: {exc.code}")
else:
    raise AssertionError("refused call returned")
must(code_of(lambda: run(RB, mp.get, ANON, "a", module_id="endpoints")) == "caller_not_allowed", "an anonymous call from the wrong module")
must(not OPS, "and none of those read or wrote anything")

# ------------------------------------------------------------------------------------------------ 5. the module's own validation still applies after the caller check
reset()
must(code_of(lambda: run(RB, mp.get, ALICE, "Bad Name!", module_id="remote-background")) == "invalid_name", "a bad name from its own module")
must(code_of(lambda: run(RB, mp.set, ALICE, "a", [[[[[[1]]]]]], module_id="remote-background")) == "invalid_value", "a bad value from its own module")
must(code_of(lambda: run(RB, mp.get, ANON, "a", module_id="remote-background")) == "signed_in_required", "an anonymous own call is signed out")
must(code_of(lambda: run(RB, mp.get, ALICE, "a", module_id=None)) == "caller_not_allowed", "a missing module id is refused by the caller check")

# ------------------------------------------------------------------------------------------------ 6. the browser views keep working through the private functions (path id)
reset()


def detail(method, module_id, name, data=None, user=ALICE):
    request = SimpleNamespace(user=user, data=data)
    view = views.ModulePreferenceDetailView()
    return getattr(view, method)(request, module_id=module_id, name=name) if method == "put" else view.delete(request, module_id=module_id, name=name)


def listing(module_id, user=ALICE):
    return views.ModulePreferenceListView().get(SimpleNamespace(user=user), module_id=module_id)


resp = detail("put", "remote-background", "header-collapsed", {"value": True})
must(resp.status_code == 200 and resp.data == {"module_id": "remote-background", "name": "header-collapsed", "value": True}, resp.data)
resp = listing("remote-background")
must(resp.status_code == 200 and resp.data == {"module_id": "remote-background", "preferences": {"header-collapsed": True}}, resp.data)
resp = detail("delete", "remote-background", "header-collapsed")
must(resp.status_code == 200 and resp.data["deleted"] is True, resp.data)
resp = detail("put", "remote-background", "Bad Name", {"value": 1})
must(resp.status_code == 400 and resp.data["code"] == "invalid_name", resp.data)
resp = detail("put", "remote-background", "x", {"value": 1, "extra": 2})
must(resp.status_code == 400 and resp.data["code"] == "invalid_value", resp.data)
resp = listing("remote-background", user=ANON)
must(resp.status_code == 401 and resp.data["code"] == "signed_in_required", resp.data)
resp = listing("core")
must(resp.status_code == 404 and resp.data["code"] == "module_not_found", resp.data)
for n in range(50):
    must(detail("put", "endpoints", f"n{n:02d}", {"value": n}).status_code == 200, f"name {n} of 50 is allowed")
resp = detail("put", "endpoints", "n50", {"value": 1})
must(resp.status_code == 400 and resp.data["code"] == "preference_limit", resp.data)
must(detail("put", "endpoints", "n00", {"value": "changed"}).status_code == 200, "an existing name at the limit can be changed")
must(views.ModulePreferenceDetailView.throttle_classes == [views.ModulePreferenceWriteMinThrottle], "the write throttle is unchanged")
must(views.ModulePreferenceWriteMinThrottle.__name__ == "ModulePreferenceWriteMinThrottle", "the throttle name is unchanged")
views_src = (APP / "module_preference_views.py").read_text(encoding="utf-8")
must("module_preferences._set(" in views_src and all(f"module_preferences.{n}(" not in views_src for n in ("set", "delete", "list_for", "get")),
     "the views call the private functions")

# ------------------------------------------------------------------------------------------------ 7. the capability: 1.1.0, requires >=1.17.37, the verified-caller note
must(mp.CAPABILITY_VERSION == "1.2.0", mp.CAPABILITY_VERSION)  # 1.1.0 is the 1.17.37 version this file was written for
meta = mp.module_preferences_contract_metadata()
must(meta["version"] == "1.2.0" and meta["requires_framework"] == ">=1.17.38", meta)
must(meta["operations"] == ["get", "set", "delete", "list_for"], "the operations are unchanged")
must("verified" in meta["caller"] and "caller_not_allowed" in meta["caller"] and "403" in meta["caller"], meta["caller"])
json.dumps(meta)
mp.register_core_module_preferences_capability()
reg = REGISTERED[-1]
must(reg["id"] == "core.module_preferences" and reg["version"] == "1.2.0" and reg["module_id"] == "core", reg)
must(reg["metadata"]["requires_framework"] == ">=1.17.38", "the registered metadata says 1.17.38")

# ------------------------------------------------------------------------------------------------ 8. contract rows, rule text and docs (read only)
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


rows = [r for r in literal("CORE_CONTRACTS") if r.get("area") == "module-preferences"]
must(sorted(r["name"] for r in rows) == ["delete", "get", "list_for", "set"], "the four Python rows")
for r in rows:
    purpose = r["purpose"]
    must("verified" in purpose and "caller_not_allowed" in purpose and "Requires framework >=1.17.38" in purpose, f"{r['name']}: {purpose[:80]}")
    must("module_id is a claim" not in purpose, f"{r['name']} no longer says the module id is a claim")
rule = next(r for r in literal("RULES") if "core.module_preferences 1.2.0" in r)
must(">=1.17.38" in rule and "verifies" in rule and "caller_not_allowed" in rule and "AD-26" in rule, "the rule names the verified caller")
doc = (ROOT / "docs" / "module-preferences.md").read_text(encoding="utf-8")
must("core.module_preferences 1.2.0" in doc and "caller_not_allowed" in doc and "AD-26" in doc, "the docs name the verified caller")
must("is a claim, with the same trust" not in doc and "does not check which module is calling" not in doc, "the docs drop the unchecked claim")
must("condition 4" in doc or "AD-26 condition 4" in doc, "the docs state the known limit")

print("[TEST] PASS module preferences caller 1.17.37")
