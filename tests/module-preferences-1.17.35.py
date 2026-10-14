#!/usr/bin/env python3
"""1.17.35: module user preferences (core.module_preferences 1.0.0), Django-free part.

Runs the real ``module_preferences.py`` and ``module_preference_views.py`` with narrow stubs: the notice module's enabled-extension check,
the model (a fake table with the lookups used), Django's transaction and user lock, and DRF's Response and APIView. Covered: name and value
validation (a bad name, a 4 KiB limit with the exact byte edge, depth 5 allowed and 6 refused, NaN, non-JSON, a null value); the
set-get-delete round trip and list_for sorted by name; an upsert keeps one row; self-only reads and writes (a second person never sees or
changes the first person's row); the module id refusals (core, tec-tac, an unknown and a disabled module) for every function; the 51st name
(preference_limit) and the update of an existing name at 50; the anonymous refusal (401); the HTTP views' answers and status codes; the
capability registration (id, version, module_id, operations, and the guarded call in apps.py); the migration 0031 and the model agree
(read with ast); the URLs and the throttle class exist; the contract rows and the rule text are present. The database part is
tests/module-preferences-runtime-1.17.35.py (dev server).
"""
from __future__ import annotations

import ast
import json
import math
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork/tec_tac"
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


# ------------------------------------------------------------------------------------------------ stubs
_stub("django")
_stub("django.contrib")
ATOMICS: list = []


class _Atomic:
    def __enter__(self):
        ATOMICS.append("enter")
        return self

    def __exit__(self, *args):
        ATOMICS.append("exit")
        return False


_stub("django.db", transaction=types.SimpleNamespace(atomic=lambda: _Atomic()))
LOCKS: list = []


class _UserQuery:
    def get(self, pk):
        LOCKS.append(pk)


class _UserManager:
    def select_for_update(self):
        return _UserQuery()


class _UserModel:
    objects = _UserManager()


_stub("django.contrib.auth", get_user_model=lambda: _UserModel)

# the notice module's check (the real one needs Django and the registry)
class NoticeError(ValueError):
    pass


INSTALLED = {"remote-background", "endpoints"}
DISABLED = {"globalsettings-off"}


def enabled_extension_id(module_id):
    name = str(module_id).strip() if isinstance(module_id, str) else ""
    if not name:
        raise NoticeError("module_id is required.")
    if name.lower() in {"core", "tec-tac"}:
        raise NoticeError("module_id may not be a Core source.")
    if name not in INSTALLED or name in DISABLED:
        raise NoticeError(f"module_id {name!r} is not an installed, enabled module.")
    return name


_stub("tec_tac.notices", NoticeError=NoticeError, enabled_extension_id=enabled_extension_id)


# the model: a fake table with the lookups module_preferences uses
class Row(types.SimpleNamespace):
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
        return Query(self, self.rows).filter(**kwargs)

    def update_or_create(self, user_id, module_id, name, defaults):
        for row in self.rows:
            if (row.user_id, row.module_id, row.name) == (user_id, module_id, name):
                row.value = defaults["value"]
                return row, False
        row = Row(user_id=user_id, module_id=module_id, name=name, value=defaults["value"])
        self.rows.append(row)
        return row, True


class TecTacModulePreference:
    objects = Manager()


_stub("tec_tac.models", TecTacModulePreference=TecTacModulePreference)

# the capability registry and the DRF pieces the views import
REGISTERED: list = []
_stub("tec_tac.capabilities", register_capability=lambda **kwargs: REGISTERED.append(kwargs) or "registered")
_stub("drf_spectacular")
_stub("drf_spectacular.utils", extend_schema=lambda **kwargs: (lambda fn: fn), extend_schema_view=lambda **kwargs: (lambda cls: cls))
_stub("rest_framework")


class Response:
    def __init__(self, data=None, status=None):
        self.data = data
        self.status_code = 200 if status is None else status


_stub("rest_framework.response", Response=Response)
_stub("rest_framework.views", APIView=type("APIView", (), {}))
_stub("tec_tac.session_security", SessionAuthenticated=type("SessionAuthenticated", (), {}))
_stub("tec_tac.throttles", ModulePreferenceWriteMinThrottle=type("ModulePreferenceWriteMinThrottle", (), {}))

from tec_tac import module_preference_views as views
from tec_tac import module_preferences as mp


class User:
    def __init__(self, pk, authenticated=True):
        self.pk = pk
        self.is_authenticated = authenticated


ALICE, BOB, ANON = User(1), User(2), User(3, authenticated=False)
MODULE = "remote-background"


def reset():
    TecTacModulePreference.objects.rows.clear()
    LOCKS.clear()


# ------------------------------------------------------------------------------------------------ 1. names
for good in ("a", "header-collapsed", "tabs.order_1", "9x", "a" * 64):
    must(mp._clean_name(good) == good, f"name {good!r} is allowed")
for bad in ("", "A", "Header", "-x", ".x", "a b", "a/b", "a" * 65, "é", None, 5, "a;"):
    try:
        mp._clean_name(bad)
    except mp.ModulePreferenceError as exc:
        must(exc.code == "invalid_name" and exc.status_code == 400, f"{bad!r}: {exc.code}")
    else:
        raise AssertionError(f"name {bad!r} is refused")

# ------------------------------------------------------------------------------------------------ 2. values
for good in (None, True, False, 0, -3, 1.5, "text", [], {}, [1, "a", None], {"a": [1, {"b": "c"}]}, [[[[[1]]]]], {"a": {"b": {"c": {"d": {"e": 1}}}}}):
    must(mp._clean_value(good) == good, f"value {good!r} is allowed")
for bad in ([[[[[[1]]]]]], {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}, math.nan, math.inf, {1, 2}, object(), b"bytes"):
    try:
        mp._clean_value(bad)
    except mp.ModulePreferenceError as exc:
        must(exc.code == "invalid_value", f"{bad!r}: {exc.code}")
    else:
        raise AssertionError(f"value {bad!r} is refused")
exact = "a" * (mp.MAX_VALUE_BYTES - 2)  # the JSON text of this string is exactly 4096 bytes
must(len(json.dumps(exact).encode("utf-8")) == mp.MAX_VALUE_BYTES and mp._clean_value(exact) == exact, "4 KiB exactly is allowed")
try:
    mp._clean_value(exact + "a")
except mp.ModulePreferenceError as exc:
    must(exc.code == "invalid_value", exc.code)
else:
    raise AssertionError("4 KiB plus one byte is refused")
must(mp.MAX_VALUE_DEPTH == 5 and mp.MAX_NAMES_PER_MODULE == 50 and mp.MAX_VALUE_BYTES == 4096, "the limits")

# ------------------------------------------------------------------------------------------------ 3. round trip, upsert and list
reset()
must(mp.get(ALICE, "header-collapsed", module_id=MODULE, default="none") == "none", "a missing name gives the default")
must(mp.set(ALICE, "header-collapsed", True, module_id=MODULE) is True, "set returns the stored value")
must(mp.get(ALICE, "header-collapsed", module_id=MODULE) is True, "get returns it")
mp.set(ALICE, "header-collapsed", False, module_id=MODULE)
must(len(TecTacModulePreference.objects.rows) == 1, "an upsert keeps one row")
must(mp.get(ALICE, "header-collapsed", module_id=MODULE) is False, "and the new value")
mp.set(ALICE, "tabs", {"order": ["a", "b"]}, module_id=MODULE)
mp.set(ALICE, "alpha", 1, module_id=MODULE)
must(mp.list_for(ALICE, module_id=MODULE) == {"alpha": 1, "header-collapsed": False, "tabs": {"order": ["a", "b"]}}, "list_for sorted by name")
must(mp.delete(ALICE, "tabs", module_id=MODULE) is True and mp.delete(ALICE, "tabs", module_id=MODULE) is False, "delete reports the row")
must("tabs" not in mp.list_for(ALICE, module_id=MODULE), "and it is gone")
must(ATOMICS.count("enter") == ATOMICS.count("exit") and len(LOCKS) >= 2, "writes run in a transaction with the person's row locked")

# ------------------------------------------------------------------------------------------------ 4. self only
reset()
mp.set(ALICE, "header-collapsed", True, module_id=MODULE)
must(mp.get(BOB, "header-collapsed", module_id=MODULE, default="fresh") == "fresh", "another person never sees the row")
must(mp.list_for(BOB, module_id=MODULE) == {}, "list_for shows only the signed-in person")
must(mp.delete(BOB, "header-collapsed", module_id=MODULE) is False, "another person cannot delete it")
must(mp.get(ALICE, "header-collapsed", module_id=MODULE) is True, "and it is still there")
mp.set(BOB, "header-collapsed", False, module_id=MODULE)
must(mp.get(ALICE, "header-collapsed", module_id=MODULE) is True and mp.get(BOB, "header-collapsed", module_id=MODULE) is False,
     "each person keeps their own value")
try:
    mp.get(ANON, "header-collapsed", module_id=MODULE)
except mp.ModulePreferenceError as exc:
    must(exc.code == "signed_in_required" and exc.status_code == 401, f"anonymous: {exc.code} {exc.status_code}")
else:
    raise AssertionError("an anonymous person is refused")

# ------------------------------------------------------------------------------------------------ 5. the module id
reset()
for module_id in ("core", "Core", "tec-tac", "unknown-module", "globalsettings-off", "", None):
    for call in (
        lambda m: mp.get(ALICE, "a", module_id=m),
        lambda m: mp.set(ALICE, "a", 1, module_id=m),
        lambda m: mp.delete(ALICE, "a", module_id=m),
        lambda m: mp.list_for(ALICE, module_id=m),
    ):
        try:
            call(module_id)
        except mp.ModulePreferenceError as exc:
            must(exc.code == "module_not_found" and exc.status_code == 404, f"{module_id!r}: {exc.code}")
        else:
            raise AssertionError(f"module {module_id!r} is refused")
must(not TecTacModulePreference.objects.rows, "a refused module writes nothing")

# ------------------------------------------------------------------------------------------------ 6. the 50 names limit
reset()
for n in range(mp.MAX_NAMES_PER_MODULE):
    mp.set(ALICE, f"n{n:02d}", n, module_id=MODULE)
must(len(mp.list_for(ALICE, module_id=MODULE)) == 50, "50 names are allowed")
mp.set(ALICE, "n00", "changed", module_id=MODULE)  # an existing name is not a new one
must(mp.get(ALICE, "n00", module_id=MODULE) == "changed", "an existing name at the limit can be changed")
try:
    mp.set(ALICE, "n50", 1, module_id=MODULE)
except mp.ModulePreferenceError as exc:
    must(exc.code == "preference_limit" and exc.status_code == 400, f"the 51st: {exc.code}")
else:
    raise AssertionError("the 51st name is refused")
must(len(mp.list_for(ALICE, module_id=MODULE)) == 50, "and nothing was written")
mp.set(BOB, "n50", 1, module_id=MODULE)  # the limit is per person and module
must(mp.get(BOB, "n50", module_id=MODULE) == 1, "another person has their own 50")
mp.set(ALICE, "n50", 1, module_id="endpoints")  # and per module
must(mp.get(ALICE, "n50", module_id="endpoints") == 1, "and another module has its own 50")

# ------------------------------------------------------------------------------------------------ 7. refusals write nothing
reset()
for name, value in (("Bad Name", 1), ("ok", math.nan), ("ok", "x" * 5000)):
    try:
        mp.set(ALICE, name, value, module_id=MODULE)
    except mp.ModulePreferenceError:
        pass
    else:
        raise AssertionError("a refused set is raised")
must(not TecTacModulePreference.objects.rows, "nothing is written when a set is refused")

# ------------------------------------------------------------------------------------------------ 8. the HTTP views
reset()
req = types.SimpleNamespace(user=ALICE, data={"value": True})
resp = views.ModulePreferenceDetailView().put(req, module_id=MODULE, name="header-collapsed")
must(resp.status_code == 200 and resp.data == {"module_id": MODULE, "name": "header-collapsed", "value": True}, resp.data)
resp = views.ModulePreferenceListView().get(types.SimpleNamespace(user=ALICE), module_id=MODULE)
must(resp.status_code == 200 and resp.data == {"module_id": MODULE, "preferences": {"header-collapsed": True}}, resp.data)
resp = views.ModulePreferenceDetailView().put(types.SimpleNamespace(user=ALICE, data={}), module_id=MODULE, name="x")
must(resp.status_code == 400 and resp.data["code"] == "invalid_value", resp.data)
resp = views.ModulePreferenceDetailView().put(types.SimpleNamespace(user=ALICE, data={"value": 1, "extra": 2}), module_id=MODULE, name="x")
must(resp.status_code == 400 and resp.data["code"] == "invalid_value", resp.data)
resp = views.ModulePreferenceDetailView().put(types.SimpleNamespace(user=ALICE, data=["value"]), module_id=MODULE, name="x")
must(resp.status_code == 400 and resp.data["code"] == "invalid_value", resp.data)
resp = views.ModulePreferenceDetailView().put(types.SimpleNamespace(user=ALICE, data={"value": 1}), module_id=MODULE, name="Bad Name")
must(resp.status_code == 400 and resp.data["code"] == "invalid_name", resp.data)
resp = views.ModulePreferenceListView().get(types.SimpleNamespace(user=ALICE), module_id="core")
must(resp.status_code == 404 and resp.data["code"] == "module_not_found", resp.data)
resp = views.ModulePreferenceDetailView().delete(types.SimpleNamespace(user=ALICE), module_id=MODULE, name="header-collapsed")
must(resp.status_code == 200 and resp.data == {"module_id": MODULE, "name": "header-collapsed", "deleted": True}, resp.data)
resp = views.ModulePreferenceDetailView().delete(types.SimpleNamespace(user=ALICE), module_id=MODULE, name="header-collapsed")
must(resp.data["deleted"] is False, resp.data)
resp = views.ModulePreferenceListView().get(types.SimpleNamespace(user=ANON), module_id=MODULE)
must(resp.status_code == 401 and resp.data["code"] == "signed_in_required", resp.data)
for n in range(mp.MAX_NAMES_PER_MODULE):
    mp.set(ALICE, f"v{n:02d}", n, module_id=MODULE)
resp = views.ModulePreferenceDetailView().put(types.SimpleNamespace(user=ALICE, data={"value": 1}), module_id=MODULE, name="v99")
must(resp.status_code == 400 and resp.data["code"] == "preference_limit", resp.data)

# ------------------------------------------------------------------------------------------------ 9. capability, apps.py, throttle, urls (source)
must(mp.CAPABILITY_ID == "core.module_preferences" and mp.CAPABILITY_VERSION == "1.0.0", "capability id and version")
mp.register_core_module_preferences_capability()
reg = REGISTERED[-1]
must(reg["id"] == "core.module_preferences" and reg["version"] == "1.0.0" and reg["module_id"] == "core", f"registered: {reg}")
must(tuple(reg["operations"]) == ("get", "set", "delete", "list_for"), "the four operations")
must(all(hasattr(reg["provider"], op) for op in ("get", "set", "delete", "list_for")), "the provider has the four operations")
must(reg["metadata"]["requires_framework"] == ">=1.17.35" and json.dumps(reg["metadata"]), "metadata is JSON and names 1.17.35")

apps_tree = ast.parse((APP / "apps.py").read_text(encoding="utf-8"))
ready = next(n for n in ast.walk(apps_tree) if isinstance(n, ast.FunctionDef) and n.name == "ready")
guarded = False
for node in ast.walk(ready):
    if isinstance(node, ast.Try):
        calls = [c for c in ast.walk(ast.Module(body=node.body, type_ignores=[])) if isinstance(c, ast.Call)
                 and getattr(c.func, "id", "") == "register_core_module_preferences_capability"]
        handled = any("core.module_preferences" in ast.unparse(h) and "logger.exception" in ast.unparse(h) for h in node.handlers)
        if calls and handled:
            guarded = True
must(guarded, "apps.ready() registers core.module_preferences inside a try whose handler logs and does not raise")

throttles_src = (APP / "throttles.py").read_text(encoding="utf-8")
must("class ModulePreferenceWriteMinThrottle(_WriteOnlyThrottle):" in throttles_src, "the write throttle class")
must('scope = "tec_tac_module_preference_write_min"' in throttles_src and 'rate = "120/min"' in throttles_src, "120 a minute")

urls_src = (APP / "urls.py").read_text(encoding="utf-8")
must('path("module-preferences/<str:module_id>/", ModulePreferenceListView.as_view()' in urls_src, "the list route")
must('path("module-preferences/<str:module_id>/<str:name>/", ModulePreferenceDetailView.as_view()' in urls_src, "the detail route")

# ------------------------------------------------------------------------------------------------ 10. migration and model agree (ast)
def class_fields(tree, class_name):
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    fields = []
    for stmt in node.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            fields.append(stmt.targets[0].id)
    return node, fields


def norm(source: str) -> str:
    """ast.unparse writes single quotes; compare with double quotes."""
    return source.replace("'", '"')


models_tree = ast.parse((APP / "models.py").read_text(encoding="utf-8"))
model_node, model_fields = class_fields(models_tree, "TecTacModulePreference")
must(model_fields == ["id", "user", "module_id", "name", "value", "updated_at"], f"model fields: {model_fields}")
model_src = norm(ast.unparse(model_node))
must('name="tectac_modpref_unique"' in model_src and '("user", "module_id", "name")' in model_src, "model constraint")
must('related_name="tec_tac_module_preferences"' in model_src, "model related name")

mig_tree = ast.parse((APP / "migrations/0031_module_preferences.py").read_text(encoding="utf-8"))
mig_src = norm(ast.unparse(mig_tree))
must('("tec_tac", "0030_notice_ledger")' in mig_src, "0031 depends on 0030")
must('name="TecTacModulePreference"' in mig_src and 'name="tectac_modpref_unique"' in mig_src, "0031 creates the model and the constraint")
mig_fields = [name for name in ("module_id", "name", "value", "updated_at", "user") if f'("{name}", models.' in mig_src]
must(sorted(mig_fields) == sorted(["module_id", "name", "value", "updated_at", "user"]), f"0031 fields: {mig_fields}")
must('related_name="tec_tac_module_preferences"' in mig_src, "0031 related name matches the model")
must('("user", "module_id", "name")' in mig_src, "0031 constraint fields match the model")
must(not list((APP / "migrations").glob("0032*")), "no later migration is claimed by this release")

# ------------------------------------------------------------------------------------------------ 11. contract rows and rule text (ast)
contracts_tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in contracts_tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


core_rows = [r for r in literal("CORE_CONTRACTS") if r.get("area") == "module-preferences"]
must(sorted(r["name"] for r in core_rows) == ["delete", "get", "list_for", "set"], "the four Python rows")
must(all("1.17.35" in r["purpose"] for r in core_rows), "each row names 1.17.35")
http = literal("HTTP_CONTRACT_DETAILS")
must("/api/tfd/module-preferences/<str:module_id>/" in http and "/api/tfd/module-preferences/<str:module_id>/<str:name>/" in http, "the HTTP rows")
must("PUT" in http["/api/tfd/module-preferences/<str:module_id>/<str:name>/"] and "DELETE" in http["/api/tfd/module-preferences/<str:module_id>/<str:name>/"],
     "PUT and DELETE are documented")
must(any("core.module_preferences 1.0.0" in rule and ">=1.17.35" in rule for rule in literal("RULES")), "the rule names the capability and the framework")
browser_src = (APP / "contracts.py").read_text(encoding="utf-8")
must("tec_tac.module_preferences" in browser_src and "docs/module-preferences.md" in browser_src, "the contract points at the docs")
must((ROOT / "docs/module-preferences.md").is_file(), "the docs page exists")

# the real render functions, exec'd from the same tree, carry the rows and the rule (as the browser-row tests do)
render_nodes = [n for n in contracts_tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
render_module = ast.Module(body=render_nodes, type_ignores=[])
ast.fix_missing_locations(render_module)
render_ns: dict = {}
exec(compile(render_module, str(APP / "contracts.py"), "exec"), render_ns)  # noqa: S102 - test-only: the real render functions
catalog = {
    "framework_version": "1.17.35", "generated_at": "2026-10-14T00:00:00+00:00", "rules": list(literal("RULES")),
    "core": [dict(r, signature="()") for r in literal("CORE_CONTRACTS")], "browser": [], "resource_directory": {}, "capabilities": [],
    "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": [],
}
rendered_md = render_ns["render_markdown"](catalog)
rendered_text = render_ns["render_text"](catalog)
for needle in ("tec_tac.module_preferences", "list_for", "/api/tfd/module-preferences/", "core.module_preferences 1.0.0"):
    must(needle in rendered_md and needle in rendered_text, f"the rendered export carries {needle!r}")

print("[TEST] PASS module preferences 1.17.35")
