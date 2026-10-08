#!/usr/bin/env python3
"""1.17.4 regression: the reporting row-scope hook (scoped_report_manager, model_row_scope, report_scope_ids).

The decision logic is a pure function and the Django glue is thin, so this runs without Django. The real reporting.py
and resources_adapter.py are loaded against stubs: a django.db.models with a Manager, a queryset and a Q that record the
filter they build, and fake user, role, site and model objects. tests/reporting-row-scope-runtime-1.17.4.py builds a
real scoped queryset on the dev server (it needs manage.py shell and cannot run here).
"""
from __future__ import annotations

import ast
import importlib.util
import logging
import sys
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


# ------------------------------------------------------------------ django stubs that record what is built
class FieldDoesNotExist(Exception):
    pass


class Q:
    """Records the condition. An empty Q is the identity for | and &, as in Django."""

    def __init__(self, **kw):
        self.node = ("leaf", dict(kw)) if kw else None

    @staticmethod
    def _join(op, left, right):
        if left.node is None:
            return right
        if right.node is None:
            return left
        out = Q()
        out.node = (op, [left.node, right.node])
        return out

    def __or__(self, other):
        return Q._join("or", self, other)

    def __and__(self, other):
        return Q._join("and", self, other)


class FakeQuerySet:
    def __init__(self, none=False, condition=None):
        self.is_none, self.condition = none, condition

    def none(self):
        return FakeQuerySet(none=True)

    def filter(self, condition):
        return FakeQuerySet(condition=condition.node)


class Manager:
    def __init__(self):
        pass

    def get_queryset(self):
        return FakeQuerySet()


def flat(node):
    """The leaves of a recorded condition as {lookup: value}, and its operators."""
    if node is None:
        return None
    if node[0] == "leaf":
        return node[1]
    return (node[0], [flat(child) for child in node[1]])


mods = {}


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    mods[name] = m
    return m


MODELS = {}


class FakeApps:
    @staticmethod
    def get_model(app_label=None, model_name=None):
        try:
            return MODELS[(app_label, model_name.lower())]
        except KeyError:
            raise LookupError(model_name) from None


db_models = mod("django.db.models", Manager=Manager, Q=Q)
mod("django")
mod("django.apps", apps=FakeApps)
mod("django.db", models=db_models, IntegrityError=type("IntegrityError", (Exception,), {}), transaction=SimpleNamespace())
mod("django.core")
mod("django.core.exceptions", FieldDoesNotExist=FieldDoesNotExist, ValidationError=type("ValidationError", (Exception,), {}))
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
sys.modules.update(mods)


def load(name):
    spec = importlib.util.spec_from_file_location(f"tec_tac.{name}", APP / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


adapter = load("resources_adapter")
rep = load("reporting")


# ------------------------------------------------------------------ fake Tactical users, roles and sites
class Rel:
    def __init__(self, ids):
        self.ids = list(ids)

    def exists(self):
        return bool(self.ids)

    def values_list(self, *fields, flat=False):
        return list(self.ids)

    def all(self):
        return self


class Role:
    def __init__(self, clients=(), sites=(), superuser=False):
        self.can_view_clients, self.can_view_sites, self.is_superuser = Rel(clients), Rel(sites), superuser


class User:
    def __init__(self, role=None, superuser=False):
        self.role, self.is_superuser = role, superuser

    def get_and_set_role_cache(self):
        return self.role


SITES = {1: 10, 2: 10, 3: 20, 4: 30}  # site id -> client id


class SiteQS:
    def filter_by_role(self, user):
        """Tactical's PermissionQuerySet rule for Site: granted sites plus the sites of granted clients."""
        role = user.role
        clients, sites = set(role.can_view_clients.ids), set(role.can_view_sites.ids)
        return SiteRows([pk for pk, client in SITES.items() if client in clients or pk in sites])


class SiteRows:
    def __init__(self, ids):
        self.ids = ids

    def values_list(self, *fields, flat=False):
        return list(self.ids)


adapter._models = lambda: (None, SimpleNamespace(objects=SimpleNamespace(all=SiteQS)), None)

# ------------------------------------------------------------------ report_scope_ids
UNRESTRICTED = {"unrestricted": True, "client_ids": frozenset(), "site_ids": frozenset()}
must(adapter.report_scope_ids(User(superuser=True)) == UNRESTRICTED, "superuser")
must(adapter.report_scope_ids(User(Role(superuser=True))) == UNRESTRICTED, "role-level superuser")
must(adapter.report_scope_ids(User(Role())) == UNRESTRICTED, "a role with no grants has full scope")
none = adapter.report_scope_ids(User(None))
must(none["unrestricted"] is False and not none["client_ids"] and not none["site_ids"] and none.get("denied") is True, f"no role sees none: {none}")
must(adapter.report_scope_ids(None)["unrestricted"] is False, "no user sees none")
client_only = adapter.report_scope_ids(User(Role(clients=[10])))
must(client_only == {"unrestricted": False, "client_ids": frozenset({10}), "site_ids": frozenset({1, 2})}, client_only)
site_only = adapter.report_scope_ids(User(Role(sites=[3])))
must(site_only == {"unrestricted": False, "client_ids": frozenset(), "site_ids": frozenset({3})}, site_only)
both = adapter.report_scope_ids(User(Role(clients=[10], sites=[3])))
must(both == {"unrestricted": False, "client_ids": frozenset({10}), "site_ids": frozenset({1, 2, 3})}, both)
must(isinstance(client_only["client_ids"], frozenset) and isinstance(client_only["site_ids"], frozenset), "ids are frozensets")

# ------------------------------------------------------------------ the spec builder (pure)
spec = rep.scope_filter_spec
must(spec(UNRESTRICTED, client_path="client_id", site_path=None)["mode"] == "all", "unrestricted sees all")
must(spec(UNRESTRICTED, client_path=None, site_path=None)["mode"] == "all", "unrestricted with no paths still sees all")
must(spec(client_only, client_path="client_id", site_path="site_id") ==
     {"mode": "filter", "clauses": [("client_id", [10]), ("site_id", [1, 2])], "unassigned": []}, "client grant: client path OR expanded sites")
must(spec(site_only, client_path="client_id", site_path="site_id") ==
     {"mode": "filter", "clauses": [("site_id", [3])], "unassigned": []}, "site-only grant: site path only")
must(spec(both, client_path="client_id", site_path="site_id")["clauses"] == [("client_id", [10]), ("site_id", [1, 2, 3])], "both grants (OR)")
must(spec(client_only, client_path=None, site_path="site_id")["clauses"] == [("site_id", [1, 2])], "a site mapping expands a client grant")
must(spec(site_only, client_path="client_id", site_path=None)["mode"] == "none", "a client mapping is not widened by a site-only grant")
must(spec(site_only, client_path="client_id", site_path=None, include_unassigned=False)["clauses"] == [], "no client clause for a site-only grant")
must(spec(client_only, client_path=None, site_path=None)["mode"] == "none", "a model with neither path gives none (fail closed)")
must(spec(client_only, client_path=None, site_path=None, include_unassigned=True)["mode"] == "none", "include_unassigned cannot rescue a model with no path")
# null-scoped rows
hidden = spec(client_only, client_path="client_id", site_path="site_id", include_unassigned=False)
shown = spec(client_only, client_path="client_id", site_path="site_id", include_unassigned=True)
must(hidden["unassigned"] == [] and shown["unassigned"] == ["client_id", "site_id"], (hidden, shown))
must(spec(site_only, client_path="client_id", site_path=None, include_unassigned=True) ==
     {"mode": "filter", "clauses": [], "unassigned": ["client_id"]}, "only the unassigned rows when no grant maps to the declared paths")
must(spec({"unrestricted": False, "client_ids": frozenset(), "site_ids": frozenset()}, client_path="client_id", site_path="site_id")["mode"] == "none", "empty grants see none")
# no role is denied even with include_unassigned
must(spec(none, client_path="client_id", site_path="site_id", include_unassigned=True)["mode"] == "none", "no role sees none, unassigned rows included")

# ------------------------------------------------------------------ path pattern
for good in ("client_id", "site_id", "agent__site__client_id", "site__client_id", "client", None):
    must(rep.scoped_report_manager(client=good) is not None, good)
for bad in ("", "  ", "__class__", "a__class__", "client__", "__client", "client___id", "1client", "client id", "client;drop", "a.b", "client-id",
            "_client", "client_", "x" * 201, 5, ["client_id"], b"client_id", "client_id\n__x"):
    try:
        rep.scoped_report_manager(client=bad)
    except rep.ReportingRegistrationError:
        pass
    else:
        raise AssertionError(f"path {bad!r} must be refused")
    try:
        rep.scoped_report_manager(site=bad)
    except rep.ReportingRegistrationError:
        pass
    else:
        raise AssertionError(f"site path {bad!r} must be refused")
for bad_flag in (1, "yes", None):
    try:
        rep.scoped_report_manager(client="client_id", include_unassigned=bad_flag)
    except rep.ReportingRegistrationError:
        pass
    else:
        raise AssertionError(f"include_unassigned {bad_flag!r} must be refused")

# ------------------------------------------------------------------ the manager (Django glue)
manager = rep.scoped_report_manager(client="client_id", site="site_id")
must(callable(manager.filter_by_role) and manager._tec_tac_scoped_report_manager is True, "manager marker")
must(isinstance(manager, Manager) and (manager.client_field, manager.site_field, manager.include_unassigned) == ("client_id", "site_id", False), "manager state")
must(rep.scoped_report_manager(client="client_id") is not rep.scoped_report_manager(client="client_id"), "each call returns its own manager")
must(type(rep.scoped_report_manager(client="a")) is type(rep.scoped_report_manager(client="b")), "one manager class")
qs = manager.filter_by_role(User(Role(clients=[10])))
must(flat(qs.condition) == ("or", [{"client_id__in": [10]}, {"site_id__in": [1, 2]}]), flat(qs.condition))
qs = manager.filter_by_role(User(Role(clients=[10], sites=[3])))
must(flat(qs.condition) == ("or", [{"client_id__in": [10]}, {"site_id__in": [1, 2, 3]}]), flat(qs.condition))
qs = manager.filter_by_role(User(Role(sites=[3])))
must(flat(qs.condition) == {"site_id__in": [3]}, flat(qs.condition))
qs = rep.scoped_report_manager(client="client_id", site="site_id", include_unassigned=True).filter_by_role(User(Role(sites=[3])))
must(flat(qs.condition) == ("or", [{"site_id__in": [3]}, ("and", [{"client_id__isnull": True}, {"site_id__isnull": True}])]), flat(qs.condition))
qs = manager.filter_by_role(User(superuser=True))
must(qs.is_none is False and qs.condition is None, "a superuser's queryset is unfiltered")
qs = manager.filter_by_role(User(Role()))
must(qs.is_none is False and qs.condition is None, "a role with no grants is unfiltered")
must(manager.filter_by_role(User(None)).is_none is True, "no role: no rows")
must(manager.filter_by_role(None).is_none is True, "no user: no rows")
must(rep.scoped_report_manager().filter_by_role(User(Role(clients=[10]))).is_none is True, "no paths: none for a scoped user")
must(rep.scoped_report_manager().filter_by_role(User(superuser=True)).is_none is False, "no paths: a superuser still sees all")
# Tactical treats a raised filter_by_role as unscoped, so the hook must fail closed instead of raising
real = adapter.report_scope_ids


def boom(user):
    raise RuntimeError("database down")


adapter.report_scope_ids = boom
must(manager.filter_by_role(User(Role(clients=[10]))).is_none is True, "a failure returns no rows and does not raise")
adapter.report_scope_ids = real


# ------------------------------------------------------------------ model_row_scope
def field(name, *, related=None, concrete=True):
    return SimpleNamespace(name=name, related_model=related, concrete=concrete)


def make_model(name, fields, objects):
    table = {f.name: f for f in fields}

    def get_field(item):
        if item not in table:
            raise FieldDoesNotExist(item)
        return table[item]

    return type(name, (), {"objects": objects, "_meta": SimpleNamespace(get_field=get_field, get_fields=lambda: fields)})


class PlainManager(Manager):
    pass


class OwnScopeManager(Manager):
    def filter_by_role(self, user):
        return self.get_queryset()


class Overridden(type(rep.scoped_report_manager(client="client_id"))):
    def filter_by_role(self, user):
        return self.get_queryset()


Site = make_model("Site", [field("id"), field("client_id")], PlainManager())
Agent = make_model("Agent", [field("id"), field("site", related=Site)], PlainManager())
base = [field("id"), field("client_id"), field("site_id"), field("agent", related=Agent), field("reverse", concrete=False)]
MODELS.update({
    ("tec_tac_x", "plain"): make_model("Plain", base, PlainManager()),
    ("tec_tac_x", "own"): make_model("Own", base, OwnScopeManager()),
    ("tec_tac_x", "good"): make_model("Good", base, rep.scoped_report_manager(client="client_id", site="site_id", include_unassigned=True)),
    ("tec_tac_x", "deep"): make_model("Deep", base, rep.scoped_report_manager(client="agent__site__client_id")),
    ("tec_tac_x", "subclassed"): make_model("Subclassed", base, Overridden(client_field="client_id")),
    ("tec_tac_x", "badpath"): make_model("BadPath", base, rep.scoped_report_manager(client="nosuch_id", site="site_id")),
    ("tec_tac_x", "reverse"): make_model("Reverse", base, rep.scoped_report_manager(client="reverse")),
    ("tec_tac_x", "throughreverse"): make_model("ThroughReverse", base, rep.scoped_report_manager(client="reverse__client_id")),
    ("tec_tac_x", "nopaths"): make_model("NoPaths", base, rep.scoped_report_manager()),
    ("tec_tac_x", "noobjects"): type("NoObjects", (), {"_meta": SimpleNamespace(get_field=lambda n: None)}),
})
NOT = {"enforced": False, "source": None, "client_field": None, "site_field": None, "include_unassigned": False}
scope = rep.model_row_scope
must(scope("tec_tac_x", "Plain") == NOT, "a plain manager is not scoped")
must(scope("tec_tac_x", "Own") == {**NOT, "source": "model"}, "a manager with its own filter_by_role is not vouched for")
must(scope("tec_tac_x", "Good") == {"enforced": True, "source": "core", "client_field": "client_id", "site_field": "site_id", "include_unassigned": True}, scope("tec_tac_x", "Good"))
must(scope("tec_tac_x", "Deep")["enforced"] is True and scope("tec_tac_x", "Deep")["site_field"] is None, "a path through a relation resolves")
must(scope("tec_tac_x", "Subclassed")["enforced"] is False and scope("tec_tac_x", "Subclassed")["source"] == "model", "a subclass that replaces filter_by_role is not Core's")
bad = scope("tec_tac_x", "BadPath")
must(bad["enforced"] is False and bad["source"] == "core" and bad["client_field"] == "nosuch_id", bad)
must(scope("tec_tac_x", "Reverse")["enforced"] is False and scope("tec_tac_x", "ThroughReverse")["enforced"] is False, "a reverse relation is not a scope column")
must(scope("tec_tac_x", "NoPaths")["enforced"] is False and scope("tec_tac_x", "NoPaths")["source"] == "core", "no declared path is not enforced")
must(scope("tec_tac_x", "NoObjects") == NOT and scope("tec_tac_x", "Missing") == NOT and scope("nope", "x") == NOT, "an unknown model or no manager")

# ------------------------------------------------------------------ status rows and the bridge status carry it
rep._provider_status = lambda module_id: {"installed": True, "enabled": True, "version": "1.0.0", "state": "available"}
rep._clear_reporting_registry_for_tests()
for public_id, model_name in (("x.good", "Good"), ("x.plain", "Plain"), ("x.own", "Own")):
    registration = rep.ReportingModelRegistration(id=public_id, module_id="x", app_label="tec_tac_x", model=model_name)
    rep._REGISTRY[public_id] = registration
rows = {row["id"]: row for row in rep.list_reporting_models()}
must(rows["x.good"]["row_scope"]["enforced"] is True and rows["x.plain"]["row_scope"]["enforced"] is False, rows)
must(rows["x.own"]["row_scope"]["source"] == "model", rows["x.own"])
status = rep.reporting_bridge_status()
must(status["row_scope_enforced"] is True, "the documented signal Report Manager reads")
must(status["row_scope_models"] == {"enforced": ["x.good"], "unscoped": ["x.own", "x.plain"]}, status["row_scope_models"])
must(rows["x.plain"]["available"] is True, "a model that does not adopt the manager stays registered (no behaviour change)")

# ------------------------------------------------------------------ contract and docs
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
contracts = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
named = {row["name"]: row["purpose"] for row in contracts if row["area"] == "reporting"}
must("filter_by_role" in named["scoped_report_manager"] and "include_unassigned" in named["scoped_report_manager"], "scoped_report_manager contract")
must("no signed-in user" in named["scoped_report_manager"] and "hidden_fields" in named["scoped_report_manager"], "the limits are in the contract")
must("row_scope" in named["model_row_scope"] and "enforced" in named["model_row_scope"], "model_row_scope contract")
must("row_scope_enforced" in named["reporting_bridge_status"] and "not that every registered model is scoped" in named["reporting_bridge_status"], "signal wording")
docs = (ROOT / "docs" / "module-reporting.md").read_text(encoding="utf-8")
for word in ("scoped_report_manager", "model_row_scope", "row_scope_enforced", "include_unassigned", "no signed-in user", "report_scope_ids"):
    must(word in docs, f"docs/module-reporting.md mentions {word}")
print("reporting row scope 1.17.4: ok")
