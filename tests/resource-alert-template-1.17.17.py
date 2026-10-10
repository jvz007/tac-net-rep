#!/usr/bin/env python3
"""1.17.17 regression: alert_template_id on client and site records (core.resources 1.3.0 -> 1.4.0), Johan's answer (a) of 9 October.

Core holds only the id. The real resources.py, resources_adapter.py and resource_views.py run here against an in-memory Tactical
(Client and Site stand-ins that behave like Django models: a copy is loaded, only the ``update_fields`` named in ``save`` are written,
a foreign key to a missing alert template fails ``full_clean``, and Tactical's own ``cache_agents_alert_template`` hook is recorded).
Django, Tactical and the real ForeignKey are dev-server only: tests/resource-alert-template-runtime-1.17.17.py.
The shared harness ends at the marker line; tests/resource-scope-descriptor-1.17.17.py reuses it.
"""
from __future__ import annotations

import contextlib
import importlib.util
import pathlib
import sys
import types

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


# ------------------------------------------------------------------------------------------------ django, drf and tec_tac stubs
class ValidationError(Exception):
    def __init__(self, message, fields=None):
        super().__init__(message)
        if fields:
            self.error_dict = fields
            self.message_dict = dict(fields)


class IntegrityError(Exception):
    pass


class _Transaction:
    @staticmethod
    def atomic():
        return contextlib.nullcontext()


class Q:
    def __init__(self, *args, **kwargs):
        pass

    def __or__(self, other):
        return self


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


class APIView:
    pass


class _Spec:
    def __call__(self, *a, **k):
        return lambda obj: obj


mod("django")
mod("django.core")
mod("django.core.exceptions", ValidationError=ValidationError)
mod("django.db", IntegrityError=IntegrityError, transaction=_Transaction())
mod("django.db.models", Q=Q)
mod("drf_spectacular")
mod("drf_spectacular.utils", extend_schema=_Spec())
mod("rest_framework")
mod("rest_framework.response", Response=Response)
mod("rest_framework.views", APIView=APIView)
pkg = mod("tec_tac")
pkg.__path__ = [str(PKG)]
CAPS = []
mod("tec_tac.capabilities", register_capability=lambda **kw: CAPS.append(kw) or kw)
mod("tec_tac.rbac", has_extension_permission=lambda user, code: code in getattr(user, "core_permissions", set()))
mod("tec_tac.session_security", SessionAuthenticated=object)
AUDITS = []
mod("tec_tac.audit", record=lambda **kw: AUDITS.append(kw) or {"recorded": True}, AuditContractError=ValueError, AuditWriteError=RuntimeError)


# ------------------------------------------------------------------------------------------------ an in-memory Tactical
TEMPLATES = {5, 6}   # the alert templates that exist (Alerts owns them; Core never lists them)
HOOKS = []           # Tactical's own cache_agents_alert_template, called from Client.save and Site.save when the template changed


class Relation:
    def __init__(self, ids=(), *, boom=False):
        self.ids, self.boom = list(ids), boom

    def _check(self):
        if self.boom:
            raise RuntimeError("relation lookup failed")

    def exists(self):
        self._check()
        return bool(self.ids)

    def all(self):
        self._check()
        return [types.SimpleNamespace(pk=i) for i in self.ids]

    def filter(self, pk=None, pk__in=None):
        self._check()
        ids = [i for i in self.ids if (pk is None or i == pk) and (pk__in is None or i in set(pk__in))]
        return Relation(ids)

    def values_list(self, *fields, flat=False):
        self._check()
        return list(self.ids)

    def add(self, obj):
        if obj.pk not in self.ids:
            self.ids.append(obj.pk)


class Rows(list):
    def first(self):
        return self[0] if self else None


class Role:
    def __init__(self, *, clients=(), sites=(), superuser=False, list_perms=True, manage=True, boom=False):
        self.can_view_clients = Relation(clients, boom=boom)
        self.can_view_sites = Relation(sites, boom=boom)
        self.is_superuser = superuser
        self.can_list_clients = self.can_list_sites = self.can_list_agents = list_perms
        self.can_manage_clients = self.can_manage_sites = manage


class User:
    is_authenticated = True

    def __init__(self, role, *, superuser=False, installer=False, core=("core.resources.clients.manage", "core.resources.sites.manage"), name="operator"):
        self.role, self.is_superuser, self.is_installer_user, self.username = role, superuser, installer, name
        self.core_permissions = set(core)

    def get_and_set_role_cache(self):
        return self.role


def visible_clients(role):
    if role is None:
        return set()  # Tactical's filter_by_role: no role sees nothing
    if role.is_superuser or not (role.can_view_clients.ids or role.can_view_sites.ids):
        return None
    return set(role.can_view_clients.ids) | {s["client_id"] for s in Site.STORE.values() if s["pk"] in role.can_view_sites.ids}


def visible_sites(role):
    if role is None:
        return set()
    if role.is_superuser or not (role.can_view_clients.ids or role.can_view_sites.ids):
        return None
    return set(role.can_view_sites.ids) | {s["pk"] for s in Site.STORE.values() if s["client_id"] in role.can_view_clients.ids}


class Query:
    def __init__(self, model, rows):
        self.model, self.rows = model, list(rows)

    def all(self):
        return Query(self.model, self.rows)

    def filter(self, **kw):
        rows = self.rows
        for key, val in kw.items():
            if key == "pk":
                rows = [r for r in rows if r["pk"] == val]
            elif key == "pk__in":
                rows = [r for r in rows if r["pk"] in set(val)]
            elif key == "client_id":
                rows = [r for r in rows if r["client_id"] == val]
            else:
                raise NotImplementedError(key)
        return Query(self.model, rows)

    def filter_by_role(self, user):
        role = user.get_and_set_role_cache()
        if self.model is Agent:
            allowed = visible_sites(role)
            return Query(self.model, [r for r in self.rows if allowed is None or r["site_id"] in allowed])
        allowed = (visible_clients if self.model is Client else visible_sites)(role)
        return Query(self.model, [r for r in self.rows if allowed is None or r["pk"] in allowed])

    def order_by(self, *fields):
        return Query(self.model, sorted(self.rows, key=lambda r: tuple(r.get(f, r["pk"]) if f != "pk" else r["pk"] for f in fields)))

    def select_for_update(self):
        return self

    def first(self):
        return self.model.from_row(self.rows[0]) if self.rows else None

    def exists(self):
        return bool(self.rows)

    def count(self):
        return len(self.rows)

    def values(self, *fields):
        return Rows({f: r[f] for f in fields} for r in self.rows)

    def values_list(self, *fields, flat=False):
        return [r[fields[0]] for r in self.rows] if flat else [tuple(r[f] for f in fields) for r in self.rows]


class _Manager:
    def __init__(self, model):
        self.model = model

    def all(self):
        return Query(self.model, self.model.STORE.values())

    def filter(self, **kw):
        return self.all().filter(**kw)

    def select_for_update(self):
        return self.all()


class _Model:
    FIELD_OF = {}

    @classmethod
    def from_row(cls, row):
        obj = cls.__new__(cls)
        obj.__dict__.update(row)
        obj.modified_by = obj.modified_time = None
        obj.last_update_fields = None
        return obj

    def _persist(self, fields):
        row = self.STORE.setdefault(self.pk, {})
        for field in fields:
            attr = self.FIELD_OF.get(field)
            if attr:  # modified_by and modified_time are Tactical bookkeeping, not part of the record
                row[attr] = getattr(self, attr)
        return row


class Client(_Model):
    STORE: dict = {}
    FIELD_OF = {"name": "name", "alert_template": "alert_template_id"}
    objects = _Manager(None)

    def __init__(self, name):
        self.pk, self.name, self.alert_template_id = None, name, None
        self.modified_by = self.modified_time = self.last_update_fields = None

    def full_clean(self, **kw):
        if self.alert_template_id is not None and self.alert_template_id not in TEMPLATES:
            raise ValidationError("bad template", {"alert_template": ["alert template instance does not exist."]})

    def save(self, update_fields=None):
        self.last_update_fields = update_fields
        if self.pk is None:
            if any(r["name"].lower() == self.name.lower() for r in self.STORE.values()):
                raise IntegrityError("duplicate")
            self.pk = max(self.STORE, default=0) + 1
            self.STORE[self.pk] = {"pk": self.pk, "name": self.name, "alert_template_id": self.alert_template_id}
            return
        old = self.STORE[self.pk]["alert_template_id"]
        self._persist(update_fields if update_fields is not None else self.FIELD_OF)
        if old != self.STORE[self.pk]["alert_template_id"]:
            HOOKS.append(("client", self.pk))


class Site(_Model):
    STORE: dict = {}
    FIELD_OF = {"name": "name", "client": "client_id", "alert_template": "alert_template_id"}
    objects = _Manager(None)

    def __init__(self, client=None, client_id=None, name=""):
        self.pk, self.name, self.alert_template_id = None, name, None
        self.client_id = client.pk if client is not None else client_id
        self.modified_by = self.modified_time = self.last_update_fields = None

    def full_clean(self, **kw):
        if self.alert_template_id is not None and self.alert_template_id not in TEMPLATES:
            raise ValidationError("bad template", {"alert_template": ["alert template instance does not exist."]})

    def save(self, update_fields=None):
        self.last_update_fields = update_fields
        if self.pk is None:
            self.pk = max(self.STORE, default=0) + 1
            self.STORE[self.pk] = {"pk": self.pk, "name": self.name, "client_id": self.client_id, "alert_template_id": self.alert_template_id}
            return
        old = self.STORE[self.pk]["alert_template_id"]
        self._persist(update_fields if update_fields is not None else self.FIELD_OF)
        if old != self.STORE[self.pk]["alert_template_id"]:
            HOOKS.append(("site", self.pk))

    def delete(self):
        self.STORE.pop(self.pk, None)


class Agent:
    STORE: dict = {}
    objects = _Manager(None)


Client.objects, Site.objects, Agent.objects = _Manager(Client), _Manager(Site), _Manager(Agent)


def reset_tactical():
    Client.STORE.clear(), Site.STORE.clear(), Agent.STORE.clear(), HOOKS.clear(), AUDITS.clear()
    Client.STORE.update({1: {"pk": 1, "name": "Alpha", "alert_template_id": None}, 2: {"pk": 2, "name": "Beta", "alert_template_id": None}})
    Site.STORE.update({
        11: {"pk": 11, "name": "Alpha One", "client_id": 1, "alert_template_id": None},
        12: {"pk": 12, "name": "Alpha Two", "client_id": 1, "alert_template_id": None},
        21: {"pk": 21, "name": "Beta One", "client_id": 2, "alert_template_id": None},
    })
    Agent.STORE.update({"a-1": {"pk": 1, "agent_id": "a-1", "site_id": 11}})


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, PKG / file)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


adapter = _load("tec_tac.resources_adapter", "resources_adapter.py")
adapter._models = lambda: (Client, Site, Agent)
resources = _load("tec_tac.resources", "resources.py")
views = _load("tec_tac.resource_views", "resource_views.py")


def ctx_for(user):
    return resources.user_context(user)


CORE = ("core.resources.clients.manage", "core.resources.sites.manage")
# ---- harness end (tests/resource-scope-descriptor-1.17.17.py reads up to this line)

reset_tactical()
whole_client = User(Role(clients=[1]))                       # may see and write client 1 and its sites
site_only = User(Role(sites=[11]))                           # one site of client 1, no whole client
mixed = User(Role(clients=[2], sites=[11]))
admin = User(Role())                                         # no relations: unrestricted
root = User(Role(superuser=True), superuser=True)
ctx_whole, ctx_site, ctx_admin = ctx_for(whole_client), ctx_for(site_only), ctx_for(admin)


def refused(call, *errors):
    try:
        call()
    except errors as exc:
        return exc
    raise AssertionError(f"call was accepted: {call}")


# ------------------------------------------------------------------------------------------------ the contract shape
must(resources.CONTRACT_VERSION == "1.4.0" and resources.CLIENT_FIELDS == ("type", "id", "name", "active", "alert_template_id"), resources.CLIENT_FIELDS)
must(resources.SITE_FIELDS == ("type", "id", "name", "client_id", "active", "alert_template_id"), resources.SITE_FIELDS)
must(resources.AGENT_FIELDS[-1] == "last_seen", "agent records are unchanged")
listed = resources.list_clients(context=ctx_admin)["items"]
must([tuple(row) for row in listed] == [resources.CLIENT_FIELDS] * 2 and [r["alert_template_id"] for r in listed] == [None, None], listed)
must(tuple(resources.get_client(1, context=ctx_admin)) == resources.CLIENT_FIELDS, "get_client")
must(all(tuple(row) == resources.SITE_FIELDS for row in resources.list_sites(context=ctx_admin)["items"]), "list_sites")
must(tuple(resources.get_site(11, context=ctx_admin)) == resources.SITE_FIELDS, "get_site")
must(tuple(resources.resolve_resource("client", 2, context=ctx_admin)) == resources.CLIENT_FIELDS, "resolve_resource")
# the old keys keep their place; the new one is last
must(list(listed[0])[:4] == ["type", "id", "name", "active"], listed[0])

# ------------------------------------------------------------------------------------------------ client: set, change, clear
before = len(AUDITS)
row = resources.update_client(1, alert_template_id=5, context=ctx_whole)
must(row["alert_template_id"] == 5 and row["name"] == "Alpha" and tuple(row) == resources.CLIENT_FIELDS, row)
must(Client.STORE[1]["alert_template_id"] == 5, "persisted: update_fields named the field")
must(HOOKS == [("client", 1)], "Tactical's own save hook ran, so the agents' cached template is refreshed")
must(resources.get_client(1, context=ctx_whole)["alert_template_id"] == 5, "a read sees it")
# the audit row: before and after carry the field, and the change flag
audit = AUDITS[-1]
must(len(AUDITS) == before + 1 and audit["action"] == "modify" and audit["object_type"] == "resource_client" and audit["object_id"] == "1" and audit["strict"] is True, audit)
must(audit["before"]["alert_template_id"] is None and audit["after"]["alert_template_id"] == 5, audit)
must(audit["metadata"] == {"alert_template_changed": True}, audit["metadata"])
# a name-only update leaves the template alone (and says it did not change it)
row = resources.update_client(1, name="Alpha Renamed", context=ctx_whole)
must(row["name"] == "Alpha Renamed" and row["alert_template_id"] == 5 and Client.STORE[1]["alert_template_id"] == 5, row)
must(AUDITS[-1]["metadata"] == {"alert_template_changed": False}, AUDITS[-1]["metadata"])
# existing call style: name positionally as a keyword only, exactly as before
must(resources.update_client(1, name="Alpha", context=ctx_whole)["name"] == "Alpha", "name-only keyword call")
# change to another template, with the name as well
row = resources.update_client(1, name="Alpha Two", alert_template_id=6, context=ctx_whole)
must(row["name"] == "Alpha Two" and row["alert_template_id"] == 6 and AUDITS[-1]["metadata"]["alert_template_changed"] is True, row)
resources.update_client(1, name="Alpha", context=ctx_whole)
# the same value again is not a change
del HOOKS[:]
resources.update_client(1, alert_template_id=6, context=ctx_whole)
must(AUDITS[-1]["metadata"] == {"alert_template_changed": False} and not HOOKS, (AUDITS[-1]["metadata"], HOOKS))
# None clears; leaving the keyword out is not None
row = resources.update_client(1, alert_template_id=None, context=ctx_whole)
must(row["alert_template_id"] is None and Client.STORE[1]["alert_template_id"] is None and AUDITS[-1]["metadata"]["alert_template_changed"] is True, row)
resources.update_client(1, alert_template_id=5, context=ctx_whole)
resources.update_client(1, name="Alpha", context=ctx_whole)
must(Client.STORE[1]["alert_template_id"] == 5, "omitting the keyword never clears the template")
must(resources.UNSET is not None and repr(resources.UNSET) == "UNSET", "the sentinel is not None")
resources.update_client(1, alert_template_id=resources.UNSET, name="Alpha", context=ctx_whole)
must(Client.STORE[1]["alert_template_id"] == 5, "passing the sentinel is the same as leaving it out")
# a digit string is accepted and stored as an integer
must(resources.update_client(1, alert_template_id=" 6 ", context=ctx_whole)["alert_template_id"] == 6, "digits as text")

# ------------------------------------------------------------------------------------------------ validation
for call in (lambda: resources.update_client(1, context=ctx_whole), lambda: resources.update_site(11, context=ctx_admin)):
    exc = refused(call, resources.ResourceValidationError)
    must("At least one" in str(exc), exc)
for bad in (True, False, 0, -1, "abc", "5.5", "", " ", "-3", 1.5, 5.0, [], {}, 2**63, "١٢"):
    refused(lambda bad=bad: resources.update_client(1, alert_template_id=bad, context=ctx_whole), resources.ResourceValidationError)
    refused(lambda bad=bad: resources.update_site(11, alert_template_id=bad, context=ctx_admin), resources.ResourceValidationError)
must(Client.STORE[1]["alert_template_id"] == 6 and Site.STORE[11]["alert_template_id"] is None, "refused values change nothing")
refused(lambda: resources.update_client(1, name="", context=ctx_whole), resources.ResourceValidationError)
# a template that does not exist: Tactical's foreign key decides; nothing is stored, no audit row
del AUDITS[:], HOOKS[:]
for target, call in (("client", lambda: resources.update_client(1, alert_template_id=99, context=ctx_whole)),
                     ("site", lambda: resources.update_site(11, alert_template_id=99, context=ctx_admin))):
    exc = refused(call, resources.ResourceValidationError)
    must("alert template" in str(exc) and exc.code == "invalid_resource_request", (target, str(exc)))
must(Client.STORE[1]["alert_template_id"] == 6 and Site.STORE[11]["alert_template_id"] is None and not AUDITS and not HOOKS, "a missing template writes nothing")

# ------------------------------------------------------------------------------------------------ site: set, change, clear, move
del AUDITS[:], HOOKS[:]
row = resources.update_site(11, alert_template_id=5, context=ctx_whole)
must(row["alert_template_id"] == 5 and tuple(row) == resources.SITE_FIELDS and row["client_id"] == 1 and Site.STORE[11]["alert_template_id"] == 5, row)
must(HOOKS == [("site", 11)] and AUDITS[-1]["object_type"] == "resource_site" and AUDITS[-1]["metadata"] == {"alert_template_changed": True}, (HOOKS, AUDITS[-1]))
must(AUDITS[-1]["before"]["alert_template_id"] is None and AUDITS[-1]["after"]["alert_template_id"] == 5, AUDITS[-1])
row = resources.update_site(11, name="Alpha One B", client_id=1, alert_template_id=6, context=ctx_whole)
must(row["name"] == "Alpha One B" and row["alert_template_id"] == 6, row)
row = resources.update_site(11, name="Alpha One", context=ctx_whole)
must(row["alert_template_id"] == 6 and AUDITS[-1]["metadata"] == {"alert_template_changed": False}, "a rename keeps the template")
row = resources.update_site(11, alert_template_id=None, context=ctx_whole)
must(row["alert_template_id"] is None and Site.STORE[11]["alert_template_id"] is None, row)
# a site move keeps the template it had
resources.update_site(12, alert_template_id=5, context=ctx_whole)
moved = resources.update_site(12, client_id=1, name="Alpha Two", context=ctx_whole)
must(moved["alert_template_id"] == 5, "a rename or move keeps the template")

# ------------------------------------------------------------------------------------------------ who may change it
# a role limited to one site: may change that site's template (a site grant), but not its client's (not a whole-client grant)
row = resources.update_site(11, alert_template_id=6, context=ctx_site)
must(row["alert_template_id"] == 6, row)
exc = refused(lambda: resources.update_client(1, alert_template_id=5, context=ctx_site), resources.ResourceNotFound)
must(Client.STORE[1]["alert_template_id"] == 6, "the client was not changed")  # still 6 from above
refused(lambda: resources.update_site(12, alert_template_id=5, context=ctx_site), resources.ResourceNotFound)  # a site it does not hold
must(Site.STORE[12]["alert_template_id"] == 5, "unchanged")
# a whole-client role can change its client and its sites
must(resources.update_client(1, alert_template_id=5, context=ctx_whole)["alert_template_id"] == 5, "whole client")
# a mixed role holds client 2 as a whole and site 11 only
must(resources.update_client(2, alert_template_id=6, context=ctx_for(mixed))["alert_template_id"] == 6, "mixed: its whole client")
refused(lambda: resources.update_client(1, alert_template_id=6, context=ctx_for(mixed)), resources.ResourceNotFound)
# Tactical can_manage_* and the Core permission are both required; can_manage_alerts is not
no_manage = User(Role(manage=False))
refused(lambda: resources.update_client(1, alert_template_id=5, context=ctx_for(no_manage)), resources.ResourcePermissionDenied)
refused(lambda: resources.update_site(11, alert_template_id=5, context=ctx_for(no_manage)), resources.ResourcePermissionDenied)
no_core = User(Role(), core=())
refused(lambda: resources.update_client(1, alert_template_id=5, context=ctx_for(no_core)), resources.ResourcePermissionDenied)
refused(lambda: resources.update_site(11, alert_template_id=5, context=ctx_for(no_core)), resources.ResourcePermissionDenied)
no_role = User(None)
refused(lambda: resources.update_client(1, alert_template_id=5, context=ctx_for(no_role)), resources.ResourcePermissionDenied)
must(not hasattr(Role(), "can_manage_alerts"), "the test role has no can_manage_alerts and still succeeded above")
# a superuser passes; a trusted service context stays read-only
must(resources.update_client(2, alert_template_id=None, context=ctx_for(root))["alert_template_id"] is None, "superuser")
service = resources.ResourceAccessContext(service_actor="governance", service_purpose="test", trusted_global=True)
refused(lambda: resources.update_client(1, alert_template_id=5, context=service), resources.ResourcePermissionDenied)
refused(lambda: resources.update_site(11, alert_template_id=5, context=service), resources.ResourcePermissionDenied)
# the template id is readable by anyone who can list clients, with no extra permission
reader = User(Role(clients=[1], manage=False), core=())
must(resources.get_client(1, context=ctx_for(reader))["alert_template_id"] == Client.STORE[1]["alert_template_id"], "readable")

# ------------------------------------------------------------------------------------------------ create does not take it
reset_tactical()
created = resources.create_client(name="Gamma", context=ctx_admin)
must(tuple(created) == resources.CLIENT_FIELDS and created["alert_template_id"] is None, created)
default_site = next(s for s in Site.STORE.values() if s["client_id"] == created["id"])
must(default_site["alert_template_id"] is None, default_site)
new_site = resources.create_site(client_id=1, name="Alpha Three", context=ctx_admin)
must(tuple(new_site) == resources.SITE_FIELDS and new_site["alert_template_id"] is None, new_site)
refused(lambda: resources.create_client(name="Delta", alert_template_id=5, context=ctx_admin), TypeError)
refused(lambda: resources.create_site(client_id=1, name="Alpha Four", alert_template_id=5, context=ctx_admin), TypeError)
# a restricted creator is still granted its new client
creator = User(Role(clients=[1]))
made = resources.create_client(name="Epsilon", context=ctx_for(creator))
must(made["id"] in creator.role.can_view_clients.ids, "creator scope")

# ------------------------------------------------------------------------------------------------ the adapter paths, directly
reset_tactical()
must(adapter.client_row({"pk": 3, "name": "X"})["alert_template_id"] is None, "a row without the key reads as None")
must(adapter.client_row({"pk": 3, "name": "X", "alert_template_id": "7"})["alert_template_id"] == 7, "integer")
must(list(adapter.site_row({"pk": 3, "name": "X", "client_id": 1, "alert_template_id": 7}))[-1] == "alert_template_id", "site key order")
page, total = adapter.page_clients(adapter.clients_queryset(user=admin, trusted=False), offset=0, limit=10)
must(total == 2 and all("alert_template_id" in r for r in page), page)
page, total = adapter.page_sites(adapter.sites_queryset(user=admin, trusted=False), offset=0, limit=10)
must(total == 3 and all("alert_template_id" in r for r in page), page)
# the update fields Core hands Tactical's save: only what changed, plus Tactical's own bookkeeping
client_obj = []
orig_first = Query.first
Query.first = lambda self: (lambda o: (client_obj.append(o), o)[1] if o is not None else None)(orig_first(self))
adapter.update_client_row(user=admin, client_id=1, alert_template_id=5)
must(set(client_obj[-1].last_update_fields) == {"alert_template", "modified_by", "modified_time"}, client_obj[-1].last_update_fields)
adapter.update_client_row(user=admin, client_id=1, name="Alpha")
must(set(client_obj[-1].last_update_fields) == {"name", "modified_by", "modified_time"}, "name only: as before 1.17.17")
adapter.update_client_row(user=admin, client_id=1, name="Alpha", alert_template_id=None)
must(set(client_obj[-1].last_update_fields) == {"name", "alert_template", "modified_by", "modified_time"}, client_obj[-1].last_update_fields)
Query.first = orig_first
must(adapter.update_client_row(user=admin, client_id=99, alert_template_id=5) is None, "a missing client reads as not found")

# ------------------------------------------------------------------------------------------------ HTTP
reset_tactical()


class Req:
    def __init__(self, user, data):
        self.user, self.data, self.query_params = user, data, {}


def patch(kind, rid, data, user=admin):
    view = views.ResourceMutableDetailView()
    view.resource_type = kind
    return view.patch(Req(user, data), rid)


r = patch("client", 1, {"alert_template_id": 5})
must(r.status_code == 200 and r.data["alert_template_id"] == 5 and Client.STORE[1]["alert_template_id"] == 5, r.__dict__)
r = patch("client", 1, {"alert_template_id": None})
must(r.status_code == 200 and r.data["alert_template_id"] is None and Client.STORE[1]["alert_template_id"] is None, r.__dict__)
r = patch("client", 1, {"name": "Alpha B", "alert_template_id": 6})
must(r.status_code == 200 and r.data["name"] == "Alpha B" and r.data["alert_template_id"] == 6, r.__dict__)
r = patch("client", 1, {"name": "Alpha"})
must(r.status_code == 200 and r.data["alert_template_id"] == 6, "a name-only PATCH leaves the template: " + str(r.data))
for body, code in (({}, 400), ({"colour": "red"}, 400), ({"name": None}, 400), ({"alert_template_id": "x"}, 400), ({"alert_template_id": True}, 400),
                   ({"alert_template_id": 99}, 400), ({"name": "Alpha", "bogus": 1}, 400), ([1], 400)):
    r = patch("client", 1, body)
    must(r.status_code == code and r.data["code"] == "invalid_resource_request", (body, r.__dict__))
r = patch("client", 99, {"alert_template_id": 5})
must(r.status_code == 404, r.__dict__)
r = patch("client", 1, {"alert_template_id": 5}, user=site_only)
must(r.status_code == 404, "a site-only role cannot change a client's template: " + str(r.__dict__))
r = patch("client", 1, {"alert_template_id": 5}, user=no_manage)
must(r.status_code == 403, r.__dict__)
r = patch("site", 11, {"alert_template_id": 5})
must(r.status_code == 200 and r.data["alert_template_id"] == 5 and r.data["client_id"] == 1, r.__dict__)
r = patch("site", 11, {"alert_template_id": None})
must(r.status_code == 200 and r.data["alert_template_id"] is None, r.__dict__)
r = patch("site", 11, {"name": "Alpha One", "client_id": 1, "alert_template_id": 6})
must(r.status_code == 200 and r.data["alert_template_id"] == 6, r.__dict__)
for body in ({}, {"colour": "red"}, {"alert_template_id": 0}, {"alert_template_id": 99}):
    r = patch("site", 11, body)
    must(r.status_code == 400, (body, r.__dict__))
r = patch("site", 11, {"alert_template_id": 5}, user=site_only)
must(r.status_code == 200, "a site grant may set that site's template")
r = patch("site", 12, {"alert_template_id": 5}, user=site_only)
must(r.status_code == 404, "but not another site's")

# ------------------------------------------------------------------------------------------------ the capability and the contract text
meta = resources.resource_contract_metadata()
must(meta["version"] == "1.4.0" and meta["version"].split(".")[0] == "1", meta["version"])
must(meta["resource_types"]["client"]["fields"] == list(resources.CLIENT_FIELDS) and meta["resource_types"]["site"]["fields"] == list(resources.SITE_FIELDS), "fields")
must(meta["write_support"]["client"] == ["create", "update", "delete", "custom_fields"], "the earlier write_support lists are unchanged")
must(meta["write_support"]["update_fields"] == {"client": ["name", "alert_template_id"], "site": ["name", "client_id", "alert_template_id"]}, meta["write_support"])
for key in ("update_client", "update_site", "scope_descriptor"):
    must(key in meta["mutation_contracts"] and "1.4.0" in meta["mutation_contracts"][key]["semantics"], key)
must("alert_template_id" in meta["mutation_contracts"]["update_client"]["body"], meta["mutation_contracts"]["update_client"])
must("PATCH /api/tfd/resources/clients/<id>/" == meta["mutation_contracts"]["update_client"]["http"], "http row")
must("delete_client" in meta["mutation_contracts"] and "client_custom_fields" in meta["mutation_contracts"], "the earlier entries stay")
registration = resources.register_core_resources_capability()
must(registration["version"] == "1.4.0" and registration["module_id"] == "core", registration["version"])
for op in ("update_client", "update_site", "scope_descriptor", "scope_unrestricted", "has_whole_client_access", "user_context"):
    must(op in registration["operations"] and callable(getattr(registration["provider"], op)), op)
must(registration["operations"][:15] == ("list_clients", "get_client", "create_client", "update_client", "delete_client", "list_sites", "get_site", "create_site",
                                         "update_site", "delete_site", "list_custom_fields", "update_custom_fields", "list_agents", "get_agent", "resolve_resource"),
     "the earlier operations keep their order")
contracts = (PKG / "contracts.py").read_text(encoding="utf-8")
for needle in ("alert_template_id", "framework >=1.17.17", "alert_template_changed"):
    must(needle in contracts, needle)
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("Contract version: `1.4.0`" in doc and "alert_template_id" in doc and "UNSET" in doc, "docs/resource-directory.md")

print("[TEST] PASS resource alert template 1.17.17")
