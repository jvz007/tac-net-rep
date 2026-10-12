#!/usr/bin/env python3
"""1.17.22 regression: Core audits changes to a role's client and site lists (can_view_clients, can_view_sites).

Tactical's /accounts/roles/ routes already read and save both lists as id lists, and PUT replaces both. Core's account guard passes
every list through untouched. What was missing is an audit row: Tactical's own audit compares a serialisation at save time and the
serializer sets many-to-many fields afterwards, so a change that only touches the two lists wrote no row. The guard now writes one
strict Core row inside its transaction, only when a list changed, ids only, capped at 1000. A failed audit write rolls the save back.

The real tactical_account_guard.py runs here against stubs; the real view, Django and the database are dev server only
(tests/role-scope-lists-runtime-1.17.22.py).
"""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "tactical_account_guard.py"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


class ObjectDoesNotExist(Exception):
    pass


class PermissionDenied(Exception):
    pass


class ValidationError(Exception):
    pass


class BooleanField:
    def run_validation(self, value):
        return bool(value)


class Relation:
    def __init__(self, ids=()):
        self.ids = list(ids)

    def values_list(self, *fields, flat=False):
        return list(self.ids)


class Role:
    ROWS: dict = {}

    class DoesNotExist(ObjectDoesNotExist):
        pass

    def __init__(self, pk, name, clients=(), sites=(), is_superuser=False):
        self.pk = self.id = pk
        self.name, self.is_superuser = name, is_superuser
        self.can_view_clients, self.can_view_sites = Relation(clients), Relation(sites)


class _Q:
    def __init__(self, rows):
        self.rows = list(rows)

    def only(self, *a):
        return self

    def select_for_update(self):
        return self

    def filter(self, pk=None, pk__gt=None, name=None):
        rows = [r for r in self.rows if (pk is None or r.pk == int(pk)) and (pk__gt is None or r.pk > pk__gt) and (name is None or r.name == name)]
        return _Q(rows)

    def order_by(self, field):
        return _Q(sorted(self.rows, key=lambda r: r.pk, reverse=field.startswith("-")))

    def values_list(self, *fields, flat=False):
        return _Q([types.SimpleNamespace(pk=r.pk, v=r.pk) for r in self.rows])

    def first(self):
        if not self.rows:
            return None
        first = self.rows[0]
        return getattr(first, "v", first) if isinstance(first, types.SimpleNamespace) else first


class _Manager:
    def only(self, *a):
        return _Q(Role.ROWS.values())

    def select_for_update(self):
        return _Q(Role.ROWS.values())

    def filter(self, **kw):
        return _Q(Role.ROWS.values()).filter(**kw)

    def order_by(self, field):
        return _Q(Role.ROWS.values()).order_by(field)


Role.objects = _Manager()


class User:
    objects = types.SimpleNamespace()


class APIKey:
    objects = types.SimpleNamespace()


@contextlib.contextmanager
def atomic():
    snapshot = {pk: (list(r.can_view_clients.ids), list(r.can_view_sites.ids)) for pk, r in Role.ROWS.items()}
    keys = set(Role.ROWS)
    try:
        yield
    except BaseException:
        for pk in list(Role.ROWS):
            if pk not in keys:
                del Role.ROWS[pk]
        for pk, (clients, sites) in snapshot.items():
            Role.ROWS[pk].can_view_clients.ids, Role.ROWS[pk].can_view_sites.ids = clients, sites
        raise


class _Transaction:
    atomic = staticmethod(atomic)

    @staticmethod
    def get_connection():
        return types.SimpleNamespace(in_atomic_block=False)

    @staticmethod
    def on_commit(cb):
        cb()


def stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


stub("django")
stub("django.core")
stub("django.core.exceptions", ObjectDoesNotExist=ObjectDoesNotExist)
stub("django.db", transaction=_Transaction)
stub("rest_framework")
stub("rest_framework.exceptions", PermissionDenied=PermissionDenied, ValidationError=ValidationError)
stub("rest_framework.fields", BooleanField=BooleanField)
stub("accounts")
stub("accounts.models", Role=Role, User=User, APIKey=APIKey)
pkg = stub("tec_tac")
pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
stub("tec_tac.rbac", is_effective_superuser=lambda actor: bool(getattr(actor, "effective_superuser", False)))
stub("tec_tac.account_security_policy", protection_enabled=lambda **kw: False)
AUDITS = []
FAIL = {"on": False}


def record(**kw):
    if FAIL["on"]:
        raise RuntimeError("audit store down")
    AUDITS.append(kw)
    return {"recorded": True}


stub("tec_tac.audit", record=record)
spec = importlib.util.spec_from_file_location("tec_tac.tactical_account_guard", MODULE)
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


class Response:
    def __init__(self, data, status_code=200):
        self.data, self.status_code = data, status_code


class Actor:
    effective_superuser = False
    is_superuser = False
    is_authenticated = True
    username = "role.manager"


class Request:
    def __init__(self, data):
        self.data, self.user = data, Actor()


def reset():
    Role.ROWS.clear()
    Role.ROWS.update({10: Role(10, "Helpdesk", clients=[1, 2], sites=[5]), 11: Role(11, "Open")})
    AUDITS.clear()
    FAIL["on"] = False


# Tactical's PUT: a full replace of both lists, answered with text.
def tactical_put(self, request, pk):
    role = Role.ROWS[int(pk)]
    if "can_view_clients" in request.data:
        role.can_view_clients.ids = list(request.data["can_view_clients"])
    if "can_view_sites" in request.data:
        role.can_view_sites.ids = list(request.data["can_view_sites"])
    if request.data.get("fail"):
        return Response("bad", status_code=400)
    return Response("Role was edited")


created_names = []


def tactical_post(self, request):
    pk = max(Role.ROWS) + 1
    Role.ROWS[pk] = Role(pk, request.data["name"], clients=request.data.get("can_view_clients", []), sites=request.data.get("can_view_sites", []))
    return Response("Role was added")


put = guard._wrap_role_update(tactical_put)
post = guard._wrap_role_create(tactical_post)

# 1. a PUT carrying both lists reaches the original handler untouched (the guard does not rewrite the payload)
reset()
payload = {"name": "Helpdesk", "is_superuser": False, "can_view_clients": [3], "can_view_sites": [5, 6]}
before_payload = copy.deepcopy(payload)
resp = put(None, Request(payload), 10)
must(resp.data == "Role was edited" and payload == before_payload, "payload untouched")
must(Role.ROWS[10].can_view_clients.ids == [3] and Role.ROWS[10].can_view_sites.ids == [5, 6], "both lists saved by the original")

# 2. a change writes one strict row: module core, object_type role_scope, ids and counts only
must(len(AUDITS) == 1, AUDITS)
row = AUDITS[0]
must(row["module_id"] == "core" and row["object_type"] == "role_scope" and row["object_id"] == "10" and row["action"] == "modify" and row["strict"] is True, row)
must(row["before"]["clients"] == {"ids": [1, 2], "count": 2, "truncated": False}, row["before"])
must(row["after"]["clients"] == {"ids": [3], "count": 1, "truncated": False}, row["after"])
must(row["after"]["sites"] == {"ids": [5, 6], "count": 2, "truncated": False}, row["after"])
must("Helpdesk" not in repr(row), "names never reach the row")

# 3. no change, no row (the same lists sent back, in another order)
reset()
put(None, Request({"name": "Helpdesk", "can_view_clients": [2, 1], "can_view_sites": [5]}), 10)
must(AUDITS == [], AUDITS)
# a PUT that does not name the lists leaves them and writes nothing
put(None, Request({"name": "Helpdesk"}), 10)
must(AUDITS == [], AUDITS)

# 4. clearing both lists (a role becoming unrestricted) is audited too
reset()
put(None, Request({"can_view_clients": [], "can_view_sites": []}), 10)
must(len(AUDITS) == 1 and AUDITS[0]["after"]["clients"]["count"] == 0 and AUDITS[0]["after"]["sites"]["count"] == 0, AUDITS)

# 5. the id lists are capped at 1000 with the true count and a truncated flag
reset()
big = list(range(1, 1501))
put(None, Request({"can_view_clients": big, "can_view_sites": []}), 11)
after = AUDITS[0]["after"]["clients"]
must(len(after["ids"]) == 1000 and after["count"] == 1500 and after["truncated"] is True and after["ids"][-1] == 1000, after)
must(AUDITS[0]["before"]["clients"]["count"] == 0, AUDITS[0]["before"])

# 6. a failing audit write aborts the save
reset()
FAIL["on"] = True
try:
    put(None, Request({"can_view_clients": [9], "can_view_sites": []}), 10)
except RuntimeError as exc:
    must("persisted Core audit record" in str(exc), str(exc))
else:
    raise AssertionError("the save was accepted without an audit row")
must(Role.ROWS[10].can_view_clients.ids == [1, 2] and Role.ROWS[10].can_view_sites.ids == [5], "the role save was rolled back")

# 7. a refused save (a 4xx answer) writes no row
reset()
put(None, Request({"can_view_clients": [9], "fail": True}), 10)
must(AUDITS == [], AUDITS)

# 8. role create writes an 'add' row for a new role that carries lists, and none for an unrestricted new role
reset()
resp = post(None, Request({"name": "Branch", "can_view_clients": [4], "can_view_sites": []}))
must(resp.data == "Role was added" and len(AUDITS) == 1, AUDITS)
must(AUDITS[0]["action"] == "add" and AUDITS[0]["object_type"] == "role_scope" and AUDITS[0]["object_id"] == "12", AUDITS[0])
must(AUDITS[0]["before"]["clients"]["count"] == 0 and AUDITS[0]["after"]["clients"]["ids"] == [4], AUDITS[0])
AUDITS.clear()
post(None, Request({"name": "Everything"}))
must(AUDITS == [], "an unrestricted new role changes nothing to audit")
# a failing audit write rolls the new role back
FAIL["on"] = True
try:
    post(None, Request({"name": "Doomed", "can_view_sites": [1]}))
except RuntimeError:
    pass
else:
    raise AssertionError("role create accepted without an audit row")
must(not any(r.name == "Doomed" for r in Role.ROWS.values()), "the new role was rolled back")

# 9. the superuser guard is unchanged: a non-superuser still cannot mint a superuser role
reset()
try:
    post(None, Request({"name": "Root", "is_superuser": True}))
except PermissionDenied:
    pass
else:
    raise AssertionError("non-superuser created a superuser role")

# 10. source checks: the guard still passes the lists through, writes strictly and ids only
source = MODULE.read_text(encoding="utf-8")
must('strict=True' in source and '"role_scope"' in source and "ROLE_SCOPE_AUDIT_CAP = 1000" in source, "guard source")
must("can_view_clients" in source and "can_view_sites" in source, "guard source names both lists")
meta_source = (ROOT / "framwork" / "tec_tac" / "resources.py").read_text(encoding="utf-8")
must('"role_scope_lists"' in meta_source, "metadata key role_scope_lists")
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("Role client and site lists" in doc and "role_scope" in doc, "docs/resource-directory.md")
policy = (ROOT / "docs" / "account-security-policy.md").read_text(encoding="utf-8")
must("role_scope" in policy, "docs/account-security-policy.md")

print("[TEST] PASS role scope lists 1.17.22")
