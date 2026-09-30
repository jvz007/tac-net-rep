#!/usr/bin/env python3
"""Regression for Core 1.17.0: the saved views service (board Q19, Q25, Q43, Q44, Q45).

Runs the real tec_tac.saved_views, saved_view_views, audit, registry and contracts code. Only the
Django/DRF boundary is faked: an in-memory TecTacSavedView model with a transaction that really rolls
back, a user model, the Tactical AuditLog, and DRF/session/throttle classes. The release-test container
does not ship Django or DRF.
"""
from __future__ import annotations

import ast
import copy
import datetime
import importlib
import json
import sys
import types
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"

pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(PKG)]
sys.modules["tec_tac"] = pkg

# --- Django boundary: in-memory model, rollback-capable transaction, users -----------------------
STORE: dict = {}
CLOCK = [0]


class IntegrityError(Exception):
    pass


class _Atomic:
    def __enter__(self):
        self.snapshot = {
            key: (obj, {k: (copy.deepcopy(v) if k in ("payload", "readers") else v) for k, v in obj.__dict__.items()})
            for key, obj in STORE.items()
        }
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            STORE.clear()
            for key, (obj, state) in self.snapshot.items():
                obj.__dict__.clear()
                obj.__dict__.update(state)
                STORE[key] = obj
        return False


django = types.ModuleType("django")
django_db = types.ModuleType("django.db")
django_db.transaction = types.SimpleNamespace(atomic=lambda: _Atomic())
django_db.IntegrityError = IntegrityError
django_contrib = types.ModuleType("django.contrib")
django_auth = types.ModuleType("django.contrib.auth")


class User:
    is_authenticated = True

    def __init__(self, pk, username, *, superuser=False, active=True):
        self.pk = pk
        self.id = pk
        self.username = username
        self.is_superuser = superuser
        self.is_active = active
        self.role = types.SimpleNamespace(is_superuser=False)

    def get_and_set_role_cache(self):
        return self.role


alice, bob, carol = User(1, "alice"), User(2, "bob"), User(3, "carol")
dave = User(4, "dave", active=False)
root = User(9, "root", superuser=True)
USERS = {user.pk: user for user in (alice, bob, carol, dave, root)}


class Anonymous:
    is_authenticated = False
    pk = None


class _UserQS:
    def __init__(self, rows):
        self.rows = rows

    def values_list(self, field, flat=False):
        return [getattr(row, field) for row in self.rows]


class _UserManager:
    def filter(self, pk__in=(), is_active=True):
        return _UserQS([u for u in USERS.values() if u.pk in set(pk__in) and u.is_active == is_active])


django_auth.get_user_model = lambda: types.SimpleNamespace(objects=_UserManager())
sys.modules.update({"django": django, "django.db": django_db, "django.contrib": django_contrib, "django.contrib.auth": django_auth})


class SavedViewRow:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def save(self, update_fields=None):
        CLOCK[0] += 1
        self.updated_at = CLOCK[0]
        STORE[str(self.id)] = self

    def delete(self):
        STORE.pop(str(self.id), None)


class QS:
    def __init__(self, rows):
        self.rows = list(rows)

    def filter(self, **kwargs):
        rows = self.rows
        for key, value in kwargs.items():
            if key == "pk":
                rows = [r for r in rows if str(r.id) == str(value)]
            else:
                rows = [r for r in rows if getattr(r, key) == value]
        return QS(rows)

    def select_related(self, *args):
        return self

    def order_by(self, *fields):
        return QS(sorted(self.rows, key=lambda r: (r.name, str(r.id))))

    def first(self):
        return self.rows[0] if self.rows else None

    def count(self):
        return len(self.rows)

    def __iter__(self):
        return iter(self.rows)


class Manager:
    force_integrity = False

    def filter(self, **kwargs):
        return QS(STORE.values()).filter(**kwargs)

    def select_related(self, *args):
        return QS(STORE.values())

    def create(self, *, owner, module_id, view_key, name, payload, readers):
        if self.force_integrity or any(
            r.owner_id == owner.pk and (r.module_id, r.view_key, r.name) == (module_id, view_key, name) for r in STORE.values()
        ):
            raise IntegrityError("unique")
        CLOCK[0] += 1
        row = SavedViewRow(
            id=uuid.uuid4(), owner=owner, owner_id=owner.pk, module_id=module_id, view_key=view_key, name=name,
            payload=payload, readers=readers, created_at=CLOCK[0], updated_at=CLOCK[0],
        )
        STORE[str(row.id)] = row
        return row


MANAGER = Manager()
SavedViewRow.objects = MANAGER
models_stub = types.ModuleType("tec_tac.models")
models_stub.TecTacSavedView = SavedViewRow
sys.modules["tec_tac.models"] = models_stub

# --- Tec-Tac / Tactical boundary ---------------------------------------------------------------
capabilities = types.ModuleType("tec_tac.capabilities")
capabilities.register_capability = lambda **kwargs: kwargs
capabilities.list_capabilities = lambda check_health=False: []
sys.modules["tec_tac.capabilities"] = capabilities

ENABLED = {"demo-disabled": False}
module_state = types.ModuleType("tec_tac.module_state")
module_state.load_state = lambda: {}
module_state.is_enabled = lambda module_id, state: ENABLED.get(module_id, True)
sys.modules["tec_tac.module_state"] = module_state

GRANTS: dict = {}
rbac_stub = types.ModuleType("tec_tac.rbac")
rbac_stub.effective_permissions = lambda actor: set(GRANTS.get(actor.pk, ()))
sys.modules["tec_tac.rbac"] = rbac_stub

rf = types.ModuleType("rest_framework")
rf_response = types.ModuleType("rest_framework.response")
rf_views = types.ModuleType("rest_framework.views")


class Response:
    def __init__(self, data=None, status=200):
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
fake_throttles.SavedViewWriteMinThrottle = MinThrottle
fake_throttles.SavedViewWriteDayThrottle = DayThrottle
sys.modules["tec_tac.throttles"] = fake_throttles

from tec_tac import audit, registry, saved_views  # noqa: E402

views = importlib.import_module("tec_tac.saved_view_views")


class FakeRow:
    pk = 1


class AuditManager:
    def __init__(self):
        self.rows = []
        self.fail = False

    def create(self, **kwargs):
        if self.fail:
            raise RuntimeError("audit db down")
        self.rows.append(kwargs)
        return FakeRow()


class FakeAuditLog:
    objects = AuditManager()


audit._auditlog_model = lambda: FakeAuditLog
AUDIT = FakeAuditLog.objects.rows


def spec(plugin_id, **kwargs):
    return registry.PluginSpec(plugin_id=plugin_id, plugin_type=kwargs.pop("plugin_type", "extension"), root=ROOT, version="1.0.0", **kwargs)


OPEN = spec("demo-open")
LOCKED = spec("demo-locked", permission_groups=(("Use", ("demo-locked.use",)),))
DISABLED = spec("demo-disabled")
LEGACY = spec("demo-legacy", plugin_type="legacy", legacy=True)
PLUGINS = [OPEN, LOCKED, DISABLED, LEGACY]
registry.get_plugins = lambda: tuple(PLUGINS)


class Request:
    def __init__(self, user, data=None, query=None):
        self.user = user
        self.data = data
        self.query_params = query or {}


LIST = views.SavedViewListCreateView()
DETAIL = views.SavedViewDetailView()


def reset():
    STORE.clear()
    del AUDIT[:]
    GRANTS.clear()
    FakeAuditLog.objects.fail = False
    MANAGER.force_integrity = False


def make(user, name="Mine", *, module="demo-open", key="endpoints", payload=None, readers=None, expect=201):
    body = {"module_id": module, "view_key": key, "name": name, "payload": {"filter": "x"} if payload is None else payload}
    if readers is not None:
        body["readers"] = readers
    response = LIST.post(Request(user, body))
    assert response.status_code == expect, (name, response.status_code, response.data)
    return response.data


def listing(user, module="demo-open", key=None):
    query = {"module": module}
    if key is not None:
        query["view_key"] = key
    return LIST.get(Request(user, query=query))


def detail(method, user, view_id, data=None):
    return getattr(DETAIL, method)(Request(user, data), uuid.UUID(str(view_id)))


# === owner creates ===========================================================================
reset()
created = make(alice, "Night shift", readers=[])
assert set(created) >= {"id", "module_id", "view_key", "name", "payload", "shared", "mine", "can_edit", "owner", "readers", "created_at", "updated_at"}
assert created["shared"] is True and created["mine"] is True and created["can_edit"] is True
assert created["readers"] == [] and created["owner"] == {"id": 1, "username": "alice"}
assert created["payload"] == {"filter": "x"} and created["module_id"] == "demo-open" and created["view_key"] == "endpoints"
assert len(STORE) == 1 and next(iter(STORE.values())).owner_id == 1
# Name is trimmed; readers default to an empty list (shared with everyone).
assert make(alice, "  Trimmed  ")["name"] == "Trimmed"
assert make(alice, "Default readers")["readers"] == []
# Core module views are allowed for any signed-in user.
assert make(bob, "Core one", module="core", key="home")["module_id"] == "core"

# === empty readers = visible to everyone; readers never shown to non-owners ====================
reset()
shared = make(alice, "Shared view")
as_bob = listing(bob, key="endpoints")
assert as_bob.status_code == 200 and as_bob.data["count"] == 1
row = as_bob.data["views"][0]
assert row["shared"] is True and row["mine"] is False and row["can_edit"] is False and "readers" not in row
assert row["owner"] == {"id": 1, "username": "alice"}
got = detail("get", carol, shared["id"])
assert got.status_code == 200 and got.data["payload"] == {"filter": "x"} and "readers" not in got.data

# === readers = [a, b] hides the view from c ====================================================
reset()
private = make(alice, "Private", readers=[2, 1])
assert private["shared"] is False and private["readers"] == [1, 2]
assert listing(carol, key="endpoints").data["count"] == 0          # not listed
assert detail("get", carol, private["id"]).status_code == 404       # no leak
assert detail("put", carol, private["id"], {"name": "X"}).status_code == 404
assert detail("delete", carol, private["id"]).status_code == 404
reader = listing(bob, key="endpoints").data["views"]
assert len(reader) == 1 and reader[0]["shared"] is False and "readers" not in reader[0]
assert detail("get", bob, private["id"]).status_code == 200
assert "readers" not in detail("get", bob, private["id"]).data
assert detail("get", alice, private["id"]).data["readers"] == [1, 2]
# A reader who is not the owner may not change or delete (403), and nothing changes.
assert detail("put", bob, private["id"], {"name": "Hijack"}).status_code == 403
assert detail("delete", bob, private["id"]).status_code == 403
assert len(STORE) == 1 and next(iter(STORE.values())).name == "Private"
# Shared views: other users cannot change or delete either.
open_view = make(alice, "Open one")
assert detail("put", bob, open_view["id"], {"name": "Hijack"}).status_code == 403
assert detail("delete", carol, open_view["id"]).status_code == 403
# No administrator override.
assert detail("put", root, open_view["id"], {"name": "Root edit"}).status_code == 403
assert detail("delete", root, open_view["id"]).status_code == 403
# "Only me" (Q43): readers holds just the owner's own id.
only_me = make(alice, "Only me", readers=[1])
assert detail("get", bob, only_me["id"]).status_code == 404 and detail("get", alice, only_me["id"]).status_code == 200
assert [v["name"] for v in listing(bob, key="endpoints").data["views"]] == ["Open one", "Private"]

# === only the owner edits and deletes ========================================================
reset()
view = make(alice, "Edit me", readers=[2])
updated = detail("put", alice, view["id"], {"name": "Renamed", "payload": {"filter": "y"}})
assert updated.status_code == 200 and updated.data["name"] == "Renamed" and updated.data["payload"] == {"filter": "y"}
assert updated.data["readers"] == [2], "omitted readers keep their value"
updated = detail("put", alice, view["id"], {"readers": []})
assert updated.data["shared"] is True and updated.data["readers"] == []
assert detail("put", alice, view["id"], {"module_id": "demo-open", "view_key": "endpoints"}).status_code == 200
assert detail("put", alice, view["id"], {"module_id": "core"}).status_code == 400
assert detail("put", alice, view["id"], {"view_key": "other"}).status_code == 400
assert detail("put", alice, view["id"], {"surprise": 1}).status_code == 400
assert detail("put", alice, view["id"], ["not", "an", "object"]).status_code == 400
assert detail("put", alice, view["id"], {"readers": [99]}).status_code == 400
assert detail("delete", alice, view["id"]).status_code == 204 and not STORE
assert detail("get", alice, view["id"]).status_code == 404
assert detail("delete", alice, view["id"]).status_code == 404

# === duplicate names => 409 ==================================================================
reset()
make(alice, "Same")
assert make(alice, "Same", expect=409) is not None
assert len(STORE) == 1
make(alice, "Same", key="other-key")                       # another view_key
make(alice, "Same", module="core", key="endpoints")        # another module
make(bob, "Same")                                          # another owner
second = make(alice, "Second")
assert detail("put", alice, second["id"], {"name": "Same"}).status_code == 409
assert next(r for r in STORE.values() if str(r.id) == second["id"]).name == "Second"
MANAGER.force_integrity = True                             # a lost race on the database constraint is also a 409
assert make(alice, "Raced", expect=409) is not None
MANAGER.force_integrity = False

# === list filters by module and view_key =====================================================
reset()
make(alice, "A1", key="alpha")
make(alice, "A2", key="alpha")
make(alice, "B1", key="beta")
make(alice, "Core1", module="core", key="alpha")
make(bob, "Bob private", key="alpha", readers=[2])
assert [v["name"] for v in listing(alice, key="alpha").data["views"]] == ["A1", "A2"]
assert [v["name"] for v in listing(alice).data["views"]] == ["A1", "A2", "B1"]
assert [v["name"] for v in listing(alice, module="core").data["views"]] == ["Core1"]
assert [v["name"] for v in listing(bob, key="alpha").data["views"]] == ["A1", "A2", "Bob private"]
assert listing(alice, module=None).status_code == 400
assert LIST.get(Request(alice, query={})).status_code == 400
assert listing(alice, key="Bad Key").status_code == 400

# === validation: module, view_key, name, payload, readers => 400 ===============================
reset()
for label, body in {
    "unknown module": dict(module_id="nope"),
    "disabled module": dict(module_id="demo-disabled"),
    "legacy module": dict(module_id="demo-legacy"),
    "missing module": dict(module_id=""),
    "module not a string": dict(module_id={"a": 1}),
    "view_key uppercase": dict(view_key="Endpoints"),
    "view_key space": dict(view_key="a b"),
    "view_key empty": dict(view_key=""),
    "view_key 65": dict(view_key="a" * 65),
    "view_key leading dash": dict(view_key="-a"),
    "view_key not a string": dict(view_key=5),
    "name empty": dict(name=""),
    "name blank": dict(name="   "),
    "name 161": dict(name="n" * 161),
    "name control": dict(name="bad\x07name"),
    "name not a string": dict(name=7),
    "payload list": dict(payload=["a"]),
    "payload string": dict(payload="a"),
    "payload null": dict(payload=None),
    "payload NaN": dict(payload={"a": float("nan")}),
    "payload not JSON": dict(payload={"a": object()}),
    "payload 64 KiB + 1": dict(payload={"a": "x" * (64 * 1024 - 8 + 1)}),
    "readers not a list": dict(readers="1"),
    "readers unknown id": dict(readers=[2, 99]),
    "readers inactive user": dict(readers=[4]),
    "readers bool": dict(readers=[True]),
    "readers string id": dict(readers=["2"]),
    "readers zero": dict(readers=[0]),
    "readers 101": dict(readers=list(range(1, 102))),
    "unknown field": dict(surprise=1),
}.items():
    base = {"module_id": "demo-open", "view_key": "endpoints", "name": "Ok", "payload": {"a": 1}}
    base.update(body)
    response = LIST.post(Request(alice, base))
    assert response.status_code == 400, (label, response.status_code, response.data)
assert not STORE and not AUDIT
assert LIST.post(Request(alice, ["x"])).status_code == 400
# Boundaries that are fine: exactly 64 KiB, 160-character name, 64-character view_key, 100 readers of real users.
exact = make(alice, "n" * 160, key="k" * 64, payload={"a": "x" * (64 * 1024 - 8)})
assert len(exact["name"]) == 160 and len(json.dumps(exact["payload"], separators=(",", ":")).encode()) == 64 * 1024
assert make(alice, "Duplicated readers", readers=[2, 2, 3])["readers"] == [2, 3]
# Non-ASCII text counts as UTF-8 bytes.
assert LIST.post(Request(alice, {"module_id": "demo-open", "view_key": "k", "name": "Wide", "payload": {"a": "漢" * 22000}})).status_code == 400

# === quota: 100 views per owner, module and view_key =========================================
reset()
for index in range(100):
    saved_views.create_view(alice, "demo-open", "busy", f"View {index:03d}", {})
make(alice, "One too many", key="busy", expect=400)
assert len([r for r in STORE.values() if r.owner_id == 1]) == 100
make(alice, "Other key", key="quiet")
make(bob, "Bob is unaffected", key="busy")
saved_views.delete_view(alice, next(r.id for r in STORE.values() if r.name == "View 000"))
make(alice, "Room again", key="busy")

# === module access (Q45) ======================================================================
reset()
make(alice, "Locked", module="demo-locked", expect=403)
assert listing(alice, module="demo-locked").status_code == 403
GRANTS[1] = {"demo-locked.use"}
locked = make(alice, "Locked", module="demo-locked")
assert listing(alice, module="demo-locked").status_code == 200
make(root, "Root may", module="demo-locked")                      # superuser
# A user without the grant cannot read even a shared view of a permissioned module.
assert listing(bob, module="demo-locked").status_code == 403
assert detail("get", bob, locked["id"]).status_code == 403
GRANTS[2] = {"demo-locked.use"}
assert detail("get", bob, locked["id"]).status_code == 200
# Revoking the grant stops the owner too, until it is given back.
GRANTS.clear()
assert detail("get", alice, locked["id"]).status_code == 403
assert detail("put", alice, locked["id"], {"name": "x"}).status_code == 403
# A permissionless module needs only a signed-in user, and Tec-Tac adds no permission of its own.
make(carol, "Carol open")
# Anonymous callers get nothing.
for call in (lambda: saved_views.list_views(Anonymous(), "demo-open"), lambda: saved_views.create_view(Anonymous(), "demo-open", "k", "n", {})):
    try:
        call()
        raise AssertionError("anonymous accepted")
    except saved_views.SavedViewPermissionDenied:
        pass

# A module that was removed or disabled: views stay in place. The owner can read and delete them, nobody else can read them.
reset()
orphan = make(alice, "Orphan")
PLUGINS.remove(OPEN)
assert listing(alice).status_code == 400
assert detail("get", alice, orphan["id"]).status_code == 200
assert detail("get", bob, orphan["id"]).status_code == 404
assert detail("put", alice, orphan["id"], {"name": "new"}).status_code == 400
assert len(STORE) == 1, "removing a module leaves its views in place"
assert detail("delete", alice, orphan["id"]).status_code == 204 and not STORE
PLUGINS.insert(0, OPEN)

# === audit rows (add, modify, delete), never the payload =========================================
reset()
SECRET = "PAYLOAD-SENTINEL-7F3A"
view = make(alice, "Audited", payload={"filter": SECRET}, readers=[2, 3])
detail("put", alice, view["id"], {"name": "Audited v2", "payload": {"filter": SECRET + "-2"}, "readers": []})
detail("delete", alice, view["id"])
assert [row["action"] for row in AUDIT] == ["add", "modify", "delete"], AUDIT
for row in AUDIT:
    assert row["username"] == "alice" and row["object_type"] == "saved_view"
    assert row["debug_info"]["module_id"] == "core" and row["debug_info"]["object_id"] == view["id"]
    assert row["debug_info"]["source"] == "tec-tac" and row["debug_info"]["actor_identity"] == "alice"
    assert SECRET not in json.dumps(row, default=str)
    assert row["before_value"] is None and row["after_value"] is None
meta = [row["debug_info"]["metadata"] for row in AUDIT]
assert meta[0] == {"module": "demo-open", "view_key": "endpoints", "name": "Audited", "shared": False, "readers_count": 2}
assert meta[1]["name"] == "Audited v2" and meta[1]["shared"] is True and meta[1]["readers_count"] == 0
assert meta[2]["name"] == "Audited v2"
# Reads and refusals write nothing.
del AUDIT[:]
view = make(alice, "Quiet")
del AUDIT[:]
detail("get", bob, view["id"])
listing(bob, key="endpoints")
detail("put", bob, view["id"], {"name": "x"})
detail("delete", bob, view["id"])
make(alice, "Quiet", expect=409)
assert not AUDIT

# === a failing audit write rolls the change back (fail closed) ====================================
reset()
FakeAuditLog.objects.fail = True
response = LIST.post(Request(alice, {"module_id": "demo-open", "view_key": "endpoints", "name": "Never saved", "payload": {}}))
assert response.status_code == 500 and not STORE, (response.status_code, STORE)
FakeAuditLog.objects.fail = False
kept = make(alice, "Kept", payload={"v": 1})
FakeAuditLog.objects.fail = True
assert detail("put", alice, kept["id"], {"name": "Changed", "payload": {"v": 2}, "readers": [2]}).status_code == 500
row = next(iter(STORE.values()))
assert (row.name, row.payload, row.readers) == ("Kept", {"v": 1}, []), "update rolled back"
assert detail("delete", alice, kept["id"]).status_code == 500 and len(STORE) == 1, "delete rolled back"
FakeAuditLog.objects.fail = False
assert detail("delete", alice, kept["id"]).status_code == 204 and not STORE

# === the Python functions enforce the same rules as HTTP =============================================
reset()
py = saved_views.create_view(alice, "demo-open", "py-key", "From Python", {"a": 1}, [2])
assert py["readers"] == [2] and py["shared"] is False
assert [v["name"] for v in saved_views.list_views(bob, "demo-open", "py-key")] == ["From Python"]
assert saved_views.list_views(carol, "demo-open", "py-key") == []
assert saved_views.get_view(alice, py["id"])["readers"] == [2]
assert "readers" not in saved_views.get_view(bob, py["id"])
for call, error in (
    (lambda: saved_views.get_view(carol, py["id"]), saved_views.SavedViewNotFound),
    (lambda: saved_views.get_view(alice, "not-a-uuid"), saved_views.SavedViewNotFound),
    (lambda: saved_views.get_view(alice, uuid.uuid4()), saved_views.SavedViewNotFound),
    (lambda: saved_views.update_view(bob, py["id"], name="x"), saved_views.SavedViewPermissionDenied),
    (lambda: saved_views.delete_view(bob, py["id"]), saved_views.SavedViewPermissionDenied),
    (lambda: saved_views.update_view(carol, py["id"], name="x"), saved_views.SavedViewNotFound),
    (lambda: saved_views.create_view(alice, "demo-open", "py-key", "From Python", {}), saved_views.SavedViewConflict),
    (lambda: saved_views.create_view(alice, "nope", "py-key", "n", {}), saved_views.SavedViewValidationError),
    (lambda: saved_views.create_view(alice, "demo-open", "py-key", "n", {}, [99]), saved_views.SavedViewValidationError),
    (lambda: saved_views.create_view(alice, "demo-locked", "py-key", "n", {}), saved_views.SavedViewPermissionDenied),
    (lambda: saved_views.update_view(alice, py["id"], view_key="else"), saved_views.SavedViewValidationError),
):
    try:
        call()
        raise AssertionError("expected " + error.__name__)
    except error:
        pass
assert issubclass(saved_views.SavedViewValidationError, saved_views.SavedViewError)
assert issubclass(saved_views.SavedViewValidationError, ValueError)
statuses = {cls.__name__: cls.status_code for cls in (
    saved_views.SavedViewValidationError, saved_views.SavedViewNotFound, saved_views.SavedViewPermissionDenied,
    saved_views.SavedViewConflict, saved_views.SavedViewAuditError)}
assert statuses == {"SavedViewValidationError": 400, "SavedViewNotFound": 404, "SavedViewPermissionDenied": 403,
                    "SavedViewConflict": 409, "SavedViewAuditError": 500}
assert saved_views.update_view(alice, py["id"], name="Renamed", readers=[])["shared"] is True
saved_views.delete_view(alice, py["id"])
assert not STORE

# === static guards ======================================================================================
for name in ("saved_views.py", "saved_view_views.py"):
    text = (PKG / name).read_text(encoding="utf-8")
    for forbidden in ("localStorage", "sessionStorage", "set_cookie", "request.COOKIES", "request.session", "document.cookie", "django.contrib.sessions"):
        assert forbidden not in text, (name, forbidden)
views_text = (PKG / "saved_view_views.py").read_text(encoding="utf-8")
assert "SessionAuthenticated" in views_text and views_text.count("extend_schema(tags=[\"Tec-Tac Saved Views\"]") == 5
assert views.SavedViewListCreateView.throttle_classes == [MinThrottle, DayThrottle]
assert views.SavedViewDetailView.throttle_classes == [MinThrottle, DayThrottle]
throttle_text = (PKG / "throttles.py").read_text(encoding="utf-8")
assert "class SavedViewWriteMinThrottle" in throttle_text and "class SavedViewWriteDayThrottle" in throttle_text
assert 'scope = "tec_tac_saved_view_write_min"' in throttle_text and 'scope = "tec_tac_saved_view_write_day"' in throttle_text
assert 'if request.method in ("GET", "HEAD", "OPTIONS")' in throttle_text
assert set(m for m in ("get", "post", "put", "delete") if m in views.SavedViewListCreateView.__dict__) == {"get", "post"}
assert set(m for m in ("get", "post", "put", "delete") if m in views.SavedViewDetailView.__dict__) == {"get", "put", "delete"}

# model, migration and deletion behaviour
models_tree = ast.parse((PKG / "models.py").read_text(encoding="utf-8"))
model_cls = next(n for n in models_tree.body if isinstance(n, ast.ClassDef) and n.name == "TecTacSavedView")


def model_fields(cls):
    return {t.id: node.value for node in cls.body if isinstance(node, ast.Assign) for t in node.targets
            if isinstance(t, ast.Name) and isinstance(node.value, ast.Call) and "models." in ast.unparse(node.value.func)}


fields = model_fields(model_cls)
assert set(fields) == {"id", "module_id", "view_key", "name", "payload", "owner", "readers", "created_at", "updated_at"}, set(fields)
assert "on_delete=models.CASCADE" in ast.unparse(fields["owner"]), "deleting a user deletes their views (Q44)"
assert "max_length=64" in ast.unparse(fields["view_key"]) and "max_length=160" in ast.unparse(fields["name"])
model_src = ast.unparse(model_cls)
for needle in ("tectac_sview_owner_name_unique", "tectac_sview_mod_key_idx", "tectac_sview_owner_key_idx", "'owner', 'module_id', 'view_key', 'name'"):
    assert needle in model_src, needle

migration_path = PKG / "migrations" / "0021_saved_views.py"
assert migration_path.exists()
migration_src = migration_path.read_text(encoding="utf-8")
migration_tree = ast.parse(migration_src)
assert '"0020_scheduler_target_parity_repair"' in migration_src
create = next(n for n in ast.walk(migration_tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == "migrations.CreateModel")
assert ast.literal_eval(create.args[0] if create.args else next(k.value for k in create.keywords if k.arg == "name")) == "TecTacSavedView"
migration_field_names = [ast.literal_eval(elt.elts[0]) for elt in next(k.value for k in create.keywords if k.arg == "fields").elts]
assert sorted(migration_field_names) == sorted(fields), (migration_field_names, sorted(fields))
for name, call in fields.items():
    if name == "owner":
        continue
    arg_keys = {k.arg: ast.unparse(k.value) for k in call.keywords}
    mig_call = next(elt.elts[1] for elt in next(k.value for k in create.keywords if k.arg == "fields").elts if ast.literal_eval(elt.elts[0]) == name)
    mig_keys = {k.arg: ast.unparse(k.value) for k in mig_call.keywords}
    assert ast.unparse(call.func) == ast.unparse(mig_call.func), name
    for key, value in arg_keys.items():
        assert mig_keys.get(key) == value or key == "primary_key", (name, key, mig_keys.get(key), value)
owner_migration = ast.unparse(next(elt.elts[1] for elt in next(k.value for k in create.keywords if k.arg == "fields").elts if ast.literal_eval(elt.elts[0]) == "owner"))
assert "CASCADE" in owner_migration and "tec_tac_saved_views" in owner_migration
for needle in ("tectac_sview_owner_name_unique", "tectac_sview_mod_key_idx", "tectac_sview_owner_key_idx", "'owner', 'module_id', 'view_key', 'name'"):
    assert needle in ast.unparse(migration_tree) or needle.replace("'", '"') in migration_src, needle
assert "('name', 'id')" in ast.unparse(migration_tree) or '("name", "id")' in migration_src
assert all("saved" not in p.name for p in (PKG / "migrations").iterdir() if p.name != "0021_saved_views.py")

# routes, OpenAPI group, catalog
urls_text = (PKG / "urls.py").read_text(encoding="utf-8")
assert 'path("saved-views/", SavedViewListCreateView.as_view(), name="tec-tac-saved-views")' in urls_text
assert 'path("saved-views/<uuid:view_id>/", SavedViewDetailView.as_view(), name="tec-tac-saved-view-detail")' in urls_text
openapi_text = (PKG / "openapi.py").read_text(encoding="utf-8")
assert '"tec_tac.saved_view_views": "Tec-Tac · Saved Views"' in openapi_text
assert '("/api/tfd/saved-views/", "Tec-Tac · Saved Views")' in openapi_text

contracts_tree = ast.parse((PKG / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in contracts_tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


http = literal("HTTP_CONTRACT_DETAILS")
assert set(http["/api/tfd/saved-views/"]) == {"GET", "POST"}
assert set(http["/api/tfd/saved-views/<uuid:view_id>/"]) == {"GET", "PUT", "DELETE"}
for status in ("400", "403", "409", "429"):
    assert status in http["/api/tfd/saved-views/"]["POST"]["errors"], status
assert any("browser storage" in rule and "saved views" in rule.lower() for rule in literal("RULES"))

# build the real catalog (same boundary stubs as the 1.16.0 test) and find the contract rows
accounts = types.ModuleType("accounts")
accounts_models = types.ModuleType("accounts.models")
accounts_models.Role = object
sys.modules.update({"accounts": accounts, "accounts.models": accounts_models})
adapter = types.ModuleType("tec_tac.resources_adapter")
for name in ("TacticalResourceAdapterError", "TacticalResourceConflictError", "TacticalResourceValidationError"):
    setattr(adapter, name, type(name, (RuntimeError,), {}))
sys.modules["tec_tac.resources_adapter"] = adapter
sys.modules.pop("tec_tac.rbac", None)
real_rbac = importlib.import_module("tec_tac.rbac")
django_utils = types.ModuleType("django.utils")
django_utils.timezone = types.SimpleNamespace(now=lambda: datetime.datetime(2026, 9, 30))
sys.modules["django.utils"] = django_utils
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
contracts.permission_catalog = lambda: []
catalog = contracts.build_contract_catalog()
rows = [row for row in catalog["core"] if row["area"] == "saved-views"]
assert [row["name"] for row in rows] == ["list_views", "get_view", "create_view", "update_view", "delete_view"], rows
for row in rows:
    assert row["import_path"] == "tec_tac.saved_views" and not row.get("signature_error"), row
    assert row["signature"].startswith("(user"), row
text = contracts.render_markdown(catalog)
assert "tec_tac.saved_views" in text and "list_views" in text

# the HTTP catalog lists both routes when the real urlpatterns are mounted
fake_urls = types.ModuleType("tec_tac.urls")


class _Route:
    def __init__(self, pattern, view_class, name):
        self.pattern = pattern
        self.name = name
        self.callback = types.SimpleNamespace(view_class=view_class)


fake_urls.urlpatterns = [
    _Route("saved-views/", views.SavedViewListCreateView, "tec-tac-saved-views"),
    _Route("saved-views/<uuid:view_id>/", views.SavedViewDetailView, "tec-tac-saved-view-detail"),
]
sys.modules["tec_tac.urls"] = fake_urls
pkg.urls = fake_urls
importlib.reload(contracts)
http_rows = {row["route"]: row for row in contracts._http_contracts()}
assert http_rows["/api/tfd/saved-views/"]["methods"] == ["GET", "POST"]
assert http_rows["/api/tfd/saved-views/<uuid:view_id>/"]["methods"] == ["GET", "PUT", "DELETE"]
assert "contract" in http_rows["/api/tfd/saved-views/"] and "contract" in http_rows["/api/tfd/saved-views/<uuid:view_id>/"]

# docs
doc = (ROOT / "docs" / "saved-views.md").read_text(encoding="utf-8")
for needle in ("readers", "owner", "filters and layout", "64 KiB", "localStorage", "requires", "1.17.0", "Removing a module", "your own user id"):
    assert needle in doc, needle
for rel in ("docs/developer-contracts.md", "docs/core-functions.md"):
    assert "saved-views.md" in (ROOT / rel).read_text(encoding="utf-8"), rel

print("[TEST] PASS saved views 1.17.0")
