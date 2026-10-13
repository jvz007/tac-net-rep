"""1.17.26 regression: one strict Core audit row per successful API key create, edit and delete (parity, AD-25).

Django and Knox are not installed on the development PC, so the real tactical_account_guard.py runs against stubs: an in-memory API key
table with a transaction that rolls back on an exception, users, a role, and Tactical's three handlers as small fakes that behave like
accounts/views.py (v1.5.2): create makes a random key value, edit drops a ``key`` in the body, delete removes. Covered: create, edit and
delete each write exactly one row with the key's id, name and owner and no key value anywhere in the row (the value is a sentinel looked
for in every field); an edit row lists the changed fields and carries owner and expiry before and after; a create whose key cannot be
found still writes a row with no id and matched 0; a protected-owner call (create, edit to a protected owner, edit and delete of a
protected owner's key) is refused with its deny row and no success row; a call Tactical refuses (400 or 404) writes no success row; a
failed audit write rolls the Tactical change back; the list still redacts a protected owner's key for a non-superuser and not for a
superuser; Core never reads the key field for the row; the contract export and docs/api-keys.md name the routes and rules.
The dev-server check (real tables) is tests/api-key-audit-runtime-1.17.26.py, not run here.
"""
from __future__ import annotations

import contextlib
import importlib.util
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "tactical_account_guard.py"
SENTINEL = "KEYVALUE-SENTINEL-8f31c0"


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


class RoleRow:
    def __init__(self, pk, is_superuser=False):
        self.pk = self.id = pk
        self.is_superuser = is_superuser


ROLES = {1: RoleRow(1, False), 2: RoleRow(2, True)}


class Role:
    DoesNotExist = ObjectDoesNotExist

    class objects:
        @staticmethod
        def only(*a):
            return types.SimpleNamespace(get=lambda pk: ROLES[int(pk)])

        select_for_update = only


class UserRow:
    def __init__(self, pk, username, role_id, is_superuser=False):
        self.pk = self.id = pk
        self.username, self.role_id, self.is_superuser = username, role_id, is_superuser
        self.role = ROLES[role_id]


USERS = {10: UserRow(10, "tech", 1), 11: UserRow(11, "other", 1), 20: UserRow(20, "rootadmin", 2, True)}


class _UserQ:
    def __init__(self, pk=None):
        self.pk = pk

    def only(self, *a, **kw):
        return self

    def select_for_update(self, **kw):
        return self

    def select_related(self, *a):
        return self

    def filter(self, pk=None):
        return _UserQ(None if pk is None else int(pk))

    def first(self):
        return USERS.get(self.pk)


class User:
    objects = _UserQ()


class KeyRow:
    def __init__(self, pk, name, user_id, key, expiration=None):
        self.pk = self.id = pk
        self.name, self.user_id, self._key, self.expiration = name, user_id, key, expiration

    @property
    def user(self):
        return USERS[self.user_id]

    @property
    def key(self):
        KEY_READS.append(self.pk)
        return self._key


KEYS: dict = {}
KEY_READS: list = []


class _KeyQ:
    def __init__(self, rows):
        self.rows = list(rows)

    def select_for_update(self, **kw):
        return self

    def select_related(self, *a):
        return self

    def filter(self, pk=None, name=None, user_id=None):
        return _KeyQ(r for r in self.rows if (pk is None or r.pk == int(pk)) and (name is None or r.name == name)
                     and (user_id is None or r.user_id == int(user_id)))

    def first(self):
        return self.rows[0] if self.rows else None

    def __getitem__(self, item):
        return self.rows[item]

    def __iter__(self):
        return iter(self.rows)


class APIKey:
    class objects:
        @staticmethod
        def select_for_update(**kw):
            return _KeyQ(KEYS.values())

        @staticmethod
        def select_related(*a):
            return _KeyQ(KEYS.values())

        @staticmethod
        def filter(**kw):
            return _KeyQ(KEYS.values()).filter(**kw)


@contextlib.contextmanager
def atomic():
    snapshot = {pk: (r.name, r.user_id, r.expiration) for pk, r in KEYS.items()}
    gone = dict(KEYS)
    try:
        yield
    except BaseException:
        KEYS.clear()
        KEYS.update(gone)
        for pk, (name, user_id, expiration) in snapshot.items():
            KEYS[pk].name, KEYS[pk].user_id, KEYS[pk].expiration = name, user_id, expiration
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
PROTECT = {"on": True}
stub("tec_tac.account_security_policy", protection_enabled=lambda **kw: PROTECT["on"])
AUDITS: list = []
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
    username = "key.admin"


class Boss(Actor):
    effective_superuser = True
    is_superuser = True


class Request:
    def __init__(self, data, user):
        self.data, self.user = data, user


NEXT = {"id": 100}
HIDE_CREATED = {"on": False}


class Views:
    """Tactical's accounts/views.py handlers, reduced to what the guard sees."""

    def list_(self, request):
        return Response([{"id": r.pk, "name": r.name, "key": r._key, "user": r.user_id, "expiration": r.expiration} for r in KEYS.values()])

    def create(self, request):
        data = request.data
        if not data.get("name") or (data["name"] in {r.name for r in KEYS.values()} and not HIDE_CREATED["on"]):
            return Response({"name": ["bad"]}, 400)
        NEXT["id"] += 1
        data["key"] = SENTINEL + str(NEXT["id"])
        row = KeyRow(NEXT["id"], data["name"], int(data["user"]), data["key"], data.get("expiration"))
        if not HIDE_CREATED["on"]:
            KEYS[row.pk] = row
        return Response("The API Key was added")

    def edit(self, request, pk):
        row = KEYS.get(int(pk))
        if row is None:
            return Response("Not found", 404)
        request.data.pop("key", None)
        for field in ("name", "user", "expiration"):
            if field in request.data:
                setattr(row, "user_id" if field == "user" else field, int(request.data[field]) if field == "user" else request.data[field])
        return Response("The API Key was edited")

    def delete(self, request, pk):
        if int(pk) not in KEYS:
            return Response("Not found", 404)
        del KEYS[int(pk)]
        return Response("The API Key was deleted")


create = guard._wrap_api_key_create(Views.create)
edit = guard._wrap_api_key_mutation(Views.edit, "update_api_key")
delete = guard._wrap_api_key_mutation(Views.delete, "delete_api_key")
lister = guard._wrap_api_key_list(Views.list_)


def reset():
    KEYS.clear()
    KEYS[1] = KeyRow(1, "ci-deploy", 10, SENTINEL + "-1", datetime(2027, 1, 1, tzinfo=timezone.utc))
    KEYS[2] = KeyRow(2, "root-key", 20, SENTINEL + "-2")
    AUDITS.clear()
    KEY_READS.clear()
    FAIL["on"] = False
    HIDE_CREATED["on"] = False
    PROTECT["on"] = True


def must_be_refused(fn, *args):
    try:
        fn(*args)
    except PermissionDenied:
        return
    raise AssertionError("must be refused")


def no_key_value(rows):
    text = repr(rows)
    must(SENTINEL not in text, "a key value is in the audit row")
    for row in rows:
        for field in ("before", "after", "metadata"):
            value = row.get(field) or {}
            must("key" not in value, (field, value))


def success_rows():
    return [r for r in AUDITS if r["action"] != "deny"]


who = Actor()
boss = Boss()

# (1) create: one strict row, id from the new key, owner named, no key value
reset()
resp = create(Views(), Request({"name": "new-tool", "user": 10}, who))
must(resp.status_code == 200 and len(KEYS) == 3, resp.data)
rows = success_rows()
must(len(rows) == 1, rows)
row = rows[0]
must(row["module_id"] == "core" and row["action"] == "add" and row["object_type"] == "api_key" and row["strict"] is True, row)
must(row["object_id"] == "101", row["object_id"])
must(row["metadata"] == {"name": "new-tool", "owner": "tech", "owner_id": 10}, row["metadata"])
must(row["after"] == {"name": "new-tool", "owner": "tech", "expiration": None} and row["before"] is None, row)
no_key_value(rows)
must(not KEY_READS, "Core never read the key field for the row")

# (2) edit: changed fields, owner and expiry before and after
reset()
resp = edit(Views(), Request({"name": "ci-deploy-2", "user": 11, "expiration": "2028-02-02T00:00:00Z", "key": "HACK"}, who), 1)
must(resp.status_code == 200 and KEYS[1].name == "ci-deploy-2" and KEYS[1].user_id == 11, resp.data)
rows = success_rows()
must(len(rows) == 1 and rows[0]["action"] == "modify" and rows[0]["object_id"] == "1" and rows[0]["strict"] is True, rows)
must(rows[0]["metadata"] == {"name": "ci-deploy-2", "owner": "other", "owner_id": 11, "changed": ["name", "owner", "expiration"]}, rows[0]["metadata"])
must(rows[0]["before"] == {"name": "ci-deploy", "owner": "tech", "expiration": "2027-01-01T00:00:00+00:00"}, rows[0]["before"])
must(rows[0]["after"] == {"name": "ci-deploy-2", "owner": "other", "expiration": "2028-02-02T00:00:00Z"}, rows[0]["after"])
no_key_value(rows)
must(not KEY_READS, "Core never read the key field")
# only the expiry changes: the list says so
AUDITS.clear()
edit(Views(), Request({"expiration": None}, who), 1)
must(success_rows()[0]["metadata"]["changed"] == ["expiration"], success_rows())
# an edit that changes nothing is still one edit row, with no changed fields
AUDITS.clear()
edit(Views(), Request({"name": "ci-deploy-2"}, who), 1)
must(len(success_rows()) == 1 and success_rows()[0]["metadata"]["changed"] == [], success_rows())

# (3) delete: one row, before names the key, no key value
reset()
resp = delete(Views(), Request({}, who), 1)
must(resp.status_code == 200 and 1 not in KEYS, resp.data)
rows = success_rows()
must(len(rows) == 1 and rows[0]["action"] == "delete" and rows[0]["object_id"] == "1" and rows[0]["strict"] is True, rows)
must(rows[0]["metadata"] == {"name": "ci-deploy", "owner": "tech", "owner_id": 10}, rows[0]["metadata"])
must(rows[0]["before"] == {"name": "ci-deploy", "owner": "tech", "expiration": "2027-01-01T00:00:00+00:00"} and rows[0]["after"] is None, rows[0])
no_key_value(rows)

# (4) a created key that cannot be found still writes a row: no id, matched 0
reset()
HIDE_CREATED["on"] = True
resp = create(Views(), Request({"name": "ghost", "user": 10}, who))
must(resp.status_code == 200, resp.data)
rows = success_rows()
must(len(rows) == 1 and rows[0]["action"] == "add" and rows[0]["object_id"] is None, rows)
must(rows[0]["metadata"]["matched"] == 0 and rows[0]["metadata"]["name"] == "ghost" and rows[0]["metadata"]["owner_id"] == 10, rows[0]["metadata"])
no_key_value(rows)
# two keys of the same name and owner cannot be told apart: also the no-id row, never a guess
reset()
KEYS[5] = KeyRow(5, "dup", 10, SENTINEL)
KEYS[6] = KeyRow(6, "dup", 10, SENTINEL)
HIDE_CREATED["on"] = True
create(Views(), Request({"name": "dup", "user": 10}, who))
must(len(success_rows()) == 1 and success_rows()[0]["object_id"] is None, success_rows())

# (5) protected owner: refused with the deny row, no success row, no change
reset()
before = {pk: (r.name, r.user_id) for pk, r in KEYS.items()}
for label, call in (
    ("create for a protected owner", lambda: create(Views(), Request({"name": "x", "user": 20}, who))),
    ("edit a protected owner's key", lambda: edit(Views(), Request({"name": "y"}, who), 2)),
    ("edit a key to a protected owner", lambda: edit(Views(), Request({"user": 20}, who), 1)),
    ("delete a protected owner's key", lambda: delete(Views(), Request({}, who), 2)),
):
    AUDITS.clear()
    must_be_refused(call)
    must(len(AUDITS) == 1 and AUDITS[0]["action"] == "deny" and AUDITS[0]["object_type"] == "superuser_account_protection", (label, AUDITS))
    must(AUDITS[0]["metadata"]["operation"] in ("create_api_key", "update_api_key", "delete_api_key"), (label, AUDITS))
    must(success_rows() == [], label)
    must({pk: (r.name, r.user_id) for pk, r in KEYS.items()} == before, label)
# a superuser may act on a protected owner's key and gets a row
AUDITS.clear()
edit(Views(), Request({"name": "root-key-2"}, boss), 2)
must(len(success_rows()) == 1 and success_rows()[0]["metadata"]["owner"] == "rootadmin", success_rows())
# protection off: the same call by a normal caller is allowed and still audited
reset()
PROTECT["on"] = False
create(Views(), Request({"name": "free", "user": 20}, who))
must(len(success_rows()) == 1 and success_rows()[0]["metadata"]["owner"] == "rootadmin", success_rows())

# (6) a call Tactical refuses writes no success row
reset()
resp = create(Views(), Request({"name": "ci-deploy", "user": 10}, who))  # a name already in use
must(resp.status_code == 400 and success_rows() == [], (resp.status_code, AUDITS))
resp = edit(Views(), Request({"name": "z"}, who), 99)  # not a known key: the wrapper finds no key, Tactical answers 404
must(resp.status_code == 404 and success_rows() == [], AUDITS)
resp = delete(Views(), Request({}, who), 99)
must(resp.status_code == 404 and success_rows() == [], AUDITS)

# (7) a failed audit write rolls the Tactical change back, for all three
reset()
FAIL["on"] = True
for call, check in (
    (lambda: create(Views(), Request({"name": "rb", "user": 10}, who)), lambda: "rb" not in {r.name for r in KEYS.values()}),
    (lambda: edit(Views(), Request({"name": "renamed"}, who), 1), lambda: KEYS[1].name == "ci-deploy"),
    (lambda: delete(Views(), Request({}, who), 1), lambda: 1 in KEYS),
):
    try:
        call()
    except RuntimeError as exc:
        must("persisted Core audit record" in str(exc), exc)
    else:
        raise AssertionError("a failed strict audit write must raise")
    must(check(), "rolled back")

# (8) the list still redacts a protected owner's key for a non-superuser, and not for a superuser
reset()
shown = {item["id"]: item["key"] for item in lister(Views(), Request({}, who)).data}
must(shown[2] == "[REDACTED]" and shown[1].startswith(SENTINEL), shown)
shown = {item["id"]: item["key"] for item in lister(Views(), Request({}, boss)).data}
must(shown[2].startswith(SENTINEL), "an effective superuser sees it")
must(AUDITS == [], "a list writes no row")

# (9) the guard is installed on all three write handlers and the source never reads the key value for a row
source = MODULE.read_text(encoding="utf-8")
must("_wrap_api_key_create" in source and "_audit_api_key_write" in source and "API_KEY_AUDIT_OBJECT" in source, "wrappers present")
audit_part = source[source.index("def _api_key_audit_view"):source.index("def install_tactical_account_guard")]
must(".key" not in audit_part.replace("_key(", "").replace("api_key", "").replace('"key"', ""), "the audit helpers never read .key")

# (10) the export and the doc name the routes and the rules
contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
for needle in ("/accounts/apikeys/", "/accounts/apikeys/<id>/", "can_list_api_keys", "can_manage_api_keys", "[REDACTED]", "object_type api_key",
               "The key value is never in a row", "matched 0", "create_api_key", "docs/api-keys.md"):
    must(needle in contracts, f"contracts.py lacks {needle!r}")
doc = (ROOT / "docs" / "api-keys.md").read_text(encoding="utf-8")
for needle in ("can_list_api_keys", "can_manage_api_keys", "never in a row", "matched", "[REDACTED]", "CQ84", "ssoproviders"):
    must(needle in doc, f"docs/api-keys.md lacks {needle!r}")

print("[TEST] PASS api key audit 1.17.26")
