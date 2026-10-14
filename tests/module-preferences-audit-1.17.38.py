#!/usr/bin/env python3
"""1.17.38 regression: core.module_preferences 1.2.0 writes one strict Core audit row per real change, and checks the person.

Covers CQ113 (audit every write and delete, no value in the row, source and module_verified on both paths, no row on a read, an
unchanged write or a refusal), CQ109 (the person may use the module, 403 module_not_allowed, on the browser route and the Python functions;
the order 401, 404, 403, then name, value and limit) and CQ114 to CQ117 (the wording of the can and cannot prove rule, no 'verified
browser' claim, AD-36 not recorded).

The real ``module_preferences.py`` and ``module_preference_views.py`` run with narrow stubs: Django's transaction (a fake atomic that
restores the fake table when the block raises, so a rollback is checked against the table), the user lock, the notice module's enabled check,
the audit module (its record call is a fake that keeps every row, and can be made to fail), the caller identity (a switch), the model (a fake
table with the lookups used), and DRF's Response and APIView. The database part (real AuditLog rows, a real rollback) runs on the dev server:
tests/module-preferences-audit-runtime-1.17.38.py.
"""
from __future__ import annotations

import ast
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


# ------------------------------------------------------------------------------------------------ the installed modules (the notice check and the audit module agree)
MODULES = {
    "remote-background": {"permissions": ("rb.view", "rb.manage"), "enabled": True, "legacy": False},
    "endpoints": {"permissions": ("ep.view",), "enabled": True, "legacy": False},
    "openmod": {"permissions": (), "enabled": True, "legacy": False},  # no permission groups: open to every signed-in person
    "modoff": {"permissions": ("off.view",), "enabled": False, "legacy": False},
    "oldmod": {"permissions": ("old.view",), "enabled": True, "legacy": True},
}


class NoticeError(ValueError):
    pass


def enabled_extension_id(module_id):
    name = str(module_id).strip() if isinstance(module_id, str) else ""
    if not name:
        raise NoticeError("module_id is required.")
    if name.lower() in {"core", "tec-tac"}:
        raise NoticeError("module_id may not be a Core source.")
    entry = MODULES.get(name)
    if entry is None or not entry["enabled"] or entry["legacy"]:
        raise NoticeError(f"module_id {name!r} is not an installed, enabled module.")
    return name


class AuditContractError(ValueError):
    pass


class AuditWriteError(RuntimeError):
    pass


def _resolve_module(module_id):
    entry = MODULES.get(module_id)
    if entry is None or not entry["enabled"]:
        raise AuditContractError(f"Unknown or ambiguous Tec-Tac module_id: {module_id}")
    return {"id": module_id, "version": "1.0.0", "permissions": entry["permissions"], "legacy": entry["legacy"]}


def _actor_can_use_module(actor, module):
    """The rule of tec_tac.audit._actor_can_use_module: a superuser or role superuser, a module with no permissions, or one of its permissions."""
    if not getattr(actor, "is_authenticated", False):
        return False
    if actor.is_superuser:
        return True
    role = actor.get_and_set_role_cache()
    if role is not None and role.is_superuser:
        return True
    permissions = tuple(module.get("permissions") or ())
    if not permissions or module.get("id") == "core":
        return True
    return bool(set(permissions) & set(actor.perms))


AUDIT_CALLS: list = []
AUDIT_FAIL: dict = {"exc": None}


def record(**kwargs):
    """The fake of tec_tac.audit.record: it keeps every call, and raises the error the test set (the strict failure)."""
    if AUDIT_FAIL["exc"] is not None:
        raise AUDIT_FAIL["exc"]
    AUDIT_CALLS.append(kwargs)
    return {"recorded": True}


CALLER: dict = {"module": None}


def calling_module_for_core_provider(provider_file):
    """The fake of Core's caller identity: the module named in CALLER, or nothing (a call from outside every module)."""
    return SimpleNamespace(module_id=CALLER["module"]) if CALLER["module"] else None


# ------------------------------------------------------------------------------------------------ Django and DRF stubs
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.notices = mod("tec_tac.notices", NoticeError=NoticeError, enabled_extension_id=enabled_extension_id)
pkg.audit = mod("tec_tac.audit", AuditContractError=AuditContractError, AuditWriteError=AuditWriteError, _resolve_module=_resolve_module,
                _actor_can_use_module=_actor_can_use_module, record=record)
mod("tec_tac.caller_identity", calling_module_for_core_provider=calling_module_for_core_provider)
REGISTERED: list = []
mod("tec_tac.capabilities", register_capability=lambda **kwargs: REGISTERED.append(kwargs) or "registered")
mod("tec_tac.session_security", SessionAuthenticated=type("SessionAuthenticated", (), {}))
mod("tec_tac.throttles", ModulePreferenceWriteMinThrottle=type("ModulePreferenceWriteMinThrottle", (), {}))
mod("django")
mod("django.contrib")
ROLLBACKS: list = []


class STORE:
    rows: list = []


OPS: list = []
LOCKS: list = []


class _Atomic:
    """A fake transaction: when the block raises, the table goes back to what it was when the block started."""

    def __enter__(self):
        self.rows_before = list(STORE.rows)
        self.state_before = [(row, dict(vars(row))) for row in STORE.rows]
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            ROLLBACKS.append(exc_type.__name__)
            STORE.rows[:] = self.rows_before
            for row, state in self.state_before:
                row.__dict__.clear()
                row.__dict__.update(state)
        return False


mod("django.db", transaction=SimpleNamespace(atomic=lambda: _Atomic()))


class _UserQuery:
    def get(self, pk):
        LOCKS.append(pk)


class _UserManager:
    def select_for_update(self):
        return _UserQuery()


mod("django.contrib.auth", get_user_model=lambda: SimpleNamespace(objects=_UserManager()))
mod("drf_spectacular")
mod("drf_spectacular.utils", extend_schema=lambda **kwargs: (lambda fn: fn), extend_schema_view=lambda **kwargs: (lambda cls: cls))
mod("rest_framework")


class Response:
    def __init__(self, data=None, status=None):
        self.data = data
        self.status_code = 200 if status is None else status


mod("rest_framework.response", Response=Response)
mod("rest_framework.views", APIView=type("APIView", (), {}))


# ------------------------------------------------------------------------------------------------ the fake model: every read and write is logged
class Row(SimpleNamespace):
    pass


class Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, **kwargs):
        OPS.append("read")
        return Query([r for r in self.rows if all(getattr(r, k) == v for k, v in kwargs.items())])

    def first(self):
        return self.rows[0] if self.rows else None

    def exists(self):
        return bool(self.rows)

    def count(self):
        return len(self.rows)

    def delete(self):
        OPS.append("write")
        gone = {id(r) for r in self.rows}
        STORE.rows[:] = [r for r in STORE.rows if id(r) not in gone]
        return len(gone), {}

    def order_by(self, field):
        return Query(sorted(self.rows, key=lambda r: getattr(r, field)))

    def __iter__(self):
        return iter(self.rows)


class Manager:
    def filter(self, **kwargs):
        OPS.append("read")
        return Query(list(STORE.rows)).filter(**kwargs)

    def update_or_create(self, user_id, module_id, name, defaults):
        OPS.append("write")
        for row in STORE.rows:
            if (row.user_id, row.module_id, row.name) == (user_id, module_id, name):
                row.value = defaults["value"]
                return row, False
        row = Row(user_id=user_id, module_id=module_id, name=name, value=defaults["value"])
        STORE.rows.append(row)
        return row, True


mod("tec_tac.models", TecTacModulePreference=SimpleNamespace(objects=Manager()))
mp = __import__("tec_tac.module_preferences", fromlist=["x"])
views = __import__("tec_tac.module_preference_views", fromlist=["x"])


class User(SimpleNamespace):
    pass


def person(pk, perms=(), superuser=False, role_superuser=False, authenticated=True):
    role = SimpleNamespace(is_superuser=role_superuser) if role_superuser else None
    return User(pk=pk, is_authenticated=authenticated, is_superuser=superuser, perms=set(perms),
                get_and_set_role_cache=lambda: role, role=role, username=f"person{pk}")


ALICE = person(1, perms=("rb.view",))  # one permission of remote-background
BOB = person(2, perms=("rb.manage", "ep.view"))
SUPER = person(3, superuser=True)
ROLE = person(4, role_superuser=True)
NOPERM = person(5)  # no permission of any module
ANON = person(None, authenticated=False)


def reset():
    STORE.rows.clear()
    OPS.clear()
    LOCKS.clear()
    AUDIT_CALLS.clear()
    ROLLBACKS.clear()
    AUDIT_FAIL["exc"] = None
    CALLER["module"] = None


def rows_of(user_pk, module_id):
    return sorted((r.name, r.value) for r in STORE.rows if r.user_id == user_pk and r.module_id == module_id)


def audit_names():
    return [c["action"] for c in AUDIT_CALLS]


def detail(method, user, module_id, name, data=None):
    request = SimpleNamespace(user=user, data=data)
    view = views.ModulePreferenceDetailView()
    if method == "put":
        return view.put(request, module_id=module_id, name=name)
    return view.delete(request, module_id=module_id, name=name)


def listing(user, module_id):
    return views.ModulePreferenceListView().get(SimpleNamespace(user=user), module_id=module_id)


def refused(fn, code, status):
    try:
        fn()
    except mp.ModulePreferenceError as exc:
        must(exc.code == code and exc.status_code == status, f"expected {code} {status}, got {exc.code} {exc.status_code}")
        return
    raise AssertionError(f"expected {code} {status}, but the call answered")


RB = "remote-background"

# ------------------------------------------------------------------------------------------------ 1. one audit row per real change, browser path (the private functions)
reset()
mp._set(ALICE, "header", True, module_id=RB)
must(len(AUDIT_CALLS) == 1, f"one row on add: {AUDIT_CALLS}")
row = AUDIT_CALLS[0]
must(row["actor"] is ALICE and row["module_id"] == "core" and row["strict"] is True, "the person is the actor, the row is Core's, strict")
must(row["action"] == "add" and row["object_type"] == "module_preference" and row["object_id"] == f"{RB}/header", row)
must(row["message"] == "Tec-Tac module preference add." and row["before"] is None and row["after"] is None, row)
must(row["metadata"] == {"module": RB, "name": "header", "source": "browser", "module_verified": False, "user_id": 1, "size_bytes": 4},
     row["metadata"])
mp._set(ALICE, "header", False, module_id=RB)
must(audit_names() == ["add", "modify"], audit_names())
must(AUDIT_CALLS[1]["metadata"]["size_bytes"] == 5 and AUDIT_CALLS[1]["object_id"] == f"{RB}/header", AUDIT_CALLS[1])
must(AUDIT_CALLS[1]["message"] == "Tec-Tac module preference modify.", AUDIT_CALLS[1]["message"])
must(mp._delete(ALICE, "header", module_id=RB) is True, "delete returns True when a row was removed")
must(audit_names() == ["add", "modify", "delete"], audit_names())
delete_meta = AUDIT_CALLS[2]["metadata"]
must("size_bytes" not in delete_meta and delete_meta == {"module": RB, "name": "header", "source": "browser", "module_verified": False, "user_id": 1},
     f"a delete carries no size: {delete_meta}")
must(AUDIT_CALLS[2]["action"] == "delete" and AUDIT_CALLS[2]["object_id"] == f"{RB}/header", AUDIT_CALLS[2])

# ------------------------------------------------------------------------------------------------ 2. the public functions: source module_python and module_verified true
reset()
CALLER["module"] = RB
mp.set(ALICE, "tabs", {"b": 1, "a": 2}, module_id=RB)
must(AUDIT_CALLS[0]["metadata"] == {"module": RB, "name": "tabs", "source": "module_python", "module_verified": True, "user_id": 1,
                                     "size_bytes": 13}, AUDIT_CALLS[0]["metadata"])  # {"a":2,"b":1} with sorted keys is 13 bytes
mp.delete(ALICE, "tabs", module_id=RB)
must(AUDIT_CALLS[1]["action"] == "delete" and AUDIT_CALLS[1]["metadata"]["source"] == "module_python"
     and AUDIT_CALLS[1]["metadata"]["module_verified"] is True, AUDIT_CALLS[1])
CALLER["module"] = None

# ------------------------------------------------------------------------------------------------ 3. the size is the UTF-8 size of the stored text, and the value never appears
reset()
mp._set(ALICE, "accent", "é", module_id=RB)
must(AUDIT_CALLS[0]["metadata"]["size_bytes"] == 4, f"'é' as JSON text is 4 bytes in UTF-8: {AUDIT_CALLS[0]['metadata']}")
MARKER = "MARKER-7f3a9c-do-not-log"
NESTED = "NESTED-5b2e-do-not-log"
value = {"text": MARKER, "deep": {"inner": NESTED}, "list": [MARKER, 1, None, True]}
mp._set(ALICE, "secret-looking", value, module_id=RB)
mp._set(ALICE, "secret-looking", {"text": "changed"}, module_id=RB)
mp._delete(ALICE, "secret-looking", module_id=RB)
everything = repr(AUDIT_CALLS)
must(MARKER not in everything and NESTED not in everything and "changed" not in everything, "the stored value never appears in a recorded call")
must(all(str(c["object_id"]).startswith(RB + "/") and "MARKER" not in str(c["object_id"]) for c in AUDIT_CALLS), "the object id is the name")

# ------------------------------------------------------------------------------------------------ 4. no row on a read, on an unchanged write, or on a delete of a missing name
reset()
mp._set(ALICE, "header", True, module_id=RB)
mark = len(AUDIT_CALLS)
mp._get(ALICE, "header", module_id=RB)
mp._list_for(ALICE, module_id=RB)
listing(ALICE, RB)
CALLER["module"] = RB
mp.get(ALICE, "header", module_id=RB)
mp.list_for(ALICE, module_id=RB)
CALLER["module"] = None
must(len(AUDIT_CALLS) == mark, f"reads write no row: {audit_names()}")
OPS.clear()
must(mp._set(ALICE, "header", True, module_id=RB) is True, "an unchanged write answers the stored value")
must(len(AUDIT_CALLS) == mark and "write" not in OPS, f"an unchanged write writes no row and no database update: {audit_names()} {OPS}")
must(mp._set(ALICE, "header", 1, module_id=RB) == 1 and len(AUDIT_CALLS) == mark + 1 and AUDIT_CALLS[-1]["action"] == "modify",
     "True and 1 are different values: the write is audited")
must(mp._set(ALICE, "header", 1.0, module_id=RB) == 1.0 and AUDIT_CALLS[-1]["action"] == "modify" and len(AUDIT_CALLS) == mark + 2,
     "1 and 1.0 are different values: the write is audited")
must(mp._set(ALICE, "header", 1.0, module_id=RB) == 1.0 and len(AUDIT_CALLS) == mark + 2, "1.0 again is unchanged")
mp._set(ALICE, "order", {"b": 1, "a": 2}, module_id=RB)
mark = len(AUDIT_CALLS)
mp._set(ALICE, "order", {"a": 2, "b": 1}, module_id=RB)
must(len(AUDIT_CALLS) == mark, "key order does not make a change: the same stored text writes nothing")
mark = len(AUDIT_CALLS)
OPS.clear()
must(mp._delete(ALICE, "missing", module_id=RB) is False, "a delete of a missing name answers False")
must(len(AUDIT_CALLS) == mark and "write" not in OPS, "and writes no row and no database update")

# ------------------------------------------------------------------------------------------------ 5. no row and no write on a refusal
reset()
mp._set(ALICE, "header", True, module_id=RB)
mark = len(AUDIT_CALLS)
rows_before = rows_of(1, RB)
REFUSALS = [
    (lambda: mp._set(ALICE, "Bad Name", 1, module_id=RB), "invalid_name", 400),
    (lambda: mp._set(ALICE, "x", [[[[[[1]]]]]], module_id=RB), "invalid_value", 400),
    (lambda: mp._set(ALICE, "x", 1, module_id="modoff"), "module_not_found", 404),
    (lambda: mp._set(ALICE, "x", 1, module_id="core"), "module_not_found", 404),
    (lambda: mp._set(ALICE, "x", 1, module_id="tec-tac"), "module_not_found", 404),
    (lambda: mp._set(ALICE, "x", 1, module_id="nope"), "module_not_found", 404),
    (lambda: mp._set(ALICE, "x", 1, module_id="oldmod"), "module_not_found", 404),
    (lambda: mp._set(NOPERM, "x", 1, module_id=RB), "module_not_allowed", 403),
    (lambda: mp._set(ANON, "x", 1, module_id=RB), "signed_in_required", 401),
    (lambda: mp._delete(NOPERM, "header", module_id=RB), "module_not_allowed", 403),
    (lambda: mp._delete(ANON, "header", module_id=RB), "signed_in_required", 401),
    (lambda: mp._delete(ALICE, "Bad Name", module_id=RB), "invalid_name", 400),
]
for call, code, status in REFUSALS:
    OPS.clear()
    refused(call, code, status)
    must(len(AUDIT_CALLS) == mark and "write" not in OPS, f"{code}: no audit row and no write")
must(rows_of(1, RB) == rows_before, "the stored row is unchanged after every refusal")
CALLER["module"] = "endpoints"
refused(lambda: mp.set(ALICE, "x", 1, module_id=RB), "caller_not_allowed", 403)
CALLER["module"] = None
must(len(AUDIT_CALLS) == mark, "a refused caller writes no row and no deny row")

# the 51st name is refused, with no row, once the 50 names are kept
reset()
for n in range(50):
    mp._set(ALICE, f"n{n:02d}", n, module_id="openmod")
mark = len(AUDIT_CALLS)
refused(lambda: mp._set(ALICE, "n50", 1, module_id="openmod"), "preference_limit", 400)
must(len(AUDIT_CALLS) == mark == 50 and len(rows_of(1, "openmod")) == 50, "the 51st name writes no row")

# ------------------------------------------------------------------------------------------------ 6. strict: a change whose row cannot be written is rolled back
reset()
mp._set(ALICE, "header", False, module_id=RB)
AUDIT_FAIL["exc"] = AuditWriteError("Tec-Tac audit write failed.")
refused(lambda: mp._set(ALICE, "header", True, module_id=RB), "audit_failed", 503)
must(rows_of(1, RB) == [("header", False)], f"the modify is rolled back: {rows_of(1, RB)}")
refused(lambda: mp._set(ALICE, "brand-new", 1, module_id=RB), "audit_failed", 503)
must(rows_of(1, RB) == [("header", False)], "the add is rolled back too")
refused(lambda: mp._delete(ALICE, "header", module_id=RB), "audit_failed", 503)
must(rows_of(1, RB) == [("header", False)], "the delete is rolled back: the row is still there")
AUDIT_FAIL["exc"] = RuntimeError("the audit store is down")  # any failure, not only the contract error
refused(lambda: mp._set(ALICE, "header", True, module_id=RB), "audit_failed", 503)
AUDIT_FAIL["exc"] = AuditContractError("a contract error is a failure too")
refused(lambda: mp._set(ALICE, "header", True, module_id=RB), "audit_failed", 503)
must(ROLLBACKS and all(name == "ModulePreferenceError" for name in ROLLBACKS), f"each failure rolled the block back: {ROLLBACKS}")
AUDIT_FAIL["exc"] = None
CALLER["module"] = RB
AUDIT_FAIL["exc"] = AuditWriteError("down")
refused(lambda: mp.set(ALICE, "header", True, module_id=RB), "audit_failed", 503)
must(rows_of(1, RB) == [("header", False)], "the public set is rolled back too")
CALLER["module"] = None
AUDIT_FAIL["exc"] = None
must(mp._set(ALICE, "header", True, module_id=RB) is True and audit_names()[-1] == "modify", "and works again once the store is back")

# ------------------------------------------------------------------------------------------------ 7. the browser views: the answers, and the failure as 503 with a code
reset()
resp = detail("put", ALICE, RB, "header", {"value": True})
must(resp.status_code == 200 and resp.data == {"module_id": RB, "name": "header", "value": True}, resp.data)
must(AUDIT_CALLS[-1]["metadata"]["source"] == "browser", "the view writes with the browser source")
must(detail("delete", ALICE, RB, "header").data["deleted"] is True and AUDIT_CALLS[-1]["action"] == "delete", "the view delete is audited")
resp = listing(ALICE, RB)
must(resp.status_code == 200 and resp.data == {"module_id": RB, "preferences": {}}, resp.data)
detail("put", ALICE, RB, "header", {"value": True})
mark = len(AUDIT_CALLS)
AUDIT_FAIL["exc"] = AuditWriteError("down")
resp = detail("put", ALICE, RB, "header", {"value": False})
must(resp.status_code == 503 and resp.data["code"] == "audit_failed" and resp.data["detail"], resp.data)
must(rows_of(1, RB) == [("header", True)] and len(AUDIT_CALLS) == mark, "the view's 503 leaves the stored value as it was")
resp = detail("delete", ALICE, RB, "header")
must(resp.status_code == 503 and resp.data["code"] == "audit_failed" and rows_of(1, RB) == [("header", True)], resp.data)
AUDIT_FAIL["exc"] = None

# ------------------------------------------------------------------------------------------------ 8. the person may use the module (CQ109): browser route and Python functions
reset()
for user in (ALICE, BOB, SUPER, ROLE):
    resp = detail("put", user, RB, "allowed", {"value": 1})
    must(resp.status_code == 200, f"{user.username} may use {RB}: {resp.data}")
resp = detail("put", NOPERM, RB, "x", {"value": 1})
must(resp.status_code == 403 and resp.data["code"] == "module_not_allowed", resp.data)
OPS.clear()
resp = listing(NOPERM, RB)
must(resp.status_code == 403 and resp.data["code"] == "module_not_allowed" and not OPS, "a read is refused before anything is read")
resp = detail("delete", NOPERM, RB, "allowed")
must(resp.status_code == 403 and resp.data["code"] == "module_not_allowed", resp.data)
must(rows_of(5, RB) == [] and rows_of(2, RB) == [("allowed", 1)] and len(AUDIT_CALLS) == 4, "nothing is written or audited for the refused person")
resp = detail("put", NOPERM, "openmod", "open", {"value": 1})
must(resp.status_code == 200, "a module with no permission groups is open to every signed-in person")
for module_id in ("oldmod", "modoff", "nope", "core", "tec-tac"):
    resp = detail("put", SUPER, module_id, "x", {"value": 1})
    must(resp.status_code == 404 and resp.data["code"] == "module_not_found", f"{module_id}: {resp.data}")
    resp = listing(ALICE, module_id)
    must(resp.status_code == 404 and resp.data["code"] == "module_not_found", f"{module_id} listing: {resp.data}")
# the order of the checks: 401 before 404 before 403 before 400
resp = listing(ANON, "nope")
must(resp.status_code == 401 and resp.data["code"] == "signed_in_required", f"401 before 404: {resp.data}")
resp = detail("put", NOPERM, "nope", "Bad Name", {"value": 1})
must(resp.status_code == 404, f"404 before 403 and 400: {resp.data}")
resp = detail("put", NOPERM, RB, "Bad Name", {"value": 1})
must(resp.status_code == 403 and resp.data["code"] == "module_not_allowed", f"403 before 400: {resp.data}")
resp = detail("put", ALICE, RB, "Bad Name", {"value": 1})
must(resp.status_code == 400 and resp.data["code"] == "invalid_name", f"400 for a person who may use it: {resp.data}")
# the Python path refuses a person who may not use the module, for every function
reset()
CALLER["module"] = RB
refused(lambda: mp.set(NOPERM, "x", 1, module_id=RB), "module_not_allowed", 403)
refused(lambda: mp.get(NOPERM, "x", module_id=RB), "module_not_allowed", 403)
refused(lambda: mp.list_for(NOPERM, module_id=RB), "module_not_allowed", 403)
refused(lambda: mp.delete(NOPERM, "x", module_id=RB), "module_not_allowed", 403)
must(not AUDIT_CALLS and not OPS, "the Python path refuses the person before anything is read or written")
mp.set(ALICE, "x", 1, module_id=RB)
must(AUDIT_CALLS[-1]["metadata"]["source"] == "module_python", "a person who may use it is served")
CALLER["module"] = None

# ------------------------------------------------------------------------------------------------ 9. the capability, the contract rows and the rule text (read only)
must(mp.CAPABILITY_VERSION == "1.2.0", mp.CAPABILITY_VERSION)
meta = mp.module_preferences_contract_metadata()
must(meta["version"] == "1.2.0" and meta["requires_framework"] == ">=1.17.38", meta)
must("module_preference" in meta["audit"] and "503 audit_failed" in meta["audit"] and "Never the value" in meta["audit"], meta["audit"])
must("module_not_allowed" in meta["access"], meta["access"])
json.dumps(meta)
mp.register_core_module_preferences_capability()
reg = REGISTERED[-1]
must(reg["id"] == "core.module_preferences" and reg["version"] == "1.2.0" and reg["metadata"]["requires_framework"] == ">=1.17.38", reg)

tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


rows = {r["name"]: r for r in literal("CORE_CONTRACTS") if r.get("area") == "module-preferences"}
must(sorted(rows) == ["delete", "get", "list_for", "set"], "the four Python rows")
must("1.2.0" in rows["set"]["purpose"] and "Requires framework >=1.17.38" in rows["set"]["purpose"], rows["set"]["purpose"])
must("Not audited" not in rows["set"]["purpose"] and "one strict Core audit row" in rows["set"]["purpose"], "set is audited, and says so")
must("audit_failed (503)" in rows["set"]["purpose"] and "module_not_allowed (403)" in rows["set"]["purpose"], "set names the two new refusals")
must("object_type module_preference" in rows["set"]["purpose"] and "never the value" in rows["set"]["purpose"], "set names the row and says no value")
must("one strict Core audit row" in rows["delete"]["purpose"] and "audit_failed (503)" in rows["delete"]["purpose"], "delete is audited")
must("A read is not audited" in rows["get"]["purpose"] and "A read is not audited" in rows["list_for"]["purpose"], "reads are not audited, and say so")
must("module_not_allowed (403)" in rows["get"]["purpose"], "get names module_not_allowed")
rule = next(r for r in literal("RULES") if r.startswith("Module user preferences (core.module_preferences 1.2.0"))
for needle in (">=1.17.38", "audit", "503 audit_failed", "module_not_allowed", "What Core can and cannot prove about the module id"):
    must(needle in rule, f"the rule names {needle}")
http = literal("HTTP_CONTRACT_DETAILS")
item = http["/api/tfd/module-preferences/<str:module_id>/<str:name>/"]
must("503" in item["PUT"]["errors"] and "audit_failed" in item["PUT"]["errors"]["503"], "PUT names audit_failed")
must("503" in item["DELETE"]["errors"] and "module_not_allowed" in item["PUT"]["errors"]["403"], "the HTTP rows name the refusals")
must("since 1.17.38" in item["PUT"]["audit"] and "never the value" in item["PUT"]["audit"], item["PUT"]["audit"])
must("module_not_allowed" in http["/api/tfd/module-preferences/<str:module_id>/"]["GET"]["errors"]["403"], "GET names module_not_allowed")
must("What Core can and cannot prove about the module id" in http["/api/tfd/module-preferences/<str:module_id>/"]["GET"]["module_id"],
     "the GET row points at the heading")

# ------------------------------------------------------------------------------------------------ 10. the docs and the release notes: the wording of CQ109, CQ114 and CQ115
doc = (ROOT / "docs" / "module-preferences.md").read_text(encoding="utf-8")
for needle in ("## What Core can and cannot prove about the module id", "## Audit", "module_not_allowed", "audit_failed",
               "core.module_preferences 1.2.0", ">=1.17.38", "AD-19 condition 5", "AD-26", "AD-31 condition 2", "AD-36", "not recorded"):
    must(needle in doc, f"docs/module-preferences.md names {needle}")
must("## Not audited" not in doc and "Not audited" not in doc.replace("**What is not audited.**", ""), "the 'Not audited' section is gone")
must("Core cannot prove" in doc and "Core can prove" in doc, "the can and cannot prove lists are there")
must("source` `browser` and `module_verified` `false`" in doc or "`module_verified` is `false`" in doc or "`module_verified` `false`" in doc,
     "the browser claim is recorded as a claim")
notes = (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.38.md").read_text(encoding="utf-8")  # moved to docs/releases at 1.17.39
must("What Core can and cannot prove about the module id" in notes, "the release notes carry the can and cannot prove heading")
must("AD-36" in notes and "not recorded" in notes, "the release notes say AD-36 is not recorded")
must("Module-facing" in notes or "module-facing" in notes, "the release notes have a module-facing heading")
for text_name, text in (("docs", doc), ("release notes", notes), ("module_preferences.py", (APP / "module_preferences.py").read_text(encoding="utf-8"))):
    must("verified browser" not in text.lower(), f"{text_name} makes no verified-browser claim")
source = (APP / "module_preferences.py").read_text(encoding="utf-8")
must("Nothing here is audited" not in source and "Reads are not audited" in source, "the module docstring says what is audited now")

print("[TEST] PASS module preferences audit 1.17.38")
