"""1.17.23 regression: the role-create audit row is never skipped silently.

The 1.17.22 wrapper found the new role with "newest pk, then pk greater than it, then the name". On an empty Role table the
lookup was skipped, a blank name was never found, and a create that left no match wrote no row without saying so. The wrapper now
compares the set of role ids before and after Tactical's create inside the same transaction. One new id is the created role. When
a concurrent create added more, those whose name equals the request name are kept and exactly one must remain. Zero new ids or an
ambiguous set raises, and the transaction rolls Tactical's create back, as a failed audit write does. A failed Tactical answer
writes nothing. The strict ``role_scope`` row is unchanged. The stubs are those of tests/role-scope-lists-1.17.22.py; the real
transaction rollback is dev server only (tests/role-create-runtime-1.17.23.py).
"""
from __future__ import annotations

import contextlib
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

    def filter(self, pk=None, pk__gt=None, pk__in=None, name=None):
        rows = [r for r in self.rows if (pk is None or r.pk == int(pk)) and (pk__gt is None or r.pk > pk__gt)
                and (pk__in is None or r.pk in pk__in) and (name is None or r.name == name)]
        return _Q(rows)

    def order_by(self, field):
        return _Q(sorted(self.rows, key=lambda r: r.pk, reverse=field.startswith("-")))

    def values_list(self, *fields, flat=False):
        # 1.17.23: the role create wrapper compares the set of ids before and after, so a flat pk list is iterable
        return [r.pk for r in self.rows]

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

    def values_list(self, *fields, flat=False):
        return _Q(Role.ROWS.values()).values_list(*fields, flat=flat)


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



def reset(rows=True):
    Role.ROWS.clear()
    if rows:
        Role.ROWS.update({10: Role(10, "Helpdesk", clients=[1, 2], sites=[5]), 11: Role(11, "Open")})
    AUDITS.clear()
    FAIL["on"] = False


def adder(*roles, status=200):
    """A stand-in for Tactical's create that adds the given (name, clients, sites) roles and answers with text."""
    def tactical_post(self, request):
        for name, clients, sites in roles:
            pk = max(Role.ROWS, default=0) + 1
            Role.ROWS[pk] = Role(pk, name, clients=clients, sites=sites)
        return Response("Role was added", status_code=status)
    return guard._wrap_role_create(tactical_post)


# 1. a create into an EMPTY Role table writes one role_scope row naming the new id (1.17.22 skipped it silently)
reset(rows=False)
resp = adder(("First", [4], []))(None, Request({"name": "First", "can_view_clients": [4]}))
must(resp.data == "Role was added" and len(AUDITS) == 1, AUDITS)
row = AUDITS[0]
must(row["object_type"] == "role_scope" and row["object_id"] == "1" and row["action"] == "add" and row["strict"] is True and row["module_id"] == "core", row)
must(row["after"]["clients"]["ids"] == [4] and row["before"]["clients"]["count"] == 0, row)

# 2. a blank name that Tactical accepted still finds the role by the id set
for payload in ({"name": "", "can_view_sites": [7]}, {"can_view_sites": [7]}, {"name": None, "can_view_sites": [7]}):
    reset()
    adder(("", [], [7]))(None, Request(dict(payload)))
    must(len(AUDITS) == 1 and AUDITS[0]["object_id"] == "12" and AUDITS[0]["after"]["sites"]["ids"] == [7], (payload, AUDITS))

# 3. an ordinary create names the new id and carries the lists (as in 1.17.22)
reset()
adder(("Branch", [4], []))(None, Request({"name": "Branch", "can_view_clients": [4]}))
must(len(AUDITS) == 1 and AUDITS[0]["object_id"] == "12" and AUDITS[0]["after"]["clients"]["ids"] == [4], AUDITS)
# an unrestricted new role has nothing to audit
reset()
adder(("Everything", [], []))(None, Request({"name": "Everything"}))
must(AUDITS == [], AUDITS)

# 4. two same-named roles created at once: the rows hold both, the wrapper takes the one it can tell apart by name
reset()
adder(("Twin", [4], []), ("Other", [9], []))(None, Request({"name": "Twin", "can_view_clients": [4]}))
must(len(AUDITS) == 1 and AUDITS[0]["object_id"] == "12" and AUDITS[0]["after"]["clients"]["ids"] == [4], AUDITS)
reset()
adder(("Other", [9], []), ("Twin", [4], []))(None, Request({"name": "Twin", "can_view_clients": [4]}))
must(len(AUDITS) == 1 and AUDITS[0]["object_id"] == "13", AUDITS)  # the later id, matched by name


def refused(factory, payload, label):
    before = {pk: r.name for pk, r in Role.ROWS.items()}
    AUDITS.clear()
    try:
        factory(None, Request(payload))
    except RuntimeError as exc:
        must("exactly one new role" in str(exc), f"{label}: {exc}")
    else:
        raise AssertionError(f"{label}: the create was accepted")
    must(AUDITS == [] and {pk: r.name for pk, r in Role.ROWS.items()} == before, f"{label}: no row, and the stub transaction rolled the roles back")


# 5. a create that adds no role raises and rolls back (no row, no role)
reset()
refused(adder(), {"name": "Ghost"}, "no new role")
reset(rows=False)
refused(adder(), {"name": "Ghost"}, "no new role, empty table")

# 6. a create that adds two roles with different names, neither matching, raises
reset()
refused(adder(("A", [1], []), ("B", [2], [])), {"name": "Neither"}, "two roles, none matches")
# two roles that both match the request name are ambiguous too
reset()
refused(adder(("Twin", [1], []), ("Twin", [2], [])), {"name": "Twin"}, "two roles with the request name")
# two new roles and a blank name cannot be told apart
reset()
refused(adder(("A", [1], []), ("B", [2], [])), {"name": ""}, "two roles, blank name")

# 7. a failed Tactical answer writes nothing and changes nothing the wrapper must undo
reset()
before_ids = set(Role.ROWS)
resp = adder(status=400)(None, Request({"name": "Bad"}))
must(resp.status_code == 400 and AUDITS == [] and set(Role.ROWS) == before_ids, "a 400 answer: no row")
reset()
resp = adder(("Weird", [4], []), status=400)(None, Request({"name": "Weird"}))
must(AUDITS == [], "a 400 answer writes no row even if the original added something")

# 8. the audit row is still strict: a failing audit write rolls the new role back
reset()
FAIL["on"] = True
try:
    adder(("Doomed", [], [1]))(None, Request({"name": "Doomed", "can_view_sites": [1]}))
except RuntimeError as exc:
    must("persisted Core audit record" in str(exc), str(exc))
else:
    raise AssertionError("role create accepted without an audit row")
must(not any(r.name == "Doomed" for r in Role.ROWS.values()), "the new role was rolled back")

# 9. the superuser guard is unchanged
reset()
try:
    adder(("Root", [], []))(None, Request({"name": "Root", "is_superuser": True}))
except PermissionDenied:
    pass
else:
    raise AssertionError("non-superuser created a superuser role")

# 10. source: no newest-pk lookup is left, and the id-set comparison is there
source = MODULE.read_text(encoding="utf-8")
create = source.split("def _wrap_role_create")[1].split("def _wrap_role_update")[0]
must("pk__gt" not in create and "newest" not in create and "ids_before" in create and "_created_role_id" in create, "id-set comparison")
must("A role create must be matched to exactly one new role." in source, "the error text")

print("[TEST] PASS role create audit 1.17.23")
