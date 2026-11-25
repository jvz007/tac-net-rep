#!/usr/bin/env python3
"""1.18.50 regression: core.access_events 1.0.0, the hook that says which people are affected when a role, its client and site scope or a user
changes. The real framwork/tec_tac/access_events.py under the stubs of tests/probe_transport_harness.py (the cache, django.dispatch, the
transaction) and a small stand-in for Tactical's Role, User and the m2m through classes. Django is not installed on this PC.

Covered: the marker and the signal (ids cleaned and capped, the reason list, the time, the TTL above the tunnel hard cap, send_robust so a faulty
receiver never stops the others, after-commit delivery inside a transaction, never raises on a cache fault); every receiver (role save, role
delete, m2m forward add/remove/clear and reverse add/remove/pre_clear for clients and sites, extension permission save and delete, user save with
and without update_fields, user delete) marks exactly the affected people and sends the signal once with the right reason; created rows fire
nothing; Tactical's role cache key is deleted; a receiver that raises does not reach Tactical's save; connect_receivers is idempotent; apps.ready
holds its own guarded blocks and keeps CRLF; the capability registers with its two operations.
"""
from __future__ import annotations

import ast
import importlib.util
import logging
import sys
import types
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
must, reset, CACHE, WALL, TXN, ae = H.must, H.reset, H.CACHE, H.WALL, H.TXN, H.ae
logging.getLogger("tec_tac.access_events").addHandler(logging.NullHandler())
logging.getLogger("tec_tac.access_events").propagate = False  # several cases log a warning on purpose
APP = H.APP


# ------------------------------------------------------------------------------------------------ Tactical's models, reduced
class Sig:
    """A Django model signal: receivers keyed by dispatch_uid (a second connect with the same uid changes nothing), matched by sender."""

    def __init__(self):
        self.rows = {}

    def connect(self, receiver, sender=None, weak=True, dispatch_uid=None):
        self.rows.setdefault(dispatch_uid or id(receiver), (receiver, sender))

    def send(self, sender, **kw):
        for receiver, wanted in list(self.rows.values()):
            if wanted is None or wanted is sender:
                receiver(sender=sender, **kw)


ROLES = {1: "Admin", 2: "Tech"}
PEOPLE = {1: [10, 11], 2: [20], 3: []}  # role id -> user ids
FAULT = {"users": False}


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def values_list(self, field, flat=False):
        return list(self.rows)


class _RoleManager:
    def filter(self, pk__in=()):
        return _Query([ROLES[i] for i in pk__in if i in ROLES])


class _UserManager:
    def filter(self, role_id=None):
        if FAULT["users"]:
            raise RuntimeError("database down")
        return _Query(PEOPLE.get(role_id, []))


class Role:
    objects = _RoleManager()


class ClientsThrough:
    pass


class SitesThrough:
    pass


Role.can_view_clients = SimpleNamespace(through=ClientsThrough)
Role.can_view_sites = SimpleNamespace(through=SitesThrough)


class User:
    objects = _UserManager()


class ExtensionRolePermission:
    pass


post_save, pre_delete, post_delete, m2m_changed = Sig(), Sig(), Sig(), Sig()
H.stub("accounts")
H.stub("accounts.models", Role=Role, User=User)
H.stub("django.db.models")
H.stub("django.db.models.signals", post_save=post_save, pre_delete=pre_delete, post_delete=post_delete, m2m_changed=m2m_changed)
H.stub("tec_tac.models", ExtensionRolePermission=ExtensionRolePermission)
H.stub("tacticalrmm")
H.stub("tacticalrmm.constants", ROLE_CACHE_PREFIX="role_")


def role(pk, name=None):
    return SimpleNamespace(pk=pk, name=name or ROLES.get(pk, "x"))


def seen():
    return list(ae.access_changed.sent)


def marked(user_id):
    return CACHE.data.get(ae.marker_key(user_id))


def fresh():
    reset()
    for sig in (post_save, pre_delete, post_delete, m2m_changed):
        sig.rows.clear()
    FAULT["users"] = False
    WALL[0] = 1_000_000.0


# ---------------------------------------------------------------- notify: markers and the signal
fresh()
must(ae.REASONS == ("role_permissions", "role_scope", "user_changed", "user_removed"), ae.REASONS)
must(ae.notify_access_changed([10, 11, 10], "role_scope") == 2, "repeats are dropped")
must(marked(10) == WALL[0] and marked(11) == WALL[0] and marked(12) is None, "one marker per person, holding the time")
must(CACHE.timeouts[ae.marker_key(10)] == ae.MARKER_SECONDS, "the marker has its TTL")
must(ae.MARKER_SECONDS > H.tun.CAP_SECONDS_MAX, "above the hard cap")
must(seen() == [{"user_ids": frozenset({10, 11}), "reason": "role_scope"}], seen())
must(ae.changed_at(10) == WALL[0] and ae.changed_at(99) is None, "changed_at reads the marker")
WALL[0] += 60
ae.notify_access_changed([10], "user_changed")
must(ae.changed_at(10) == WALL[0] and ae.changed_at(11) < ae.changed_at(10), "the newest change wins")
for bad in (True, False, 0, -4, "7", None, 1.5):
    must(ae.changed_at(bad) is None, ("changed_at refuses", bad))
fresh()
must(ae.notify_access_changed([True, 0, -1, "5", None, 2.0], "role_scope") == 0 and not seen() and not CACHE.data, "no valid id: nothing is written or sent")
must(ae.notify_access_changed([10], "something_else") == 0 and not seen() and not CACHE.data, "a reason off the list sends nothing")
must(ae.notify_access_changed(5, "role_scope") == 0, "not iterable")
must(ae.notify_access_changed(range(1, 6001), "role_scope") == ae.MAX_USER_IDS == 5000, "the id list is capped")
must(len(seen()[0]["user_ids"]) == 5000 and len([k for k in CACHE.data if k.startswith(ae.MARKER_PREFIX)]) == 5000, "5000 ids, 5000 markers")

# inside a transaction the work waits for the commit
fresh()
TXN.in_atomic_block = True
must(ae.notify_access_changed([10], "role_scope") == 1, "taken")
must(not seen() and marked(10) is None and len(TXN.pending) == 1, "nothing before the commit")
TXN.pending.pop()()
must(marked(10) == WALL[0] and len(seen()) == 1, "delivered at the commit")
TXN.in_atomic_block = False

# a receiver that raises does not stop the others, and notify never raises
fresh()
got = []
ae.access_changed.connect(lambda **kw: (_ for _ in ()).throw(RuntimeError("receiver bug")))
ae.access_changed.connect(lambda **kw: got.append(kw["user_ids"]))
must(ae.notify_access_changed([10], "role_scope") == 1 and got == [frozenset({10})], "the next receiver still ran")
# a cache fault: nothing raises
fresh()
CACHE.down = True
must(ae.notify_access_changed([10], "role_scope") in (0, 1), "no exception")
must(ae.changed_at(10) is None, "a cache fault reads as None")
must(ae.mark_changed([10]) == 0, "mark_changed survives a cache fault")
CACHE.down = False
# mark_changed writes markers and sends no signal
fresh()
must(ae.mark_changed([10, True, 0, 11]) == 2 and marked(10) == WALL[0] and not seen(), "markers, no signal")

# ---------------------------------------------------------------- connect_receivers
fresh()
must(ae.connect_receivers() is True, "connected")
counts = {name: len(sig.rows) for name, sig in (("post_save", post_save), ("pre_delete", pre_delete), ("post_delete", post_delete), ("m2m", m2m_changed))}
must(counts == {"post_save": 3, "pre_delete": 1, "post_delete": 2, "m2m": 2}, counts)
ae.connect_receivers()
must({name: len(sig.rows) for name, sig in (("post_save", post_save), ("pre_delete", pre_delete), ("post_delete", post_delete), ("m2m", m2m_changed))} == counts, "a second call changes nothing")
must(all(uid.startswith("tec-tac-access-events-") for sig in (post_save, pre_delete, post_delete, m2m_changed) for uid in sig.rows), "fixed dispatch uids")


def last():
    return seen()[-1] if seen() else None


def expect(label, users, reason, count=1):
    must(len(seen()) == count, (label, "signals sent", seen()))
    must(last()["user_ids"] == frozenset(users) and last()["reason"] == reason, (label, last()))
    for user in users:
        must(marked(user) == WALL[0], (label, "marker", user))


def nothing(label):
    must(not seen() and not [k for k in CACHE.data if k.startswith(ae.MARKER_PREFIX)], (label, seen()))


def clear():
    CACHE.data.clear()
    ae.access_changed.sent.clear()


# role save and delete
post_save.send(Role, instance=role(1), created=True)
nothing("a new role holds nobody")
post_save.send(Role, instance=role(1), created=False)
expect("role saved", [10, 11], "role_permissions")
clear()
pre_delete.send(Role, instance=role(2))
expect("role deleted", [20], "role_permissions")
clear()
post_save.send(Role, instance=role(3), created=False)
nothing("a role nobody holds")

# m2m, forward: the instance is the role
for through in (ClientsThrough, SitesThrough):
    for action in ("post_add", "post_remove", "post_clear"):
        clear()
        CACHE.data["role_Admin"] = "cached role object"
        m2m_changed.send(through, instance=role(1), action=action, reverse=False, pk_set={5} if action != "post_clear" else None)
        expect(f"{through.__name__} {action} forward", [10, 11], "role_scope")
        must("role_Admin" not in CACHE.data, "Tactical's role cache key is deleted so a re-check cannot read the old role")
    for action in ("pre_clear", "pre_add", "pre_remove"):
        clear()
        m2m_changed.send(through, instance=role(1), action=action, reverse=False, pk_set={5})
        nothing(f"{through.__name__} {action} forward")


# m2m, reverse: the instance is a client or a site; pk_set holds role ids
def holder(accessor, role_ids):
    return SimpleNamespace(**{accessor: _Query(role_ids)})


for through, accessor in ((ClientsThrough, "role_clients"), (SitesThrough, "role_sites")):
    for action in ("post_add", "post_remove"):
        clear()
        CACHE.data["role_Admin"] = CACHE.data["role_Tech"] = "cached"
        m2m_changed.send(through, instance=holder(accessor, []), action=action, reverse=True, pk_set={1, 2})
        expect(f"{accessor} {action} reverse", [10, 11, 20], "role_scope")
        must("role_Admin" not in CACHE.data and "role_Tech" not in CACHE.data, "both roles' cache keys are deleted")
    clear()
    m2m_changed.send(through, instance=holder(accessor, [2]), action="pre_clear", reverse=True, pk_set=None)
    expect(f"{accessor} pre_clear reverse (the roles are read before the clear)", [20], "role_scope")
    clear()
    m2m_changed.send(through, instance=holder(accessor, [2]), action="post_clear", reverse=True, pk_set=None)
    nothing(f"{accessor} post_clear reverse")
    clear()
    m2m_changed.send(through, instance=holder(accessor, []), action="pre_clear", reverse=True, pk_set=None)
    nothing(f"{accessor} pre_clear with no role")
    clear()
    m2m_changed.send(through, instance=holder(accessor, []), action="post_add", reverse=True, pk_set=set())
    nothing(f"{accessor} post_add with no role")

# a Tec-Tac extension permission of a role
clear()
post_save.send(ExtensionRolePermission, instance=SimpleNamespace(role_id=1), created=True)
nothing("a new permission row")
post_save.send(ExtensionRolePermission, instance=SimpleNamespace(role_id=1), created=False)
expect("permission saved", [10, 11], "role_permissions")
clear()
post_delete.send(ExtensionRolePermission, instance=SimpleNamespace(role_id=2))
expect("permission deleted", [20], "role_permissions")

# a user
clear()
post_save.send(User, instance=SimpleNamespace(pk=40), created=True, update_fields=None)
nothing("a new user")
post_save.send(User, instance=SimpleNamespace(pk=40), created=False, update_fields=None)
expect("user saved, no update_fields", [40], "user_changed")
clear()
post_save.send(User, instance=SimpleNamespace(pk=40), created=False, update_fields=frozenset({"last_login"}))
nothing("a last_login save")
post_save.send(User, instance=SimpleNamespace(pk=40), created=False, update_fields=frozenset({"dark_mode", "totp_key"}))
nothing("a preference save")
for field in ("role", "role_id", "is_active", "is_superuser", "block_dashboard_login"):
    clear()
    post_save.send(User, instance=SimpleNamespace(pk=41), created=False, update_fields=frozenset({"last_login", field}))
    expect(f"user save naming {field}", [41], "user_changed")
clear()
post_delete.send(User, instance=SimpleNamespace(pk=42))
expect("user deleted", [42], "user_removed")

# a failing receiver never reaches Tactical's save
clear()
FAULT["users"] = True
try:
    post_save.send(Role, instance=role(1), created=False)
    pre_delete.send(Role, instance=role(1))
    m2m_changed.send(ClientsThrough, instance=role(1), action="post_add", reverse=False, pk_set={1})
    post_save.send(ExtensionRolePermission, instance=SimpleNamespace(role_id=1), created=False)
except Exception as error:
    raise AssertionError(f"a receiver raised into Tactical's save: {error!r}") from error
nothing("a database fault marks nobody")
FAULT["users"] = False

# ---------------------------------------------------------------- the capability and apps.py
registered: list = []
stub_caps = types.ModuleType("tec_tac.capabilities")
stub_caps.register_capability = lambda **kw: registered.append(kw) or kw
sys.modules["tec_tac.capabilities"] = stub_caps
ae.register_core_access_events_capability()
must(len(registered) == 1, registered)
cap = registered[0]
must(cap["id"] == "core.access_events" and cap["module_id"] == "core" and cap["version"] == "1.0.0" and list(cap["operations"]) == ["access_changed", "changed_at"], cap["id"])
must(cap["provider"].access_changed is ae.access_changed, "the provider hands out the signal")
fresh()
ae.notify_access_changed([10], "role_scope")
must(cap["provider"].changed_at(user_id=10) == WALL[0], "the provider reads a marker")
meta = ae.access_events_contract_metadata()
must(cap["metadata"] == meta and meta["version"] == "1.0.0" and "framework >=1.18.50" in meta["added_in"], meta)
for reason in ae.REASONS:
    must(reason in meta["signal"], reason)
must(not hasattr(cap["provider"], "notify_access_changed") and not hasattr(cap["provider"], "mark_changed"), "a module cannot raise the signal")

apps = (APP / "apps.py").read_bytes().decode("utf-8")
tree = ast.parse(apps)
guarded = {}
for node in ast.walk(tree):
    if isinstance(node, ast.Try):
        body = ast.dump(ast.Module(body=node.body, type_ignores=[]))
        for name in ("register_core_access_events_capability", "connect_receivers"):
            if f"id='{name}'" in body:
                guarded[name] = (bool(node.handlers), sum(1 for n in ("register_core_access_events_capability", "connect_receivers", "register_core_probe_transport_capability") if f"id='{n}'" in body))
must(guarded == {"register_core_access_events_capability": (True, 1), "connect_receivers": (True, 1)}, ("each in its own guarded block", guarded))
must("\r\n" in apps and apps.count("\n") == apps.count("\r\n"), "apps.py keeps CRLF")

# ---------------------------------------------------------------- the file itself
source = (APP / "access_events.py").read_bytes()
must(b"\r" not in source, "access_events.py is LF")
text = source.decode("utf-8")
top_level = [n for n in ast.parse(text).body if isinstance(n, (ast.Import, ast.ImportFrom))]
must(not any("accounts" in (getattr(n, "module", "") or "") or "tec_tac" in (getattr(n, "module", "") or "") for n in top_level), "Tactical's models are imported inside functions only")
for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
    must(forbidden not in text.lower(), forbidden)
doc = (H.ROOT / "docs" / "access-events.md").read_text(encoding="utf-8")
for needle in ("core.access_events", "access_changed", "changed_at", "role_permissions", "role_scope", "user_changed", "user_removed", "queryset.update", "5000", "send_robust",
               "has_capability", "1.18.50", "backstop"):
    must(needle in doc, "the docs name " + needle)
print("PASS access events 1.18.50")
