#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.68 regression (the target-resolver contract): a module-owned target type reads as endpoints.

The real scheduler_target_resolvers.py, resources_adapter.py (on a small fake of Tactical's Agent), scheduler.py, system_actions.py and
system_action_confirmation.py on the stub harness of scheduler-completion-harness-1.17.61.py. Module code is compiled under stub plugin folders so
the real frame walk of caller_identity decides who is calling.

Covered. (1) Registration: only the module's own code may register (Core code and another module are refused); the type may not be one Core reads
itself, must be a plain lowercase word and, once the module has a scheduled action, must be listed in its target_types; a different resolver under the
same key is refused and the same one is accepted again. (2) Resolution fails closed: a list of agent numbers or agent ids resolves; a bad token, an id
that names no endpoint, an ambiguous id, more than MAX_AGENTS ids, a result that is not a list, an exception and a type the module no longer lists
all mean unresolved (None), nothing is guessed or truncated; nothing but the module's own key is read. (3) The adapter: agent_pks_for_identifiers and
agent_rows_in_scope (stored scope and live person) on a fake Agent; a module-owned type resolves through agent_pks_for_scheduler_targets only
with a module id and a resolver. (4) A scoped person may create a resolver-backed schedule only when every resolved endpoint is in their scope (one
miss refuses), a scheduler manager keeps the shortcut, a type with no resolver keeps the rule 'unrestricted only'. (5) A system action on such a
schedule: creation and run no longer answer targets_unresolved, an endpoint outside the resolved set is still outside_targets, and a type with no
resolver is still targets_unresolved. (6) The browser routes pass the module id (read as source).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"

BOTH = ("can_manage_winupdates", "can_run_bulk")
alice, bob = User("alice"), User("bob")
roots = {}
MANAGER = {"alice": False, "bob": False}
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: True
views._native_scheduler_manager = lambda user: MANAGER.get(user.username, False)
views._can_access_target_scope = lambda user, targets, strict=False, **kw: True


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
_orig_save = Schedule.save


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    _orig_save(self, update_fields)


Schedule.save = _save


def handler(context):
    return {"ok": True}


# ---- a small fake of Tactical's Agent model, enough for the two adapter functions this release adds
class FQ:
    def __init__(self, **kw):
        self.kw, self.parts = kw, None

    def __or__(self, other):
        node = FQ()
        node.parts = [self, other]
        return node

    def test(self, row):
        if self.parts:
            return any(part.test(row) for part in self.parts)
        for key, wanted in self.kw.items():
            name, _, op = key.rpartition("__")
            must(op == "in", key)
            if row[name] not in wanted:
                return False
        return True


class FQS:
    def __init__(self, rows):
        self.rows = list(rows)

    def all(self):
        return FQS(self.rows)

    def filter(self, *qs, **kw):
        return FQS(r for r in self.rows if all(q.test(r) for q in qs) and FQ(**kw).test(r))

    def order_by(self, *fields):
        return FQS(sorted(self.rows, key=lambda r: r[fields[0]]))

    def values_list(self, *fields):
        return [tuple(r[f] for f in fields) for r in self.rows]

    def filter_by_role(self, user):
        d = DESCRIPTORS[user.username]
        if d["unrestricted"]:
            return self
        return FQS(r for r in self.rows if r["site__client_id"] in d["whole_client_ids"] or r["site_id"] in d["site_ids"])


AGENTS = [
    {"pk": 1, "agent_id": "AAAAAAAAAAAAAAAAAAAAA", "hostname": "h1", "plat": "windows", "site__client_id": 10, "site_id": 100},
    {"pk": 2, "agent_id": "BBBBBBBBBBBBBBBBBBBBB", "hostname": "h2", "plat": "windows", "site__client_id": 10, "site_id": 101},
    {"pk": 3, "agent_id": "CCCCCCCCCCCCCCCCCCCCC", "hostname": "h3", "plat": "linux", "site__client_id": 20, "site_id": 200},
    {"pk": 4, "agent_id": "3", "hostname": "h4", "plat": "windows", "site__client_id": 30, "site_id": 300},  # its agent id is the text "3": ambiguous with endpoint number 3
    {"pk": 5, "agent_id": "EEEEEEEEEEEEEEEEEEEEE", "hostname": "h5", "plat": "windows", "site__client_id": 30, "site_id": 301},
]
FakeAgent = type("FakeAgent", (), {"objects": FQS(AGENTS)})
sys.modules["django.db"].IntegrityError = type("IntegrityError", (Exception,), {})
spec = importlib.util.spec_from_file_location("tec_tac.resources_adapter_real", APP / "resources_adapter.py")
adapter = importlib.util.module_from_spec(spec)
sys.modules["tec_tac.resources_adapter_real"] = adapter
spec.loader.exec_module(adapter)
adapter.Q = FQ
adapter._models = lambda: (None, None, FakeAgent)

REGISTER_SRC = (
    "def register(resolvers, module_id, target_type, fn):\n"
    "    return resolvers.register_target_resolver(module_id, target_type, fn)\n"
)
modules = {}


def fresh():
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    sched._ACTIONS.clear()
    roots["maintenance"] = plugin("maintenance", system_actions=[])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.install"])
    roots["patching"] = plugin("patching", system_actions=["patching.scan"])
    for name in ("maintenance", "patchmanagement"):
        modules[name] = compile_as(roots[name] / "apps.py", REGISTER_SRC)
    HONOURED["patchmanagement"] = "patching"
    sched.register_scheduled_action(id="maintenance.run", module_id="maintenance", label="run", handler=handler, target_types=("none", "profile"))
    sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=handler, target_types=("none", "endpoint", "profile"))
    sa.register_system_action("patching.scan", "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
    for who in ("alice", "bob"):
        FLAGS[who] = set(BOTH)
        SCOPE[who] = {1, 2, 3, 4, 5}
        MANAGER[who] = False
    resolvers._pks_for = lambda identifiers: adapter.agent_pks_for_identifiers(identifiers=identifiers)


def register(module, target_type="profile", fn=None):
    return modules[module]["register"](resolvers, module, target_type, fn or (lambda targets: [1, 2]))


def refused(call, kind=resolvers.TargetResolverRegistrationError):
    try:
        call()
    except kind as exc:
        return exc
    raise AssertionError("the call was accepted")


# ---- (1) registration
fresh()
def profile_resolver(targets):
    return [1, 2]


register("maintenance", "profile", profile_resolver)
register("maintenance", "profile", profile_resolver)  # the same resolver again is accepted
refused(lambda: register("maintenance", "profile", lambda targets: [3]))  # a different one under the same key is refused
must(resolvers.has_resolver("maintenance", "profile") and not resolvers.has_resolver("maintenance", "group") and not resolvers.has_resolver("patching", "profile"), "has_resolver")
refused(lambda: resolvers.register_target_resolver("maintenance", "profile", profile_resolver))  # Core's own code is not a module
refused(lambda: modules["patchmanagement"]["register"](resolvers, "maintenance", "profile", profile_resolver))  # another module may not register for it
for native in ("none", "client", "clients", "site", "endpoint", "endpoints", "agent", "agents", "dynamic", "", "Client "):
    refused(lambda native=native: register("maintenance", native))
for bad in ("Profile!", "9lives", "a b", "x" * 80, None, 5):
    refused(lambda bad=bad: register("maintenance", bad))
refused(lambda: register("maintenance", "profile2", None))  # not callable
refused(lambda: register("maintenance", "group"))  # no scheduled action of the module lists it
resolvers._clear_for_tests()
ENABLED["maintenance"] = False
refused(lambda: register("maintenance", "profile"))  # a disabled module is not a caller
ENABLED["maintenance"] = True
resolvers._clear_for_tests()
register("maintenance", "profile", profile_resolver)
must(sched.get_scheduled_action("maintenance.run").target_types == ("none", "profile"), "the registered action is unchanged")
sched._ACTIONS.pop("maintenance.run")
must(not resolvers.has_resolver("maintenance", "profile"), "the type is checked again at use: no action lists it any more")
must(resolvers.resolve_agent_pks("maintenance", {"type": "profile", "ids": [1]}) is None, "so it does not resolve")
print("       only the module's own code registers; native, odd and undeclared types, a conflicting resolver and a disabled module are refused; the type is checked again at use")

# ---- (2) resolution fails closed
fresh()
LISTING = {"value": [1, 2]}
register("maintenance", "profile", lambda targets: LISTING["value"])
T = {"type": "profile", "ids": [7]}


def pks():
    return resolvers.resolve_agent_pks("maintenance", T)


must(pks() == {1, 2}, pks())
LISTING["value"] = ["AAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBB", 1]
must(pks() == {1, 2}, "agent ids and numbers mix and repeat safely")
LISTING["value"] = iter([2, 5])
must(pks() == {2, 5}, "any iterable")
LISTING["value"] = []
must(pks() == set(), "a resolver that names no endpoint reaches nothing")
for label, value in (("a bad token", [1, 2.5]), ("a bool", [True]), ("a none", [None]), ("zero", [0]), ("an empty text", [" "]), ("a huge text", ["x" * 80]), ("a dict", {"a": 1}),
                     ("a text", "AAAAAAAAAAAAAAAAAAAAA"), ("none", None), ("an id that names no endpoint", [1, 99]), ("an agent id that names none", ["ZZZZZZZZZZZZZZZZZZZZZ"]),
                     ("an ambiguous id (endpoint 3 and the agent id '3')", ["3"])):
    LISTING["value"] = value
    must(pks() is None, (label, pks()))
LISTING["value"] = [3]
must(pks() == {3}, "a whole number is an endpoint number, even when an agent id spells the same digits")
register_calls = []
register("maintenance", "boom", lambda targets: 1 / 0) if False else None
sched.register_scheduled_action(id="maintenance.other", module_id="maintenance", label="other", handler=handler, target_types=("boom", "flood"))
register("maintenance", "boom", lambda targets: 1 / 0)
must(resolvers.resolve_agent_pks("maintenance", {"type": "boom"}) is None, "an exception means unresolved")
register("maintenance", "flood", lambda targets: range(sa.MAX_AGENTS + 1))
must(resolvers.resolve_agent_pks("maintenance", {"type": "flood"}) is None, "more than MAX_AGENTS ids is unresolved, never truncated")
seen = []
resolvers._RESOLVERS[("maintenance", "profile")] = lambda targets: (seen.append(targets), targets.update(ids=[999]), [1])[2]
original = {"type": "profile", "ids": [7]}
must(resolvers.resolve_agent_pks("maintenance", original) == {1} and original == {"type": "profile", "ids": [7]}, "the resolver gets a copy and cannot change the schedule's targets")
must(resolvers.resolve_agent_pks("maintenance", {"type": "client", "ids": [1]}) is None and resolvers.resolve_agent_pks("maintenance", {"type": "none"}) is None and resolvers.resolve_agent_pks("maintenance", "x") is None, "a native type is never resolved here")
must(resolvers.resolve_agent_pks("patching", T) is None, "another module's key is never read")
print("       numbers and agent ids resolve; a bad token, a missing, an ambiguous or a huge answer, a non-list and an exception are all unresolved; the resolver gets a copy")

# ---- (3) the adapter on a fake Agent
must(adapter.agent_pks_for_identifiers(identifiers=[1, "BBBBBBBBBBBBBBBBBBBBB"]) == {1, 2}, "identifiers")
for bad in ([99], ["nope"], ["3"], [1, "3"]):
    refused(lambda bad=bad: adapter.agent_pks_for_identifiers(identifiers=bad), adapter.TacticalResourceAdapterError)
snapshot = {"v": 1, "scope": {"unrestricted": False, "whole_client_ids": [10], "site_ids": [301]}, "flags": []}
rows = adapter.agent_rows_in_scope(pks=[1, 2, 3, 5], snapshot=snapshot, limit=10)
must([r["pk"] for r in rows] == [1, 2, 5] and set(rows[0]) == {"pk", "agent_id", "hostname", "platform", "client_id", "site_id"} and rows[2]["site_id"] == 301, rows)
must([r["pk"] for r in adapter.agent_rows_in_scope(pks=None, snapshot=snapshot, limit=10)] == [1, 2, 5], "every endpoint of the stored scope")
must(len(adapter.agent_rows_in_scope(pks=None, snapshot=snapshot, limit=2)) == 3, "limit + 1 rows come back so the caller can refuse; nothing is truncated silently")
must(adapter.agent_rows_in_scope(pks=[1], snapshot={"v": 1, "scope": {"unrestricted": False, "whole_client_ids": [], "site_ids": []}, "flags": []}, limit=5) == [], "an empty snapshot reaches nothing")
must([r["pk"] for r in adapter.agent_rows_in_scope(pks=[3, 4], snapshot={"v": 1, "scope": {"unrestricted": True, "whole_client_ids": [], "site_ids": []}, "flags": []}, limit=5)] == [3, 4], "unrestricted")
DESCRIPTORS["alice"] = {"unrestricted": False, "whole_client_ids": [20], "site_ids": []}
must([r["pk"] for r in adapter.agent_rows_in_scope(pks=[1, 3], user=alice, limit=5)] == [3], "a live person")
refused(lambda: adapter.agent_rows_in_scope(pks=[1], limit=5), adapter.TacticalResourceAdapterError)
refused(lambda: adapter.agent_rows_in_scope(pks=[1], snapshot=snapshot, user=alice, limit=5), adapter.TacticalResourceAdapterError)
fresh()
register("maintenance", "profile", lambda targets: [1, 3])
must(adapter.agent_pks_for_scheduler_targets(targets={"type": "profile", "ids": [7]}) is None, "no module id: a module-owned type stays unresolved")
must(adapter.agent_pks_for_scheduler_targets(targets={"type": "profile", "ids": [7]}, module_id="maintenance") == ({1, 3}, 0), "with a module id and a resolver it resolves")
must(adapter.agent_pks_for_scheduler_targets(targets={"type": "profile", "ids": [7]}, module_id="patching") is None, "another module has no resolver for the type")
must(adapter.agent_pks_for_scheduler_targets(targets={"type": "endpoint", "ids": [1, 2]}) == ({1, 2}, 0), "a native type resolves as before")
print("       the adapter resolves identifiers, bounds rows by a stored scope or a person, refuses ambiguity, and a module-owned type resolves only with a module id and a resolver")

# ---- (4) who may create a resolver-backed schedule
fresh()
register("maintenance", "profile", lambda targets: [1, 2])
resources = sys.modules["tec_tac.resources_adapter"]
resources.agent_pks_in_role_scope = lambda *, user, pks: bool(pks) and set(pks) <= SCOPE.get(user.username, set())
SCOPE["alice"], SCOPE["bob"] = {1, 2, 3}, {1}
must(sched._resolver_scope_check(alice, "maintenance", T) is True, "every resolved endpoint is in alice's scope")
must(sched._resolver_scope_check(bob, "maintenance", T) is False, "one miss refuses")
MANAGER["bob"] = True
must(sched._resolver_scope_check(bob, "maintenance", T) is True and sched._resolver_scope_check(bob, "maintenance", T, strict=True) is False, "a scheduler manager keeps the shortcut, but never for a takeover (strict)")
must(sched._resolver_scope_check(alice, "maintenance", {"type": "other"}) is None and sched._resolver_scope_check(alice, "maintenance", {"type": "endpoint", "ids": [1]}) is None and sched._resolver_scope_check(alice, "patching", T) is None,
     "no resolver for the type or module: the old rule applies")
resolvers._RESOLVERS[("maintenance", "profile")] = lambda targets: (_ for _ in ()).throw(RuntimeError("module bug"))
must(sched._resolver_scope_check(alice, "maintenance", T) is False, "an unresolvable type is False (and not the old unrestricted-only rule)")
resolvers._RESOLVERS[("maintenance", "profile")] = lambda targets: []
must(sched._resolver_scope_check(bob, "maintenance", T, strict=True) is False, "a resolver that names no endpoint cannot be checked against a scope, so a takeover is refused (1.17.69, AD-42)")
SCOPE["alice"], SCOPE["bob"] = {1, 2, 3}, {1}
MANAGER["bob"] = False
resolvers._RESOLVERS[("maintenance", "profile")] = lambda targets: [1, 2]
action = sched.get_scheduled_action("maintenance.run")
sched._check_person_may_schedule(alice, action, T)  # no exception
try:
    sched._check_person_may_schedule(bob, action, T)
    raise AssertionError("bob's scope does not cover endpoint 2")
except sched.SchedulerNotAllowed:
    pass
print("       a scoped person may use a profile target only when every resolved endpoint is in their scope; a type with no resolver keeps the old rule; a takeover never takes the manager shortcut")

# ---- (5) a system action on such a schedule (the real adapter answers, so the whole chain from the resolver to the run is the real one)
fresh()
resources.agent_pks_for_scheduler_targets = adapter.agent_pks_for_scheduler_targets
roots["patching"] = plugin("patching", system_actions=["patching.scan", "patching.handler"])
modules["patching"] = compile_as(roots["patching"] / "apps.py", REGISTER_SRC)
register("maintenance", "profile", lambda targets: [1, 2])
modules["patching"]["register"](resolvers, "patching", "profile", lambda targets: [1, 2])
sa._ACTIONS.clear()
sa.register_system_action("patching.scan", "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
sa.register_system_action("patching.handler", "patching", "Handler", "winupdate.scan", BOTH)
SCOPE["alice"] = {1, 2, 3}
must(sa._target_pks({"type": "profile", "ids": [7]}, "maintenance") == ({1, 2}, 0) and sa._target_pks({"type": "profile", "ids": [7]}) is None, "_target_pks passes the module id")
scan = sched._ACTIONS["patching.scan"] = sched.ScheduledAction("patching.scan", "patching", "scan", handler, "", ("none", "endpoint", "profile"))
info = conf._controls(alice, scan, {"type": "profile", "ids": [7]}, None)
must(info["total"] == 2, info)
try:
    conf._controls(alice, scan, {"type": "other", "ids": [7]}, None)
    raise AssertionError("no resolver for the type")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "targets_unresolved", exc.reason)
info = conf._controls(alice, scan, {"type": "profile", "ids": [7]}, None, resolver_module="maintenance")
must(info["total"] == 2, "a delegation grant names the module that owns the profile type")
SCOPE["alice"] = {1}
try:
    conf._controls(alice, scan, {"type": "profile", "ids": [7]}, None)
    raise AssertionError("endpoint 2 is outside alice's scope")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "out_of_scope", exc.reason)
SCOPE["alice"] = {1, 2, 3}
print("       creation reads a module-owned type through its resolver, refuses an endpoint outside the person's scope, and stays targets_unresolved with no resolver")

CFG = {"agents": [1, 2]}
HANDLER = "def handler(context):\n    return sa.run_system_action(context, action_id='patching.handler', agent_ids=CFG['agents'])\n"
ns = compile_as(roots["patching"] / "handlers.py", HANDLER, sa=sa, CFG=CFG)
sched._ACTIONS["patching.handler"] = sched.ScheduledAction("patching.handler", "patching", "handler", ns["handler"], "", ("none", "profile"), timeout_seconds=600)
sched_targets = {"type": "profile", "ids": [7]}


def last_denial():
    rows = [a for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]
    return rows[-1]["metadata"]["reason"] if rows else None


def _row(client):
    return {"agent_id": f"a{client}", "hostname": f"h{client}", "platform": "windows", "client_id": client, "site_id": client * 10}


def _snap(*clients):
    return {"v": 1, "captured_for": "alice", "captured_at": "", "scope": {"unrestricted": False, "whole_client_ids": list(clients), "site_ids": []}, "flags": []}


AGENT_ROWS.update({1: _row(1), 2: _row(1), 3: _row(9)})


def profile_run(stored=None):
    run = make_run("patching.handler", "patching", user=alice, owner="user", targets=sched_targets)
    run.schedule.created_by_username = "alice"
    run.schedule.creation_scope = _snap(1) if stored is None else stored
    return run


result = go(profile_run())
must(isinstance(result, dict) and result.get("outcome") == "queued" and result["agents"] == 2 and len(TASK_CALLS) == 1, result)
CFG["agents"] = [1, 2, 3]
go(profile_run())
must(last_denial() == "outside_targets", AUDITS)
# 1.17.68 (precheck round 0): the resolver's answer is cut to the scope stored when the person saved the schedule
CFG["agents"] = [1, 2, 3]
register("maintenance", "profile", lambda targets: [1, 2, 3])
modules["patching"]["register"](resolvers, "patching", "profile", lambda targets: [1, 2, 3])
del TASK_CALLS[:]
go(profile_run())
must(last_denial() == "out_of_scope" and not TASK_CALLS, "the resolver named endpoint 3 (client 9), which the stored scope never had: " + str(last_denial()))
go(profile_run(stored={}))
must(last_denial() == "creation_scope_unavailable" and not TASK_CALLS, "no stored scope: " + str(last_denial()))
go(profile_run(stored=_snap(1, 9)))
must(len(TASK_CALLS) == 1, "with the whole answer inside the stored scope the run is queued")
register("maintenance", "profile", lambda targets: [1, 2])
modules["patching"]["register"](resolvers, "patching", "profile", lambda targets: [1, 2])
resolvers._clear_for_tests()
CFG["agents"] = [1, 2]
go(profile_run())
must(last_denial() == "targets_unresolved", AUDITS)
print("       a run on a profile schedule is no longer targets_unresolved; an endpoint outside the resolved set is still outside_targets; no resolver is still targets_unresolved")

# ---- (6) the call sites carry the module id (read as source)
views_src = (APP / "scheduler_views.py").read_text(encoding="utf-8")
must('_require_target_scope(request.user, data.get("targets"), payload=True, module_id=action.module_id)' in views_src and views_src.count("module_id=action.module_id)") >= 2, "POST and PATCH")
must("module_id=schedule.module_id" in views_src, "the saved schedule's own module id for read, list, run now")
must("def _require_target_scope(user, targets, *, payload=False, module_id=None, strict=False):" in views_src and "def _can_access_target_scope(user, targets, *, module_id=None, strict=False) -> bool:" in views_src, "the new keywords have defaults, so every old call still works")
sa_src = (APP / "system_actions.py").read_text(encoding="utf-8")
must("resolved = _target_pks(run.targets_snapshot or {}, module_id)" in sa_src, "the run resolves through the run's module")
must("resolved = sa._target_pks(canonical, resolver_module or action.module_id)" in (APP / "system_action_confirmation.py").read_text(encoding="utf-8"), "creation resolves through the action's module")
print("       the browser routes, the confirmation and the run pass the module id; every new keyword has a default")
print("PASS scheduler target resolver 1.17.68")
