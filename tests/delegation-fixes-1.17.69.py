#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.69 regression: the three Medium findings of the 1.17.68-2 review (AD-42, AD-43).

The real delegation.py, caller_identity.py, system_actions.py, scheduler.py and the target resolver registry on the stub harness of
scheduler-completion-harness-1.17.61.py, with the setup of tests/delegation-run-1.17.68.py. Unlike tests/delegation-grant-1.17.68.py nothing replaces
``delegation._person_covers`` with a canned answer: the owner module's resolver decides.

Covered. (1) A grant takeover is judged by the resolver of the OWNER module (maintenance), not of the provider: an engineer whose scope covers every
endpoint the resolver names takes the grant over (one strict row, scope stored again); one who misses an endpoint is refused with takeover_out_of_scope
and the grant, its owner and its stored scope are unchanged. Without a resolver the native strict rule still answers. (2) A resolver that names no
endpoint: refused in strict mode for everyone, refused at creation (``_check_person_may_schedule``) for a person who is neither a scheduler manager nor
unrestricted in Tactical, with its own plain text; the run-time owner check and the non-strict paths keep their old answer; a resolver that names
endpoints keeps every earlier answer. (3) The five delegation.py functions take no caller: a module that imports delegation.py and names another module
is refused wrong_module, Core code and a test file are caller_unverified, a disabled or legacy module is caller_unverified; the capability route and the
five wrappers still work for maintenance and patchmanagement.
"""
from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

RUN_TEST = Path(__file__).resolve().parent / "delegation-run-1.17.68.py"
_prefix = RUN_TEST.read_text(encoding="utf-8").split("# ---- (1) the whole path, with the owner disabled")[0]
exec(compile(_prefix, str(RUN_TEST), "exec"), globals())  # noqa: S102 - the repo's own shared test setup, not user input

MANAGER = {}
UNRESTRICTED = {}
views._native_scheduler_manager = lambda user: MANAGER.get(user.username, False)
views._can_access_target_scope = lambda user, targets, strict=False, **kw: True
resources = sys.modules["tec_tac.resources_adapter"]
resources.tactical_scope_unrestricted = lambda *, user: UNRESTRICTED.get(user.username, False)
carol = User("carol")
T = {"type": "profile", "ids": [7]}
OWNER_PKS = {"value": [1, 2]}
# The real takeover seam asks the scheduler, which asks the owner module's resolver first: nothing is replaced with a canned answer.
deleg._person_covers = lambda person, action, targets: bool(sched._person_covers_targets(person, action, targets))


def setup():
    fresh()
    sched.register_scheduled_action(id="maintenance.profiles", module_id="maintenance", label="Maintenance profiles", handler=lambda context: {"ok": True},
                                    target_types=("none", "profile"), timeout_seconds=600)
    resolvers._RESOLVERS[("maintenance", "profile")] = lambda targets: OWNER_PKS["value"]
    OWNER_PKS["value"] = [1, 2]
    MANAGER.clear()
    UNRESTRICTED.clear()
    carol.is_active = True
    FLAGS["carol"] = set(BOTH)
    SCOPE["carol"] = {1, 2}
    DESCRIPTORS["carol"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    mods["evilmod"] = compile_as(plugin("evilmod", category="premium", system_actions=[]) / "apps.py", EVIL_SRC, deleg=deleg)


EVIL_SRC = (
    "def describe(deleg, request, **kw):\n    return deleg.describe(request, **kw)\n"
    "def register(deleg, request, **kw):\n    return deleg.register(request, **kw)\n"
    "def remove(deleg, **kw):\n    return deleg.remove(**kw)\n"
    "def issue(deleg, context, **kw):\n    return deleg.issue_ticket(context, **kw)\n"
    "def start(deleg, ticket, **kw):\n    return deleg.start(ticket, **kw)\n"
)

# ---- (1) the takeover is judged by the owner module's resolver
setup()
save_grant()  # alice owns it
SCOPE["bob"] = {1, 2}
before = dict(Grant.objects.rows[0].__dict__)
result = save_grant(user=bob)
must(result == {"grant_key": GK, "created": False, "owner_changed": True}, result)
g = Grant.objects.rows[0]
must(g.created_by is bob and g.created_by_username == "bob" and g.creation_scope["captured_for"] == "bob", g.__dict__)
rows = [a for a in AUDITS if a["object_type"] == "delegation_grant" and a["action"] == "modify"]
must(len(rows) == 1 and rows[0]["strict"] is True and rows[0]["metadata"]["owner_changed_to"] == "bob", rows)
# a miss: the controls (which read the confirmed endpoints) pass, the owner's resolver names endpoint 3 as well, bob's scope lacks it
setup()
save_grant()
SCOPE["bob"] = {1, 2}
request = RealRequest(bob)
base = dict(owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=TARGETS, parameters=None)
token = mods["maintenance"]["describe"](sa, request, **base)["confirmation_id"]
OWNER_PKS["value"] = [1, 2, 3]
before = dict(Grant.objects.rows[0].__dict__)
del AUDITS[:]
refused(lambda: mods["maintenance"]["register"](sa, request, grant_key=GK, confirmation_id=token, **base), "takeover_out_of_scope")
g = Grant.objects.rows[0]
must(g.created_by is alice and g.created_by_username == "alice" and g.creation_scope == before["creation_scope"] and g.targets == before["targets"], "owner, scope and targets unchanged")
must(not [a for a in AUDITS if a["object_type"] == "delegation_grant" and a["action"] != "deny"] and len([a for a in AUDITS if a["action"] == "deny"]) == 1, "one deny row, no change row")
# a resolver that names nothing refuses the takeover; a resolver that faults refuses it
OWNER_PKS["value"] = []
refused(lambda: mods["maintenance"]["register"](sa, request, grant_key=GK, confirmation_id=token, **base), "takeover_out_of_scope")
resolvers._RESOLVERS[("maintenance", "profile")] = lambda targets: (_ for _ in ()).throw(RuntimeError("module bug"))
refused(lambda: mods["maintenance"]["register"](sa, request, grant_key=GK, confirmation_id=token, **base), "takeover_out_of_scope")
must(Grant.objects.rows[0].created_by is alice, "still alice's")
# no resolver at all: None, so the 3-argument seam answers as before
must(deleg._owner_scope_check(bob, "maintenance", TARGETS) is False, "a faulting resolver is False")
del resolvers._RESOLVERS[("maintenance", "profile")]
must(deleg._owner_scope_check(bob, "maintenance", TARGETS) is None, "no resolver: None, the old rule decides")
src = Path(deleg.__file__).read_text(encoding="utf-8")
must("_owner_scope_check(person, owner_module, canonical)" in src and "covered = _person_covers(person, action, canonical)" in src, "the takeover asks the owner's resolver first")
print("       a takeover is judged by the owner module's resolver: a covering engineer takes the grant, one with a miss, an empty list or a faulting resolver is refused with nothing changed")

# ---- (2) a resolver that names no endpoint
setup()
OWNER_PKS["value"] = []
action = sched.get_scheduled_action("maintenance.profiles")
MANAGER["bob"] = True
UNRESTRICTED["carol"] = True
must(sched._resolver_scope_check(bob, "maintenance", T, strict=True) is False, "strict: refused for a scheduler manager")
must(sched._resolver_scope_check(alice, "maintenance", T, strict=True) is False, "strict: refused for a scoped person")
must(sched._resolver_scope_check(alice, "maintenance", T) is True and sched._resolver_scope_check(bob, "maintenance", T) is True, "non-strict, no refuse_empty: unchanged")
must(sched._resolver_scope_check(alice, "maintenance", T, refuse_empty=True) is False, "creation: a scoped person is refused")
must(sched._resolver_scope_check(bob, "maintenance", T, refuse_empty=True) is True, "creation: a native scheduler manager keeps the shortcut")
must(sched._resolver_scope_check(carol, "maintenance", T, refuse_empty=True) is True, "creation: an unrestricted person is accepted")
try:
    sched._check_person_may_schedule(alice, action, T)
    raise AssertionError("a scoped person saved a schedule whose profile names no endpoint")
except sched.SchedulerNotAllowed as exc:
    must(str(exc) == sched.EMPTY_TARGET_LIST_REFUSED and "names no endpoints" in str(exc) and "outside" not in str(exc), str(exc))
sched._check_person_may_schedule(bob, action, T)
sched._check_person_may_schedule(carol, action, T)
# the run-time owner check and the view paths keep today's answer for an empty list
schedule = SimpleNamespace(owner_type=Schedule.OwnerType.USER, owner_key="k", created_by=alice, action_id="maintenance.profiles", targets=T, module_id="maintenance")
must(sched._runtime_authorization_error(schedule) is None, "an empty profile does not fail a run that has nothing to do")
# a resolver that names endpoints keeps every earlier answer
OWNER_PKS["value"] = [1, 2]
SCOPE["alice"], SCOPE["bob"] = {1, 2}, {1}
MANAGER["bob"] = False
must(sched._resolver_scope_check(alice, "maintenance", T, refuse_empty=True) is True and sched._resolver_scope_check(alice, "maintenance", T, strict=True) is True, "covered: True")
must(sched._resolver_scope_check(bob, "maintenance", T, refuse_empty=True) is False and sched._resolver_scope_check(bob, "maintenance", T) is False, "one miss: False")
must(sched._resolver_scope_check(alice, "maintenance", {"type": "other"}, refuse_empty=True) is None, "no resolver for the type: None")
sched._check_person_may_schedule(alice, action, T)
try:
    sched._check_person_may_schedule(bob, action, T)
    raise AssertionError("bob misses endpoint 2")
except sched.SchedulerNotAllowed as exc:
    must("outside the person's Tactical scope" in str(exc), str(exc))
must(resolvers.resolve_agent_pks("maintenance", T) == {1, 2}, "resolve_agent_pks is untouched")
OWNER_PKS["value"] = []
must(resolvers.resolve_agent_pks("maintenance", T) == set(), "resolve_agent_pks still returns an empty set")
print("       an empty resolver result is refused in strict mode and at creation for a scoped non-manager (own text); run-time and view paths, managers, unrestricted people and every non-empty answer are unchanged")

# ---- (3) the five delegation.py functions take no caller
for name in ("describe", "register", "remove", "issue_ticket", "start"):
    params = list(inspect.signature(getattr(deleg, name)).parameters)
    must("caller" not in params, (name, params))
try:
    deleg.remove("maintenance", owner_module="maintenance", grant_key=GK)
    raise AssertionError("a caller argument was accepted")
except TypeError:
    pass
setup()
save_grant()
good_token = ticket()
request = RealRequest(alice)
base = dict(owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=TARGETS, parameters=None)
evil = mods["evilmod"]
live, _run = live_context()
# (b) a module that imports delegation.py and names another module is refused
refused(lambda: evil["describe"](deleg, request, **base), "wrong_module")
refused(lambda: evil["register"](deleg, request, grant_key=GK, confirmation_id="x", **base), "wrong_module")
refused(lambda: evil["remove"](deleg, owner_module="maintenance", grant_key=GK), "wrong_module")
refused(lambda: evil["issue"](deleg, live, grant_key=GK), "wrong_module")
refused(lambda: evil["start"](deleg, good_token, action_id=INSTALL, agent_ids=[1, 2]), "wrong_module")
must(len(Grant.objects.rows) == 1 and Grant.objects.rows[0].created_by is alice, "the rogue calls changed nothing")
# the provider module itself may not pretend to be the owner, and the owner may not start
refused(lambda: mods["patchmanagement"]["describe"](sa, request, **base), "wrong_module")
refused(lambda: mods["maintenance"]["start"](sa, good_token, action_id=INSTALL, agent_ids=[1, 2]), "wrong_module")
# (c) a test file and a Core frame are not modules
refused(lambda: deleg.describe(request, **base), "caller_unverified")
refused(lambda: deleg.remove(owner_module="maintenance", grant_key=GK), "caller_unverified")
core_frame = compile_as(str(APP / "scheduler.py"), "def call(deleg, request, **kw):\n    return deleg.describe(request, **kw)\n", deleg=deleg)
refused(lambda: core_frame["call"](deleg, request, **base), "caller_unverified")
# (d) a disabled and a legacy module
ENABLED["maintenance"] = False
refused(lambda: mods["maintenance"]["describe"](sa, request, **base), "caller_unverified")
ENABLED["maintenance"] = True
mods["oldmod"] = compile_as(plugin("oldmod", legacy=True, system_actions=[]) / "apps.py", EVIL_SRC, deleg=deleg)
refused(lambda: mods["oldmod"]["describe"](deleg, request, **base), "caller_unverified")
# (e) the legitimate paths still work, through the wrappers and through the capability provider
must(mods["maintenance"]["describe"](sa, request, **base)["required"] is True, "wrapper: describe")
provider = compile_as(roots["maintenance"] / "service.py", "def go(sa, request, **kw):\n    return sa._PROVIDER.describe_delegation(request, **kw)\n")
must(provider["go"](sa, request, **base)["required"] is True, "capability route: describe")
must(save_grant(user=alice, key="profile:8")["created"] is True, "register through the wrapper")
live, _run = live_context()
must(isinstance(mods["maintenance"]["issue"](sa, live, grant_key=GK), str), "issue through the wrapper")
run = start(good_token)
must(run.status == "queued", "start through the wrapper as the provider")
must(mods["maintenance"]["remove"](sa, owner_module="maintenance", grant_key="profile:8") is True, "remove through the wrapper")
print("       the five functions take no caller; a module naming another module is wrong_module, Core and test frames are caller_unverified, disabled and legacy modules too; the wrappers and the capability route still work")
print("PASS delegation fixes 1.17.69")
