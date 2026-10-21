#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.68 regression (Johan, 21 October 2026, Q-APM12 option b): a schedule keeps the scope it was created with.

Johan: "If an engineer was responsible to configure APM and leaves the business his account will be disabled, but the work that he has done
shouldn't be undone." The real scheduler.py, scheduler_creation_scope.py, scheduler_run_context.py, system_actions.py and tasks.py on the stub
harness of scheduler-completion-harness-1.17.61.py (no Django, no database).

Covered. (1) The snapshot: shape, flags (true ones only, sorted), scope ids, the fail-closed empty snapshot when a read faults, and a wrong shape is
never repaired. (2) It is stored when a person creates or edits through reconcile_schedule and is NOT stored by start_one_off_run or by a module
call without a request; another person who only switches the schedule off changes neither the owner nor the stored scope. (3) For an unattended
run, a disabled owner and a role that was narrowed afterwards change nothing: held_at_creation and resolved_endpoints read only the snapshot (the
owner's live row is never read: the reload raises here), and the result is always the schedule's targets AND the snapshot, never wider. (4) A schedule
made before migration 0037 has no snapshot: has_creation_scope is False and both reads raise CreationScopeUnavailable with plain text; Core invents
none. (5) A person-started run still uses the owner's live scope, exactly as before. (6) The ceiling: more than the limit raises and nothing is
truncated; a bad limit is a ValueError; ``none`` returns [] unless whole_scope=True; a module-owned type reads through its resolver; a read fault is
a SchedulerTransientError and an unreadable target an error that retries cannot fix. (7) The info is a copy. (8) The browser POST and PATCH store the
scope (read as source).
"""
from __future__ import annotations

from datetime import time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True

BOTH = ("can_manage_winupdates", "can_run_bulk")
alice, bob = User("alice"), User("bob")


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: True
COVER = {"alice": True, "bob": True}
views._can_access_target_scope = lambda user, targets, strict=False, **kw: COVER.get(user.username, False) if strict else True

_orig_save = Schedule.save


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    _orig_save(self, update_fields)


Schedule.save = _save
root = plugin("patching", system_actions=[])


def handler(context):
    return {"ok": True}


sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=handler, target_types=("none", "endpoint", "profile"))
KW = dict(owner_module="patching", owner_key="nightly", action_id="patching.scan", schedule_type="daily", run_time=time(3, 0))
ALICE_SCOPE = {"mode": "mixed", "unrestricted": False, "whole_client_ids": [10], "site_ids": [300]}
ROWS = {
    1: dict(agent_id="agent-one", hostname="h1", platform="windows", client_id=10, site_id=100),
    2: dict(agent_id="agent-two", hostname="h2", platform="windows", client_id=10, site_id=100),
    3: dict(agent_id="agent-three", hostname="h3", platform="windows", client_id=10, site_id=101),
    4: dict(agent_id="agent-four", hostname="h4", platform="windows", client_id=20, site_id=200),
    5: dict(agent_id="agent-five", hostname="h5", platform="windows", client_id=30, site_id=300),
    6: dict(agent_id="agent-six", hostname="h6", platform="windows", client_id=30, site_id=301),
}


def fresh():
    reset()
    AGENT_ROWS.update({pk: dict(row) for pk, row in ROWS.items()})
    DESCRIPTORS["alice"] = dict(ALICE_SCOPE)
    DESCRIPTORS["bob"] = {"mode": "unrestricted", "unrestricted": True, "whole_client_ids": [], "site_ids": []}
    FLAGS["alice"], FLAGS["bob"] = set(BOTH), set(BOTH)
    COVER.update(alice=True, bob=True)
    for user in (alice, bob):
        user.is_active = True
    rc._reload_user = lambda pk: USERS.get(pk)


def raises(call, kind=Exception):
    try:
        call()
    except kind as exc:
        return exc
    raise AssertionError("the call did not raise")


# ---- (1) the snapshot
fresh()
snap = creation_scope.capture(alice)
must(snap["v"] == 1 and snap["captured_for"] == "alice" and snap["captured_at"], snap)
must(snap["scope"] == {"unrestricted": False, "whole_client_ids": [10], "site_ids": [300]}, snap)
must(snap["flags"] == sorted(BOTH), snap)
FLAGS["alice"] = {"can_run_bulk"}
must(creation_scope.capture(alice)["flags"] == ["can_run_bulk"], "only the flags the person holds")
must(creation_scope.capture(bob)["scope"]["unrestricted"] is True, "an unrestricted person is stored as unrestricted")
nobody = User("nobody")
must(creation_scope.capture(nobody)["scope"] == {"unrestricted": False, "whole_client_ids": [], "site_ids": []} and creation_scope.capture(nobody)["flags"] == [], "no scope, no flag")
real = creation_scope._descriptor
creation_scope._descriptor = lambda user: (_ for _ in ()).throw(RuntimeError("tactical unreadable"))
empty = creation_scope.capture(alice)
creation_scope._descriptor = real
must(empty["scope"] == {"unrestricted": False, "whole_client_ids": [], "site_ids": []} and empty["flags"] == [], "a read fault stores the empty snapshot, never a wide one")
must(creation_scope.normalize(snap) == snap and creation_scope.normalize({**snap, "v": 2}) is None and creation_scope.normalize({}) is None and creation_scope.normalize(None) is None, "normalize")
must(creation_scope.normalize({**snap, "flags": ["drop table"]}) is None and creation_scope.normalize({**snap, "scope": {"unrestricted": "yes"}}) is None, "a wrong shape is not repaired")
print("       the snapshot holds the scope ids and the flags the person held; a read fault stores the empty one; a wrong shape is refused")

# ---- (2) when it is stored
fresh()
created = sched.reconcile_schedule(**KW, targets={"type": "endpoint", "ids": ["agent-one"]}, confirmed_by_request=RealRequest(alice))
stored = creation_scope.snapshot_of(created)
must(stored is not None and stored["captured_for"] == "alice" and stored["scope"]["whole_client_ids"] == [10], created.creation_scope)
DESCRIPTORS["alice"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10, 20], "site_ids": []}
again = sched.reconcile_schedule(**KW, targets={"type": "endpoint", "ids": ["agent-one"]}, confirmed_by_request=RealRequest(alice))
must(again is created and creation_scope.snapshot_of(created)["scope"]["whole_client_ids"] == [10, 20], "the same person saving again stores the scope they have now")
before = dict(created.creation_scope)
sched.reconcile_schedule(**KW, targets={"type": "endpoint", "ids": ["agent-one"]})
must(created.creation_scope == before, "a module call with no request changes nothing")
off = sched.reconcile_schedule(**KW, targets={"type": "endpoint", "ids": ["agent-one"]}, enabled=False, confirmed_by_request=RealRequest(bob))
must(off.created_by is alice and off.enabled is False and creation_scope.snapshot_of(off)["captured_for"] == "alice", "another person who only switches it off moves neither the owner nor the scope")
fresh()
run = sched.start_one_off_run(user=alice, owner_module="patching", action_id="patching.scan", targets={"type": "none"})
must(creation_scope.snapshot_of(run.schedule) is None and run.schedule.creation_scope == {}, "start_one_off_run stores no scope")
print("       reconcile_schedule with a person stores the scope (again on every edit by the owner); a module call, a one-off run and another person who only disables it store nothing")

# ---- (3) an unattended run reads the snapshot only
IDS = ["1", "2", "4", "5"]


def unattended_run(owner=alice, *, snapshot="make", targets=None, manual=False, module="patching"):
    run = make_run("patching.scan", module, user=owner, owner="user", targets=targets if targets is not None else {"type": "endpoint", "ids": list(IDS)}, manual=manual, status="running")
    run.schedule.created_by_username = owner.username if owner else "alice"
    if snapshot == "make":
        run.schedule.creation_scope = creation_scope.capture(owner)
    elif snapshot is not None:
        run.schedule.creation_scope = snapshot
    return run


def verified_for(run):
    context = rc.issue_run_context({"run_id": str(run.id)}, run_id=run.id)
    return rc.verify_run_context(context, expected_module_id=run.module_id, expected_action_id=run.action_id)


fresh()
FLAGS["alice"] = set(BOTH)
# the endpoints are looked up by agent number; the harness stub of the target resolver reads these from EXISTING_AGENTS / the numbers in the ids
mod_targets = {"type": "endpoint", "ids": ["1", "2", "4", "5"]}
run = unattended_run(targets=mod_targets)
verified = verified_for(run)
must(verified.unattended is True and verified.has_creation_scope is True, verified)
rows = verified.resolved_endpoints()
must([r["pk"] for r in rows] == [1, 2, 5], [r["pk"] for r in rows])  # 4 is outside what alice could see when she saved it
must(set(rows[0]) == {"pk", "agent_id", "hostname", "platform", "client_id", "site_id"}, rows[0])
must(verified.held_at_creation("can_run_bulk") is True and verified.held_at_creation("can_reboot_agents") is False and verified.held_at_creation("not_a_flag") is False and verified.held_at_creation(5) is False, "flags")
# alice leaves: disabled, demoted, scope narrowed to nothing, and her row cannot even be read
alice.is_active = False
FLAGS["alice"] = set()
DESCRIPTORS["alice"] = {"mode": "none", "unrestricted": False, "whole_client_ids": [], "site_ids": []}
rc._reload_user = lambda pk: (_ for _ in ()).throw(RuntimeError("the owner's live row must not be read for an unattended run"))
again = verified_for(run)
must([r["pk"] for r in again.resolved_endpoints()] == [1, 2, 5], "a disabled and narrowed owner changes nothing")
must(again.held_at_creation("can_run_bulk") is True, "the flag she held at creation is still held at creation")
must(again.has_tactical_permission("can_run_bulk") is False, "the live read is unchanged and still fails closed")
alice.is_active = True
rc._reload_user = lambda pk: USERS.get(pk)
print("       a disabled, demoted and narrowed owner changes nothing: the unattended run reads the stored scope, never the live row, and keeps the same endpoints")

# ---- the result is never wider than the targets AND the snapshot
fresh()
run = unattended_run(owner=alice, targets={"type": "endpoint", "ids": ["1", "3", "6"]})
must([r["pk"] for r in verified_for(run).resolved_endpoints()] == [1, 3], "6 is in the targets but not in the stored scope (site 301 of client 30 is not granted)")
run = unattended_run(owner=alice, targets={"type": "endpoint", "ids": ["4"]})
must(verified_for(run).resolved_endpoints() == [], "an endpoint outside the stored scope is not returned, whatever the targets say")
bob_run = unattended_run(owner=bob, targets={"type": "endpoint", "ids": ["1", "4", "6"]})
must([r["pk"] for r in verified_for(bob_run).resolved_endpoints()] == [1, 4, 6], "an unrestricted creator reaches every target")
must(verified_for(bob_run).creation_scope_info()["scope"]["unrestricted"] is True, "info")
print("       the result is always the run's targets AND the stored scope")

# ---- (4) a schedule made before 0037
fresh()
legacy = unattended_run(snapshot=None)
v = verified_for(legacy)
must(v.has_creation_scope is False and v.creation_scope_info() is None, "no snapshot")
for call in (v.resolved_endpoints, lambda: v.held_at_creation("can_run_bulk")):
    exc = raises(call, sched.CreationScopeUnavailable)
    must(isinstance(exc, sched.SchedulerPermanentError) and "Edit it and save it once" in str(exc) and exc.reason == "creation_scope_unavailable", exc)
legacy_bad = unattended_run(snapshot={"v": 9, "scope": "nope"})
must(verified_for(legacy_bad).has_creation_scope is False, "a snapshot with the wrong shape is no snapshot")
print("       a schedule with no stored scope raises CreationScopeUnavailable in plain words; Core invents none and a wrong shape is not accepted")

# ---- (5) a person-started run keeps the live scope
fresh()
manual = unattended_run(targets={"type": "endpoint", "ids": ["1", "2", "4", "5"]}, manual=True)
v = verified_for(manual)
must(v.unattended is False, "a manual run is never unattended")
must([r["pk"] for r in v.resolved_endpoints()] == [1, 2, 5], "alice's live scope today")
DESCRIPTORS["alice"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [20], "site_ids": []}
must([r["pk"] for r in v.resolved_endpoints()] == [4], "a run a person started follows the person's live scope, as before")
FLAGS["alice"] = {"can_run_bulk"}
must(v.held_at_creation("can_run_bulk") is True and v.held_at_creation("can_manage_winupdates") is False, "a person-started run asks the live flag")
legacy_manual = unattended_run(snapshot=None, manual=True)
must(verified_for(legacy_manual).resolved_endpoints() is not None, "a person-started run needs no stored scope")
print("       a run a person started still uses the owner's live scope and flags, exactly as before")

# ---- (6) limits, none, resolvers and faults
fresh()
run = unattended_run(targets={"type": "endpoint", "ids": ["1", "2", "3", "5"]})
v = verified_for(run)
exc = raises(lambda: v.resolved_endpoints(limit=2), sched.SchedulerPermanentError)
must("more than 2 endpoints" in str(exc), exc)
must(len(v.resolved_endpoints(limit=4)) == 4, "exactly the limit is allowed")
for bad in (0, -1, 1.5, "5", True, sa.MAX_AGENTS + 1):
    raises(lambda bad=bad: v.resolved_endpoints(limit=bad), ValueError)
none_run = unattended_run(targets={"type": "none"})
nv = verified_for(none_run)
must(nv.resolved_endpoints() == [], "none names no endpoint")
must([r["pk"] for r in nv.resolved_endpoints(whole_scope=True)] == [1, 2, 3, 5], "whole_scope returns the whole stored scope")
exc = raises(lambda: nv.resolved_endpoints(whole_scope=True, limit=2), sched.SchedulerPermanentError)
must("more than 2" in str(exc), "whole scope above the limit raises, never truncates")
# a module-owned type reads through the resolver the module registered (stubbed here as the adapter answer)
RESOLVED_MODULE_TARGETS[("patching", "profile")] = {1, 3, 4}
profile_run = unattended_run(targets={"type": "profile", "ids": [7]})
pv = verified_for(profile_run)
must([r["pk"] for r in pv.resolved_endpoints()] == [1, 3], "a profile target is the resolver's endpoints AND the stored scope (4 is cut)")
unknown = unattended_run(targets={"type": "otherthing", "ids": [7]})
raises(lambda: verified_for(unknown).resolved_endpoints(), sched.SchedulerPermanentError)  # no resolver: unresolved, not guessed
bad_shape = unattended_run(targets={"type": "endpoint"})
raises(lambda: verified_for(bad_shape).resolved_endpoints(), sched.SchedulerPermanentError)  # a target the shape check refuses
real_rows = sys.modules["tec_tac.resources_adapter"].agent_rows_in_scope
sys.modules["tec_tac.resources_adapter"].agent_rows_in_scope = lambda **kw: (_ for _ in ()).throw(RuntimeError("database down"))
exc = raises(lambda: v.resolved_endpoints(), sched.SchedulerTransientError)
sys.modules["tec_tac.resources_adapter"].agent_rows_in_scope = real_rows
must("Try again" in str(exc) and "database" not in str(exc), exc)
print("       the limit raises and never truncates, none needs whole_scope, a profile type reads through its resolver, an unreadable target is permanent and a fault is transient")

# ---- (7) the info is a copy
fresh()
v = verified_for(unattended_run())
info = v.creation_scope_info()
info["scope"]["whole_client_ids"].append(99)
info["flags"].clear()
must(v.creation_scope_info()["scope"]["whole_client_ids"] == [10] and v.held_at_creation("can_run_bulk") is True, "changing the copy changes nothing")
import dataclasses  # noqa: E402

raises(lambda: setattr(v, "_creation_scope", None), dataclasses.FrozenInstanceError)
print("       creation_scope_info returns a copy and the verified run is frozen")

# ---- (8) the browser routes store it (read as source: they need Django)
view_src = (APP / "scheduler_views.py").read_text(encoding="utf-8")
post = view_src.split("    def post(self, request):", 1)[1].split("class SchedulerDetailView", 1)[0]
must("creation_scope=scheduler_creation_scope.capture(request.user)" in post and "owner_type=TecTacSchedule.OwnerType.USER" in post, "POST stores the creator's scope")
patch = view_src.split("    def patch(self, request, schedule_id):", 1)[1].split("    def delete(self, request, schedule_id):", 1)[0]
must("schedule.creation_scope = scheduler_creation_scope.capture(request.user)" in patch and "if takeover or (edited and not other_person):" in patch, "PATCH stores the editor's scope only for an edit by the owner or a takeover")
must(patch.index("_require_target_scope(") < patch.index("scheduler_creation_scope.capture"), "the permission and scope checks still come first")
sig = sched.reconcile_schedule.__wrapped__ if hasattr(sched.reconcile_schedule, "__wrapped__") else sched.reconcile_schedule
import inspect  # noqa: E402

must(list(inspect.signature(sig).parameters)[-2:] == ["confirmed_by_request", "confirmation_id"], "reconcile_schedule keeps its signature")
print("       the browser POST stores the creator's scope and PATCH stores the editor's on an edit, after the permission and scope checks")
print("PASS scheduler creation scope 1.17.68")
