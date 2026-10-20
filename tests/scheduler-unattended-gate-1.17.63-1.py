#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.63-1 regression (review of 1.17.63, round 1): the unattended exemption of AD-13 condition 2 is gated on a recorded decision and tied to a system action.

The real scheduler.py, scheduler_run_context.py, system_actions.py and tasks.py on the stub harness of scheduler-completion-harness-1.17.61.py.
Covered: (1) while ``AD13_CONDITION_2_AMENDED`` is False (the shipped value) a scheduled ``unattended=True`` run with a demoted, deactivated or
deleted creator is refused by the tick (AuthorizationRevoked) and by verify_run_context, and the helper never answers True; (2) the switch and the
documents agree: when the module standard and the accepted-decisions index (outside this repository, found only in the workspace) carry the amended
condition 2 text the switch must be True, and while either lacks it the switch must be False; (3) with the switch True the exemption needs the
action's own id in the signed manifest ``system_actions`` at registration AND at every decision, and a system action of the same id registered by
the module.
"""
from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

# ---- (2) the switch and the documents agree
tree = ast.parse((APP / "scheduler.py").read_text(encoding="utf-8"))
value = [n.value.value for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "AD13_CONDITION_2_AMENDED" for t in n.targets)]
must(len(value) == 1 and isinstance(value[0], bool), "one literal AD13_CONDITION_2_AMENDED switch in scheduler.py")
must(sched.AD13_CONDITION_2_AMENDED is value[0], "the module value is the literal")
MARKER = "flagged unattended is not re-checked"
workspace_docs = HERE.parents[2] / "docs"
standard, index = workspace_docs / "tec-tac-module-standard.md", workspace_docs / "review-accepted-decisions.md"
if standard.is_file() and index.is_file():
    recorded = all(MARKER in p.read_text(encoding="utf-8") for p in (standard, index))
    must(value[0] is recorded, f"the switch ({value[0]}) and the documents (amended text present: {recorded}) disagree")
    print(f"       documents found: amended AD-13 condition 2 recorded={recorded}, switch={value[0]}")
else:
    must(value[0] is False, "no authority documents to read: the switch must stay False")
    print("       authority documents not in this checkout: the switch is False")
SHIPPED = sched.AD13_CONDITION_2_AMENDED

alice = User("alice")
plugin("patching", system_actions=["patching.scan", "patching.other"])
SEEN = []


def handler(context):
    SEEN.append(context)
    try:
        v = rc.verify_run_context(context, expected_module_id="patching", expected_action_id=context["action_id"], require_owner=False)
    except sched.SchedulerRunContextInvalid as exc:
        return {"invalid": str(exc)}
    return {"verified": True, "unattended": v.unattended}


sa.register_system_action("patching.scan", "patching", "patching.scan", "winupdate.scan", ("can_manage_winupdates", "can_run_bulk"))
sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=handler, unattended=True)
FLAGS["alice"] = {"can_run_bulk", "can_manage_winupdates"}
sched.recover_stale_runs = lambda now: {}
sched._recover_event_jobs_safely = lambda now: {}
sched.cleanup_once_schedules = lambda now: 0
sched.cleanup_run_history = lambda now: 0
REFUSED = {"invalid": "The person who owns this schedule may no longer run it."}


def make_schedule(action_id="patching.scan", *, creator=alice, name="alice"):
    return Schedule.objects.create(
        name="s", module_id=action_id.split(".")[0], action_id=action_id, owner_type="user", owner_module="", owner_key="",
        created_by=creator, created_by_username=name, enabled=True, schedule_type="interval", interval_seconds=3600,
        interval_anchor_at=NOW[0] - timedelta(hours=3), targets={"type": "none"}, last_due_key="", updated_at=None,
    )


def tick():
    del QUEUED_IDS[:]
    return sched.dispatch_due_schedules(NOW[0])


def skipped_types(result):
    return sorted(r.error_type for r in Run.objects.rows if str(r.id) in result["skipped"])


def run_for(schedule):
    return Run.objects.create(
        schedule=schedule, schedule_snapshot_id=schedule.id, schedule_name="s", module_id=schedule.module_id, action_id=schedule.action_id,
        owner_type=schedule.owner_type, owner_module=schedule.owner_module, owner_key=schedule.owner_key, status="queued", manual=False,
        scheduled_for=NOW[0], last_queued_at=NOW[0],
    )


# ---- (1) the shipped state: the re-check holds for every scheduled run, even of an unattended action
must(SHIPPED is False, "the shipped switch is False until the amendment is recorded")
for how in ("demoted", "deactivated", "deleted"):
    reset()
    if how == "demoted":
        AUTH["deny"] = True
    elif how == "deactivated":
        alice.is_active = False
    s = make_schedule(creator=None if how == "deleted" else alice)
    must(sched._is_unattended_scheduled_run(s) is False, f"{how}: the helper never answers True while the amendment is absent")
    r = tick()
    must(not r["queued"] and skipped_types(r) == ["AuthorizationRevoked"], (how, r))
    if how != "deleted":
        must(go(run_for(s)) == REFUSED, how)
    AUTH["deny"] = False
    alice.is_active = True
print("       switch False: a demoted, deactivated or deleted creator's scheduled unattended run is refused by the tick and by verify_run_context")
reset()
make_schedule()
r = tick()
must(len(r["queued"]) == 1, ("a healthy creator still runs", r))

# ---- (3) with the switch True: the id is bound to a system action
sched.AD13_CONDITION_2_AMENDED = True
try:
    reset()
    AUTH["deny"] = True
    s = make_schedule()
    must(sched._is_unattended_scheduled_run(s) is True, "bound action, switch True")
    r = tick()
    must(len(r["queued"]) == 1, ("switch True and bound: exempt", r))
    AUTH["deny"] = False

    # registration: the action's own id must be in the manifest list
    try:
        sched.register_scheduled_action(id="patching.unlisted", module_id="patching", label="u", handler=handler, unattended=True)
        raise AssertionError("an unattended action whose id is not in system_actions was registered")
    except sched.SchedulerError as exc:
        must("system_actions" in str(exc), exc)
    plugin("other", system_actions=["other.scan"])
    try:
        sched.register_scheduled_action(id="other.thing", module_id="other", label="u", handler=handler, unattended=True)
        raise AssertionError("a manifest listing a different id was accepted")
    except sched.SchedulerError:
        pass
    sched.register_scheduled_action(id="patching.other", module_id="patching", label="o", handler=handler, unattended=True)  # listed, no system action yet

    # decision time: no system action registered, the id removed from the manifest, an unreadable manifest
    reset()
    AUTH["deny"] = True
    listed_only = make_schedule("patching.other")
    must(sched._is_unattended_scheduled_run(listed_only) is False, "listed in the manifest but no system action registered: not exempt")
    r = tick()
    must(not r["queued"] and skipped_types(r) == ["AuthorizationRevoked"], r)
    reset()
    AUTH["deny"] = True
    PLUGINS["patching"].system_actions = ("patching.other",)  # patching.scan removed from the signed manifest after registration
    gone = make_schedule("patching.scan")
    must(sched._is_unattended_scheduled_run(gone) is False, "removed from the manifest: the helper answers False")
    r = tick()
    must(not r["queued"] and skipped_types(r) == ["AuthorizationRevoked"], ("a removed manifest id is re-checked by the tick", r))
    must(go(run_for(gone)) == REFUSED, "a removed manifest id is re-checked by verify_run_context")
    PLUGINS["patching"].system_actions = ("patching.scan", "patching.other")
    STATE_FAULT["registry"] = True
    must(sched._is_unattended_scheduled_run(make_schedule()) is False, "an unreadable manifest answers False")
    STATE_FAULT["registry"] = False
    AUTH["deny"] = False
finally:
    sched.AD13_CONDITION_2_AMENDED = SHIPPED
print("       switch True: the action id must be in the manifest at registration and at every decision, with a system action of the same id")
print("PASS scheduler unattended gate 1.17.63-1")
