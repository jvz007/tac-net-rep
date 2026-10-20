#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.63-1, rewritten in 1.17.65: the amended AD-13 condition 2 is switched on, recorded in the authority documents, and a module-owned schedule stays tied to a system action.

The real scheduler.py, scheduler_run_context.py, system_actions.py and tasks.py on the stub harness of scheduler-completion-harness-1.17.61.py.
Covered: (1) ``AD13_CONDITION_2_AMENDED`` is ONE literal in scheduler.py and it is True; when the module standard and the accepted-decisions
index (outside this repository, found only in the workspace) are present they must carry the amended text ("A scheduled run is not re-checked
against its creator" and "not at every scheduled run"), and the switch must be True without them too; (2) a user-owned scheduled run of a
demoted, deactivated or deleted creator is queued by the tick and verifies; (3) a MODULE-owned schedule with a creator name is exempt only for
an action whose own id is in the signed manifest ``system_actions`` at registration AND at every decision, with a system action of the same id
registered by the module. The ``unattended=`` keyword keeps its registration validation and has no effect.
"""
from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

# ---- (1) the switch is one literal and it is True; the documents carry the amended text
tree = ast.parse((APP / "scheduler.py").read_text(encoding="utf-8"))
value = [n.value.value for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "AD13_CONDITION_2_AMENDED" for t in n.targets)]
must(len(value) == 1 and isinstance(value[0], bool), "one literal AD13_CONDITION_2_AMENDED switch in scheduler.py")
must(sched.AD13_CONDITION_2_AMENDED is value[0], "the module value is the literal")
must(value[0] is True, "the amended AD-13 condition 2 is signed (20 October 2026): the switch must be True")
MARKERS = {"tec-tac-module-standard.md": "A scheduled run is not re-checked against its creator", "review-accepted-decisions.md": "not at every scheduled run"}
workspace_docs = HERE.parents[2] / "docs"
if all((workspace_docs / name).is_file() for name in MARKERS):
    for name, marker in MARKERS.items():
        must(marker in (workspace_docs / name).read_text(encoding="utf-8"), f"{name} lacks the amended condition 2 text")
    print("       documents found: the amended AD-13 condition 2 is recorded and the switch is True")
else:
    print("       authority documents not in this checkout: the switch is True anyway")
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


def make_schedule(action_id="patching.scan", *, creator=alice, name="alice", owner_type="user", owner_key=""):
    return Schedule.objects.create(
        name="s", module_id=action_id.split(".")[0], action_id=action_id, owner_type=owner_type, owner_module="patching" if owner_type == "module" else "", owner_key=owner_key,
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


# ---- (2) a user-owned scheduled run of a demoted, deactivated or deleted creator is queued and verifies
must(SHIPPED is True, "the shipped switch is True")
for how in ("demoted", "deactivated", "deleted"):
    reset()
    if how == "demoted":
        AUTH["deny"] = True
    elif how == "deactivated":
        alice.is_active = False
    s = make_schedule(creator=None if how == "deleted" else alice)
    must(sched._is_unattended_scheduled_run(s) is True, f"{how}: the helper answers True")
    r = tick()
    must(len(r["queued"]) == 1 and not r["skipped"], (how, r))
    must(go(run_for(s)) == {"verified": True, "unattended": True}, how)
    AUTH["deny"] = False
    alice.is_active = True
print("       switch True: a demoted, deactivated or deleted creator's user-owned scheduled run is queued and verifies")

# ---- (3) a module-owned schedule with a creator name stays bound to a system action
try:
    reset()
    s = make_schedule(creator=None, owner_type="module", owner_key="recurring")
    must(sched._is_unattended_scheduled_run(s) is True, "module-owned, bound action, creator name stored")

    # registration: the keyword keeps its validation (the action's own id must be in the manifest list) and has no effect
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
    listed_only = make_schedule("patching.other", creator=None, owner_type="module", owner_key="recurring")
    must(sched._is_unattended_scheduled_run(listed_only) is False, "listed in the manifest but no system action registered: not exempt")
    PLUGINS["patching"].system_actions = ("patching.other",)  # patching.scan removed from the signed manifest after registration
    gone = make_schedule("patching.scan", creator=None, owner_type="module", owner_key="recurring")
    must(sched._is_unattended_scheduled_run(gone) is False, "removed from the manifest: the helper answers False")
    PLUGINS["patching"].system_actions = ("patching.scan", "patching.other")
    STATE_FAULT["registry"] = True
    must(sched._is_unattended_scheduled_run(make_schedule(creator=None, owner_type="module", owner_key="recurring")) is False, "an unreadable manifest answers False")
    STATE_FAULT["registry"] = False
finally:
    sched.AD13_CONDITION_2_AMENDED = SHIPPED
print("       module-owned: the action id must be in the manifest at every decision, with a system action of the same id")
print("PASS scheduler unattended gate 1.17.63-1")
