#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.85 regression: Run now of a declared ``scheduler_person_actions`` action acts as the person who pressed it.

Same stub harness as scheduler-person-actions-1.17.80.py. Covered: (1) queue_manual_run stores the clicker, and the handler verifies with the clicker as
user (not the creator), unattended False, started_by_username set; (2) with no clicker, an undeclared action or another module's action the manual run still
has no person; (3) the clicker is re-checked live: inactive, without the permission or without the scope the verify refuses; (4) the audit row names the clicker;
(5) contract text, docs and notes carry the new wording.
"""
from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
sched.recover_stale_runs = lambda now: {}
sched._recover_event_jobs_safely = lambda now: {}
sched.cleanup_once_schedules = lambda now: 0
sched.cleanup_run_history = lambda now: 0

# 1.17.81: the manifest answer is cached by a fingerprint of the manifest files; here the fingerprint is the stub registry state
sched._manifest_signature = lambda: (STATE_FAULT["registry"], tuple((k, tuple(getattr(p, "scheduler_person_actions", ()))) for k, p in PLUGINS.items()))
alice, bob = User("alice"), User("bob")
PERMS = {"alice": True, "bob": True}
SCOPES = {"alice": True, "bob": True}


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: PERMS.get(user.username, False)
views._can_access_target_scope = lambda user, targets, **kw: SCOPES.get(user.username, False)
_orig_save = Schedule.save


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    _orig_save(self, update_fields)


Schedule.save = _save
SEEN = []


def verifying_handler(action_id):
    def handler(context):
        try:
            v = rc.verify_run_context(context, expected_module_id="patchmanagement", expected_action_id=action_id, require_owner=True)
        except sched.SchedulerRunContextInvalid as exc:
            return {"invalid": str(exc)}
        SEEN.append(v)
        return {"user": v.user.username, "unattended": v.unattended, "creator": v.creator_username}
    return handler


def fresh(declared=("patchmanagement.notice", "patchmanagement.reboot")):
    reset()
    PLUGINS.clear()
    plugin("patchmanagement", category="premium")
    PLUGINS["patchmanagement"].scheduler_person_actions = tuple(declared)
    plugin("other")
    del SEEN[:]
    sched._ACTIONS.clear()
    for who in PERMS:
        PERMS[who] = SCOPES[who] = True
    for user in (alice, bob):
        user.is_active = True
    for name in ("notice", "reboot", "plain"):
        sched.register_scheduled_action(id=f"patchmanagement.{name}", module_id="patchmanagement", label=name, handler=verifying_handler(f"patchmanagement.{name}"))
    sched.register_scheduled_action(id="other.notice", module_id="other", label="n", handler=verifying_handler("other.notice"))


def create(action="patchmanagement.notice", key="profile:1", person=alice, module="patchmanagement"):
    kw = dict(owner_module=module, owner_key=key, action_id=action, schedule_type="interval", interval_seconds=3600, interval_anchor_at=NOW[0] - timedelta(hours=3), targets={"type": "none"})
    return sched.reconcile_schedule(**kw, confirmed_by_request=RealRequest(person) if person else None)


def run_for(schedule, *, manual=False):
    return Run.objects.create(
        schedule=schedule, schedule_snapshot_id=schedule.id, schedule_name="s", module_id=schedule.module_id, action_id=schedule.action_id,
        owner_type=schedule.owner_type, owner_module=schedule.owner_module, owner_key=schedule.owner_key, status="queued", manual=manual,
        scheduled_for=NOW[0], last_queued_at=NOW[0], targets_snapshot={"type": "none"},
    )


def person_rows():
    return [a for a in AUDITS if a["action"] == "run" and (a.get("metadata") or {}).get("run_as") == "creator"]


NO_PERSON = "This run has no person behind it."
REFUSED = "The person who owns this schedule may no longer run it."


sched._queue_run = lambda run: run


def manual_run(schedule, clicker):
    run = sched.queue_manual_run(schedule, started_by=clicker)
    return run


def clicker_rows():
    return [a for a in AUDITS if a["action"] == "run" and (a.get("metadata") or {}).get("run_as") == "clicker"]


NO_PERSON = "This run has no person behind it."
REFUSED = "The person who pressed Run now may no longer run this action."

# ---- (1) the clicker is the person, not the creator
for action in ("patchmanagement.notice", "patchmanagement.reboot"):
    fresh()
    s = create(action, person=alice)
    must(sched.manual_person_action(s) is True, "declared")
    run = manual_run(s, bob)
    must(run.manual is True and run.started_by is bob and run.started_by_username == "bob", run.__dict__)
    run.started_by_id = bob.pk
    out = go(run)
    must(out == {"user": "bob", "unattended": False, "creator": "alice"}, out)
    must(SEEN[-1].started_by_username == "bob" and SEEN[-1].unattended is False, SEEN[-1])
print("       a manual run of a declared action verifies with the person who pressed it (creator unchanged)")

# a creator-less schedule works too: the clicker is the person
fresh()
s = create(person=None)
run = manual_run(s, bob)
run.started_by_id = bob.pk
must(go(run) == {"user": "bob", "unattended": False, "creator": None}, "no stored creator needed for a clicker")

# ---- (2) no clicker, undeclared, other module: no person
fresh()
out = go(manual_run(create(), None))
must(out == {"invalid": NO_PERSON}, out)
fresh()
s = create("patchmanagement.plain")
must(sched.manual_person_action(s) is False)
run = manual_run(s, bob)
run.started_by_id = bob.pk
must(go(run) == {"invalid": NO_PERSON}, "undeclared action: the clicker is not honoured")
fresh(declared=())
s = create("patchmanagement.notice")
run = manual_run(s, bob)
run.started_by_id = bob.pk
must(go(run) == {"invalid": NO_PERSON}, "delisted action")
fresh()
PLUGINS["patchmanagement"].scheduler_person_actions = ("patchmanagement.notice", "other.notice")
s = create("other.notice", key="x", module="other")
must(sched.manual_person_action(s) is False, "another module's action")
print("       no clicker, an undeclared, delisted or foreign action: still no person")

# ---- (3) re-checked live, fail closed
for how in ("inactive", "permission", "scope"):
    fresh()
    s = create(person=alice)
    run = manual_run(s, bob)
    run.started_by_id = bob.pk
    {"inactive": lambda: setattr(bob, "is_active", False), "permission": lambda: PERMS.update(bob=False), "scope": lambda: SCOPES.update(bob=False)}[how]()
    out = go(run)
    must(out == {"invalid": REFUSED} and not clicker_rows(), (how, out))
    for user in (alice, bob):
        user.is_active = True
    PERMS.update(alice=True, bob=True)
    SCOPES.update(alice=True, bob=True)
print("       a clicker who is inactive, lacks the permission or lacks the scope is refused (creator rights do not help)")

# the creator losing the right does not stop a clicker who holds it
fresh()
s = create(person=alice)
PERMS["alice"] = False
run = manual_run(s, bob)
run.started_by_id = bob.pk
must(go(run) == {"user": "bob", "unattended": False, "creator": "alice"}, "the clicker's rights decide")

# ---- (4) audit row names the clicker (tasks.py); (5) text
tasks = (APP / "tasks.py").read_text(encoding="utf-8")
must('"run_as": "clicker"' in tasks and "manual_person_action(schedule, action_id)" in tasks)
views_src = (APP / "scheduler_views.py").read_text(encoding="utf-8")
must("queue_manual_run(schedule, started_by=request.user if person_run else None)" in views_src and "_audit_run_now_refusal" in views_src)
must("started_by_username" in (APP / "scheduler_run_context.py").read_text(encoding="utf-8"))
must("Since 1.17.85" in (APP / "contracts.py").read_text(encoding="utf-8"))
must("1.17.85" in (ROOT / "docs" / "module-scheduling.md").read_text(encoding="utf-8"))
must((ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.85.md").is_file())
print("PASS scheduler manual run person 1.17.85")
