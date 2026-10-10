#!/usr/bin/env python3
"""1.17.17 regression: a one-off schedule cannot be run again from the browser, and the one-off: key prefix is Core's (held Medium of 1.17.16).

Before 1.17.17 any user who held the action's permission could POST run-now on another user's one-off schedule: the run then executed
as the first user (the worker re-checks ``created_by``). ``SchedulerRunNowView`` now refuses every one-off schedule with 403 before any
other check, and ``reconcile_schedule`` refuses an ``owner_key`` that starts with ``one-off:`` so only ``start_one_off_run`` can make one.
Uses the harness of tests/scheduler-tactical-permission-1.17.17.py (real scheduler.py, tasks.py, rbac.py and scheduler_views.py on stubs).
"""
from __future__ import annotations

import ast
from pathlib import Path

_here = Path(__file__).resolve().parent
_source = (_here / "scheduler-tactical-permission-1.17.17.py").read_text(encoding="utf-8")
_cut = _source.index("# ---- harness end")
exec(compile(_source[:_cut], str(_here / "scheduler-tactical-permission-1.17.17.py"), "exec"), globals())
H = globals()
(must, sched, sv, Schedule, Run, User, PermissionDenied, Granted, timedelta, NOW, QUEUED, handler, execute, reset, GRANTS, SimpleNamespace, sys, APP, ROOT) = (
    H[k] for k in ("must", "sched", "sv", "Schedule", "Run", "User", "PermissionDenied", "Granted", "timedelta", "NOW", "QUEUED", "handler", "execute", "reset",
                   "GRANTS", "SimpleNamespace", "sys", "APP", "ROOT"))

sys.modules["tec_tac.resources_adapter"].tactical_scope_unrestricted = lambda user: True  # a user with unrestricted Tactical scope
sys.modules["tec_tac.resources_adapter"].canonical_agent_target_ids = lambda identifiers: list(identifiers)

Schedule.created_by_id = property(lambda self: getattr(self.created_by, "id", None))
Schedule.save = lambda self, update_fields=None: self in Schedule.objects.rows or Schedule.objects.rows.append(self)  # reconcile_schedule builds then saves
user_a = User("usera", Granted(11))
user_b = User("userb", Granted(12))
admin = User("admin", Granted(13, can_do_server_maint=True))
for rid in (11, 12):
    GRANTS.add((rid, "patching.run"))
sched.register_scheduled_action(id="patching.scan", module_id="patching", label="Patch scan", handler=handler, target_types=("none",), permission="patching.run")

CALLS = []
_real_queue = sv.queue_manual_run
sv.queue_manual_run = lambda schedule: CALLS.append(schedule) or _real_queue(schedule)


def run_now(user, schedule):
    try:
        return sv.SchedulerRunNowView().post(SimpleNamespace(user=user), str(schedule.pk))
    except PermissionDenied as exc:
        return exc


reset()
del CALLS[:]
one_off_run = sched.start_one_off_run(user=user_a, owner_module="patching", action_id="patching.scan", targets=None)
one_off = Schedule.objects.rows[0]
must(sched.is_one_off_schedule(one_off), one_off.__dict__)
# the start itself queued the one run (through scheduler.queue_manual_run, not the view's name)
before = (len(Schedule.objects.rows), len(Run.objects.rows), len(QUEUED), len(CALLS))
must(before == (1, 1, 1, 0), before)

# ---- another user with the permission and scope: refused, nothing queued
for who, label in ((user_b, "second user"), (user_a, "the owner"), (admin, "a scheduler manager")):
    reply = run_now(who, one_off)
    must(isinstance(reply, PermissionDenied), (label, reply))
    must("one-off run is managed by module 'patching' and cannot be run again" in str(reply), (label, str(reply)))
    after = (len(Schedule.objects.rows), len(Run.objects.rows), len(QUEUED), len(CALLS))
    must(after == before, (label, "no new run row, nothing queued, queue_manual_run not called", after))
# a user without even the action permission gets the same 403 (the one-off refusal comes first)
reply = run_now(User("nobody", Granted(14)), one_off)
must(isinstance(reply, PermissionDenied) and "cannot be run again" in str(reply), reply)

# ---- the run Core queued still executes as its owner
must(execute(one_off_run) == {"ok": True} and one_off_run.status == "succeeded", one_off_run.__dict__)
reply = run_now(user_b, one_off)
must(isinstance(reply, PermissionDenied) and len(Run.objects.rows) == 1, "after the run finished it still cannot be repeated")

# ---- ordinary schedules still run now
reset()
del CALLS[:]
module_owned = Schedule.objects.create(name="m", module_id="patching", action_id="patching.scan", owner_type="module", owner_module="patching", owner_key="nightly",
                                       targets={"type": "none"})
reply = run_now(user_b, module_owned)
must(getattr(reply, "status_code", None) == 202 and len(Run.objects.rows) == 1 and len(CALLS) == 1, reply)
must(Run.objects.rows[0].manual is True and Run.objects.rows[0].owner_key == "nightly", Run.objects.rows[0].__dict__)
user_owned = Schedule.objects.create(name="u", module_id="patching", action_id="patching.scan", owner_type="user", created_by=user_a, targets={"type": "none"})
reply = run_now(user_a, user_owned)
must(getattr(reply, "status_code", None) == 202 and len(CALLS) == 2, reply)
# a module key that only looks like the prefix is an ordinary schedule
look_alike = Schedule.objects.create(name="l", module_id="patching", action_id="patching.scan", owner_type="module", owner_module="patching",
                                     owner_key="my-one-off:x", targets={"type": "none"})
must(getattr(run_now(user_b, look_alike), "status_code", None) == 202, "only keys that start with one-off: are one-offs")
# a user-owned schedule whose key happens to start with the prefix is not a module one-off either
odd = Schedule.objects.create(name="o", module_id="patching", action_id="patching.scan", owner_type="user", owner_key="one-off:x", created_by=user_a,
                              targets={"type": "none"})
must(getattr(run_now(user_a, odd), "status_code", None) == 202, "the prefix is reserved for module-owned schedules")

# ---- reconcile_schedule: the prefix is reserved to Core
reset()
for key in ("one-off:abc", "one-off:", " one-off:abc ", "one-off:" + "x" * 20):
    try:
        sched.reconcile_schedule(owner_module="patching", owner_key=key, action_id="patching.scan", schedule_type="once",
                                 run_at=NOW[0] + timedelta(days=1), targets={"type": "none"})
        raise AssertionError(f"owner_key {key!r} accepted")
    except sched.SchedulerError as exc:
        must("one-off:" in str(exc) and "reserved to Core" in str(exc), exc)
    must(not Schedule.objects.rows, "nothing is created")
# an ordinary key (and one that merely contains the text) still reconciles
made = sched.reconcile_schedule(owner_module="patching", owner_key="nightly", action_id="patching.scan", schedule_type="once",
                                run_at=NOW[0] + timedelta(days=1), targets={"type": "none"})
must(made is not None and made.owner_key == "nightly" and len(Schedule.objects.rows) == 1, Schedule.objects.rows)
sched.reconcile_schedule(owner_module="patching", owner_key="a-one-off:b", action_id="patching.scan", schedule_type="once",
                         run_at=NOW[0] + timedelta(days=1), targets={"type": "none"})
must(len(Schedule.objects.rows) == 2, "a key that only contains the text is fine")
# start_one_off_run does not go through reconcile_schedule and still works
again = sched.start_one_off_run(user=user_a, owner_module="patching", action_id="patching.scan", targets=None)
must(again.status == "queued" and Schedule.objects.rows[-1].owner_key.startswith("one-off:"), again.__dict__)
# disable and remove stay as they are for a one-off key (cleanup relies on them)
must(sched.disable_owned_schedule(owner_module="patching", owner_key=Schedule.objects.rows[-1].owner_key) is not None, "disable still works")

# ---- every route that queues a run (source check): each call site is known and covered
views_path = APP / "scheduler_views.py"
views_text = views_path.read_text(encoding="utf-8")
tree = ast.parse(views_text)
lines = views_text.splitlines()
sites = []
for klass in (n for n in tree.body if isinstance(n, ast.ClassDef)):
    for fn in (n for n in klass.body if isinstance(n, ast.FunctionDef)):
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "queue_manual_run":
                body = "\n".join(lines[fn.lineno - 1:node.lineno - 1])
                sites.append((klass.name, fn.name, "is_one_off_schedule(" in body, "TecTacSchedule.objects.create(" in body))
must(sorted(s[:2] for s in sites) == [("SchedulerRunNowView", "post"), ("SchedulerSelfTestView", "post")],
     f"a new route queues a run: decide whether it takes an existing schedule id and refuses one-off schedules, then list it here: {sites}")
for klass, fn, refuses, makes_own in sites:
    # a route that takes an existing schedule id must refuse one-off schedules first; one that makes its own user-owned schedule needs no check
    must(refuses or makes_own, f"{klass}.{fn} queues a run for a schedule it did not make and does not refuse one-off schedules")
must(any(s[0] == "SchedulerRunNowView" and s[2] for s in sites), "run-now refuses one-off schedules")
must(any(s[0] == "SchedulerSelfTestView" and s[3] and not s[2] for s in sites), "the self-test makes its own USER-owned schedule")
# no other module of Core queues a run apart from scheduler.start_one_off_run
callers = sorted(p.name for p in APP.glob("*.py") if "queue_manual_run(" in p.read_text(encoding="utf-8") and p.name not in ("scheduler.py", "scheduler_views.py"))
must(not callers, f"other files call queue_manual_run: {callers}")
# in the view the refusal comes before the permission checks and before the queue
segment = views_text[views_text.index("class SchedulerRunNowView"):views_text.index("class SchedulerRunListView")]
must(segment.index("is_one_off_schedule(") < segment.index("_require_action(") < segment.index("queue_manual_run("), "order of the checks in run-now")

# ---- docs
doc = (ROOT / "docs" / "scheduler.md").read_text(encoding="utf-8")
must("cannot be run again" in doc and "`one-off:`" in doc and "reserved to Core" in doc, "docs/scheduler.md states both rules")

print("[TEST] PASS scheduler one-off run-now 1.17.17")
