#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.87 regression (held Medium of the 1.17.86 review): pausing and resuming a schedule must not move ``updated_at``.

``updated_at`` is auto_now and is the revision baseline: an occurrence older than it is treated as a pre-edit baseline and consumed
(a ``once`` schedule is then switched off with no run and no missed row). Before 1.17.87 the pause and resume saves wrote ``updated_at``, so a
``once`` schedule whose occurrence fell inside the pause was swallowed on the resume tick. Same stub harness as scheduler-module-pause-1.17.86.py,
with the stub save stamping ``updated_at`` the way auto_now does (only when the save writes that field)."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

_here = Path(__file__).resolve().parent
_source = (_here / "scheduler-module-pause-1.17.86.py").read_text(encoding="utf-8")
_cut = _source.index("# (1) disabled module")
exec(compile(_source[:_cut], str(_here / "scheduler-module-pause-1.17.86.py"), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

CLOCK = [NOW[0]]
_plain_save = Schedule.save


def _auto_now_save(self, update_fields=None):
    # Django's auto_now: pre_save runs only for the fields the save writes, so an update_fields without updated_at leaves it alone
    if update_fields is None or "updated_at" in update_fields:
        self.updated_at = CLOCK[0]
    _plain_save(self, update_fields)


Schedule.save = _auto_now_save


def make_once(policy="run_on_recovery"):
    t0 = NOW[0]
    s = Schedule.objects.create(
        name="once", module_id="checks", action_id="checks.provider-run", owner_type="module", owner_module="checks", owner_key="once", enabled=True,
        schedule_type="once", run_at=t0 + timedelta(minutes=10), missed_policy=policy, missed_grace_minutes=60, targets={"type": "none"},
        updated_at=t0, created_at=t0,
    )
    return s


for policy, grace_ok in (("run_on_recovery", True), ("skip", False)):
    fresh()
    CLOCK[0] = NOW[0]
    s = make_once(policy)
    ENABLED["checks"] = False
    CLOCK[0] = NOW[0] + timedelta(minutes=5)  # the pause tick, before the occurrence
    sched.dispatch_due_schedules(CLOCK[0])
    must(s.paused_reason == "paused: module disabled" and s.updated_at == NOW[0], ("the pause did not move updated_at", s.updated_at))
    ENABLED["checks"] = True
    CLOCK[0] = NOW[0] + timedelta(minutes=40)
    sched._apply_module_pause(s, {"schema": 1, "modules": {}})  # the resume step alone
    must(s.paused_reason == "" and s.enabled is True and s.updated_at == NOW[0], ("the resume did not move updated_at or switch the schedule off", s.updated_at))
    s.paused_reason = "paused: module disabled"  # back to paused, so the tick below does the real resume
    CLOCK[0] = NOW[0] + timedelta(minutes=40)  # the resume tick, after the occurrence (inside a 60 minute grace)
    out = sched.dispatch_due_schedules(CLOCK[0])
    runs = [r for r in Run.objects.rows if r.module_id == "checks"]
    must(len(runs) == 1, (policy, "exactly one run or missed row, not a silent consume", len(runs)))
    if grace_ok:
        must(runs[0].status == "queued" and out["queued"], ("run_on_recovery queues the occurrence", runs[0].status))
    else:
        must(runs[0].status == "skipped" and runs[0].error_type == "MissedSkip", ("skip writes a missed row", runs[0].status, runs[0].error_type))
    must(s.last_due_key, "the occurrence is recorded")
    # the person's on switch: a ran once schedule ends as ONCE always did; the point is that it ended by running or by a missed row
print("PASS scheduler module pause 1.17.87")
