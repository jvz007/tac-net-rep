#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.97 regression: the schedules of a disabled module are paused automatically (one audit row per module change) and hidden.

Scheduler (a), Johan, 30 October 2026. Core already paused a disabled module's schedules lazily at each tick (1.17.86). Now
``scheduler.sync_module_schedule_state`` does it in bulk (the tick calls it once, the list view calls it too), writes ONE audit row per module change
(action disable or enable, object type scheduler_module, metadata module_id and count) and never one per schedule or per tick. ``enabled`` and
``updated_at`` are never touched. ``ScheduleVisibility`` and ``hidden_module_ids`` read the module state live, so the API can leave the schedules
out without waiting for a tick. ``queue_manual_run`` and the worker refuse a paused or hidden schedule, so a run queued before the disable never
starts. An unreadable module state pauses nothing in the database, hides module-bound schedules and flags it. Core's own ids and legacy plugins are
never paused or hidden. Same stub harness as tests/scheduler-module-pause-1.17.86.py (Django is not needed). The API views are in
tests/scheduler-module-hide-views-1.17.97.py."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

_here = Path(__file__).resolve().parent
_name = "scheduler-module-pause-1.17.86.py"
_source = (_here / _name).read_text(encoding="utf-8")
_cut = _source.index("# (1) disabled module")
exec(compile(_source[:_cut], str(_here / _name), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sys.modules["tec_tac.registry"].get_plugins = lambda: discover_plugins()  # the module registry the visibility reads (the stub raises when STATE_FAULT is set)
CALLS: list = []
_fresh_86 = fresh


def fresh():
    _fresh_86()
    WORKER_GUARD["on"] = True
    CALLS.clear()
    plugin("legacyx", legacy=True)
    sched.register_scheduled_action(id="checks.probe", module_id="checks", label="probe", handler=lambda context: CALLS.append("checks") or {"ok": True})
    sched.register_scheduled_action(id="gone.probe", module_id="gone", label="probe", handler=lambda context: CALLS.append("gone") or {"ok": True})
    sched.register_scheduled_action(id="tec-tac.probe", module_id="tec-tac", label="probe", handler=lambda context: CALLS.append("tec-tac") or {"ok": True})


def module_rows():
    return [a for a in AUDITS if a.get("object_type") == "scheduler_module"]


def schedule_rows():
    return [a for a in AUDITS if a.get("object_type") == "scheduler_schedule"]


def make_for(mid, key, action, *, enabled=True, owner_type="module", owner_module=None):
    return Schedule.objects.create(
        name=key, module_id=mid, action_id=action, owner_type=owner_type, owner_module=(mid if owner_module is None else owner_module), owner_key=key if owner_type == "module" else "",
        enabled=enabled, schedule_type="interval", interval_seconds=60, interval_anchor_at=NOW[0] - timedelta(hours=3), targets={"type": "none"}, updated_at=NOW[0], created_at=NOW[0],
    )


# (1) disable, then enable: every schedule comes back exactly as it was
fresh()
a, d = make("checks", "a"), make("checks", "d")
c = make("checks", "c", enabled=False)  # a person switched this one off
b = make("other", "b")
before = {s.pk: (s.enabled, s.updated_at) for s in Schedule.objects.rows}
ENABLED["checks"] = False
for _ in range(3):
    sched.dispatch_due_schedules(NOW[0])
must(a.paused_reason == "paused: module disabled" and d.paused_reason == "paused: module disabled", "both enabled schedules of the module are paused")
must(c.paused_reason == "" and b.paused_reason == "", "a person-disabled schedule and another module's schedule are not paused")
rows = module_rows()
must(len(rows) == 1 and rows[0]["action"] == "disable" and rows[0]["object_id"] == "checks", ("ONE audit row for the module change", rows))
must(rows[0]["metadata"]["module_id"] == "checks" and rows[0]["metadata"]["count"] == 2, rows[0]["metadata"])
must(not schedule_rows(), "no per-schedule audit row any more")
must(all(r.module_id != "checks" for r in Run.objects.rows), "nothing of the disabled module runs")
must(any(r.module_id == "other" for r in Run.objects.rows), "another module still runs")
must({s.pk: (s.enabled, s.updated_at) for s in Schedule.objects.rows} == before, "enabled and updated_at are untouched by the pause")
Run.objects.rows[:] = []
ENABLED["checks"] = True
sched.dispatch_due_schedules(NOW[0])
must(a.paused_reason == "" and d.paused_reason == "" and c.paused_reason == "", "Core cleared exactly the reason it set")
must(a.enabled is True and d.enabled is True and c.enabled is False, "enabled ones run again, the person-disabled one stays off")
must({s.pk: (s.enabled, s.updated_at) for s in Schedule.objects.rows} == before, "the round trip restores every schedule exactly (updated_at too)")
must({r.schedule.pk for r in Run.objects.rows if r.module_id == "checks"} == {a.pk, d.pk}, "the resumed schedules run again")
rows = module_rows()
must(len(rows) == 2 and rows[1]["action"] == "enable" and rows[1]["metadata"]["count"] == 2, ("one resume row with the count", rows))
sched.dispatch_due_schedules(NOW[0] + timedelta(seconds=61))
must(len(module_rows()) == 2, "no audit row on later ticks")
print("       disable then enable: one audit row each with the count, enabled and updated_at untouched, the person-disabled one stays off")

# (2) sync on its own (what the list view calls): idempotent, and it sees a change the tick has not seen yet
fresh()
a = make("checks", "a")
ENABLED["checks"] = False
out = sched.sync_module_schedule_state()
must(out["paused"] == 1 and a.paused_reason and len(module_rows()) == 1, out)
out = sched.sync_module_schedule_state()
must(out["paused"] == 0 and len(module_rows()) == 1, "a second sync writes nothing")
ENABLED["checks"] = True
out = sched.sync_module_schedule_state()
must(out["resumed"] == 1 and a.paused_reason == "" and len(module_rows()) == 2, out)
print("       sync_module_schedule_state alone is idempotent and audited once per change")

# (3) hidden_module_ids and the visibility reads
fresh()
ENABLED.update({"checks": False, "legacyx": False})
state = {"schema": 1, "modules": {"checks": {}, "other": {}, "legacyx": {}, "core": {}, "tec-tac": {}}}
ENABLED["core"] = ENABLED["tec-tac"] = False
must(sched.hidden_module_ids(state) == frozenset({"checks"}), ("Core's own ids and a legacy plugin are never named", sched.hidden_module_ids(state)))
must(sched.hidden_module_ids(None) == frozenset(), "an unreadable state names none")
vis = sched.ScheduleVisibility()
user_sched = make_for("checks", "", "checks.probe", owner_type="user", owner_module="")
core_sched = make_for("tec-tac", "core-one", "tec-tac.probe")
legacy_sched = make_for("legacyx", "leg", "checks.probe")
orphan = make_for("gone", "o", "gone.probe")
must(vis.hidden(make("checks", "m")) and vis.hidden(user_sched), "module-owned and user schedules of a disabled module are hidden")
must(not vis.hidden(core_sched) and not vis.hidden(legacy_sched), "Core's own actions and legacy plugins are never hidden")
must(vis.kind(orphan) == "orphaned" and not vis.hidden(orphan), "a module that is not installed is orphaned, shown, not hidden")
must(vis.unreadable is False and sched.ScheduleVisibility(read_state=False).hidden(user_sched) is False, "read_state=False asks nothing of the module state")
print("       hidden_module_ids and ScheduleVisibility: disabled hidden, Core and legacy never, not installed shown as orphaned")

# (3b) the tick never runs an orphan (a module that is not installed): it is paused, no run, no failing run; it returns with the module
fresh()
orphan = make_for("gone", "o", "gone.probe")
person_off = make_for("gone", "p", "gone.probe", enabled=False)
for _ in range(2):
    sched.dispatch_due_schedules(NOW[0])
must(orphan.paused_reason == "paused: owner module not installed" and person_off.paused_reason == "", "paused, the person-disabled one untouched")
must(not [r for r in Run.objects.rows if r.module_id == "gone"] and not CALLS, "an orphan never runs and never fails a run")
rows = module_rows()
must(len(rows) == 1 and rows[0]["action"] == "disable" and rows[0]["metadata"]["module_id"] == "gone" and rows[0]["metadata"]["count"] == 1, ("one audit row for the module", rows))
plugin("gone")
sched.dispatch_due_schedules(NOW[0])
must(orphan.paused_reason == "" and orphan.enabled is True and any(r.module_id == "gone" for r in Run.objects.rows), "installed again: it runs as it was")
print("       the tick never runs an orphan, writes one audit row, and the schedule returns with the module")

# (4) queue_manual_run refuses a paused or hidden schedule; an enabled module's schedule queues as before
fresh()
a = make_for("checks", "a", "checks.probe")
must(sched.queue_manual_run(a) is not None and len(Run.objects.rows) == 1, "an enabled module queues as before")
ENABLED["checks"] = False
for bad in (a, make_for("checks", "p", "checks.probe")):
    try:
        sched.queue_manual_run(bad)
    except sched.SchedulerError as exc:
        must("disabled" in str(exc), exc)
    else:
        raise AssertionError("a hidden schedule was queued")
ENABLED["checks"] = True
a.paused_reason = "paused: module disabled"
try:
    sched.queue_manual_run(a)
except sched.SchedulerError:
    pass
else:
    raise AssertionError("a paused schedule was queued")
must(len(Run.objects.rows) == 1, "nothing more was queued")
print("       queue_manual_run: a hidden or paused schedule is refused, an enabled one queues as before")

# (5) a run queued before the disable never starts: the worker skips it with a plain reason
fresh()
queued = make_run("checks.probe", "checks", owner="module")
ENABLED["checks"] = False
out = go(queued)
must(queued.status == "skipped" and "disabled" in queued.error and queued.error_type == "ModuleUnavailable" and not CALLS, (queued.status, queued.error, CALLS))
must(queued.finished_at is not None, "the skipped run is finished")
ENABLED["checks"] = True
again = make_run("checks.probe", "checks", owner="module")
go(again)
must(again.status == "succeeded" and CALLS == ["checks"], (again.status, CALLS))
orphan_run = make_run("gone.probe", "gone", owner="module")
go(orphan_run)
must(orphan_run.status == "skipped" and "not installed" in orphan_run.error and CALLS == ["checks"], (orphan_run.status, orphan_run.error))
core_run = make_run("tec-tac.probe", "tec-tac", owner="module")
go(core_run)
must(core_run.status == "succeeded" and CALLS == ["checks", "tec-tac"], "Core's own action is never blocked")
print("       worker guard: a run queued before the disable is skipped with a reason, the handler never runs; Core's own action runs")

# (6) an unreadable module state: nothing changes in the database, module-bound schedules are skipped and hidden, Core's own still run
fresh()
a = make_for("checks", "a", "checks.probe")
core_sched = make_for("tec-tac", "core-one", "tec-tac.probe")
STATE["corrupt"] = True
out = sched.dispatch_due_schedules(NOW[0])
must(a.paused_reason == "" and not module_rows(), "an unreadable state pauses nothing in the database and writes no audit row")
must(all(r.module_id != "checks" for r in Run.objects.rows), "the module-bound schedule waits")
must(any(r.module_id == "tec-tac" for r in Run.objects.rows), "Core's own schedule still runs")
vis = sched.ScheduleVisibility()
must(vis.unreadable and vis.hidden(a) and not vis.hidden(core_sched), "module-bound schedules are hidden, fail closed")
must(sched.sync_module_schedule_state()["state_unreadable"] is True and a.paused_reason == "", "sync reports it and changes nothing")
unreadable = make_run("checks.probe", "checks", owner="module")
go(unreadable)
must(unreadable.status == "skipped" and "module state" in unreadable.error, (unreadable.status, unreadable.error))
STATE["corrupt"] = False
print("       unreadable state: nothing written, module-bound hidden and skipped, Core's own unaffected")

# (7) the registry cannot be read: every module counts as installed, so nothing is orphaned
fresh()
orphan = make_for("gone", "o", "gone.probe")
STATE_FAULT["registry"] = True
vis = sched.ScheduleVisibility()
must(vis.kind(orphan) == "" and sched.installed_module_ids() is None, "an unreadable registry means installed")
STATE_FAULT["registry"] = False
must(sched.installed_module_ids() >= {"checks", "other", "tec-tac", "core"} and "gone" not in sched.installed_module_ids(), sched.installed_module_ids())
print("       an unreadable registry never orphans a schedule; installed_module_ids names the registry plus Core's ids")

# (8) an enabled module keeps today's rules (regression assertion): runs, shows, audits nothing
fresh()
a, b = make_for("checks", "a", "checks.probe"), make_for("other", "b", "checks.probe")
for _ in range(2):
    sched.dispatch_due_schedules(NOW[0])
must(len([r for r in Run.objects.rows if r.module_id in ("checks", "other")]) == 2 and not module_rows(), "enabled modules run, nothing is paused or audited")
must(a.paused_reason == "" and sched.serialize_schedule(a)["paused"] is False and sched.serialize_schedule(a)["orphaned"] is False, "enabled schedules show as they did")
print("       enabled modules keep today's rules")

# (9) text checks: the tick calls the sync once, no per-schedule pause row is written, the docs say so
src = (APP / "scheduler.py").read_text(encoding="utf-8")
tick = src[src.index("def dispatch_due_schedules"): src.index("def queue_manual_run")]
must(tick.count("sync_module_schedule_state(") == 1 and "ScheduleVisibility()" in tick, "the tick reads the state once and syncs once")
must("Core paused this schedule because module" not in src, "the per-schedule pause audit row is gone")
print("[TEST] PASS scheduler module hide 1.17.97")
