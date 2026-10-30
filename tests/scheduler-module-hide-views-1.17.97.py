#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.97 regression, the API half of Scheduler (a): the real SchedulerListView, SchedulerDetailView, SchedulerRunNowView and the run list filter
leave out the schedules of a disabled module (404 for a detail, Run now and delete), read the module state live at request time, flag an unreadable
state and keep every enabled module's schedule exactly as before. Harness of tests/scheduler-views-monthly-1.17.89.py (the real scheduler.py and
scheduler_views.py on stubs; Django and DRF are not needed)."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

_here = Path(__file__).resolve().parent
_source = (_here / "scheduler-tactical-permission-1.17.17.py").read_text(encoding="utf-8")
_cut = _source.index("# ---- harness end")
exec(compile(_source[:_cut], str(_here / "scheduler-tactical-permission-1.17.17.py"), "exec"), globals())  # noqa: S102 - the shared test harness
H = globals()
(must, sched, sv, Schedule, Run, User, Granted, handler, reset, SimpleNamespace, sys, NotFound, AUDITS) = (
    H[k] for k in ("must", "sched", "sv", "Schedule", "Run", "User", "Granted", "handler", "reset", "SimpleNamespace", "sys", "NotFound", "AUDITS"))

T0 = dt.datetime(2026, 10, 30, 12, 0, tzinfo=dt.timezone.utc)
Schedule.defaults.update(month_week=None, month_weekday=None, created_by_username="", confirmed_by_username="", creation_scope={}, latest_status=None, updated_at=T0,
                         paused_reason="", schedule_type="interval", interval_seconds=60)
Schedule.save = lambda self, update_fields=None: self in Schedule.objects.rows or Schedule.objects.rows.append(self)
Schedule.created_by_id = property(lambda self: getattr(self.created_by, "id", None))
Schedule.runs = property(lambda self: SimpleNamespace(all=list, first=lambda: None))
sv.scheduler_creation_scope = SimpleNamespace(capture=lambda user: {})
boss = User("boss", Granted(30, can_do_server_maint=True))

# the module state and registry the views read (the real module_state needs fcntl)
ENABLED = {"checks": True, "other": True}
STATE = {"unreadable": False}
PLUGINS = ["checks", "other"]
sys.modules["tec_tac.module_state"].load_state = lambda: (_ for _ in ()).throw(OSError("state down")) if STATE["unreadable"] else {"schema": 1, "modules": {m: {} for m in ENABLED}}
sys.modules["tec_tac.module_state"].is_enabled = lambda module_id, state=None: ENABLED.get(module_id, True)
sys.modules["tec_tac.registry"].get_plugins = lambda: tuple(SimpleNamespace(plugin_id=i, legacy=False, plugin_type="extension", permission_groups=()) for i in PLUGINS)

# the query layer the list view uses
Schedule.objects.select_related = lambda *a: SimpleNamespace(annotate=lambda **k: list(Schedule.objects.rows))
sv.TecTacScheduleRun = SimpleNamespace(objects=SimpleNamespace(filter=lambda **k: SimpleNamespace(order_by=lambda *a: SimpleNamespace(values=lambda *a: [None]))))
sv.get_object_or_404 = lambda qs, pk: next((r for r in Schedule.objects.rows if str(r.pk) == str(pk)), None) or (_ for _ in ()).throw(NotFound("no schedule"))
sched.register_scheduled_action(id="checks.probe", module_id="checks", label="probe", handler=handler, target_types=("none",), permission=None)
sched.register_scheduled_action(id="other.probe", module_id="other", label="probe", handler=handler, target_types=("none",), permission=None)
sched.register_scheduled_action(id="tec-tac.probe", module_id="tec-tac", label="probe", handler=handler, target_types=("none",), permission=None)
LIST, DETAIL, RUNNOW = sv.SchedulerListView, sv.SchedulerDetailView, sv.SchedulerRunNowView
QUEUED_RUNS: list = []
sv.queue_manual_run = lambda schedule, **kw: QUEUED_RUNS.append(schedule) or SimpleNamespace(id="run-1")
sv.serialize_run = lambda run: {"id": run.id}


def make(mid, key, action=None, *, enabled=True, owner_module=None):
    return Schedule.objects.create(name=key, module_id=mid, action_id=action or f"{mid}.probe", owner_type="module", owner_module=(mid if owner_module is None else owner_module),
                                   owner_key=key, enabled=enabled, targets={"type": "none"}, created_at=T0)


def listing(**query):
    return LIST().get(SimpleNamespace(user=boss, query_params=dict(query)))


def ids(reply):
    return {row["name"] for row in reply.data["schedules"]}


def fresh():
    reset()
    ENABLED.update({"checks": True, "other": True})
    STATE["unreadable"] = False
    PLUGINS[:] = ["checks", "other"]
    del QUEUED_RUNS[:]


# (1) the list leaves out a disabled module's schedules and reads the state at request time (no tick needed)
fresh()
a, b, core = make("checks", "a"), make("other", "b"), make("tec-tac", "c")
reply = listing()
must(reply.status_code == 200 and ids(reply) == {"a", "b", "c"} and reply.data["module_state_unreadable"] is False, reply.data)
ENABLED["checks"] = False
reply = listing()
must(ids(reply) == {"b", "c"} and reply.data["count"] == 2, ("the disabled module's schedule is absent at once", ids(reply)))
must(a.paused_reason == "paused: module disabled", "the list also brought the pause up to date")
rows = [x for x in AUDITS if x.get("object_type") == "scheduler_module"]
must(len(rows) == 1 and rows[0]["metadata"]["count"] == 1, rows)
listing()
must(len([x for x in AUDITS if x.get("object_type") == "scheduler_module"]) == 1, "a second list writes no second row")
ENABLED["checks"] = True
must(ids(listing()) == {"a", "b", "c"} and a.paused_reason == "", "enabled again: back, and the reason Core set is cleared")
print("       list: a disabled module's schedules are left out at request time; enabled again they are back as they were")

# (2) detail, Run now and delete answer 404 for a hidden schedule; the enabled ones answer as before
fresh()
a, b = make("checks", "a"), make("other", "b")
ENABLED["checks"] = False
for call in (lambda: DETAIL().get(SimpleNamespace(user=boss), str(a.pk)),
             lambda: DETAIL().delete(SimpleNamespace(user=boss, query_params={}), str(a.pk)),
             lambda: RUNNOW().post(SimpleNamespace(user=boss), str(a.pk))):
    try:
        call()
    except NotFound:
        pass
    else:
        raise AssertionError("a hidden schedule answered")
must(not QUEUED_RUNS, "Run now queued nothing")
must(DETAIL().get(SimpleNamespace(user=boss), str(b.pk)).data["name"] == "b", "another module's schedule answers as before")
print("       detail, delete and Run now: 404 for a disabled module's schedule, unchanged for an enabled one")

# (3) an unreadable module state: module-bound schedules are hidden and the list says so; Core's own stay
fresh()
a, core = make("checks", "a"), make("tec-tac", "c")
STATE["unreadable"] = True
reply = listing()
must(ids(reply) == {"c"} and reply.data["module_state_unreadable"] is True and a.paused_reason == "", (ids(reply), reply.data))
try:
    DETAIL().get(SimpleNamespace(user=boss), str(a.pk))
except NotFound:
    pass
else:
    raise AssertionError("a module-bound schedule answered with an unreadable state")
print("       unreadable state: module-bound schedules hidden, module_state_unreadable true, Core's own listed")

# (4) the run list leaves out the runs of hidden schedules (the filter the view applies to its query)
fresh()
ENABLED["checks"] = False
vis = sched.ScheduleVisibility()
must(vis.hidden_run_filter() == (frozenset({"checks"}), False), vis.hidden_run_filter())
STATE["unreadable"] = True
must(sched.ScheduleVisibility().hidden_run_filter() == (frozenset(), True), "an unreadable state keeps only Core's own runs")
src = (APP / "scheduler_views.py").read_text(encoding="utf-8")
base = src[src.index("def _base_queryset"): src.index("def _row_visible")]
must("hidden_run_filter()" in base and "module_id__in" in base and "owner_module__in" in base, "the run list query applies the filter")
print("       run list: the query leaves out hidden runs, and keeps only Core's own when the state is unreadable")

# (5) an orphaned (not installed) module's schedules are NOT hidden: they show with the additive fields
fresh()
sched.register_scheduled_action(id="gone.probe", module_id="gone", label="probe", handler=handler, target_types=("none",), permission=None)
o = make("gone", "o")
reply = listing()
row = next(r for r in reply.data["schedules"] if r["name"] == "o")
must(row["orphaned"] is True and row["owner_module_installed"] is False and row["orphan_label"] == "Owner module not installed", row)
must(o.paused_reason == "paused: owner module not installed" and row["paused"] is True, "paused by Core, shown")
must(next(r for r in reply.data["schedules"] if r["name"] == "o") and listing(orphaned="true").data["count"] == 1 and listing(orphaned="false").data["count"] == 0, "the orphaned filter")
must(listing(orphaned="maybe").status_code == 400, "a bad filter value is a 400")
print("       an orphaned schedule is listed (not hidden) with orphaned, owner_module_installed and the label; the filter works")

print("[TEST] PASS scheduler module hide views 1.17.97")
