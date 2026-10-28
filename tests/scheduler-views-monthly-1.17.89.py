#!/usr/bin/env python3
"""1.17.89 regression (the two Lows of the 1.17.88 review): the real SchedulerListView.post and SchedulerDetailView.patch accept, return and refuse the
nth-weekday fields; a PATCH that makes a monthly schedule weekly clears day_of_month, month_week and month_weekday; the confirmation key ignores
a pair on a schedule that is not monthly. Harness of tests/scheduler-run-now-person-strict-1.17.87.py (real scheduler.py and scheduler_views.py on stubs)."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

_here = Path(__file__).resolve().parent
_source = (_here / "scheduler-tactical-permission-1.17.17.py").read_text(encoding="utf-8")
_cut = _source.index("# ---- harness end")
exec(compile(_source[:_cut], str(_here / "scheduler-tactical-permission-1.17.17.py"), "exec"), globals())  # noqa: S102 - the shared test harness
H = globals()
(must, sched, sv, Schedule, User, Granted, handler, reset, SimpleNamespace, sys) = (
    H[k] for k in ("must", "sched", "sv", "Schedule", "User", "Granted", "handler", "reset", "SimpleNamespace", "sys"))

# the view stubs of the harness parse no dates; this test sends HH:MM strings
sv.parse_time = lambda text: dt.time.fromisoformat(text) if text else None
sv.parse_datetime = lambda text: None
Schedule.defaults.update(month_week=None, month_weekday=None, created_by_username="", confirmed_by_username="", creation_scope={}, latest_status=None, updated_at=dt.datetime(2026, 10, 28, tzinfo=dt.timezone.utc))
Schedule.save = lambda self, update_fields=None: self in Schedule.objects.rows or Schedule.objects.rows.append(self)
sched.register_scheduled_action(id="patching.window", module_id="patching", label="Window", handler=handler, target_types=("none",), permission=None)
boss = User("boss", Granted(30, can_do_server_maint=True))
sv.scheduler_creation_scope = SimpleNamespace(capture=lambda user: {})

Schedule.runs = property(lambda self: SimpleNamespace(all=list))  # no runs in this test
Schedule.objects.select_related = lambda *names: Schedule.objects
sv.get_object_or_404 = lambda qs, pk: next(r for r in Schedule.objects.rows if str(r.pk) == str(pk))
Schedule.created_by_id = property(lambda self: getattr(self.created_by, 'id', None))
LIST, DETAIL = sv.SchedulerListView, sv.SchedulerDetailView


def post(body):
    return LIST().post(SimpleNamespace(user=boss, data=dict(body)))


def patch(schedule, body):
    return DETAIL().patch(SimpleNamespace(user=boss, data=dict(body)), str(schedule.pk))


BASE = {"name": "Window", "action_id": "patching.window", "module_id": "patching", "targets": {"type": "none"}, "schedule_type": "monthly", "run_time": "03:00"}


def fields(reply):
    return {k: reply.data.get(k) for k in ("day_of_month", "month_week", "month_weekday", "schedule_type")}


# POST: the pair is accepted and returned; day_of_month is empty
reset()
reply = post({**BASE, "month_week": 2, "month_weekday": 1})
must(reply.status_code == 201, reply.data)
must(fields(reply) == {"day_of_month": None, "month_week": 2, "month_weekday": 1, "schedule_type": "monthly"}, fields(reply))
stored = Schedule.objects.rows[0]
must((stored.month_week, stored.month_weekday, stored.day_of_month) == (2, 1, None), "the row holds the pair")

# POST: the last Friday, and a day of the month, both still work
must(fields(post({**BASE, "month_week": -1, "month_weekday": 4}))["month_week"] == -1, "last weekday")
must(fields(post({**BASE, "day_of_month": 15}))["day_of_month"] == 15, "day of the month still works")

# POST refusals: both modes, neither, half a pair, out of range, a boolean. Nothing is saved for any of them.
before = len(Schedule.objects.rows)
for body, part in (({"day_of_month": 12, "month_week": 2, "month_weekday": 1}, "not both"), ({}, "require day_of_month"),
                   ({"month_week": 2}, "go together"), ({"month_weekday": 1}, "go together"), ({"month_week": 5, "month_weekday": 1}, "month_week"),
                   ({"month_week": 2, "month_weekday": 7}, "month_weekday"), ({"month_week": True, "month_weekday": 1}, "month_week")):
    reply = post({**BASE, **body})
    must(reply.status_code == 400 and part in reply.data["detail"], (body, reply.status_code, reply.data))
must(len(Schedule.objects.rows) == before, "a refused POST saves nothing")

# PATCH: send only the pair and the day goes; send only the day and the pair goes
reset()
s = Schedule.objects.create(name="W", module_id="patching", action_id="patching.window", owner_type="user", created_by=boss, schedule_type="monthly",
                            run_time=dt.time(3, 0), day_of_month=12, targets={"type": "none"})
reply = patch(s, {"month_week": 3, "month_weekday": 2})
must(reply.status_code == 200 and fields(reply) == {"day_of_month": None, "month_week": 3, "month_weekday": 2, "schedule_type": "monthly"}, reply.data)
reply = patch(s, {"day_of_month": 20})
must(reply.status_code == 200 and fields(reply) == {"day_of_month": 20, "month_week": None, "month_weekday": None, "schedule_type": "monthly"}, reply.data)
reply = patch(s, {"month_week": -1, "month_weekday": 6, "day_of_month": 5})
must(reply.status_code == 400 and "not both" in reply.data["detail"], reply.data)
must((s.day_of_month, s.month_week) == (20, None), "a refused PATCH changes nothing")
reply = patch(s, {"month_week": 2})
must(reply.status_code == 400 and "go together" in reply.data["detail"], reply.data)

# PATCH to weekly (1.17.89): the monthly fields are cleared and do not come back when the schedule is made monthly again
reply = patch(s, {"month_week": 2, "month_weekday": 1})
must(reply.status_code == 200 and s.month_week == 2, "nth weekday set")
reply = patch(s, {"schedule_type": "weekly", "weekdays": [1]})
must(reply.status_code == 200 and fields(reply) == {"day_of_month": None, "month_week": None, "month_weekday": None, "schedule_type": "weekly"}, reply.data)
must((s.day_of_month, s.month_week, s.month_weekday) == (None, None, None), "the row holds none of the monthly fields")
reply = patch(s, {"schedule_type": "monthly"})
must(reply.status_code == 400 and "require day_of_month" in reply.data["detail"], "monthly again needs a fresh choice: " + str(reply.data))
reply = patch(s, {"schedule_type": "monthly", "day_of_month": 9})
must(reply.status_code == 200 and fields(reply)["day_of_month"] == 9 and s.month_week is None, reply.data)

# the confirmation key: a pair counts only on a monthly schedule
from tec_tac import system_action_confirmation as sac

pair = {"run_time": "03:00", "month_week": 2, "month_weekday": 1}
must("month_week" in sac.when_key({**pair, "schedule_type": "monthly"}), "monthly keeps the pair")
must(sac.when_key({**pair, "schedule_type": "weekly", "weekdays": [1]}) == sac.when_key({"schedule_type": "weekly", "run_time": "03:00", "weekdays": [1]}),
     "a weekly schedule with a stale pair has the key of a weekly schedule without one")
print("PASS scheduler views monthly 1.17.89")
