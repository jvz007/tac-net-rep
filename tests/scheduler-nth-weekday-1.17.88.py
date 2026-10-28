#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.88: a monthly schedule can run on the nth weekday of the month (month_week 1-4 or -1 for the last, month_weekday 0-6).

Same stub harness as the other scheduler tests (no Django). Checks the date maths for every week and weekday, month and year boundaries, a
month that has only four of a weekday, the schedule's own zone, strict validation and plain messages, the edit switch between the two
monthly modes, reconcile_schedule, the serializer, the confirmation key and text, and that day_of_month schedules behave exactly as before."""
from __future__ import annotations

import calendar
from datetime import date, datetime, time, timedelta, timezone as dt_timezone
from pathlib import Path
from zoneinfo import ZoneInfo

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
sched._zone = lambda value: ZoneInfo(value or "UTC")  # the harness stubs the zone out; the real one is needed here
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
UTC = dt_timezone.utc
SAST = ZoneInfo("Africa/Johannesburg")


def sched_row(**kw):
    base = dict(schedule_type="monthly", run_time=time(2, 30), timezone="UTC", day_of_month=None, month_week=None, month_weekday=None, weekdays=[])
    base.update(kw)
    return SimpleNamespace(**base)


# ---- the date maths, against calendar for every month of 2024 to 2027, every weekday, every week
for year in range(2024, 2028):
    for month in range(1, 13):
        days = [d for d in range(1, calendar.monthrange(year, month)[1] + 1)]
        for weekday in range(7):
            matching = [d for d in days if date(year, month, d).weekday() == weekday]
            for week in (1, 2, 3, 4):
                got = sched.nth_weekday_date(year, month, week, weekday)
                must(got == date(year, month, matching[week - 1]), (year, month, week, weekday, got))
            got = sched.nth_weekday_date(year, month, -1, weekday)
            must(got == date(year, month, matching[-1]), ("last", year, month, weekday, got))
            must(got.weekday() == weekday and got.month == month, got)
print("       nth_weekday_date: first to fourth and last, every weekday, every month 2024-2027")

# a month with only four Mondays (February 2027 has exactly four of every weekday): the fourth and the last are the same day
must(sched.nth_weekday_date(2027, 2, 4, 0) == sched.nth_weekday_date(2027, 2, -1, 0) == date(2027, 2, 22), "four Mondays")
# a month with five Mondays (March 2027 starts on a Monday): the last is the fifth, the fourth is one week earlier
must(sched.nth_weekday_date(2027, 3, 4, 0) == date(2027, 3, 22) and sched.nth_weekday_date(2027, 3, -1, 0) == date(2027, 3, 29), "five Mondays")
# a month where the 1st is the weekday itself, and one where it is the day before
must(sched.nth_weekday_date(2026, 10, 1, 3) == date(2026, 10, 1), "1 Oct 2026 is a Thursday")
must(sched.nth_weekday_date(2026, 10, 2, 2) == date(2026, 10, 14), "second Wednesday of October 2026")
print("       a month with four of a weekday, one with five, and a first day that is the weekday")

# ---- next and latest occurrence: second Tuesday at 02:30 UTC
s = sched_row(month_week=2, month_weekday=1)
nxt = sched.next_occurrence(s, datetime(2026, 10, 1, 0, 0, tzinfo=UTC))
must(nxt == datetime(2026, 10, 13, 2, 30, tzinfo=UTC), nxt)  # 13 October 2026 is the second Tuesday
nxt = sched.next_occurrence(s, datetime(2026, 10, 13, 2, 30, tzinfo=UTC))
must(nxt == datetime(2026, 10, 13, 2, 30, tzinfo=UTC), "an occurrence at exactly now is still due")
nxt = sched.next_occurrence(s, datetime(2026, 10, 13, 2, 31, tzinfo=UTC))
must(nxt == datetime(2026, 11, 10, 2, 30, tzinfo=UTC), nxt)  # month boundary: next is the second Tuesday of November
nxt = sched.next_occurrence(s, datetime(2026, 12, 20, 0, 0, tzinfo=UTC))
must(nxt == datetime(2027, 1, 12, 2, 30, tzinfo=UTC), nxt)  # year boundary
late = sched.latest_occurrence(s, datetime(2026, 10, 20, 0, 0, tzinfo=UTC))
must(late == datetime(2026, 10, 13, 2, 30, tzinfo=UTC), late)
late = sched.latest_occurrence(s, datetime(2026, 10, 13, 2, 29, tzinfo=UTC))
must(late == datetime(2026, 9, 8, 2, 30, tzinfo=UTC), late)  # before this month's run: last month's
late = sched.latest_occurrence(s, datetime(2027, 1, 5, 0, 0, tzinfo=UTC))
must(late == datetime(2026, 12, 8, 2, 30, tzinfo=UTC), late)  # year boundary backwards
# the last Friday, across a month that has four and one that has five Fridays
s = sched_row(month_week=-1, month_weekday=4)
must(sched.next_occurrence(s, datetime(2026, 10, 1, tzinfo=UTC)) == datetime(2026, 10, 30, 2, 30, tzinfo=UTC), "last Friday of Oct 2026")
must(sched.next_occurrence(s, datetime(2026, 10, 31, tzinfo=UTC)) == datetime(2026, 11, 27, 2, 30, tzinfo=UTC), "last Friday of Nov 2026")
must(sched.next_occurrence(s, datetime(2027, 1, 1, tzinfo=UTC)) == datetime(2027, 1, 29, 2, 30, tzinfo=UTC), "last Friday of Jan 2027")
# a long walk: every occurrence over three years is the right weekday and strictly later than the one before
walk, cursor = [], datetime(2025, 1, 1, tzinfo=UTC)
s = sched_row(month_week=3, month_weekday=6)
for _ in range(36):
    cursor = sched.next_occurrence(s, cursor)
    walk.append(cursor)
    cursor += timedelta(minutes=1)
must(all(w.weekday() == 6 and 15 <= w.day <= 21 for w in walk) and walk == sorted(set(walk)) and len(walk) == 36, walk)
print("       next and latest occurrence across month and year boundaries; 36 months in a row")

# ---- the schedule's own zone: 01:30 in Johannesburg on the second Tuesday is 23:30 UTC the evening before
s = sched_row(month_week=2, month_weekday=1, timezone="Africa/Johannesburg", run_time=time(1, 30))
nxt = sched.next_occurrence(s, datetime(2026, 10, 1, tzinfo=UTC))
must(nxt == datetime(2026, 10, 12, 23, 30, tzinfo=UTC) and nxt.astimezone(SAST).weekday() == 1, nxt)
# a zone with daylight saving: the local wall time stays, the UTC time moves (as for every other monthly schedule)
s = sched_row(month_week=1, month_weekday=0, timezone="Europe/London", run_time=time(3, 0))
summer, winter = sched.next_occurrence(s, datetime(2026, 7, 1, tzinfo=UTC)), sched.next_occurrence(s, datetime(2026, 12, 1, tzinfo=UTC))
must(summer == datetime(2026, 7, 6, 2, 0, tzinfo=UTC) and winter == datetime(2026, 12, 7, 3, 0, tzinfo=UTC), (summer, winter))
print("       computed in the schedule's own zone, local wall time kept")

# ---- day_of_month schedules are exactly as before, including 31 in a short month, and a pair that is not set
s = sched_row(day_of_month=31)
must(sched.next_occurrence(s, datetime(2026, 2, 1, tzinfo=UTC)) == datetime(2026, 2, 28, 2, 30, tzinfo=UTC), "31 falls on the last day of February")
must(sched.next_occurrence(s, datetime(2026, 10, 15, tzinfo=UTC)) == datetime(2026, 10, 31, 2, 30, tzinfo=UTC), "31 October")
must(sched.latest_occurrence(s, datetime(2026, 3, 1, tzinfo=UTC)) == datetime(2026, 2, 28, 2, 30, tzinfo=UTC), "latest 31 before March")
s = sched_row(day_of_month=15)
must(sched.next_occurrence(s, datetime(2026, 10, 16, tzinfo=UTC)) == datetime(2026, 11, 15, 2, 30, tzinfo=UTC), "15th")
must(sched.next_occurrence(sched_row(), datetime(2026, 10, 16, tzinfo=UTC)) is None and sched.latest_occurrence(sched_row(), datetime(2026, 10, 16, tzinfo=UTC)) is None, "no day set: no run")
must(sched.next_occurrence(sched_row(month_week=2), datetime(2026, 10, 16, tzinfo=UTC)) is None, "half a pair on a stored row runs nothing")
print("       day_of_month schedules unchanged (31 in a short month, 15th, none set)")


# ---- validation: strict, plain messages
def refused(payload, text, **kw):
    try:
        sched.validate_schedule_payload(payload, **kw)
    except sched.SchedulerError as exc:
        must(text in str(exc), (payload, str(exc)))
        return
    raise AssertionError(f"accepted: {payload}")


ok = sched.validate_schedule_payload({"schedule_type": "monthly", "month_week": 2, "month_weekday": 1}, partial=True)
must(ok["month_week"] == 2 and ok["month_weekday"] == 1, ok)
for week in (1, 2, 3, 4, -1):
    sched.validate_schedule_payload({"month_week": week, "month_weekday": 0}, partial=True)
for week in (0, 5, -2, 6, "2", 2.0, True, [2], {}):
    refused({"month_week": week, "month_weekday": 1}, "month_week must be", partial=True)
for day in (-1, 7, "1", 1.0, True, False):
    refused({"month_week": 2, "month_weekday": day}, "month_weekday must be", partial=True)
refused({"month_week": 2, "month_weekday": None}, "go together", partial=True)
refused({"month_week": None, "month_weekday": 3}, "go together", partial=True)
refused({"month_week": 2, "month_weekday": ""}, "go together", partial=True)
cleared = sched.validate_schedule_payload({"month_week": "", "month_weekday": ""}, partial=True)
must(cleared["month_week"] is None and cleared["month_weekday"] is None, cleared)
# shape: exactly one monthly mode
mon = {"schedule_type": "monthly"}
sched.check_monthly_shape({**mon, "day_of_month": 5})
sched.check_monthly_shape({**mon, "month_week": -1, "month_weekday": 6})
sched.check_monthly_shape({"schedule_type": "weekly"})
for bad, text in (({**mon}, "require day_of_month, or month_week"),
                  ({**mon, "day_of_month": 5, "month_week": 1, "month_weekday": 1}, "not both"),
                  ({**mon, "month_week": 1}, "go together"),
                  ({**mon, "month_weekday": 1}, "go together"),
                  ({**mon, "day_of_month": 0}, "require day_of_month, or month_week")):
    try:
        sched.check_monthly_shape(bad)
    except sched.SchedulerError as exc:
        must(text in str(exc), (bad, str(exc)))
    else:
        raise AssertionError(f"accepted: {bad}")
print("       validation: ranges, types, booleans, pairs, exactly one monthly mode")

# ---- the edit switch: sending one mode replaces the other
merged = {"day_of_month": 12, "month_week": None, "month_weekday": None}
sched.switch_monthly_mode(merged, {"month_week": 3, "month_weekday": 2})
must(merged["day_of_month"] is None, merged)
merged = {"day_of_month": None, "month_week": 3, "month_weekday": 2}
sched.switch_monthly_mode(merged, {"day_of_month": 9})
must(merged["month_week"] is None and merged["month_weekday"] is None, merged)
merged = {"day_of_month": None, "month_week": 3, "month_weekday": 2}
sched.switch_monthly_mode(merged, {"name": "renamed"})
must(merged == {"day_of_month": None, "month_week": 3, "month_weekday": 2}, "an edit that sends neither mode keeps the stored one")
merged = {"day_of_month": 4, "month_week": 3, "month_weekday": 2}
sched.switch_monthly_mode(merged, {"day_of_month": 4, "month_week": 3, "month_weekday": 2})
must(merged["day_of_month"] == 4, "both sent: left for the shape check to refuse")
try:
    sched.check_monthly_shape({**mon, **merged})
except sched.SchedulerError:
    pass
else:
    raise AssertionError("both modes sent were accepted")
print("       an edit switches between the two monthly modes; both sent is refused")

# ---- reconcile_schedule (module path): accepts, stores, returns, audits, changes the timing signature
reset()
sched._ACTIONS.clear()
plugin("patchmanagement")
sched.register_scheduled_action(id="patchmanagement.scan", module_id="patchmanagement", label="Scan", handler=lambda context: {}, target_types=("none",))
_orig_save = Schedule.save


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    _orig_save(self, update_fields)


Schedule.save = _save
made = sched.reconcile_schedule(owner_module="patchmanagement", owner_key="monthly", action_id="patchmanagement.scan", schedule_type="monthly",
                                run_time=time(3, 0), month_week=2, month_weekday=1)
must(made.month_week == 2 and made.month_weekday == 1 and made.day_of_month is None, made.__dict__)
must(sched.next_occurrence(made, datetime(2026, 10, 1, tzinfo=UTC)) == datetime(2026, 10, 13, 3, 0, tzinfo=UTC), "next run from a reconciled schedule")
made.last_due_key = "old"
again = sched.reconcile_schedule(owner_module="patchmanagement", owner_key="monthly", action_id="patchmanagement.scan", schedule_type="monthly",
                                 run_time=time(3, 0), month_week=2, month_weekday=1)
must(again is made and made.last_due_key == "old", "an unchanged reconcile does not reset the due key")
sched.reconcile_schedule(owner_module="patchmanagement", owner_key="monthly", action_id="patchmanagement.scan", schedule_type="monthly",
                         run_time=time(3, 0), month_week=-1, month_weekday=1)
must(made.month_week == -1 and made.last_due_key == "", "a changed pair is a timing change")
sched.reconcile_schedule(owner_module="patchmanagement", owner_key="monthly", action_id="patchmanagement.scan", schedule_type="monthly",
                         run_time=time(3, 0), day_of_month=10)
must(made.day_of_month == 10 and made.month_week is None and made.month_weekday is None, "back to a day of the month")
for kw, text in (({"day_of_month": 10, "month_week": 1, "month_weekday": 1}, "not both"), ({}, "require day_of_month"), ({"month_week": 1}, "go together"),
                 ({"month_week": 5, "month_weekday": 1}, "month_week must be")):
    try:
        sched.reconcile_schedule(owner_module="patchmanagement", owner_key="bad", action_id="patchmanagement.scan", schedule_type="monthly", run_time=time(3, 0), **kw)
    except sched.SchedulerError as exc:
        must(text in str(exc), (kw, str(exc)))
    else:
        raise AssertionError(f"accepted: {kw}")
# an old call without the new keywords is what it was
old = sched.reconcile_schedule(owner_module="patchmanagement", owner_key="old", action_id="patchmanagement.scan", schedule_type="monthly", run_time=time(4, 0), day_of_month=1)
must(old.day_of_month == 1 and old.month_week is None, old.__dict__)
# a weekly schedule is untouched by the new fields
wk = sched.reconcile_schedule(owner_module="patchmanagement", owner_key="weekly", action_id="patchmanagement.scan", schedule_type="weekly", run_time=time(4, 0), weekdays=[1])
must(wk.month_week is None and wk.weekdays == [1], wk.__dict__)
# the serializer returns the fields
made.updated_at = NOW[0]
row = sched.serialize_schedule(made)
must(row["month_week"] is None and row["month_weekday"] is None and row["day_of_month"] == 10, row)
made.day_of_month, made.month_week, made.month_weekday = None, 4, 2
row = sched.serialize_schedule(made)
must(row["month_week"] == 4 and row["month_weekday"] == 2 and row["day_of_month"] is None, row)
print("       reconcile_schedule: stored, changed, switched back, refused when wrong; an old call is unchanged")

# ---- the confirmation key and text: unchanged for every other timing, new for the pair
base = {"schedule_type": "monthly", "run_time": "03:00", "day_of_month": 5, "timezone": "UTC"}
before = conf.when_key(base)
must("month_week" not in before and "month_weekday" not in before, "a day_of_month timing keeps its 1.17.87 key")
pair = conf.when_key({**base, "day_of_month": None, "month_week": 2, "month_weekday": 1})
must(pair["month_week"] == 2 and pair["month_weekday"] == 1, pair)
must(conf._digest(pair) != conf._digest(conf.when_key({**base, "day_of_month": None, "month_week": 3, "month_weekday": 1})), "a different week is a different key")
must(conf.when_text({**base, "day_of_month": None, "month_week": 2, "month_weekday": 1}) == "on the second Tuesday of every month at 03:00 (UTC)", conf.when_text({**base, "day_of_month": None, "month_week": 2, "month_weekday": 1}))
must(conf.when_text({**base, "day_of_month": None, "month_week": -1, "month_weekday": 4}) == "on the last Friday of every month at 03:00 (UTC)", "last Friday")
must(conf.when_text(base) == "on day 5 of every month at 03:00 (UTC)", conf.when_text(base))
must(not conf.when_key({**base, "month_week": True, "month_weekday": 1}).get("month_week"), "a boolean is not a week")
print("       confirmation key and text: old keys unchanged, the pair worded in plain English")

print("PASS scheduler nth weekday 1.17.88")
