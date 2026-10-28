#!/usr/bin/env python3
"""1.17.90 regression (the 1.17.89 review Low): the three monthly fields are cleared for a non-monthly schedule on POST as well as PATCH (one place,
``_apply_schedule_fields``), and a stale monthly field on an old non-monthly row does not count as an edit, so a rename by a second full-scope
person moves no ownership and writes no owner_changed audit row. Also reads migration 0042 as source. Same harness as the 1.17.89 view test."""
from __future__ import annotations

import ast
from pathlib import Path

_here = Path(__file__).resolve().parent
_name = "scheduler-views-monthly-1.17.89.py"
_source = (_here / _name).read_text(encoding="utf-8")
_cut = _source.index("# POST: the pair is accepted and returned")
exec(compile(_source[:_cut], str(_here / _name), "exec"), globals())  # noqa: S102 - the shared test harness
H = globals()
AUDITS = H["AUDITS"]
dt = H["dt"]
BASE = H["BASE"]
Granted = H["Granted"]
Schedule = H["Schedule"]
User = H["User"]
boss = H["boss"]
fields = H["fields"]
must = H["must"]
patch = H["patch"]
post = H["post"]
reset = H["reset"]

# POST a weekly schedule with day_of_month=5 (and a stale pair): the row stores None for all three
reset()
reply = post({**BASE, "schedule_type": "weekly", "weekdays": [1], "day_of_month": 5, "month_week": 2, "month_weekday": 1})
must(reply.status_code == 201, reply.data)
stored = Schedule.objects.rows[0]
must((stored.day_of_month, stored.month_week, stored.month_weekday) == (None, None, None), (stored.day_of_month, stored.month_week, stored.month_weekday))
must(fields(reply) == {"day_of_month": None, "month_week": None, "month_weekday": None, "schedule_type": "weekly"}, fields(reply))
# a monthly POST still keeps its day
must(fields(post({**BASE, "day_of_month": 15}))["day_of_month"] == 15, "monthly keeps day_of_month")

# an old weekly row with a stale day_of_month=5, renamed by a second full-scope person: nothing moves, no owner_changed row
reset()
owner = User("owner", Granted(31, can_do_server_maint=True))
old = Schedule.objects.create(name="W", module_id="patching", action_id="patching.window", owner_type="user", created_by=owner, created_by_username="owner",
                              schedule_type="weekly", weekdays=[1], run_time=dt.time(3, 0), day_of_month=5, targets={"type": "none"})
del AUDITS[:]
reply = patch(old, {"name": "Renamed"})
must(reply.status_code == 200, reply.data)
must(old.name == "Renamed" and old.created_by is owner and old.created_by_username == "owner", "the creator is unchanged")
must(not any("owner_changed_from" in (a.get("metadata") or {}) or "owner_changed_from" in (a.get("extra") or {}) for a in AUDITS), AUDITS)
must(old.day_of_month is None, "the save clears the stale value")

# an edit that really changes the timing by another person still moves the owner (the rule is not weakened)
old2 = Schedule.objects.create(name="W2", module_id="patching", action_id="patching.window", owner_type="user", created_by=owner, created_by_username="owner",
                               schedule_type="weekly", weekdays=[1], run_time=dt.time(3, 0), day_of_month=5, targets={"type": "none"})
reply = patch(old2, {"run_time": "04:00"})
must(reply.status_code == 200 and old2.created_by is boss, "a real edit still takes the ownership")

# migration 0042 clears the fields on non-monthly rows only (read as source)
tree = ast.parse((_here.parent / "framwork/tec_tac/migrations/0042_clear_monthly_fields_non_monthly.py").read_text(encoding="utf-8"))
text = ast.unparse(tree)
must(".exclude(schedule_type='monthly').update(day_of_month=None, month_week=None, month_weekday=None)" in text, "non-monthly rows only")
must("0041_schedule_nth_weekday" in text, "depends on 0041")
print("PASS scheduler monthly clear 1.17.90")
