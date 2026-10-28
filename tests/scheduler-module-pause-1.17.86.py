#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.86 regression: a disabled module's schedules are paused by Core and resumed exactly; Run now of a declared person action uses strict scope;
_resolve_view refuses a view with no __module__. Same stub harness as scheduler-manual-run-person-1.17.85.py (Django is not needed)."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
sched.recover_stale_runs = lambda now: {}
sched._recover_event_jobs_safely = lambda now: {}
sched.cleanup_once_schedules = lambda now: 0
sched.cleanup_run_history = lambda now: 0
sched._queue_run = lambda run: run
_orig_save = Schedule.save


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    _orig_save(self, update_fields)


Schedule.save = _save
STATE = {"corrupt": False}
sys.modules["tec_tac.module_state"].load_state = lambda: ({"_corrupt": True} if STATE["corrupt"] else {"schema": 1, "modules": {}})
sys.modules["tec_tac.module_state"].is_enabled = lambda module_id, state=None: False if (state or {}).get("_corrupt") else ENABLED.get(module_id, True)


def fresh():
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    STATE["corrupt"] = False
    sched._ACTIONS.clear()
    for mid in ("checks", "other"):
        plugin(mid)
        sched.register_scheduled_action(id=f"{mid}.provider-run", module_id=mid, label=mid, handler=lambda context: {})


def make(mid="checks", key="k", enabled=True):
    s = Schedule.objects.create(
        name=mid, module_id=mid, action_id=f"{mid}.provider-run", owner_type="module", owner_module=mid, owner_key=key, enabled=enabled,
        schedule_type="interval", interval_seconds=60, interval_anchor_at=NOW[0] - timedelta(hours=3), targets={"type": "none"}, updated_at=NOW[0], created_at=NOW[0],
    )
    return s


def pause_rows():
    return [a for a in AUDITS if (a.get("metadata") or {}).get("paused") is not None]


# (1) disabled module: nothing queued, paused once, audit once across many ticks
fresh()
a, b, c = make("checks", "a"), make("other", "b"), make("checks", "c", enabled=False)
ENABLED["checks"] = False
for _ in range(3):
    out = sched.dispatch_due_schedules(NOW[0])
must(not out["queued"] or all(r.module_id != "checks" for r in Run.objects.rows), "no run for the disabled module")
must(a.paused_reason == "paused: module disabled" and b.paused_reason == "" and c.paused_reason == "", "only the enabled schedule of the disabled module is paused")
must(len(pause_rows()) == 1 and pause_rows()[0]["action"] == "disable", ("one audit row, not one per tick", len(pause_rows())))
must(a.enabled is True, "a paused schedule stays enabled (visible as paused, not off)")
must(sched.serialize_schedule(a)["paused"] is True and sched.serialize_schedule(a)["next_run_at"] is None and sched.serialize_schedule(b)["paused"] is False, "API shows paused")
must(sched.get_owned_schedule("checks", "a")["paused"] is True, "owned read shows paused")
must(any(r.module_id == "other" for r in Run.objects.rows), "another module still runs")

# (2) enabled again: Core resumes exactly the ones it paused; a person-disabled one stays off
ENABLED["checks"] = True
Run.objects.rows[:] = []
out = sched.dispatch_due_schedules(NOW[0])
must(a.paused_reason == "" and c.paused_reason == "" and c.enabled is False, "resumed; the person-disabled one untouched")
must(any(r.module_id == "checks" for r in Run.objects.rows), "the resumed schedule runs again")
must(len(pause_rows()) == 2 and pause_rows()[1]["action"] == "enable", "one resume row")
sched.dispatch_due_schedules(NOW[0] + timedelta(seconds=61))
must(len(pause_rows()) == 2, "no more rows")

# (3) a person who disables a paused schedule, then re-enables while the module is off, stays paused
fresh()
a = make()
ENABLED["checks"] = False
sched.dispatch_due_schedules(NOW[0])
a.enabled = False
sched.dispatch_due_schedules(NOW[0])
a.enabled = True
Run.objects.rows[:] = []
sched.dispatch_due_schedules(NOW[0])
must(not Run.objects.rows and a.paused_reason, "still paused while the module is off")

# (4) unreadable state: nothing queued, nothing written
fresh()
a = make()
STATE["corrupt"] = True
out = sched.dispatch_due_schedules(NOW[0])
must(not Run.objects.rows and a.paused_reason == "" and not pause_rows(), "unreadable state fails closed without changing the row")

# (5) text checks
src = (APP / "scheduler_views.py").read_text(encoding="utf-8")
must("strict=person_run)" in src, "Run now uses strict scope for a declared person action")
sc = (APP / "system_commands.py").read_text(encoding="utf-8")
must("or not module or module.split" in sc, "_resolve_view requires a __module__")
must("0039_run_started_by" in (APP / "migrations" / "0040_schedule_paused_reason.py").read_text(encoding="utf-8"))
must("paused_reason" in (APP / "models.py").read_text(encoding="utf-8"))
must("tactical_detail" in (ROOT / "docs" / "system-actions.md").read_text(encoding="utf-8").split("**Result.**", 1)[1][:900])
print("PASS scheduler module pause 1.17.86")
