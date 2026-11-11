#!/usr/bin/env python3
"""1.17.115 regression: ``tec_tac.scheduler.next_run_for_action(module_id, action_id)`` (request from certificatemanagement 0.4.3, 10 November 2026).

Django is not installed on this PC, so the REAL functions are cut out of scheduler.py by AST (next_run_for_action, next_occurrence,
ScheduleVisibility, the registry and module-state readers and the small time helpers) and run against stubs for the model, the module state and
the registry. Covered: the earliest of several schedules wins; a user-made schedule counts; disabled, paused, orphaned, module-disabled,
unreadable-state and finished-once schedules are left out; a foreign or unregistered action and an empty or over-long module id raise
SchedulerError; the answer holds only the two keys; the 500-row cap and the ``.only()`` field list hold; one bad row is skipped and never
raised; the contract row is present; and the signatures of get_owned_schedule, reconcile_schedule and removed_owned_schedule are unchanged.
"""
from __future__ import annotations

import ast
import calendar
import logging
import sys
import types
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=dt_timezone.utc)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ---------------------------------------------------------------------------------------------------------------- stubs
class OwnerType:
    USER = "user"
    MODULE = "module"


class ScheduleType:
    ONCE = "once"
    INTERVAL = "interval"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


CALLS = []


class Rows(list):
    def only(self, *fields):
        CALLS.append(("only", fields))
        return self

    def __getitem__(self, item):
        if isinstance(item, slice):
            CALLS.append(("slice", item.stop))
            return Rows(list.__getitem__(self, item))
        return list.__getitem__(self, item)


class Manager:
    rows: list = []  # noqa: RUF012 - test stub

    def filter(self, **kwargs):
        CALLS.append(("filter", kwargs))
        return Rows(r for r in self.rows if all(getattr(r, k) == v for k, v in kwargs.items()))


class TecTacSchedule:
    OwnerType = OwnerType
    ScheduleType = ScheduleType
    objects = Manager()


class Sched:
    def __init__(self, action="cert.scan", module="certificatemanagement", owner_type=OwnerType.MODULE, owner_module="certificatemanagement",
                 enabled=True, paused_reason="", hours=1, kind=ScheduleType.INTERVAL, **extra):
        self.action_id, self.module_id, self.owner_type, self.owner_module = action, module, owner_type, owner_module
        self.enabled, self.paused_reason, self.schedule_type, self.timezone = enabled, paused_reason, kind, "UTC"
        self.run_at, self.run_time, self.weekdays, self.day_of_month = None, None, [], None
        self.month_week = self.month_weekday = None
        self.interval_seconds = hours * 3600
        self.interval_anchor_at = NOW + timedelta(hours=hours)
        self.__dict__.update(extra)


class Timezone:
    @staticmethod
    def is_naive(value):
        return value.tzinfo is None

    @staticmethod
    def now():
        return NOW


UNREADABLE = object()
STATE = {"value": {"modules": {}}}
INSTALLED = {"certificatemanagement", "halopsa"}
DISABLED = set()


def _load_state():
    if STATE["value"] is UNREADABLE:
        raise RuntimeError("unreadable")
    return STATE["value"]


pkg = types.ModuleType("tec_tac")
module_state = types.ModuleType("tec_tac.module_state")
module_state.load_state = _load_state
module_state.is_enabled = lambda module_id, state: module_id not in DISABLED
registry = types.ModuleType("tec_tac.registry")
registry.get_plugins = lambda: [types.SimpleNamespace(plugin_id=i, legacy=False) for i in sorted(INSTALLED)]
pkg.module_state, pkg.registry = module_state, registry
pkg.__path__ = []
sys.modules.update({"tec_tac": pkg, "tec_tac.module_state": module_state, "tec_tac.registry": registry})

ACTIONS = {
    "cert.scan": types.SimpleNamespace(id="cert.scan", module_id="certificatemanagement"),
    "halo.sync": types.SimpleNamespace(id="halo.sync", module_id="halopsa"),
}

# ------------------------------------------------------------------------------------------- the real code, cut by AST
tree = ast.parse((APP / "scheduler.py").read_text(encoding="utf-8"))
WANTED_FUNCS = {"next_run_for_action", "next_occurrence", "_as_utc", "_zone", "_local_occurrence", "_monthly_day", "uses_nth_weekday",
                "nth_weekday_date", "_module_state_for_tick", "_registry_ids", "get_scheduled_action"}
WANTED_CLASSES = {"ScheduleVisibility", "SchedulerError"}
WANTED_ASSIGNS = {"NEXT_RUN_ROW_CAP", "_NEXT_RUN_FIELDS", "MIN_INTERVAL_SECONDS", "CORE_OWN_MODULE_IDS", "_UNREAD"}
body = []
for node in tree.body:
    if (isinstance(node, ast.FunctionDef) and node.name in WANTED_FUNCS) or (isinstance(node, ast.ClassDef) and node.name in WANTED_CLASSES) or isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in WANTED_ASSIGNS for t in node.targets):
        body.append(node)
found = {n.name for n in body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
must(found == WANTED_FUNCS | WANTED_CLASSES, sorted((WANTED_FUNCS | WANTED_CLASSES) ^ found))
log = logging.getLogger("test.scheduler")
log.addHandler(logging.NullHandler())
log.propagate = False
ns = {
    "__name__": "tec_tac.scheduler", "__package__": "tec_tac", "datetime": datetime, "timedelta": timedelta, "dt_timezone": dt_timezone,
    "calendar": calendar, "ZoneInfo": ZoneInfo, "ZoneInfoNotFoundError": ZoneInfoNotFoundError, "timezone": Timezone,
    "TecTacSchedule": TecTacSchedule, "logger": log, "_ACTIONS": ACTIONS,
}
exec(compile(ast.Module(body=body, type_ignores=[]), "scheduler.py", "exec"), ns)  # noqa: S102 - the real code, not user input
SchedulerError = ns["SchedulerError"]
fn = ns["next_run_for_action"]


def ask(rows, module="certificatemanagement", action="cert.scan", state=None):
    Manager.rows = rows
    STATE["value"] = state if state is not None else {"modules": {}}
    CALLS.clear()
    return fn(module, action)


def raises(*args, **kwargs):
    try:
        ask(*args, **kwargs)
    except SchedulerError:
        return True
    return False


# ---------------------------------------------------------------------------------------------------------- the answers
answer = ask([Sched(hours=5), Sched(hours=2), Sched(hours=9)])
must(answer == {"next_run_at": (NOW + timedelta(hours=2)).isoformat(), "enabled_schedules": 3}, answer)
must(set(answer) == {"next_run_at", "enabled_schedules"}, "time and count only")
must(answer["next_run_at"].endswith("+00:00"), "UTC ISO-8601")

# a schedule a person made counts
answer = ask([Sched(hours=7), Sched(owner_type=OwnerType.USER, owner_module="", hours=3)])
must(answer["enabled_schedules"] == 2 and answer["next_run_at"] == (NOW + timedelta(hours=3)).isoformat(), answer)

# nothing live
must(ask([]) == {"next_run_at": None, "enabled_schedules": 0}, "no rows")

# left out: disabled, paused, orphaned owner, a disabled module, a finished once schedule
must(ask([Sched(enabled=False, hours=1), Sched(hours=8)])["enabled_schedules"] == 1, "disabled schedule")
must(ask([Sched(paused_reason="module disabled", hours=1), Sched(hours=8)])["next_run_at"] == (NOW + timedelta(hours=8)).isoformat(), "paused")
must(ask([Sched(owner_module="gone", hours=1), Sched(hours=8)])["enabled_schedules"] == 1, "orphaned owner module")
DISABLED.add("certificatemanagement")
must(ask([Sched(hours=1)]) == {"next_run_at": None, "enabled_schedules": 0}, "owner module disabled")
DISABLED.clear()
DISABLED.add("halopsa")
must(ask([Sched(owner_type=OwnerType.USER, owner_module="", hours=2)])["enabled_schedules"] == 1, "a disabled module that is not bound does not matter")
DISABLED.clear()
must(ask([Sched(hours=1)], state=UNREADABLE) == {"next_run_at": None, "enabled_schedules": 0}, "unreadable module state counts as none")
must(ask([Sched(hours=1)], state={"_corrupt": True}) == {"next_run_at": None, "enabled_schedules": 0}, "corrupt module state counts as none")
finished = Sched(kind=ScheduleType.ONCE, run_at=NOW - timedelta(days=1))
future = Sched(kind=ScheduleType.ONCE, run_at=NOW + timedelta(days=1))
answer = ask([finished, future])
must(answer["enabled_schedules"] == 1 and answer["next_run_at"] == (NOW + timedelta(days=1)).isoformat(), answer)
must(ask([finished]) == {"next_run_at": None, "enabled_schedules": 0}, "finished once schedule")

# a daily schedule uses the real next_occurrence
daily = Sched(kind=ScheduleType.DAILY, run_time=datetime(2026, 1, 1, 18, 30, tzinfo=dt_timezone.utc).time())
must(ask([daily])["next_run_at"] == datetime(2026, 11, 11, 18, 30, tzinfo=dt_timezone.utc).isoformat(), "daily")

# ---------------------------------------------------------------------------------------------------------- refusals
must(raises([], module="halopsa", action="cert.scan"), "another module's action")
must(raises([], action="no.such.action"), "an unregistered action")
must(raises([], module=""), "empty module id")
must(raises([], module="   "), "blank module id")
must(raises([], module=None), "no module id")
must(raises([], module="m" * 101), "module id over 100 characters")
must(raises([], action=""), "empty action id")

# ---------------------------------------------------------------------------------------------------------- the read is bounded
answer = ask([Sched(hours=1 + (i % 20)) for i in range(800)])
must(answer["enabled_schedules"] == 500, answer)
must(("slice", 500) in CALLS, CALLS)
only = next(c[1] for c in CALLS if c[0] == "only")
must(only == ns["_NEXT_RUN_FIELDS"] and "name" not in only and "parameters" not in only and "targets" not in only, only)
needed = {"schedule_type", "timezone", "run_at", "run_time", "weekdays", "day_of_month", "month_week", "month_weekday", "interval_seconds",
          "interval_anchor_at", "module_id", "owner_module", "owner_type", "enabled", "paused_reason"}
must(needed <= set(only), needed - set(only))
filt = next(c[1] for c in CALLS if c[0] == "filter")
must(filt == {"action_id": "cert.scan", "enabled": True, "paused_reason": ""}, filt)

# one row that fails to compute is skipped, never raised
answer = ask([Sched(hours=1, timezone="Not/AZone"), Sched(hours=4)])
must(answer == {"next_run_at": (NOW + timedelta(hours=4)).isoformat(), "enabled_schedules": 1}, answer)

# ---------------------------------------------------------------------------------------------------------- contract and compatibility
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
start = contracts.index('"name": "next_run_for_action"')
row = contracts[contracts.rfind("{", 0, start):contracts.index("},", start)]
must('"area": "scheduler"' in row and '"import_path": "tec_tac.scheduler"' in row, row)
must("requires framework >=1.17.115" in row and "additive" in row and "never a schedule id" in row, row)


def signature(name):
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.unparse(node.args), (ast.unparse(node.returns) if node.returns else None)


must(signature("get_owned_schedule") == ("owner_module: str, owner_key: str", "dict | None"), signature("get_owned_schedule"))
must(signature("removed_owned_schedule")[0] == "owner_module: str, owner_key: str", signature("removed_owned_schedule"))
must(signature("reconcile_schedule")[0].startswith("*, owner_module: str, owner_key: str, action_id: str, schedule_type: str"), signature("reconcile_schedule"))
must(signature("next_run_for_action") == ("module_id: str, action_id: str", "dict"), signature("next_run_for_action"))
print("scheduler-next-run-for-action-1.17.115: ok")
