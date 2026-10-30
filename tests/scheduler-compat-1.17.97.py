#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.97 compatibility: every call a module makes today keeps its signature and its answer.

Core 1.17.97 adds removed_owned_schedule, the orphaned fields and routes and the hide of a disabled module's schedules. Nothing a module calls changed:
reconcile_schedule, get_owned_schedule, disable_owned_schedule and remove_owned_schedule keep their signatures (read as source), and keep their old answers
for an enabled module, a key nobody removed and a call with enabled=False (run on the stub harness of tests/scheduler-module-pause-1.17.86.py). The only
new answer is for a key an administrator removed: reconcile_schedule without a person's request returns None and creates nothing (the answer it already gave
for enabled=False when none exists), and a person's own save still creates it. When modules/ is on this PC every call of those functions is read with ast:
the keywords they pass are still in the signatures, and the modules that already read removed_owned_schedule are printed (information, not a failure)."""
from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path

_here = Path(__file__).resolve().parent
_name = "scheduler-module-pause-1.17.86.py"
_source = (_here / _name).read_text(encoding="utf-8")
_cut = _source.index("# (1) disabled module")
exec(compile(_source[:_cut], str(_here / _name), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sys.modules["tec_tac.registry"].get_plugins = lambda: discover_plugins()


def params(fn):
    return [a.arg for a in fn.args.posonlyargs + fn.args.args], [a.arg for a in fn.args.kwonlyargs]


tree = ast.parse((APP / "scheduler.py").read_text(encoding="utf-8"))
FUNCS = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
pos, kw = params(FUNCS["reconcile_schedule"])
must(pos == [] and kw[:4] == ["owner_module", "owner_key", "action_id", "schedule_type"] and kw[-2:] == ["confirmed_by_request", "confirmation_id"] and len(kw) == 25, (pos, kw))
RECONCILE = set(kw)
must(params(FUNCS["get_owned_schedule"]) == (["owner_module", "owner_key"], []), "get_owned_schedule keeps its signature")
must(params(FUNCS["disable_owned_schedule"]) == ([], ["owner_module", "owner_key"]), "disable_owned_schedule keeps its signature")
must(params(FUNCS["remove_owned_schedule"]) == ([], ["owner_module", "owner_key"]), "remove_owned_schedule keeps its signature")
must(params(FUNCS["removed_owned_schedule"]) == (["owner_module", "owner_key"], []), "the new read takes the same two names as get_owned_schedule")
must(params(FUNCS["serialize_schedule"])[1] == ["include_runs", "visibility"], "serialize_schedule only gained a trailing optional keyword")
print("       Core: reconcile_schedule, get_owned_schedule, disable_owned_schedule and remove_owned_schedule keep their signatures; removed_owned_schedule is new")

# ---- behaviour: the old answers for the cases that did not change
KW = dict(owner_module="checks", owner_key="profile:1", action_id="checks.probe", schedule_type="interval", interval_seconds=3600, interval_anchor_at=NOW[0] - timedelta(hours=3),
          targets={"type": "none"})
fresh()
sched.register_scheduled_action(id="checks.probe", module_id="checks", label="probe", handler=lambda context: {})
must(sched.reconcile_schedule(**{**KW, "enabled": False}) is None and not Schedule.objects.rows, "enabled=False with none stored: None, nothing created (as before)")
first = sched.reconcile_schedule(**KW)
must(first is not None and first.enabled is True and first.owner_key == "profile:1" and first.owner_type == "module", "an enabled module creates the schedule as before")
again = sched.reconcile_schedule(**KW)
must(again is first and len(Schedule.objects.rows) == 1, "an identical call is idempotent")
off = sched.reconcile_schedule(**{**KW, "enabled": False})
must(off is first and first.enabled is False, "enabled=False switches an existing schedule off and returns it (as before)")
must(sched.removed_owned_schedule("checks", "profile:1") is None, "an unremoved key has no marker")
owned = sched.get_owned_schedule("checks", "profile:1")
must(set(owned) == {"enabled", "paused", "paused_reason", "schedule_type", "next_run_at", "last_run_at", "last_run_status", "last_run_finished_at", "created_by_username"}, sorted(owned))
must(sched.get_owned_schedule("checks", "nobody") is None, "an unknown key answers None")
must(sched.disable_owned_schedule(owner_module="checks", owner_key="profile:1") is first and sched.disable_owned_schedule(owner_module="checks", owner_key="none") is None, "disable_owned_schedule as before")
must(sched.remove_owned_schedule(owner_module="checks", owner_key="profile:1") is True and sched.remove_owned_schedule(owner_module="checks", owner_key="profile:1") is False, "remove_owned_schedule as before")
print("       an enabled module, a key nobody removed and enabled=False: the same answers as before 1.17.97")

# ---- the modules
modules = ROOT.parents[1] / "modules"
if not modules.is_dir():
    print("       modules/ is not on this PC: the module read was skipped")
    print("[TEST] PASS scheduler compat 1.17.97")
    raise SystemExit(0)
CALLS = {"reconcile_schedule": RECONCILE, "get_owned_schedule": {"owner_module", "owner_key"}, "disable_owned_schedule": {"owner_module", "owner_key"},
         "remove_owned_schedule": {"owner_module", "owner_key"}}
users = {name: set() for name in CALLS}
readers = set()
for path in sorted(modules.rglob("*.py")):
    parts = path.relative_to(modules).parts
    if "node_modules" in parts or "tests" in parts or path.name.startswith("test_") or len(parts) < 2:
        continue
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        mtree = ast.parse(text)
    except (OSError, SyntaxError):
        continue
    if "removed_owned_schedule" in text:
        readers.add(parts[0])
    if "tec_tac" not in text:
        continue
    for node in ast.walk(mtree):
        if isinstance(node, ast.Call):
            func = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if func in CALLS:
                keywords = {k.arg for k in node.keywords if k.arg}
                must(keywords <= CALLS[func] or any(k.arg is None for k in node.keywords), f"{path.relative_to(modules)}: {func} passes a keyword that is not in the signature: {sorted(keywords - CALLS[func])}")
                users[func].add(parts[0])
must(len(users["reconcile_schedule"]) >= 17, f"{len(users['reconcile_schedule'])} modules call reconcile_schedule")
print(f"       modules/: {len(users['reconcile_schedule'])} modules call reconcile_schedule, {len(users['get_owned_schedule'])} read get_owned_schedule: every keyword is still in the signature")
print(f"       modules that already read removed_owned_schedule (information, not a failure): {sorted(readers) if readers else 'none'}")
print("[TEST] PASS scheduler compat 1.17.97")
