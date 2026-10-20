#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.61 regression (R-20): Core's fixed function table, SYSTEM_FUNCTIONS, holds exactly three rows since 1.17.66 (two before) and each is real in Tactical v1.5.2.

Covered: exactly two rows (winupdate.scan and winupdate.install); every row names an owner module and at least the two minimum flags,
takes no username, accepts one list of agent numbers; every named Tactical callable exists in a pinned excerpt of the v1.5.2 signatures
(and, when reference/tacticalrmm is present, in its real source: an @app.task function with the pinned parameter list, and the bulk view
that calls it through .delay); only install re-approves by policy (it calls approve_updates, scan does not); install is refused for a
replacement and accepted for Windows Patching; the table cannot be changed at run time; a row added without an owner or minimum flags is
caught by the row check this test runs. A new row is a Core release, so this test pins the row count.
"""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

# The pinned excerpt of Tactical v1.5.2 (reference/tacticalrmm/api/tacticalrmm/winupdate/tasks.py): module, function, parameter names.
V152_SIGNATURES = {
    ("winupdate.tasks", "bulk_check_for_updates_task"): ("pks",),
    ("winupdate.tasks", "bulk_install_updates_task"): ("pks",),
}
REAL_FLAGS = {"can_manage_winupdates", "can_run_bulk"}
WINUPDATE_ROWS = {"winupdate.scan", "winupdate.install"}  # scripts.run is pinned by system-actions-table-1.17.66.py


def row_problems(row) -> list:
    """What is wrong with one table row. A row must have an owner, minimum flags, a pinned Tactical callable and honest defaults."""
    problems = []
    if not row.owner_module:
        problems.append("no owner module")
    if not row.min_flags:
        problems.append("no minimum flags")
    if not set(row.min_flags) <= REAL_FLAGS | {"can_run_scripts", "can_reboot_agents"}:
        problems.append("a minimum flag that is not a Role flag")
    if (row.module_path, row.function_name) not in V152_SIGNATURES:
        problems.append("a Tactical callable that is not in the pinned v1.5.2 excerpt")
    if row.accepts != "agent_pks":
        problems.append("accepts is not agent_pks")
    if row.takes_username and row.key != "scripts.run":
        problems.append("a username parameter needs Johan's sign-off first (CQ175 signed it for scripts.run only)")
    if "done" in row.result_text.lower() or "completed" in row.result_text.lower():
        problems.append("the result text claims more than 'queued' (AD-25)")
    return problems


table = sa.SYSTEM_FUNCTIONS
must(set(table) == WINUPDATE_ROWS | {"scripts.run"}, f"exactly three rows, found {sorted(table)}")
for key, row in table.items():
    must(row.key == key, key)
    if key not in WINUPDATE_ROWS:
        continue
    must(row_problems(row) == [], (key, row_problems(row)))
    must(row.owner_module == "patching" and set(row.min_flags) == REAL_FLAGS, (key, row))
    must(row.result_text == "Queued in Tactical; the result shows in each endpoint's update list.", row.result_text)
must(table["winupdate.scan"].reapproves_by_policy is False and table["winupdate.install"].reapproves_by_policy is True)
print("       exactly three rows; each winupdate row has an owner, both minimum flags, no username and an honest 'queued' text")

# the row check really catches a row with no owner or flags
good = table["winupdate.scan"]
from dataclasses import replace  # noqa: E402

must("no owner module" in row_problems(replace(good, owner_module="")))
must("no minimum flags" in row_problems(replace(good, min_flags=())))
must("a Tactical callable that is not in the pinned v1.5.2 excerpt" in row_problems(replace(good, function_name="bulk_unknown_task")))
must(any("a username parameter needs Johan's sign-off first" in p for p in row_problems(replace(good, takes_username=True))))
must(row_problems(replace(good, result_text="Done")), "a text that says done is caught")
print("       a row added without an owner or minimum flags (or a script task, or a username) fails the row check")

# the pinned excerpt matches the real v1.5.2 source when it is on this PC
reference = ROOT.parents[1] / "reference" / "tacticalrmm" / "api" / "tacticalrmm"
tasks_file = reference / "winupdate" / "tasks.py"
if tasks_file.is_file():
    tree = ast.parse(tasks_file.read_text(encoding="utf-8"))
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    for (_module_path, name), params in V152_SIGNATURES.items():
        node = functions[name]
        must(tuple(a.arg for a in node.args.args) == params, (name, [a.arg for a in node.args.args]))
        must(any("app.task" in ast.unparse(d) for d in node.decorator_list), f"{name} is a Celery task")
    install_calls = {c.func.attr for c in ast.walk(functions["bulk_install_updates_task"]) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
    scan_calls = {c.func.attr for c in ast.walk(functions["bulk_check_for_updates_task"]) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
    must("approve_updates" in install_calls and "approve_updates" not in scan_calls, "only install re-approves by policy")
    views = (reference / "agents" / "views.py").read_text(encoding="utf-8")
    must("bulk_install_updates_task.delay(agents)" in views and "bulk_check_for_updates_task.delay(agents)" in views, "Tactical's bulk view calls the tasks through .delay(pks)")
    must("RunBulkPerms" in views[views.index("def bulk(request)") - 200: views.index("def bulk(request)")], "Tactical's bulk route needs can_run_bulk")
    print("       the rows match the real v1.5.2 source (task signatures, approve_updates, the bulk view)")
else:
    print("       reference/tacticalrmm is not on this PC: the pinned excerpt stands in for it")

# install: refused for a replacement, accepted for Windows Patching
PLUGINS.clear()
ENABLED.clear()
HONOURED.clear()
sa._clear_for_tests()
plugin("patching", system_actions=["patching.install", "patching.scan"])
plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.install", "patchmanagement.scan"])
HONOURED["patchmanagement"] = "patching"
BOTH = ["can_manage_winupdates", "can_run_bulk"]
must(sa.register_system_action("patchmanagement.install", "patchmanagement", "APM install", "winupdate.install", BOTH).via_replacement is True)  # 1.17.66, CQ173
must(sa.register_system_action("patching.install", "patching", "Install", "winupdate.install", BOTH) is not None)
must(sa.register_system_action("patchmanagement.scan", "patchmanagement", "APM scan", "winupdate.scan", BOTH).via_replacement is True)
print("       install is accepted for Windows Patching and for the honoured replacement (CQ173, R-36 not built); scan is allowed for both")

# immutable at run time
for attempt in (lambda: table.__setitem__("os.system", good), lambda: table.pop("winupdate.scan"), lambda: table.update({"x": good}), lambda: table.clear()):
    try:
        attempt()
        raise AssertionError("the table was changed")
    except (TypeError, AttributeError):
        pass
try:
    good.owner_module = "other"
    raise AssertionError("a row was changed")
except FrozenInstanceError:
    pass
try:
    good.min_flags += ("can_x",)
    raise AssertionError("a row was changed")
except FrozenInstanceError:
    pass
must(isinstance(good.min_flags, tuple) and type(table).__name__ == "mappingproxy", "rows hold tuples and the table is a read-only mapping")
must(set(table) == WINUPDATE_ROWS | {"scripts.run"}, "unchanged after the attempts")
print("       the table is a read-only mapping of frozen rows: a module cannot add or change a row")

# the table is the only place a Tactical callable is named
source = (APP / "system_actions.py").read_text(encoding="utf-8")
must(source.count("import_module(") == 1 and "os.system" not in source and "subprocess" not in source and "requests" not in source and "urllib" not in source,
     "one lazy import of the table's module and no HTTP or process call")
must(".delay(" in source and "apply_async" not in source and ".objects." not in source.replace("TecTacScheduleRun.objects", ""),
     "the task is started with .delay like Tactical's bulk view, and Core writes no Tactical model")
print("       Core imports only the table's task module and starts it with .delay: no HTTP, no process, no model write")

print("PASS system actions table 1.17.61")
