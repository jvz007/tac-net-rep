#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.66 regression (CQ175): Core's fixed function table holds exactly three rows, and the new row is real in Tactical v1.5.2.

Replaces the two-row pin of system-actions-table-1.17.61.py. Covered: exactly winupdate.scan, winupdate.install and scripts.run; scripts.run is
Script Execution's, needs can_run_bulk AND can_run_scripts, takes a username and the parameters schema, and never re-approves by policy; the
pinned v1.5.2 keyword list of bulk_script_task matches the call Core builds, keyword for keyword (and, when reference/tacticalrmm is on this PC,
the real source: an @app.task function with that keyword-only list, and the bulk view that reads can_run_bulk only); every row of the table
is a frozen row in a read-only mapping; no row can carry a free-form command.
"""
from __future__ import annotations

import ast
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

# The pinned excerpt of Tactical v1.5.2 (reference/tacticalrmm/api/tacticalrmm/scripts/tasks.py): bulk_script_task takes these keywords only.
BULK_SCRIPT_KEYWORDS = ("script_pk", "agent_pks", "args", "timeout", "username", "run_as_user", "env_vars", "custom_field_pk", "collector_all_output", "save_to_agent_note")

table = sa.SYSTEM_FUNCTIONS
must(set(table) == {"winupdate.scan", "winupdate.install", "scripts.run"}, f"exactly three rows, found {sorted(table)}")
row = table["scripts.run"]
must(row.module_path == "scripts.tasks" and row.function_name == "bulk_script_task" and row.owner_module == "scriptexecution", row)
must(set(row.min_flags) == {"can_run_bulk", "can_run_scripts"} and row.takes_username is True and row.reapproves_by_policy is False and row.accepts == "agent_pks", row)
must(row.result_text == sa.QUEUED_TEXT and "done" not in row.result_text.lower(), "an honest 'queued' text")
must(tuple(row.parameters) == ("script_pk", "args", "env_vars", "timeout", "run_as_user", "collector_all_output", "save_to_agent_note"), row.parameters)
for key in ("winupdate.scan", "winupdate.install"):
    must(table[key].takes_username is False and table[key].parameters == () and table[key].owner_module == "patching", key)
print("       exactly three rows; scripts.run is Script Execution's, takes a username and needs can_run_bulk and can_run_scripts")

# the call Core builds names exactly the keywords the pinned v1.5.2 task takes, once each
args, kwargs = row.build_call([5, 6], row.validate_parameters({"script_pk": 3}), "alice")
must(args == () and tuple(sorted(kwargs)) == tuple(sorted(BULK_SCRIPT_KEYWORDS)), (args, sorted(kwargs)))
must(kwargs["agent_pks"] == [5, 6] and kwargs["username"] == "alice" and kwargs["custom_field_pk"] is None, kwargs)
args, kwargs = table["winupdate.scan"].build_call([5, 6], {}, "")
must(args == ([5, 6],) and kwargs == {}, "the winupdate rows keep their call shape: one positional list")
print("       the call Core builds for scripts.run uses exactly the pinned v1.5.2 keywords; the winupdate rows keep their call shape")

reference = ROOT.parents[1] / "reference" / "tacticalrmm" / "api" / "tacticalrmm"
tasks_file = reference / "scripts" / "tasks.py"
if tasks_file.is_file():
    tree = ast.parse(tasks_file.read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "bulk_script_task")
    must(not node.args.args and tuple(a.arg for a in node.args.kwonlyargs) == BULK_SCRIPT_KEYWORDS, [a.arg for a in node.args.kwonlyargs])
    must(any("app.task" in ast.unparse(d) for d in node.decorator_list), "bulk_script_task is a Celery task")
    views = (reference / "agents" / "views.py").read_text(encoding="utf-8")
    must("bulk_script_task.delay(" in views, "Tactical's bulk view starts it through .delay")
    start = views.index("def bulk(request)")
    must("RunBulkPerms" in views[start - 200:start], "Tactical's bulk route needs can_run_bulk")
    print("       the pinned keywords match the real v1.5.2 source (task signature, the bulk view, can_run_bulk)")
else:
    print("       reference/tacticalrmm is not on this PC: the pinned keyword list stands in for it")

# immutable at run time, and no row can carry a command
for attempt in (lambda: table.__setitem__("os.system", row), lambda: table.pop("scripts.run"), lambda: table.update({"x": row}), lambda: table.clear()):
    try:
        attempt()
        raise AssertionError("the table was changed")
    except (TypeError, AttributeError):
        pass
try:
    row.owner_module = "other"
    raise AssertionError("a row was changed")
except Exception as exc:  # FrozenInstanceError
    must(type(exc).__name__ == "FrozenInstanceError", exc)
must(type(table).__name__ == "mappingproxy", "the table is a read-only mapping")
src = (APP / "system_actions.py").read_text(encoding="utf-8")
must("bulk_command_task" not in src, "no command task is in the table (CQ194 waits for Johan)")
print("       the table is a read-only mapping of frozen rows, and no row carries a free-form command")
print("PASS system actions table 1.17.66")
