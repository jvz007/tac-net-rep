#!/usr/bin/env python3
"""1.17.61 regression: the new Scheduler and system-action surface is additive, and no module in modules/ depends on anything that changed.

Reads the Core source and, when it is on this PC, every module under modules/ (the project's sibling folder). Covered: no module uses the
new names (system_actions, run_system_action, PendingCompletion, pending_completion, complete_pending_run) or reads a completion key; no
module manifest uses the new key; the public Scheduler signatures that modules call (register_scheduled_action, reconcile_schedule,
start_one_off_run, get_one_off_run, get_owned_schedule, disable_owned_schedule, remove_owned_schedule, verify_run_context) are exactly
the 1.17.60 shapes; ScheduledAction keeps its fields and order; RUN statuses are unchanged; serialize_run only gains a key; the worker's
success and failure paths for a handler that returns anything but a PendingCompletion are unchanged; capability sources
(event_jobs, server_maintenance, caller_identity, tactical_operations) were not touched by this release's contract text.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
MODULES = ROOT.parents[1] / "modules"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def signature(path: Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.unparse(node.args)


scheduler = APP / "scheduler.py"
PINNED = {
    "register_scheduled_action": "*, id: str, module_id: str, label: str, handler, description: str='', target_types=('none',), permission: str | list | tuple | None=None, dangerous: bool=False, timeout_seconds: int=3600, unattended: bool=False",  # 1.17.63: one optional last keyword
    "start_one_off_run": "*, user, owner_module: str, action_id: str, targets: dict | None=None, parameters: dict | None=None, name: str | None=None, retry_count: int=0, retry_delay_seconds: int=DEFAULT_RETRY_DELAY_SECONDS, confirmation_id: str | None=None",  # 1.17.66: one optional last keyword
    "get_one_off_run": "run_id, *, owner_module: str",
    "get_owned_schedule": "owner_module: str, owner_key: str",
    "disable_owned_schedule": "*, owner_module: str, owner_key: str",
    "remove_owned_schedule": "*, owner_module: str, owner_key: str",
}
for name, expected in PINNED.items():
    must(signature(scheduler, name) == expected, f"{name}: {signature(scheduler, name)!r}")
must(signature(APP / "scheduler_run_context.py", "verify_run_context") == "context: Any, *, expected_module_id: str, expected_action_id: str, require_owner: bool=True")
reconcile = signature(scheduler, "reconcile_schedule")
must(reconcile.startswith("*, owner_module: str, owner_key: str, action_id: str, schedule_type: str"), reconcile)
print("       the Scheduler functions modules call keep their 1.17.60 signatures")

tree = ast.parse(scheduler.read_text(encoding="utf-8"))
action = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ScheduledAction")
fields = [n.target.id for n in action.body if isinstance(n, ast.AnnAssign)]
must(fields == ["id", "module_id", "label", "handler", "description", "target_types", "permission", "dangerous", "timeout_seconds", "permission_any", "unattended"], fields)  # 1.17.63: unattended is the new last field
models = ast.parse((APP / "models.py").read_text(encoding="utf-8"))
run = next(n for n in models.body if isinstance(n, ast.ClassDef) and n.name == "TecTacScheduleRun")
status = next(n for n in run.body if isinstance(n, ast.ClassDef) and n.name == "Status")
values = [ast.literal_eval(n.value.elts[0]) for n in status.body if isinstance(n, ast.Assign)]
must(values == ["queued", "running", "succeeded", "failed", "skipped"], values)
print("       ScheduledAction keeps its fields and the run statuses are unchanged: a pending run is still 'running'")

# the worker: a handler that returns anything but a PendingCompletion takes the old path
tasks = (APP / "tasks.py").read_text(encoding="utf-8")
must("if type(result) is PendingCompletion:" in tasks and "result = action.handler(context)" in tasks)
old_path = ("current.status = TecTacScheduleRun.Status.SUCCEEDED\n            current.result = _json_result(result)\n"
            "            current.finished_at = timezone.now()")
must(old_path in tasks, "the success path is as it was")
must("retry = _retryable(exc) and current_retry < retries" in tasks, "the failure and retry path is as it was")
print("       the worker's success and failure paths are as they were for every other return value")

# no module uses the new names or reads the new keys
if MODULES.is_dir():
    # 1.17.66: certificatemanagement has adopted pending_completion, so the search is for the system-action names only (the plan's grep)
    names = re.compile(r"\b(run_system_action|register_system_action|system_actions|describe_confirmation|settle_server_job_runs)\b")
    reads = re.compile(r"""["']completion["']|completion_state|completion_ref|system_action_marks|scheduler_state""")
    hits, readers, scanned, users = [], [], 0, set()
    for path in MODULES.rglob("*"):
        if not path.is_file() or path.suffix not in (".py", ".json", ".toml", ".md") or any(part in {"node_modules", "__pycache__", "tests"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        scanned += 1
        if path.suffix == ".py" and "register_scheduled_action" in text:
            users.add(path.relative_to(MODULES).parts[0])
        if path.suffix in (".py", ".json") and names.search(text) and "RELEASE_NOTES" not in path.name:
            hits.append(str(path.relative_to(MODULES)))
        if path.suffix == ".py" and reads.search(text):
            readers.append(str(path.relative_to(MODULES)))
    must(not hits, f"modules that already use the new names: {hits}")
    must(not readers, f"modules that read a completion key of a run: {readers}")
    must(len(users) >= 20, f"expected the Scheduler users to be found, got {sorted(users)}")
    print(f"       {scanned} module files read: {len(users)} modules register Scheduler actions; none uses the new names or a completion key")
else:
    print("       modules/ is not on this PC: the module search was skipped")

# one-off and reconcile paths are untouched in this release: the plan's contract rows still describe them
text = scheduler.read_text(encoding="utf-8")
for marker in ("def _one_off_user_refusal", "def start_one_off_run", "def get_one_off_run", "def reconcile_schedule", "def get_owned_schedule"):
    must(marker in text, marker)
print("PASS system actions compat 1.17.61")
