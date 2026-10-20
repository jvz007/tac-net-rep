#!/usr/bin/env python3
"""1.17.62 compatibility: the server-maintenance and event-job contracts that modules call are unchanged, and no module is broken by the hook.

Reads Core and every module under modules/ as source (ast). Covered: the provider methods start, get_job, cancel, list_jobs and list_actions
keep their exact signatures and the capability keeps its version and operations; ``register_event_job`` and ``EventJobPublisher.publish``
keep theirs; every call a module makes to the server-maintenance provider (certificatemanagement, securityWAF, tacticalupdater,
globalsettings) uses only keywords that still exist; no module defines an event job named ``<module>.server_job_finished`` yet, none calls
the new internal names, and none reads the new disk or table names, so adopting the hook is the module's own opt-in release; the new
``list_actions`` key is additive and the root helper's registry keys stay accepted; no module code reads ``disabled_reason``.
The hook adds no manifest key and no capability.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
MODULES = ROOT.parents[1] / "modules"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def signature_of(path, class_name, func_name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == func_name:
                    return ast.unparse(item.args) + " -> " + (ast.unparse(item.returns) if item.returns else "")
    raise AssertionError(f"{class_name}.{func_name} not found")


SM = APP / "server_maintenance.py"
PINS = {
    "start": "self, *, action: str, parameters: dict | None=None, context: dict, user=None -> dict",
    "get_job": "self, *, job_id: str, context: dict -> dict",
    "cancel": "self, *, job_id: str, context: dict, user=None -> dict",
    "list_jobs": "self, *, status: str | None=None, action: str | None=None, limit: int=100, include_output: bool=False, context: dict | None=None -> list[dict]",
    "list_actions": "self, *, context: dict -> list[dict]",
}
for name, pin in PINS.items():
    must(signature_of(SM, "ServerMaintenanceProvider", name) == pin, (name, signature_of(SM, "ServerMaintenanceProvider", name)))
text = SM.read_text(encoding="utf-8")
must('CAPABILITY_VERSION = "1.1.0"' in text and 'operations=("start", "get_job", "cancel", "list_jobs", "list_actions"),' in text, "capability version and operations")
must(signature_of(APP / "event_jobs.py", "EventJobPublisher", "publish") == "self, key, payload=None -> PublishResult", "publish")
ej_text = (APP / "event_jobs.py").read_text(encoding="utf-8")
must("def register_event_job(*, id, module_id, label, handler, soft_time_limit_seconds=None, max_attempts=None, backoff_seconds=None,\n                       max_backoff_seconds=None, expires_seconds=None, max_backlog=None, dedupe_seconds=None, audit_success=False):" in ej_text, "register_event_job")
must('CAPABILITY_VERSION = policy.CAPABILITY_VERSION' in ej_text, "the event jobs capability version is unchanged")
policy_text = (APP / "event_jobs_policy.py").read_text(encoding="utf-8")
must('CAPABILITY_VERSION = "1.1.0"' in policy_text, "core.event_jobs stays 1.1.0")
print("       start, get_job, cancel, list_jobs, list_actions, register_event_job and publish keep their signatures; both capabilities keep their versions")

# the job file keeps every key it had; the hook reads only keys that were there since 1.17.17
for key in ('"schema": 1,', '"action_revision"', '"action_permission": permission,', '"owner_module": owner_module,', '"status": "queued",', '"context": operation_context,', '"exit_result": None,', '"failure": None,'):
    must(key in text, f"the job file key {key} is unchanged")
hooks_text = (APP / "server_job_hooks.py").read_text(encoding="utf-8")
for key in ('job.get("owner_module")', 'job.get("status")', 'job.get("action")'):
    must(key in hooks_text, key)
print("       the job file is unchanged, and the hook reads only the keys that have been in it since 1.17.17")

# every module call to the provider uses keywords that still exist
CALLS = {"start": {"action", "parameters", "context", "user"}, "get_job": {"job_id", "context"}, "cancel": {"job_id", "context", "user"},
         "list_jobs": {"status", "action", "limit", "include_output", "context"}, "list_actions": {"context"}}
seen = {}
users = []
for path in sorted(MODULES.rglob("*.py")):
    parts = path.relative_to(MODULES).parts
    if len(parts) < 2 or "tests" in parts or "node_modules" in parts:
        continue
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        continue
    if "server_maintenance" not in source and "server-maintenance" not in source:
        continue
    users.append(parts[0])
    try:
        tree = ast.parse(source)
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in CALLS:
            receiver = ast.unparse(node.func.value).lower()
            if "maint" not in receiver and "provider" not in receiver:
                continue
            for kw in node.keywords:
                if kw.arg is not None:
                    must(kw.arg in CALLS[node.func.attr], f"{path.relative_to(MODULES)}: {node.func.attr}({kw.arg}=) is not a keyword of the provider")
            seen.setdefault(parts[0], 0)
            seen[parts[0]] += 1
must({"certificatemanagement", "securityWAF", "tacticalupdater"} <= set(users), sorted(set(users)))
print(f"       {len(set(users))} modules mention server maintenance ({', '.join(sorted(set(users)))}); every provider call of {len(seen)} of them uses keywords that still exist")

# no module collides with the hook, calls its internals or reads the new names
NAMES = ("server_job_finished", "server_job_hooks", "publish_for_core", "TecTacServerJobHook", "deliver_finished_server_jobs", "disabled_reason", "module removed")
hits = []
for path in sorted(MODULES.rglob("*")):
    parts = path.relative_to(MODULES).parts
    if not path.is_file() or len(parts) < 2 or "tests" in parts or "node_modules" in parts or path.suffix not in (".py", ".json", ".sh", ".md", ".js", ".vue"):
        continue
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        continue
    for name in NAMES:
        if name in source:
            hits.append((str(path.relative_to(MODULES)), name))
must(not hits, f"a module already uses a name this release adds: {hits[:5]}")
print("       no module defines the hook's event job, calls its internals or reads the new disabled_reason key: adopting it is each module's own opt-in release")

# the hook adds no manifest key, no capability and no route
registry_text = (APP / "registry.py").read_text(encoding="utf-8")
must("server_job" not in registry_text and "server_job" not in (APP / "urls.py").read_text(encoding="utf-8"), "no manifest key, no route")
must("register_capability" not in hooks_text, "the hook is not a capability")
helper = (ROOT / "scripts" / "server-maintenance-helper.py").read_text(encoding="utf-8")
must("MODULE_ACTION_KEYS = frozenset({" in helper and '"protected"})' in helper, "the manifest action keys are the same set")
print("       no manifest key, no capability and no route was added")

print("PASS server job hook compat 1.17.62")
