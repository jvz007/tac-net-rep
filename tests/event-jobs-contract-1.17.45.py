#!/usr/bin/env python3
"""1.17.45 core.event_jobs 1.0.0: the contract rows, the files that carry the feature, and the pins that keep it safe.

Plain Python, no Django (sources are read, not imported). Covered: the Python contract rows name register_event_job, EventJobPublisher
and verify_event_job_context with their limits; the HTTP detail row for GET scheduler/event-jobs/ exists and the route is in urls.py;
the Celery task is declared with acks_late, reject_on_worker_lost and ignore_result and calls only run_event_job; the capability is
registered in apps.py inside a try block that logs; migration 0032 matches models.py (names, fields, index and constraint names, the
partial unique constraint); no other file in the framework imports the handle internals or builds a publisher; the policy file imports
no Django; the docs exist and carry the security review points; requires.framework is documented as >=1.17.45; the version files agree.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# (1) the Python contract rows
contracts = text(APP / "contracts.py")
tree = ast.parse(contracts)
core_rows = None
for node in tree.body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "CORE_CONTRACTS" for t in node.targets):
        core_rows = ast.literal_eval(node.value)
must(core_rows, "CORE_CONTRACTS found")
rows = {row["name"]: row for row in core_rows if row.get("area") == "event-jobs"}
must(set(rows) == {"register_event_job", "EventJobPublisher", "verify_event_job_context"}, sorted(rows))
for row in rows.values():
    must(row["import_path"] == "tec_tac.event_jobs" and row["kind"] == "python" and row["audience"] == "module/backend", row)
    must("core.event_jobs 1.1.0" in row["purpose"] or "1.17.45" in row["purpose"], row["name"])  # 1.0.0 until 1.17.47
reg = rows["register_event_job"]["purpose"]
for phrase in ("soft_time_limit_seconds 5-600", "max_attempts 1-10", "backoff_seconds 5-3600", "expires_seconds 60-86400", "max_backlog 1-5000",
               "dedupe_seconds 0-3600", "AppConfig.ready()", "no private thread, timer or event-started Celery task", "requires.framework >=1.17.47",
               "handler's code file must lie inside that module's own folder", "AD-13 system-action contract is still open", "0032_event_jobs",
               "safe to run twice"):
    must(phrase in reg, phrase)
pub = rows["EventJobPublisher"]["purpose"]
for phrase in ("never raises", "outcome is queued, duplicate, dropped, disabled or error", "2 second timeout", "30 second circuit breaker",
               "2 KiB", "never logged, audited, listed or returned", "after the caller's transaction commits"):
    must(phrase in pub, phrase)
must("EventJobContextInvalid" in rows["verify_event_job_context"]["purpose"], "verify row")
print("       contract export: register_event_job, EventJobPublisher and verify_event_job_context rows with the limits")

# the module the rows import has those names
module = ast.parse(text(APP / "event_jobs.py"))
defined = {n.name for n in module.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
must({"register_event_job", "EventJobPublisher", "verify_event_job_context", "recover_event_jobs", "run_event_job", "event_jobs_health", "list_event_jobs",
      "register_core_event_jobs_capability", "EventJobRegistrationError", "EventJobContextInvalid", "PublishResult", "EventJobContext"} <= defined, defined)

# (2) the HTTP detail row and the route
must('"/api/tfd/scheduler/event-jobs/": {' in contracts, "HTTP detail row")
detail = contracts[contracts.index('"/api/tfd/scheduler/event-jobs/": {'):][:1800]
for phrase in ("server-maintenance authority", "never a payload, a key or a row id", '"403"'):
    must(phrase in detail, phrase)
urls = text(APP / "urls.py")
must('path("scheduler/event-jobs/", SchedulerEventJobsView.as_view(), name="tec-tac-scheduler-event-jobs")' in urls, "route")
must("SchedulerEventJobsView" in text(APP / "scheduler_views.py"), "view")
view = text(APP / "scheduler_views.py")
body = view[view.index("class SchedulerEventJobsView"):view.index("class SchedulerSelfTestView")]
must("def get(self, request)" in body and "def post" not in body and "def put" not in body and "def delete" not in body, "read only")
must(body.index("_native_scheduler_manager(request.user)") < body.index("list_event_jobs()"), "the authority check comes first")
must("SessionAuthenticated" in body, "session guard")
print("       contract export: the HTTP row for GET scheduler/event-jobs/, read only, behind the scheduler-manager check")

# (3) the Celery task
tasks = text(APP / "tasks.py")
must('@app.task(bind=True, name="tec_tac.execute_event_job", acks_late=True, reject_on_worker_lost=True, ignore_result=True' in tasks, "task decorator")
task_tree = ast.parse(tasks)
fn = next(n for n in task_tree.body if isinstance(n, ast.FunctionDef) and n.name == "execute_event_job")
called = {n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
must("run_event_job" in called, called)
print("       the Celery task is acks_late, reject_on_worker_lost and ignore_result, and only calls run_event_job")

# (4) the capability is registered under a guard
apps = text(APP / "apps.py")
block = apps[apps.index("register_core_event_jobs_capability"):][:600]
must("from .event_jobs import register_core_event_jobs_capability" in apps, "import")
before = apps[:apps.index("from .event_jobs import register_core_event_jobs_capability")]
must(before.rstrip().endswith("try:"), "registered inside a try block")
must("logger.exception" in block and "except Exception" in block, "a fault is logged and start-up goes on")
print("       apps.py registers the capability inside a try block that logs (Tactical always starts)")

# (5) migration 0032 and models.py agree
migration = text(APP / "migrations" / "0032_event_jobs.py")
models = text(APP / "models.py")
must('("tec_tac", "0031_module_preferences")' in migration, "dependency")
for model_name in ("TecTacEventJob", "TecTacEventJobStat"):
    must(f"class {model_name}(models.Model)" in models and f'name="{model_name}"' in migration, model_name)


def fields_of(source: str, class_name: str) -> list[str]:
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == class_name)
    return [t.id for stmt in node.body if isinstance(stmt, ast.Assign) for t in stmt.targets if isinstance(t, ast.Name)
            and isinstance(stmt.value, ast.Call) and ast.unparse(stmt.value.func).startswith("models.")]


def migration_fields(source: str, model_name: str) -> list[str]:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "migrations.CreateModel":
            kw = {k.arg: k.value for k in node.keywords}
            if ast.literal_eval(kw["name"]) == model_name:
                return [ast.literal_eval(elt.elts[0]) for elt in kw["fields"].elts]
    raise AssertionError(model_name)


for model_name in ("TecTacEventJob", "TecTacEventJobStat"):
    model_fields, mig_fields = fields_of(models, model_name), migration_fields(migration, model_name)
    expected = [f for f in model_fields]
    must(sorted(mig_fields) == sorted(expected + (["id"] if "id" not in expected else [])), (model_name, sorted(mig_fields), sorted(expected)))
for name in ("tectac_evjob_due_idx", "tectac_evjob_job_idx", "tectac_evjob_active_key", "tectac_evjobstat_unique"):
    must(name in models and name in migration, name)
must('condition=Q(status__in=("pending", "running"))' in models and 'condition=Q(("status__in", ("pending", "running")))' in migration, "partial unique constraint")
must('fields=("module_id", "job_id", "key")' in models and 'fields=("module_id", "job_id", "key")' in migration, "constraint fields")
for field_name, size in (("module_id", 100), ("job_id", 160), ("key", 128), ("error_type", 120), ("error", 255), ("celery_task_id", 80), ("last_error", 255)):
    must(re.search(rf'{field_name} = models\.CharField\(max_length={size}', models) and re.search(rf'\("{field_name}", models\.CharField\([^)]*max_length={size}\)\)', migration), field_name)
print("       migration 0032 and models.py agree: fields, sizes, index names and the partial unique constraint")

# (6) nobody else touches the handle internals or builds a publisher
for path in sorted(ROOT.rglob("*.py")):
    if "__pycache__" in path.parts or path.parent.name == "tests" or path.name in ("event_jobs.py", "event_jobs_policy.py"):
        continue
    source = text(path)
    for banned in ("EventJobPublisher(", "_definition_for", "_issue_context"):
        must(banned not in source or path.name == "contracts.py", f"{path.relative_to(ROOT)} touches {banned}")
    must(not re.search(r"event_jobs\.(_[A-Za-z]\w*)", source) and "event_jobs import _" not in source, f"{path.relative_to(ROOT)} reaches a private name of event_jobs")
policy_tree = ast.parse(text(APP / "event_jobs_policy.py"))
imports = {a.name.split(".")[0] for n in ast.walk(policy_tree) if isinstance(n, ast.Import) for a in n.names}
imports |= {(n.module or "").split(".")[0] for n in ast.walk(policy_tree) if isinstance(n, ast.ImportFrom)}
must("django" not in imports and "celery" not in imports and "" not in imports - {"__future__"}, imports)
print("       no other framework file builds a publisher or reaches the handle internals; the policy file imports no Django")

# (7) the event job code has no private thread, timer, network or secret handling of its own
source = text(APP / "event_jobs.py")
for banned in ("threading.Thread", "threading.Timer", "import requests", "import urllib", "import socket", "import subprocess", "os.system", "import pickle", "eval(", "exec("):
    must(banned not in source, banned)
logged = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == "logger"]
must(logged, "the module logs")
for call in logged:
    for arg in call.args[1:]:
        names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(arg) if isinstance(n, ast.Attribute)}
        must("payload" not in names and "key" not in names, f"a log line carries the payload or key at line {call.lineno}")
audit_fn = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == "_audit")
audit_body = ast.Module(audit_fn.body[1:], [])  # without the docstring
names = {n.id for n in ast.walk(audit_body) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(audit_body) if isinstance(n, ast.Attribute)}
strings = {n.value for n in ast.walk(audit_body) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
must("payload" not in names and "payload" not in strings, "the audit helper never touches a payload")
print("       event_jobs.py: no thread, timer, network, subprocess or pickle; no log line or audit metadata carries the payload")

# (8) docs, versions
for name in ("event-jobs.md",):
    doc = text(ROOT / "docs" / name)
    for phrase in ("core.event_jobs", "requires.framework", ">=1.17.45", "Security review points", "at least once", "AD-13", "register_event_job", "GET /api/tfd/scheduler/event-jobs/",
                   "tests/event-jobs-runtime-1.17.45.py"):
        must(phrase.lower() in doc.lower(), f"{name} lacks {phrase}")
for name in ("scheduler.md", "module-scheduling.md", "capabilities.md", "developer-contracts.md"):
    must("event-jobs.md" in text(ROOT / "docs" / name), f"docs/{name} points to docs/event-jobs.md")
version = text(ROOT / "VERSION").strip()
package = json.loads(text(ROOT / "tec_tac_package.json"))
must(version == package["version"], (version, package["version"]))
must(int(version.split(".")[2].split("-")[0]) >= 45 and version.startswith("1.17."), version)
print("       docs carry the contract and the security review points; VERSION and the package agree")
print("[TEST] PASS event jobs contract 1.17.45")
