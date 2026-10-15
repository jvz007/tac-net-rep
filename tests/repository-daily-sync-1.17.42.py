#!/usr/bin/env python3
"""1.17.42 (CQ122): the daily module repository sync through the Scheduler.

Covered: the action tec-tac.module-repository-sync is registered once, for module tec-tac, with no target and timeout 900; the handler
syncs only enabled repositories (sync_all's own rule) and skips disabled ones; one count-only audit row per run, with no address and no
remote error text in it; a partly failed run succeeds, an all-failed run raises SchedulerPermanentError (after its audit row); no
enabled repository is a clean zero run; ensure_repository_sync_schedule passes daily, 03:00, the settings time zone, run_on_recovery with
a 360 minute grace, concurrency skip and no retry, and does nothing when the schedule exists; a failed create never raises;
sync_schedule_status reads the owned schedule and gives null when absent; the list route adds sync_schedule; the catalog GET still makes
no outbound call.

module_repository.py imports Django and the scheduler, so the real functions are read with ast and run with stubs in sys.modules
(relative imports resolve through sys.modules, so the stubs replace tec_tac.audit, tec_tac.scheduler and tec_tac.models).
"""
from __future__ import annotations

import ast
import json
import logging
import re
import sys
import tempfile
import types
from datetime import time as dt_time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_PATH = ROOT / "framwork/tec_tac/module_repository.py"
VIEWS_PATH = ROOT / "framwork/tec_tac/module_repository_views.py"
SCHED_PATH = ROOT / "framwork/tec_tac/scheduler.py"
REPO_TREE = ast.parse(REPO_PATH.read_text(encoding="utf-8"))
VIEWS_TREE = ast.parse(VIEWS_PATH.read_text(encoding="utf-8"))
SCHED_TREE = ast.parse(SCHED_PATH.read_text(encoding="utf-8"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def extract(tree, names):
    picked = []
    for node in tree.body:
        is_def = isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
        is_assign = isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets)
        if is_def or is_assign:
            picked.append(node)
    found = {getattr(n, "name", None) or n.targets[0].id for n in picked}
    must(not (set(names) - found), f"not found in source: {sorted(set(names) - found)}")
    return picked


# ----------------------------------------------------------------------------------------------------------- stubs for the imports
class ModuleRepositoryError(RuntimeError):
    pass


class SchedulerPermanentError(RuntimeError):
    pass


AUDIT_ROWS: list[dict] = []
SCHED = {"owned": None, "reconcile": [], "fail_create": False}
ROW = {"row": None}


def record(**kwargs):
    AUDIT_ROWS.append(kwargs)
    return {"recorded": True}


def service_audit_actor(**kwargs):
    return ("actor", kwargs["service"], kwargs["identity"])


def get_owned_schedule(owner_module, owner_key):
    return SCHED["owned"]


def reconcile_schedule(**kwargs):
    if SCHED["fail_create"]:
        raise RuntimeError("the scheduler refused the definition")
    SCHED["reconcile"].append(kwargs)
    SCHED["owned"] = {"enabled": True, "schedule_type": kwargs["schedule_type"], "next_run_at": "2026-10-16T01:00:00+00:00",
                      "last_run_at": None, "last_run_status": None, "last_run_finished_at": None}
    return None


class _Query:
    def filter(self, **kwargs):
        return self

    def first(self):
        return ROW["row"]


class TecTacSchedule:
    class ScheduleType:
        DAILY = "daily"

    class MissedPolicy:
        RUN_ON_RECOVERY = "run_on_recovery"
        SKIP = "skip"

    class ConcurrencyPolicy:
        SKIP = "skip"

    class OwnerType:
        MODULE = "module"

    objects = _Query()


settings_stub = types.SimpleNamespace(TIME_ZONE="Africa/Johannesburg")
sys.modules["django"] = types.ModuleType("django")
sys.modules["django.conf"] = types.ModuleType("django.conf")
sys.modules["django.conf"].settings = settings_stub
sys.modules["tec_tac.audit"] = types.ModuleType("tec_tac.audit")
sys.modules["tec_tac.audit"].record = record
sys.modules["tec_tac.audit"].service_audit_actor = service_audit_actor
sys.modules["tec_tac.scheduler"] = types.ModuleType("tec_tac.scheduler")
sys.modules["tec_tac.scheduler"].SchedulerPermanentError = SchedulerPermanentError
sys.modules["tec_tac.scheduler"].get_owned_schedule = get_owned_schedule
sys.modules["tec_tac.scheduler"].reconcile_schedule = reconcile_schedule
sys.modules["tec_tac.models"] = types.ModuleType("tec_tac.models")
sys.modules["tec_tac.models"].TecTacSchedule = TecTacSchedule

WORK = Path(tempfile.mkdtemp(prefix="daily-sync-")) / "repositories"
ns: dict = {"json": json, "re": re, "logging": logging, "Path": Path, "dt_time": dt_time,
            "__package__": "tec_tac", "__name__": "tec_tac.module_repository"}
ns["CONFIG_FILE"] = WORK / "repositories.json"
ns["CACHE_ROOT"] = WORK / "cache"
ns["REPO_ID_RE"] = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
ns["ModuleRepositoryError"] = ModuleRepositoryError
ns["logger"] = logging.getLogger("tec-tac-test")
names = {
    "SYNC_ACTION_ID", "SYNC_OWNER_MODULE", "SYNC_OWNER_KEY", "SYNC_RUN_TIME", "SYNC_MISSED_GRACE_MINUTES",
    "_utcnow", "_default_config", "load_repositories", "public_repository", "list_repositories", "_skipped_summary",
    "_repo", "repository_status", "sync_all", "run_scheduled_sync", "ensure_repository_sync_schedule", "sync_schedule_status",
    "_atomic_repo_json", "_cached_modules",
}
exec(compile(ast.Module(body=extract(REPO_TREE, names), type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only

# the repository sync itself is stubbed: it is the network path (1.17.39 tests cover it). Each id behaves as the test sets it.
SYNCED: list[str] = []
BEHAVIOUR: dict = {}


def fake_sync_repository(repository_id):
    SYNCED.append(repository_id)
    behaviour = BEHAVIOUR.get(repository_id, "ok")
    if behaviour == "fail":
        raise ModuleRepositoryError(f"Repository request failed for https://secret.example.test/{repository_id}.json")
    return {**ns["public_repository"](ns["_repo"](repository_id)), "sync": {"status": "ok", "synced_at": "2026-10-15T00:00:00+00:00",
                                                                      "error": None, "module_count": 3, "skipped_count": 2, "skipped": []}}


ns["sync_repository"] = fake_sync_repository


def write_config(repos):
    ns["CONFIG_FILE"].parent.mkdir(parents=True, exist_ok=True)
    ns["CONFIG_FILE"].write_text(json.dumps({"schema": 1, "repositories": repos}), encoding="utf-8")


def repo(rid, enabled=True):
    return {"id": rid, "name": rid.title(), "url": f"https://{rid}.example.test/index.json", "trust": "official", "priority": 100,
            "enabled": enabled, "created_at": "2026-10-01T00:00:00+00:00", "updated_at": "2026-10-01T00:00:00+00:00"}


def reset(repos):
    AUDIT_ROWS.clear()
    SYNCED.clear()
    BEHAVIOUR.clear()
    write_config(repos)


# ----------------------------------------------------------------------------------------------------- (1) the action is registered
registrations = []
for node in ast.walk(SCHED_TREE):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "register_scheduled_action":
        kw = {k.arg: k.value for k in node.keywords}
        if isinstance(kw.get("id"), ast.Constant) and kw["id"].value == "tec-tac.module-repository-sync":
            registrations.append(kw)
must(len(registrations) == 1, f"registered once, found {len(registrations)}")
kw = registrations[0]
must(kw["module_id"].value == "tec-tac", "module tec-tac")
must(isinstance(kw["permission"], ast.Constant) and kw["permission"].value is None, "permission None")
must(kw["timeout_seconds"].value == 900, "timeout 900")
must(isinstance(kw["target_types"], ast.Tuple) and [e.value for e in kw["target_types"].elts] == ["none"], "target none")
must(kw["handler"].id == "_module_repository_sync_handler", "the handler is the module repository sync")
print("       action registered once: tec-tac, no target, permission None, timeout 900")

# ------------------------------------------------------------------- (2) the handler syncs only enabled repositories, and skips disabled
reset([repo("alpha"), repo("beta"), repo("gamma", enabled=False)])
counts = ns["run_scheduled_sync"]({"parameters": {}})
must(sorted(SYNCED) == ["alpha", "beta"], SYNCED)
must(counts == {"repositories": 2, "ok": 2, "failed": 0, "entries_skipped": 4}, counts)
must(len(AUDIT_ROWS) == 1, AUDIT_ROWS)
must(AUDIT_ROWS[0]["after"] == counts and AUDIT_ROWS[0]["action"] == "sync" and AUDIT_ROWS[0]["module_id"] == "core", AUDIT_ROWS[0])
must(AUDIT_ROWS[0]["object_type"] == "module_repository" and AUDIT_ROWS[0]["object_id"] == "module-repository-sync", AUDIT_ROWS[0])
print("       handler: enabled repositories synced, disabled skipped, counts returned, one audit row")

# ------------------------------------------------------- (3) the audit row and the result never carry an address or a remote error
reset([repo("alpha"), repo("beta")])
BEHAVIOUR["beta"] = "fail"
counts = ns["run_scheduled_sync"]({})
dump = json.dumps({"rows": AUDIT_ROWS, "counts": counts}, default=str)
must("http" not in dump and "secret" not in dump and "example.test" not in dump, dump)
must(counts == {"repositories": 2, "ok": 1, "failed": 1, "entries_skipped": 2}, counts)
must(len(AUDIT_ROWS) == 1, AUDIT_ROWS)
print("       partly failed: succeeds with counts; the audit row and result carry no address or remote text")

# ------------------------------------------------------------------------------- (4) all failed raises, after its audit row
reset([repo("alpha"), repo("beta")])
BEHAVIOUR["alpha"] = "fail"
BEHAVIOUR["beta"] = "fail"
try:
    ns["run_scheduled_sync"]({})
except SchedulerPermanentError as error:
    must("previous catalogs are kept" in str(error) and "secret" not in str(error), str(error))
else:
    raise AssertionError("all enabled repositories failing must raise")
must(len(AUDIT_ROWS) == 1 and AUDIT_ROWS[0]["after"] == {"repositories": 2, "ok": 0, "failed": 2, "entries_skipped": 0}, AUDIT_ROWS)
print("       all failed: SchedulerPermanentError after one audit row")

# ------------------------------------------------------------------------------- (5) no enabled repository is a clean zero run
reset([repo("gamma", enabled=False)])
counts = ns["run_scheduled_sync"]({})
must(counts == {"repositories": 0, "ok": 0, "failed": 0, "entries_skipped": 0} and SYNCED == [], (counts, SYNCED))
must(len(AUDIT_ROWS) == 1, AUDIT_ROWS)
print("       no enabled repository: zero counts, no raise")

# ---------------------------------------------------------------- (6) ensure creates the schedule with the agreed settings, once
SCHED.update({"owned": None, "reconcile": [], "fail_create": False})
must(ns["ensure_repository_sync_schedule"]() is True, "the first call creates it")
must(len(SCHED["reconcile"]) == 1, SCHED["reconcile"])
call = SCHED["reconcile"][0]
must(call["owner_module"] == "tec-tac" and call["owner_key"] == "module-repository-sync", call)
must(call["action_id"] == "tec-tac.module-repository-sync" and call["schedule_type"] == "daily", call)
must(call["run_time"] == dt_time(3, 0) and call["timezone_name"] == "Africa/Johannesburg", call)
must(call["missed_policy"] == "run_on_recovery" and call["missed_grace_minutes"] == 360, call)
must(call["concurrency_policy"] == "skip" and call["retry_count"] == 0, call)
must(call["name"] == "Module repository sync (daily, 03:00)", call["name"])
must(ns["ensure_repository_sync_schedule"]() is False and len(SCHED["reconcile"]) == 1, "an existing schedule is not re-saved")
print("       ensure: daily 03:00, settings zone, run_on_recovery 360 minutes, skip, no retry; no re-save when it exists")

# ------------------------------------------------------------------ (7) a deleted row comes back; a failed create never raises
SCHED["owned"] = None
must(ns["ensure_repository_sync_schedule"]() is True and len(SCHED["reconcile"]) == 2, "a deleted row is recreated")
SCHED["owned"] = None
SCHED["fail_create"] = True
must(ns["ensure_repository_sync_schedule"]() is False, "a failed create returns False")
SCHED["fail_create"] = False
print("       deleted row recreated; a failed create logs and returns False")

# ------------------------------------------------------------------------------ (8) sync_schedule_status reads the owned schedule
SCHED["owned"] = {"enabled": True, "schedule_type": "daily", "next_run_at": "2026-10-16T01:00:00+00:00",
                  "last_run_at": "2026-10-15T01:00:00+00:00", "last_run_status": "succeeded", "last_run_finished_at": None}
ROW["row"] = types.SimpleNamespace(run_time=dt_time(3, 0), timezone="Africa/Johannesburg")
status = ns["sync_schedule_status"]()
must(status == {"enabled": True, "time": "03:00", "timezone": "Africa/Johannesburg", "next_run_at": "2026-10-16T01:00:00+00:00",
                "last_run_at": "2026-10-15T01:00:00+00:00", "last_run_status": "succeeded"}, status)
SCHED["owned"] = None
must(ns["sync_schedule_status"]() is None, "null when absent")
ROW["row"] = None
print("       sync_schedule_status: the owned schedule's fields, null when absent")

# ----------------------------------------------------------------------- (9) the list route adds sync_schedule, and no address
views_text = VIEWS_PATH.read_text(encoding="utf-8")
must('"sync_schedule": sync_schedule_status()' in views_text, "the list response carries sync_schedule")
must("sync_schedule_status" in views_text.split("class ModuleRepositoryListView")[0], "the function is imported in the views")
print("       list route: sync_schedule added")

# -------------------------------------------------------- (10) the catalog GET still makes no outbound call (source and behaviour)
repo_tree = REPO_TREE


def function_named(tree, name, owner=None):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found")


forbidden = {"_fetch", "sync_all", "sync_repository", "run_scheduled_sync", "ensure_repository_sync_schedule"}


def calls_in(node):
    names_called = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            if isinstance(sub.func, ast.Name):
                names_called.add(sub.func.id)
            elif isinstance(sub.func, ast.Attribute):
                names_called.add(sub.func.attr)
    return names_called


must(not (calls_in(function_named(repo_tree, "online_catalog")) & forbidden), "online_catalog makes no sync or fetch call")
catalog_view = next(n for n in ast.walk(VIEWS_TREE) if isinstance(n, ast.ClassDef) and n.name == "ModuleOnlineCatalogView")
catalog_get = next(n for n in catalog_view.body if isinstance(n, ast.FunctionDef) and n.name == "get")
must(not (calls_in(catalog_get) & forbidden), "the catalog GET makes no sync or fetch call")
must(not (calls_in(function_named(repo_tree, "_availability")) & forbidden), "_availability reads the cache only")
print("       catalog GET: no sync, fetch or schedule call in its path")

# ------------------------------------------------------- (11) the scheduler docs name the action, and the repository docs the sync
for name, needle in (
    ("docs/scheduler.md", "tec-tac.module-repository-sync"),
    ("docs/module-repositories.md", "Daily sync (1.17.42)"),
):
    text = (ROOT / name).read_text(encoding="utf-8")
    must(needle in text, f"{name} names {needle!r}")
print("       docs: scheduler action and daily sync section present")

print("[TEST] PASS repository daily sync 1.17.42")
