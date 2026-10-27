#!/usr/bin/env python3
"""1.17.19 regression (CQ64 a): the Scheduler hands a handler a context only Core can have issued, and a handler can verify it.

No Django: the module's small private lookups (_load_run, _authorization_error, _reload_user, _check_flag, _user_has_flag,
_user_resource_context, _is_one_off_key) are replaced with stubs. Covered: a context Core issued verifies and gives the owner from
the database row, not from the dict; a mutated dict changes nothing; a plain dict, a copy, a JSON or pickle round-trip, a context
built directly, and a subclass are refused; a run that is not running, a missing run and a missing schedule are refused; an owner
who is inactive or lost the action or the scope is refused; a module-owned run needs ``require_owner=False``; the permission check
re-reads the owner on every call and fails closed; the registry forgets a collected context; a lookup error ends in
SchedulerRunContextInvalid; tasks.execute_schedule_run issues the context with the same keys as before; the docs carry the limits.
"""
from __future__ import annotations

import copy
import gc
import importlib.util
import json
import pickle
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


class SchedulerError(Exception):
    pass


class SchedulerRunContextInvalid(SchedulerError):
    pass


pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(APP)]
sched = types.ModuleType("tec_tac.scheduler")
sched.SchedulerError, sched.SchedulerRunContextInvalid = SchedulerError, SchedulerRunContextInvalid
sys.modules.update({"tec_tac": pkg, "tec_tac.scheduler": sched})
spec = importlib.util.spec_from_file_location("tec_tac.scheduler_run_context", APP / "scheduler_run_context.py")
ctx_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ctx_mod
spec.loader.exec_module(ctx_mod)

# ---- the stubbed lookups
USERS = {}
FLAGS = {}
STATE = {"run": None, "auth_error": None, "load_boom": None, "flag_boom": None}


def user(pk, name, active=True):
    obj = SimpleNamespace(pk=pk, username=name, is_active=active)
    USERS[pk] = obj
    return obj


def make_run(owner_type="user", owner_key=None, status="running", owner=None, schedule=True):
    sch = SimpleNamespace(id="sched-1", module_id="scriptmanager", action_id="run-script", created_by=owner) if schedule else None
    return SimpleNamespace(id="run-1", status=status, schedule=sch, schedule_snapshot_id="sched-1", module_id="scriptmanager",
                           action_id="run-script", owner_type=owner_type, owner_key=owner_key, owner_module="scriptmanager" if owner_type == "module" else "")


def _load_run(run_id):
    if STATE["load_boom"]:
        raise STATE["load_boom"]
    run = STATE["run"]
    return run if run is not None and str(run.id) == str(run_id) else None


ctx_mod._load_run = _load_run
ctx_mod._is_one_off_key = lambda key: bool(key) and str(key).startswith("one-off:")
ctx_mod._authorization_error = lambda schedule: STATE["auth_error"]
# 1.17.63: the two helpers added with the unattended rule. An ordinary run is never unattended; the creator name is read from created_by.
ctx_mod._is_unattended_scheduled_run = lambda run: False
ctx_mod._creator_names = lambda schedule: (str(getattr(getattr(schedule, "created_by", None), "username", "") or ""), "")
ctx_mod._scheduled_person_action = lambda schedule, action_id: False  # 1.17.80: a declared module action; none in these tests
ctx_mod._reload_user = lambda pk: USERS.get(pk)
ctx_mod._check_flag = lambda flag: flag if isinstance(flag, str) and re.fullmatch(r"can_[a-z_]+", flag) else (_ for _ in ()).throw(ValueError("bad flag"))


def _user_has_flag(owner, flag):
    if STATE["flag_boom"]:
        raise STATE["flag_boom"]
    return flag in FLAGS.get(owner.pk, set())


ctx_mod._user_has_flag = _user_has_flag
ctx_mod._user_resource_context = lambda owner: ("resource-context", owner.username)

FIELDS = {"schedule_id": "sched-1", "run_id": "run-1", "module_id": "scriptmanager", "action_id": "run-script", "target_mode": "agents",
          "targets": [], "parameters": {}, "scheduled_for": None, "manual": False, "attempt": 1, "owner_type": "user", "owner_module": None,
          "owner_key": None, "owner_user_id": 5, "owner_username": "dave", "one_off": False}


# 1.17.20: a handler names its own module id and action id
IDS = {"expected_module_id": "scriptmanager", "expected_action_id": "run-script"}


def issue():
    return ctx_mod.issue_run_context(dict(FIELDS), run_id="run-1")


def refused(context, **kw):
    try:
        ctx_mod.verify_run_context(context, **{**IDS, **kw})
    except SchedulerRunContextInvalid as exc:
        must(str(exc), "a plain message")
        return str(exc)
    raise AssertionError("verified a context that must be refused")


owner = user(5, "dave")
STATE["run"] = make_run(owner=owner)

# ---- a Core-issued context verifies; the owner comes from the row
ctx = issue()
must(isinstance(ctx, dict) and ctx["owner_username"] == "dave" and json.loads(json.dumps(ctx)) == json.loads(json.dumps(FIELDS)), "dict compatible")
must(ctx_mod.is_core_issued_run_context(ctx) and not ctx_mod.is_core_issued_run_context(dict(ctx)), "identity registry")
verified = ctx_mod.verify_run_context(ctx, **IDS)
must(verified.user is owner and verified.owner_user_id == 5 and verified.owner_username == "dave", verified)
must(verified.run_id == "run-1" and verified.schedule_id == "sched-1" and verified.module_id == "scriptmanager" and verified.one_off is False, verified)
try:
    verified.run_id = "x"
    raise AssertionError("VerifiedSchedulerRun is not frozen")
except Exception as exc:  # FrozenInstanceError
    must(type(exc).__name__ == "FrozenInstanceError", exc)
# mutating the dict changes nothing
ctx["owner_username"], ctx["owner_user_id"] = "root", 1
again = ctx_mod.verify_run_context(ctx, **IDS)
must(again.owner_username == "dave" and again.owner_user_id == 5, "the owner is read from the database")

# ---- anything that is not the issued object is refused
good = issue()
for label, fake in (
    ("plain dict", dict(FIELDS)), ("star copy", {**good}), ("dict()", dict(good)), ("copy.copy", copy.copy(good)),
    ("deepcopy", copy.deepcopy(good)), ("json", json.loads(json.dumps(good))), ("pickle", pickle.loads(pickle.dumps(good))),
    ("built directly", ctx_mod.SchedulerRunContext(FIELDS)), ("None", None), ("a string", "run-1"),
):
    must(not ctx_mod.is_core_issued_run_context(fake), label)
    refused(fake)


class Sub(ctx_mod.SchedulerRunContext):
    pass


refused(Sub(FIELDS))
must(ctx_mod.verify_run_context(good, **IDS).user is owner, "the issued object still verifies after the refusals")

# ---- the run and the schedule
for label, run in (("finished", make_run(owner=owner, status="succeeded")), ("queued", make_run(owner=owner, status="queued")),
                   ("missing", None), ("no schedule", make_run(owner=owner, schedule=False))):
    STATE["run"] = run
    refused(issue())
STATE["run"] = make_run(owner=owner)

# ---- the owner
STATE["auth_error"] = "The user lost the action."
refused(issue())
STATE["auth_error"] = None
STATE["run"] = make_run(owner=None)
refused(issue())  # a user-owned run with no created_by has no person
STATE["run"] = make_run(owner_type="module", owner_key="plain-key", owner=None)
refused(issue())  # module-owned, no person
free = ctx_mod.verify_run_context(issue(), require_owner=False, **IDS)
must(free.user is None and free.owner_user_id is None and free.owner_module == "scriptmanager", free)
refused(issue(), require_owner=True)
STATE["run"] = make_run(owner_type="module", owner_key="one-off:abc", owner=owner)
one_off = ctx_mod.verify_run_context(issue(), **IDS)
must(one_off.one_off is True and one_off.user is owner and one_off.owner_username == "dave", one_off)

# ---- has_tactical_permission re-reads the owner on every call and fails closed
STATE["run"] = make_run(owner=owner)
run = ctx_mod.verify_run_context(issue(), **IDS)
FLAGS[5] = {"can_list_scripts"}
must(run.has_tactical_permission("can_list_scripts") is True, "granted")
FLAGS[5] = set()
must(run.has_tactical_permission("can_list_scripts") is False, "revoked between two calls")
FLAGS[5] = {"can_list_scripts"}
for bad in ("list_scripts", "CAN_X", "can_x; drop", 5, None, ""):
    must(run.has_tactical_permission(bad) is False, bad)
USERS[5] = user(5, "dave", active=False)
must(run.has_tactical_permission("can_list_scripts") is False, "an inactive owner")
USERS[5] = user(5, "dave")
del USERS[5]
must(run.has_tactical_permission("can_list_scripts") is False, "a deleted owner")
USERS[5] = user(5, "dave")
STATE["flag_boom"] = RuntimeError("db down")
must(run.has_tactical_permission("can_list_scripts") is False, "a raising lookup")
STATE["flag_boom"] = None
must(ctx_mod.verify_run_context(issue(), **IDS).resource_context() == ("resource-context", "dave"), "resource context is the owner's")
del USERS[5]
try:
    run.resource_context()
    raise AssertionError("resource_context for a deleted owner")
except SchedulerRunContextInvalid:
    pass
USERS[5] = user(5, "dave")
# a verified run with no person
STATE["run"] = make_run(owner_type="module", owner_key="k", owner=None)
nobody = ctx_mod.verify_run_context(issue(), require_owner=False, **IDS)
must(nobody.has_tactical_permission("can_list_scripts") is False, "no owner, no permission")
try:
    nobody.resource_context()
    raise AssertionError("resource_context without an owner")
except SchedulerRunContextInvalid:
    pass

# ---- the registry forgets a collected context
STATE["run"] = make_run(owner=owner)
before = len(ctx_mod._ISSUED)
temp = issue()
must(len(ctx_mod._ISSUED) == before + 1, "remembered")
del temp
gc.collect()
must(len(ctx_mod._ISSUED) == before, "forgotten")

# ---- a lookup error ends in SchedulerRunContextInvalid, never a bare exception
for boom in (RuntimeError("db down"), KeyError("x"), ValueError("y")):
    STATE["load_boom"] = boom
    refused(issue())
STATE["load_boom"] = None
STATE["run"] = SimpleNamespace(id="run-1", status="running", schedule=SimpleNamespace(created_by=owner))  # a half-built row
refused(issue())
STATE["run"] = make_run(owner=owner)
ctx_mod._authorization_error = lambda schedule: (_ for _ in ()).throw(RuntimeError("auth lookup down"))
refused(issue())

# ---- the wiring: tasks.execute_schedule_run issues the context with the same keys as before
tasks = (APP / "tasks.py").read_text(encoding="utf-8")
must("from .scheduler_run_context import issue_run_context" in tasks and "issue_run_context({" in tasks and "run_id=run.id)" in tasks, "tasks.py issues the context")
body = tasks[tasks.index("issue_run_context({"):tasks.index("run_id=run.id)")]
for key in ("schedule_id", "run_id", "module_id", "action_id", "target_mode", "targets", "parameters", "scheduled_for", "manual", "attempt", "**_handler_owner(run, schedule)"):
    must(f'"{key}"' in body or key in body, key)
must("result = action.handler(context)" in tasks, "the handler still gets the context")
must(tasks.count("action.handler(") == 1, "the one place a handler is called")
sched_src = (APP / "scheduler.py").read_text(encoding="utf-8")
must("class SchedulerRunContextInvalid(SchedulerError)" in sched_src and "verify_run_context" in sched_src and "SchedulerRunContext, VerifiedSchedulerRun" in sched_src, "scheduler.py re-exports")
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
for name in ("verify_run_context", "VerifiedSchedulerRun", "SchedulerRunContextInvalid"):
    must(f'"name": "{name}"' in contracts, name)
must('"name": "issue_run_context"' not in contracts, "issue_run_context stays private")

# ---- the docs
docs = " ".join((ROOT / "docs/scheduler.md").read_text(encoding="utf-8").split())
must("## Verify a run context (Core 1.17.19)" in docs, "docs section")
must("cannot stop deliberately hostile signed module code" in docs, "the limit is stated")
must("same Python process as Core" in docs and "no per-run signed token" in docs and "not the AD-13 system-action contract" in docs, "limits")
must("can_list_scripts" in docs and "issue_run_context" not in docs, "example, and no private name in the docs")
print("[TEST] PASS scheduler run context 1.17.19")
