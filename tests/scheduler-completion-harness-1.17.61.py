#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""Shared stub harness for the 1.17.61 Scheduler completion and system-action tests (exec'd by them, as accounts-contract-1.17.27.py is).

No Django, no Celery, no database. The REAL tec_tac/scheduler.py, scheduler_completion.py, scheduler_run_context.py, caller_identity.py,
system_actions.py and tasks.py run against: in-memory models (a mini query layer that understands the lookups Core uses), a stub audit
module, stub Tactical task functions (``winupdate.tasks``), a stub server-maintenance job store and a temporary extensions folder.
Module code is compiled under that folder with ``compile_as`` so the real frame walk of caller_identity decides who is calling.

Run on its own, this file only builds the harness and prints nothing.
"""
from __future__ import annotations

import importlib.util
import itertools
import logging
import sys
import tempfile
import types
import uuid
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from types import SimpleNamespace

logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
NOW = [datetime(2026, 10, 20, 12, 0, tzinfo=dt_timezone.utc)]
COUNTER = itertools.count(1)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


mods: dict = {}


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    mods[name] = m
    sys.modules[name] = m
    return m


# ------------------------------------------------------------------------------------------------ in-memory models
class Choices:
    def __init__(self, **kw):
        self.__dict__.update(kw)
        self.values = list(kw.values())


class QNode:
    def __init__(self, op="and", children=None, **kw):
        self.op, self.children = op, (children or ([kw] if kw else []))

    def __and__(self, other):
        return QNode("and", [self, other])

    def __or__(self, other):
        return QNode("or", [self, other])


def _lookup(row, key):
    parts = key.split("__")
    ops = {"in", "lt", "lte", "gt", "gte", "isnull"}
    op = parts.pop() if len(parts) > 1 and parts[-1] in ops else "exact"
    value = row
    for part in parts:
        value = value.get(part) if isinstance(value, dict) else getattr(value, part)
        if value is None:
            break
    return value, op


def match(row, spec):
    if isinstance(spec, QNode):
        results = [match(row, child) for child in spec.children]
        return all(results) if spec.op == "and" else any(results)
    for key, expected in spec.items():
        value, op = _lookup(row, key)
        if op == "in":
            ok = value in expected
        elif op == "lt":
            ok = value is not None and value < expected
        elif op == "lte":
            ok = value is not None and value <= expected
        elif op == "gt":
            ok = value is not None and value > expected
        elif op == "gte":
            ok = value is not None and value >= expected
        elif op == "isnull":
            ok = (value is None) == expected
        else:
            ok = value == expected or (key in ("pk", "id") and str(value) == str(expected))  # Django accepts a text uuid for a uuid key
        if not ok:
            return False
    return True


class Query(list):
    def first(self):
        return self[0] if self else None

    def exists(self):
        return bool(self)

    def values_list(self, *fields, flat=False):  # 1.17.63: the tick lists the ids of the enabled schedules
        return [getattr(r, fields[0]) for r in self]

    def filter(self, *qs, **kw):
        return Query(r for r in self if all(match(r, q) for q in qs) and match(r, kw))

    def select_for_update(self, of=None):
        return self

    def select_related(self, *a):
        return self

    def only(self, *a):
        return self

    def order_by(self, *fields):
        key = fields[0].lstrip("-") if fields else "created_at"
        return Query(sorted(self, key=lambda r: (getattr(r, key, None) is None, getattr(r, key, None) or 0), reverse=bool(fields and fields[0].startswith("-"))))

    def get(self, pk):
        for item in self:
            if str(item.pk) == str(pk):
                return item
        raise Run.DoesNotExist(pk)


class Manager:
    def __init__(self):
        self.rows = []

    def filter(self, *qs, **kw):
        return Query(self.rows).filter(*qs, **kw)

    def select_for_update(self, of=None):
        return Query(self.rows)

    def select_related(self, *a):
        return Query(self.rows)

    def create(self, **kw):
        row = self.model(**kw)
        self.rows.append(row)
        return row


SAVES = []  # (model name, update_fields): a typo in update_fields is caught because every name must be a real field


class Model:
    def __init__(self, **kw):
        self.pk = self.id = uuid.uuid4()
        self.created_at = NOW[0] - timedelta(days=1) + timedelta(seconds=next(COUNTER))
        self.__dict__.update({k: (list(v) if isinstance(v, list) else dict(v) if isinstance(v, dict) else v) for k, v in self.defaults.items()})
        self.__dict__.update(kw)

    def save(self, update_fields=None):
        for name in update_fields or ():
            must(name in self.defaults or name in ("created_at", "id"), f"{type(self).__name__}.save(update_fields) names an unknown field {name!r}")
        SAVES.append((type(self).__name__, tuple(update_fields or ())))


class Schedule(Model):
    OwnerType = Choices(USER="user", MODULE="module")
    ScheduleType = Choices(ONCE="once", DAILY="daily", WEEKLY="weekly", MONTHLY="monthly", INTERVAL="interval")
    TargetMode = Choices(SNAPSHOT="snapshot", DYNAMIC="dynamic")
    MissedPolicy = Choices(SKIP="skip", RUN_ON_RECOVERY="run_on_recovery", EXPIRE="expire")
    ConcurrencyPolicy = Choices(SKIP="skip", QUEUE="queue", ALLOW="allow")
    defaults = dict(name="", module_id="", action_id="", owner_type="user", owner_module="", owner_key="", enabled=True, run_at=None, run_time=None,
                    weekdays=[], day_of_month=None, interval_seconds=None, interval_anchor_at=None, last_run_at=None, last_due_key="",
                    created_by=None, updated_by=None, parameters={}, targets={}, target_mode="snapshot", retry_count=0, retry_delay_seconds=60,
                    timezone="UTC", missed_policy="skip", missed_grace_minutes=60, concurrency_policy="skip", target_state="valid",
                    target_state_detail="", updated_at=None, schedule_type="once",
                    created_by_username="", confirmed_by_username="",  # 1.17.63: the names migration 0036 adds
                    creation_scope={})  # 1.17.68: migration 0037 adds the scope a person had when they saved the schedule

    @property
    def runs(self):
        return Query(r for r in Run.objects.rows if r.schedule is self)

    def delete(self):
        Schedule.objects.rows.remove(self)
        for run in Run.objects.rows:
            if run.schedule is self:
                run.schedule = None


class Run(Model):
    DoesNotExist = type("DoesNotExist", (Exception,), {})
    Status = Choices(QUEUED="queued", RUNNING="running", SUCCEEDED="succeeded", FAILED="failed", SKIPPED="skipped")
    defaults = dict(status="queued", manual=False, result={}, error="", error_type="", celery_task_id="", attempt=0, started_at=None,
                    finished_at=None, schedule=None, schedule_snapshot_id=None, schedule_name="", module_id="", action_id="",
                    owner_type="user", owner_module="", owner_key="", targets_snapshot={}, parameters_snapshot={},
                    target_mode_snapshot="snapshot", retry_count_snapshot=0, retry_delay_seconds_snapshot=60, last_queued_at=None,
                    scheduled_for=None, completion_state="", completion_ref={}, completion_started_at=None, system_action_marks=[])


Run.schedule_id = property(lambda self: self.schedule.pk if self.schedule is not None else None)
Schedule.objects = Manager()
Schedule.objects.model = Schedule
Run.objects = Manager()
Run.objects.model = Run


class Grant(Model):
    """1.17.68: the stand-in of TecTacDelegationGrant (migration 0037)."""
    defaults = dict(owner_module="", grant_key="", provider_module="", action_id="", targets={}, parameters={}, parameters_digest="", created_by=None,
                    created_by_username="", confirmed_by_username="", creation_scope={}, enabled=True, updated_at=None)

    def save(self, update_fields=None):
        self.updated_at = NOW[0] + timedelta(seconds=next(COUNTER))  # auto_now: every save moves it
        if self not in Grant.objects.rows:
            Grant.objects.rows.append(self)

    def delete(self):
        Grant.objects.rows.remove(self)


Grant.objects = Manager()
Grant.objects.model = Grant


class State:
    @classmethod
    def current(cls):
        return cls()

    def save(self, update_fields=None):
        pass


class Config:
    once_retention_hours = 48
    run_retention_days = 90
    queued_stale_minutes = 10

    @classmethod
    def current(cls):
        return cls()


class ValidationError(Exception):
    pass


AUDITS: list = []
AUDIT_FAIL = {"strict": False, "all": False}


def audit_record(**kw):
    if AUDIT_FAIL["all"] or (AUDIT_FAIL["strict"] and kw.get("strict")):
        raise RuntimeError("audit store down")
    AUDITS.append(kw)
    return {"recorded": True}


mod("django")
mod("django.core")
mod("django.core.exceptions", ValidationError=ValidationError)
mod("django.db", transaction=SimpleNamespace(atomic=lambda *a, **k: nullcontext()))
mod("django.db.models", Q=lambda *a, **k: QNode(**k))
mod("django.utils")
mod("django.utils.timezone", now=lambda: NOW[0], is_naive=lambda v: v.tzinfo is None)
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.models", TecTacSchedule=Schedule, TecTacScheduleRun=Run, TecTacSchedulerConfig=Config, TecTacSchedulerState=State, TecTacDelegationGrant=Grant)
QUEUED_IDS: list = []


class FakeQueueTask:
    def apply_async(self, *, args, time_limit):
        QUEUED_IDS.append(args[0])
        return SimpleNamespace(id="celery-queue-1")


mod("tec_tac.tasks", execute_schedule_run=FakeQueueTask())
mod("tec_tac.capabilities", capability_status=None, CapabilityDisabled=type("CD", (Exception,), {}), CapabilityUnavailable=type("CU", (Exception,), {}),
    CapabilityVersionMismatch=type("CV", (Exception,), {}), CapabilityUnhealthy=type("CH", (Exception,), {}))
mod("tacticalrmm")
mod("tacticalrmm.celery", app=SimpleNamespace(task=lambda *a, **k: (lambda fn: fn)))
AUTH = {"deny": False}
mod("tec_tac.scheduler_views", _can_use_action=lambda user, action: not AUTH["deny"], _can_access_target_scope=lambda user, targets, **kw: not AUTH["deny"],
    _canonicalize_endpoint_targets_for_user=lambda user, targets: targets, _native_scheduler_manager=lambda user: False)
audit_stub = mod("tec_tac.audit", record=audit_record, service_audit_actor=lambda **kw: SimpleNamespace(kind="service", **kw))
pkg.audit = audit_stub

# ---- a temporary extensions folder, the module list, the module state, replacement and role stubs
TMP = Path(tempfile.mkdtemp(prefix="tectac-completion-"))
EXT = TMP / "extensions"
LIB = TMP / "lib"
EXT.mkdir()
LIB.mkdir()
PLUGINS: dict = {}
ENABLED: dict = {}
HONOURED: dict = {}  # replacement module id -> the core module it honourably replaces right now
STATE_FAULT = {"registry": False}


def plugin(plugin_id, *, enabled=True, legacy=False, category="core", replaces="", system_actions=()):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version="1.0.0", legacy=legacy, category=category,
                                         replaces=replaces, system_actions=tuple(system_actions))
    ENABLED[plugin_id] = enabled
    return root


def discover_plugins():
    if STATE_FAULT["registry"]:
        raise RuntimeError("registry unreadable")
    return tuple(PLUGINS.values())


mod("tec_tac.registry", discover_plugins=discover_plugins)
mod("tec_tac.module_state", load_state=lambda: {"schema": 1, "modules": {}}, is_enabled=lambda module_id, state=None: ENABLED.get(module_id, True))
mod("tec_tac.module_replacement", honoured_replacement=lambda module_id: HONOURED.get(module_id))
mod("tec_tac.module_category", effective_category=lambda declared: (str(declared or "").strip().lower() or "test"))
KNOWN_FLAGS = {"can_manage_winupdates", "can_run_bulk", "can_run_scripts", "can_reboot_agents"}
FLAGS: dict = {}  # username -> set of flags the user holds
SCOPE: dict = {}  # username -> set of agent numbers inside the user's role scope


def _validate_tactical_flag(flag):
    if flag not in KNOWN_FLAGS:
        raise ValueError(f"Unknown Tactical role permission: {flag!r}")
    return flag


mod("tec_tac.rbac", _validate_tactical_flag=_validate_tactical_flag, has_tactical_permission=lambda user, flag: flag in FLAGS.get(user.username, set()),
    tactical_permission_catalog=lambda user: {flag: flag in FLAGS.get(user.username, set()) for flag in sorted(KNOWN_FLAGS)})
SCOPE_CALLS: list = []


def _agents_in_role_scope(*, user, pks):
    SCOPE_CALLS.append((user.username, list(pks)))
    return bool(pks) and set(pks) <= SCOPE.get(user.username, set())


# 1.17.62: the targets of a run's snapshot, resolved to agent numbers (the stub of resources_adapter.agent_pks_for_scheduler_targets).
EXISTING_AGENTS: set | None = None  # None: every endpoint number exists
CLIENT_AGENTS: dict = {}  # client id -> agent numbers
SITE_AGENTS: dict = {}  # site id -> agent numbers
TARGET_CALLS: list = []


RESOLVED_MODULE_TARGETS: dict = {}  # 1.17.68: (module id, target type) -> the agent numbers a registered resolver names (the stub of the resolver path)


def _agent_pks_for_scheduler_targets(*, targets, module_id=None):
    TARGET_CALLS.append(targets)
    ref = sys.modules["tec_tac.scheduler_targets"].tactical_scope_ref(targets)
    kind, values = ref["kind"], ref["values"]
    if kind == "module":
        found = RESOLVED_MODULE_TARGETS.get((module_id, str(targets.get("type")))) if module_id else None
        return None if found is None else (set(found), 0)
    if kind == "none":
        return set(), 0
    if kind == "endpoint":
        found = {int(v) for v in values if str(v).isdigit() and (EXISTING_AGENTS is None or int(v) in EXISTING_AGENTS)}
        return found, len({str(v) for v in values}) - len(found)
    table = CLIENT_AGENTS if kind == "client" else SITE_AGENTS
    known = [v for v in values if v in table]
    return set().union(*[table[v] for v in known]) if known else set(), len(set(values)) - len(known)


# 1.17.68: the creation-time scope reads and the endpoint rows of a stored scope (the stubs of resources_adapter.role_scope_descriptor and agent_rows_in_scope)
DESCRIPTORS: dict = {}  # username -> the scope descriptor of the user
AGENT_ROWS: dict = {}  # agent number -> {"agent_id", "hostname", "platform", "client_id", "site_id"}
ROW_CALLS: list = []


def _role_scope_descriptor(user):
    return DESCRIPTORS.get(user.username, {"mode": "none", "unrestricted": False, "whole_client_ids": [], "site_ids": []})


def _agent_rows_in_scope(*, pks, snapshot=None, user=None, limit):
    ROW_CALLS.append({"pks": None if pks is None else list(pks), "snapshot": snapshot, "user": getattr(user, "username", None), "limit": limit})
    if (snapshot is None) == (user is None):
        raise RuntimeError("give a stored scope or a person")
    out = []
    for pk in sorted(AGENT_ROWS if pks is None else pks):
        row = AGENT_ROWS.get(pk)
        if row is None:
            continue
        if snapshot is not None:
            scope = snapshot["scope"]
            inside = scope["unrestricted"] or row["client_id"] in scope["whole_client_ids"] or row["site_id"] in scope["site_ids"]
        else:
            descriptor = _role_scope_descriptor(user)
            inside = descriptor["unrestricted"] or row["client_id"] in descriptor["whole_client_ids"] or row["site_id"] in descriptor["site_ids"]
        if inside:
            out.append({"pk": pk, **row})
    return out[: limit + 1]


mod("tec_tac.resources_adapter", agent_pks_in_role_scope=_agents_in_role_scope, agent_pks_for_scheduler_targets=_agent_pks_for_scheduler_targets,
    role_scope_descriptor=_role_scope_descriptor, agent_rows_in_scope=_agent_rows_in_scope, agent_pks_for_identifiers=lambda *, identifiers: {int(i) for i in identifiers})

# ---- the stub server-maintenance job store (the real file is read by the source-pin tests)
JOBS: dict = {}


class ServerMaintenanceNotFound(Exception):
    pass


class ServerMaintenanceError(Exception):
    pass


JOB_FAULT = {"unreadable": False}


def _read_job(job_id):
    if JOB_FAULT["unreadable"]:
        raise ServerMaintenanceError("state unreadable")
    try:
        return JOBS[str(job_id)]
    except KeyError:
        raise ServerMaintenanceNotFound("not found") from None


sm_stub = mod("tec_tac.server_maintenance", _read_job=_read_job, ServerMaintenanceNotFound=ServerMaintenanceNotFound,
              ServerMaintenanceError=ServerMaintenanceError, TERMINAL_STATES=frozenset({"succeeded", "failed", "cancelled", "dispatch_failed"}))
pkg.server_maintenance = sm_stub

# ---- the stub Tactical task functions (winupdate.tasks), recorded like Celery's .delay
TASK_CALLS: list = []
DELAY_FAIL = {"raise": False}


class FakeTacticalTask:
    def __init__(self, name):
        self.name = name

    def __call__(self, *args, **kwargs):  # a Celery task is callable in-process as well as through .delay
        return None

    def delay(self, *args, **kwargs):
        if DELAY_FAIL["raise"]:
            raise RuntimeError("broker unreachable")
        TASK_CALLS.append((self.name, args, kwargs))
        return SimpleNamespace(id=f"celery-{self.name}-{len(TASK_CALLS)}")


def install_winupdate_stub(scan=True, install=True):
    attrs = {}
    if scan:
        attrs["bulk_check_for_updates_task"] = FakeTacticalTask("scan")
    if install:
        attrs["bulk_install_updates_task"] = FakeTacticalTask("install")
    mod("winupdate")
    sys.modules["winupdate"].__path__ = []
    mod("winupdate.tasks", **attrs)


install_winupdate_stub()


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, APP / file)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    setattr(pkg, name.split(".")[-1], m)
    return m


load("tec_tac.scheduler_targets", "scheduler_targets.py")
load("tec_tac.scheduler_timing", "scheduler_timing.py")
rc = load("tec_tac.scheduler_run_context", "scheduler_run_context.py")
ci = load("tec_tac.caller_identity", "caller_identity.py")
completion = load("tec_tac.scheduler_completion", "scheduler_completion.py")
sched = load("tec_tac.scheduler", "scheduler.py")
sched._zone = lambda value: None
tasks = load("tec_tac.tasks_real", "tasks.py")
sa = load("tec_tac.system_actions", "system_actions.py")
resolvers = load("tec_tac.scheduler_target_resolvers", "scheduler_target_resolvers.py")
creation_scope = sys.modules["tec_tac.scheduler_creation_scope"]

# ---- owners: the database users the run context re-reads
USERS: dict = {}


class User:
    def __init__(self, username, *, active=True, installer=False):
        self.pk = len(USERS) + 100
        self.username, self.is_active, self.is_installer_user, self.is_authenticated = username, active, installer, True
        USERS[self.pk] = self


rc._reload_user = lambda pk: USERS.get(pk)
rc._check_flag = lambda flag: _validate_tactical_flag(flag)
rc._user_has_flag = lambda user, flag: flag in FLAGS.get(user.username, set())


def compile_as(filename, source, **names):
    ns: dict = {"__name__": "probe", **names}
    exec(compile(source, str(filename), "exec"), ns)  # noqa: S102 - test-only stand-ins compiled under a chosen code file name
    return ns


# ---- running a run through the REAL worker task
class Retry(Exception):
    pass


class Task:
    def __init__(self, retries=0):
        self.request = SimpleNamespace(retries=retries)
        self.retry_args = None

    def retry(self, *, exc, countdown, max_retries):
        self.retry_args = (countdown, max_retries)
        return Retry()


def go(run, retries=0):
    """Run ``run`` through the real ``execute_schedule_run``. Returns what it returned, or the exception it raised."""
    task = Task(retries)
    try:
        return tasks.execute_schedule_run(task, str(run.id))
    except Retry:
        return "retried"
    except Exception as exc:  # the worker re-raises a failure after recording it
        return exc


AUTO_TARGETS = None  # 1.17.62: a test may set a function that returns the targets snapshot of every run make_run builds


def make_run(action_id, module_id, *, user=None, owner="one-off", retries=0, status="queued", targets=None, manual=False):
    """A queued run on a fresh schedule. ``owner`` is ``one-off`` (a module's one-off run for ``user``), ``user`` or ``module`` (no person). ``manual`` (1.17.65) makes it a person-started run, which keeps the owner re-check."""
    if owner == "one-off":
        sched_kw = dict(owner_type="module", owner_module=module_id, owner_key=f"one-off:{uuid.uuid4()}", created_by=user, enabled=False)
    elif owner == "user":
        sched_kw = dict(owner_type="user", created_by=user, enabled=True)
    else:
        sched_kw = dict(owner_type="module", owner_module=module_id, owner_key="recurring", created_by=None, enabled=True)
    schedule = Schedule.objects.create(name="s", module_id=module_id, action_id=action_id, **sched_kw)
    return Run.objects.create(
        schedule=schedule, schedule_snapshot_id=schedule.id, schedule_name="s", module_id=module_id, action_id=action_id, owner_type=schedule.owner_type, manual=manual,
        owner_module=schedule.owner_module, owner_key=schedule.owner_key, status=status, scheduled_for=NOW[0], retry_count_snapshot=retries,
        last_queued_at=NOW[0], started_at=NOW[0] if status == "running" else None,
        targets_snapshot=targets if targets is not None else (AUTO_TARGETS() if AUTO_TARGETS is not None else {}),
    )


def reset():
    del Schedule.objects.rows[:], Run.objects.rows[:], AUDITS[:], TASK_CALLS[:], SCOPE_CALLS[:], SAVES[:], QUEUED_IDS[:], TARGET_CALLS[:]
    del Grant.objects.rows[:], ROW_CALLS[:]
    RESOLVED_MODULE_TARGETS.clear()
    AGENT_ROWS.clear()
    DESCRIPTORS.clear()
    resolvers._clear_for_tests()
    global EXISTING_AGENTS
    EXISTING_AGENTS = None
    CLIENT_AGENTS.clear()
    SITE_AGENTS.clear()
    AUDIT_FAIL.update(strict=False, all=False)
    AUTH["deny"] = False
    DELAY_FAIL["raise"] = False
    JOBS.clear()
    JOB_FAULT["unreadable"] = False
    STATE_FAULT["registry"] = False
    completion._REFUSALS.clear()
    sa._UNMATCHED.clear()
    install_winupdate_stub()
    NOW[0] = datetime(2026, 10, 20, 12, 0, tzinfo=dt_timezone.utc)
