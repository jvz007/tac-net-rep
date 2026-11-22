#!/usr/bin/env python3
# ruff: noqa: E402
"""1.18.44 regression: core.result_checks 1.0.0 (B2): reader registration, start, run_check, the tick step, retention and the read route.

No Django, no Celery, no database, no network. The REAL tec_tac/result_checks.py, result_check_views.py and caller_identity.py run against an
in-memory mini ORM and stubs. Module code is compiled under a temporary extensions folder, so the real frame walk decides who is calling.
"""
from __future__ import annotations

import ast
import importlib.util
import logging
import sys
import tempfile
import types
import uuid
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from types import SimpleNamespace

import os
if not os.environ.get("RC_DEBUG"):
    logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
NOW = [datetime(2026, 11, 22, 12, 0, tzinfo=dt_timezone.utc)]
COUNTER = [0]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def raises(exc, fn, *a, **k):
    try:
        fn(*a, **k)
    except exc as error:
        return error
    raise AssertionError(f"{exc.__name__} not raised")


# ------------------------------------------------------------------------------------------------ a mini ORM
def _lookup(row, key):
    parts = key.split("__")
    ops = {"in", "lt", "lte", "gt", "gte", "isnull"}
    op = parts.pop() if len(parts) > 1 and parts[-1] in ops else "exact"
    value = row
    for part in parts:
        value = getattr(value, part, None)
        if value is None:
            break
    return value, op


def _match(row, spec):
    for key, expected in spec.items():
        value, op = _lookup(row, key)
        if op == "in":
            ok = value in expected
        elif op == "lt":
            ok = value is not None and value < expected
        elif op == "lte":
            ok = value is not None and value <= expected
        elif op == "isnull":
            ok = (value is None) == expected
        else:
            ok = value == expected or (key in ("pk", "result_check_id") and str(value) == str(expected))  # Django accepts a text uuid
        if not ok:
            return False
    return True


class Query(list):
    model = None

    def filter(self, **kw):
        return self._new(r for r in self if _match(r, kw))

    def _new(self, rows):
        out = Query(rows)
        out.model = self.model
        return out

    def select_for_update(self):
        return self

    def order_by(self, *fields):
        def key(r):
            return tuple((v is None, v if v is not None else 0) for v in (getattr(r, f, None) for f in fields))
        return self._new(sorted(self, key=key))

    def values_list(self, field, flat=False):
        return [getattr(r, field) for r in self]

    def first(self):
        return self[0] if self else None

    def count(self):
        return len(self)

    def exists(self):
        return bool(self)

    def update(self, **kw):
        for row in self:
            for k, v in kw.items():
                setattr(row, k, v)
        return len(self)

    def delete(self):
        for row in list(self):
            row.delete()

    def __getitem__(self, item):
        result = list.__getitem__(self, item)
        return self._new(result) if isinstance(item, slice) else result


class Manager:
    def __init__(self, model):
        self.model, self.rows = model, []

    def _q(self):
        q = Query(self.rows)
        q.model = self.model
        return q

    def filter(self, **kw):
        return self._q().filter(**kw)

    def select_for_update(self):
        return self._q()

    def create(self, **kw):
        row = self.model(**kw)
        self.rows.append(row)
        return row

    def bulk_create(self, rows, batch_size=None):
        self.rows.extend(rows)
        return rows

    def bulk_update(self, rows, fields, batch_size=None):
        for name in fields:
            must(name in self.model.fields, f"bulk_update names an unknown field {name!r}")
        return len(rows)


class Base:
    fields: dict = {}

    def __init_subclass__(cls, **kw):
        cls.objects = Manager(cls)

    def __init__(self, **kw):
        COUNTER[0] += 1
        self.pk = self.id = uuid.uuid4()
        self.__dict__.update({k: (dict(v) if isinstance(v, dict) else v) for k, v in self.fields.items()})
        self.__dict__.update(kw)
        if "user" in kw:
            self.user_id = kw["user"].pk
        self.created_at = NOW[0]


class Check(Base):
    fields = dict(module_id="", reader_id="", label="", job_ref={}, status="open", next_check_at=None, deadline_at=None, closed_at=None,
                  queued_until=None, running_until=None, notice_sent=False, user=None, user_id=None)

    def delete(self):
        Check.objects.rows.remove(self)
        for item in [i for i in Item.objects.rows if i.result_check_id == self.pk]:
            Item.objects.rows.remove(item)


class Item(Base):
    fields = dict(result_check_id=None, endpoint_id="", hostname="", state="running", exit_code=None, checked_at=None)

    def __init__(self, **kw):
        super().__init__(**kw)
        self.pk = self.id = COUNTER[0]  # a BigAutoField: insertion order


class User:
    objects = None

    def __init__(self, username, *, active=True, installer=False, agent=None, blocked=False):
        self.pk = len(UserManager.rows) + 100
        self.username, self.is_active, self.is_installer_user, self.agent, self.block_dashboard_login = username, active, installer, agent, blocked
        self.is_superuser = False
        UserManager.rows.append(self)


class _UserManager(Manager):
    pass


UserManager = _UserManager(User)
User.objects = UserManager


def reset():
    Check.objects.rows.clear()
    Item.objects.rows.clear()
    UserManager.rows.clear()
    AUDITS.clear()
    NOTICES.clear()
    SENT.clear()
    SEEN_CLEAR()
    BROKER["down"] = False
    NOTICE_FAIL["on"] = False
    ENABLED.clear()
    rc._READERS.clear()
    READER.update(answer=None, calls=[], raises=False)
    NOW[0] = datetime(2026, 11, 22, 12, 0, tzinfo=dt_timezone.utc)


def SEEN_CLEAR():
    rc._SEEN.clear()


# ------------------------------------------------------------------------------------------------ stubs
def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


AUDITS: list = []
NOTICES: list = []
SENT: list = []
BROKER = {"down": False}
NOTICE_FAIL = {"on": False}
ENABLED: dict = {}
PLUGINS: dict = {}
TMP = Path(tempfile.mkdtemp(prefix="tectac-resultchecks-"))
EXT = TMP / "extensions"
EXT.mkdir()

mod("django")
django_db = mod("django.db", transaction=SimpleNamespace(atomic=lambda *a, **k: nullcontext()))
django_utils = mod("django.utils")
django_tz = mod("django.utils.timezone", now=lambda: NOW[0])
django_utils.timezone = django_tz
django_contrib = mod("django.contrib")
django_auth = mod("django.contrib.auth", get_user_model=lambda: User)
django_contrib.auth = django_auth
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.models", TecTacResultCheck=Check, TecTacResultCheckItem=Item)
mod("tec_tac.registry", discover_plugins=lambda: tuple(PLUGINS.values()))
mod("tec_tac.module_state", load_state=lambda: {"schema": 1, "modules": {}}, is_enabled=lambda module_id, state=None: ENABLED.get(module_id, True))
mod("tec_tac.audit", record=lambda **kw: AUDITS.append(kw) or {"recorded": True}, service_audit_actor=lambda **kw: SimpleNamespace(**kw))


def publish_system_notice(recipients, **kw):
    if NOTICE_FAIL["on"]:
        raise RuntimeError("notice store down")
    NOTICES.append({"recipients": list(recipients), **kw})
    return len(list(recipients))


mod("tec_tac.notices", publish_system_notice=publish_system_notice)


class FakeApp:
    @contextmanager
    def connection_for_write(self, transport_options=None, connect_timeout=None):
        must(transport_options and transport_options["socket_timeout"] == connect_timeout, "one bounded broker attempt")
        yield "broker"


class FakeTask:
    app = FakeApp()

    def apply_async(self, *, args, connection, retry, expires, ignore_result, soft_time_limit, time_limit):
        must(connection == "broker" and retry is False and ignore_result is True and soft_time_limit == 100 and time_limit == 120, "task options")
        if BROKER["down"]:
            raise OSError("broker down")
        SENT.append(args[0])


mod("tec_tac.tasks", run_result_check=FakeTask())
CAPS: list = []
mod("tec_tac.capabilities", register_capability=lambda **kw: CAPS.append(kw) or kw)


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, APP / file)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    setattr(pkg, name.split(".")[-1], m)
    return m


ci = load("tec_tac.caller_identity", "caller_identity.py")
rc = load("tec_tac.result_checks", "result_checks.py")

# DRF and spectacular stand-ins for the view
class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


class APIView:
    pass


mod("rest_framework")
mod("rest_framework.response", Response=Response)
mod("rest_framework.views", APIView=APIView)
mod("drf_spectacular")
mod("drf_spectacular.utils", extend_schema=lambda **k: (lambda f: f), extend_schema_view=lambda **k: (lambda f: f))
mod("tec_tac.session_security", SessionAuthenticated=object)
views = load("tec_tac.result_check_views", "result_check_views.py")


def plugin(plugin_id, *, enabled=True, legacy=False):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version="1.0.0", legacy=legacy)
    ENABLED[plugin_id] = enabled
    return root


def compile_as(filename, source, **names):
    ns: dict = {"__name__": "probe", **names}
    exec(compile(source, str(filename), "exec"), ns)  # noqa: S102 - test-only module code compiled under a chosen file name
    return ns


READER = {"answer": None, "calls": [], "raises": False}


def _read(job_ref, ids, user):
    READER["calls"].append((job_ref, list(ids), user))
    if READER["raises"]:
        raise RuntimeError("reader down")
    answer = READER["answer"]
    return answer(job_ref, ids, user) if callable(answer) else answer


MODULE_SOURCE = """
def reader(job_ref, ids, user):
    return READ(job_ref, ids, user)

def other_reader(job_ref, ids, user):
    return {}

def do_register(**kw):
    return rc.register_result(**kw)

def do_start(user, **kw):
    return rc.start(user, **kw)
"""


def module_code(module_id):
    plugin(module_id)
    ns = compile_as(EXT / module_id / "ready.py", MODULE_SOURCE.replace("register_result", "register_reader"), rc=rc, READ=_read)
    return ns


SE = module_code("scriptexecution")
OTHER = module_code("othermodule")
READER_ID = "scriptexecution.bulk-script"


def register(ns=None, **kw):
    ns = ns or SE
    args = dict(id=READER_ID, module_id="scriptexecution", reader=ns["reader"])
    args.update(kw)
    return ns["do_register"](**args)


def start(user, ns=None, **kw):
    ns = ns or SE
    args = dict(reader_id=READER_ID, label="Run script", endpoint_ids=["a1", "a2", "a3"], job_ref={"script": 7}, deadline_seconds=600)
    args.update(kw)
    return ns["do_start"](user, **args)


def new_user(name="tech"):
    return User(name)


def check_row(check_id):
    return next(r for r in Check.objects.rows if str(r.pk) == str(check_id))


def items_of(check_id):
    return {i.endpoint_id: i for i in Item.objects.rows if str(i.result_check_id) == str(check_id)}


def fresh(name="tech"):
    reset()
    plugin("scriptexecution")
    plugin("othermodule")
    user = new_user(name)
    register()
    return user


# ================================================================================ registration
reset()
plugin("scriptexecution")
plugin("othermodule")
must(register() == READER_ID, "a reader registers")
must(register() == READER_ID, "the identical definition again is fine")
error = raises(rc.ResultCheckRegistrationError, register, ns=SE, reader=SE["other_reader"])
must(isinstance(error, ValueError), "a different definition is refused with a ValueError")
must(rc._READERS[READER_ID].reader is SE["reader"], "the first definition stays")
raises(rc.ResultCheckRegistrationError, register, ns=OTHER, id="scriptexecution.x", module_id="scriptexecution", reader=OTHER["reader"])  # code outside the module's folder
raises(rc.ResultCheckRegistrationError, register, id="scriptexecution.x", module_id="othermodule")  # id does not start with the module id
raises(rc.ResultCheckRegistrationError, register, id="bad id", module_id="scriptexecution")
raises(rc.ResultCheckRegistrationError, register, id="scriptexecution.y", reader="not callable")
raises(rc.ResultCheckRegistrationError, register, id="ghost.y", module_id="ghost")  # not installed
ENABLED["scriptexecution"] = False
raises(rc.ResultCheckRegistrationError, register, id="scriptexecution.z")  # disabled
ENABLED["scriptexecution"] = True
plugin("legacymod", legacy=True)
legacy_ns = compile_as(EXT / "legacymod" / "r.py", "def reader(a, b, c):\n    return {}\n")
raises(rc.ResultCheckRegistrationError, register, ns=SE, id="legacymod.q", module_id="legacymod", reader=legacy_ns["reader"])
raises(rc.ResultCheckRegistrationError, register, id="scriptexecution.w", reader=lambda a, b, c: {})  # defined in this test file, not in the module
generated = compile_as("<string>", "def reader(a, b, c):\n    return {}\n")
raises(rc.ResultCheckRegistrationError, register, id="scriptexecution.v", reader=generated["reader"])
must(sorted(rc._READERS) == [READER_ID], "refused readers are not stored")

# ================================================================================ start: caller rule
user = fresh()
check_id = start(user)
must(isinstance(check_id, str) and uuid.UUID(check_id), "start by the owning module returns a check id")
row = check_row(check_id)
must(row.user is user and row.module_id == "scriptexecution" and row.reader_id == READER_ID and row.label == "Run script" and row.status == "open", "row stored")
must(row.next_check_at == NOW[0] + timedelta(seconds=60) and row.deadline_at == NOW[0] + timedelta(seconds=600), "first check in 60 s, deadline as asked")
must(sorted(items_of(check_id)) == ["a1", "a2", "a3"] and all(i.state == "running" and i.exit_code is None for i in items_of(check_id).values()), "items start running")

user = fresh()
OTHER_ERR = raises(rc.ResultCheckRefused, start, user, ns=OTHER)
must(OTHER_ERR.code == "not_owner" and "othermodule" not in str(OTHER_ERR) and "scriptexecution" not in str(OTHER_ERR), "another module is refused, the text names no module")
must(not Check.objects.rows, "nothing stored on a refusal")
core_ns = compile_as(APP / "some_core_file.py", MODULE_SOURCE.replace("register_result", "register_reader"), rc=rc, READ=_read)
must(raises(rc.ResultCheckRefused, start, user, ns=core_ns).code == "caller", "Core is refused")
must(raises(rc.ResultCheckRefused, rc.start, user, reader_id=READER_ID, label="x", endpoint_ids=["a"], job_ref={}, deadline_seconds=60).code == "caller", "an unverified caller (this file) is refused")
generated_ns = compile_as("<string>", MODULE_SOURCE.replace("register_result", "register_reader"), rc=rc, READ=_read)
must(raises(rc.ResultCheckRefused, start, user, ns=generated_ns).code == "caller", "generated code is refused")
ENABLED["scriptexecution"] = False
must(raises(rc.ResultCheckRefused, start, user).code == "caller", "a disabled module is refused")
ENABLED["scriptexecution"] = True
must(raises(rc.ResultCheckRefused, start, user, reader_id="scriptexecution.unknown").code == "unknown_reader", "an unknown reader is refused")
must(not Check.objects.rows, "still nothing stored")
# the audit row of a wrong caller: at most one per module and reason per 5 minutes, reason code only
refused = [a for a in AUDITS if a["action"] == "custom:result-check-refused"]
must(len(refused) == 3, f"one audit row per module and reason, not per call: {len(refused)}")
must(all(set(a["metadata"]) == {"requested_by", "reason"} for a in refused), "reason code only")
before = len(AUDITS)
raises(rc.ResultCheckRefused, start, user, ns=OTHER)
must(len(AUDITS) == before, "the same refusal inside 5 minutes writes no second row")
rc._SEEN.clear()
raises(rc.ResultCheckRefused, start, user, ns=OTHER)
must(len(AUDITS) == before + 1, "after the window a row is written again")

# ================================================================================ start: validation
user = fresh()


def invalid(**kw):
    raises(rc.ResultCheckInvalid, start, user, **kw)


for bad in ("", "   ", "x" * 81, "a\nb", "a\x00b", 5, None):
    invalid(label=bad)
must(start(user, label="x" * 80), "an 80 character label is fine")
invalid(endpoint_ids=[])
invalid(endpoint_ids=["a%d" % i for i in range(1001)])
must(start(user, endpoint_ids=["a%d" % i for i in range(1000)]), "1000 endpoints are fine")
invalid(endpoint_ids=["a", "a"])
invalid(endpoint_ids=["a", ""])
invalid(endpoint_ids=["a", 5])
invalid(endpoint_ids=["x" * 201])
invalid(endpoint_ids="abc")
must(start(user, endpoint_ids=["x" * 200]), "a 200 character id is fine")
invalid(job_ref=[1])
invalid(job_ref="x")
invalid(job_ref={"a": "x" * 2100})
invalid(job_ref={"a": object()})
must(start(user, job_ref={"a": "x" * 2000}), "a job_ref under 2 KiB is fine")
for bad in (59, 86401, True, "600", 60.0, None, 0):
    invalid(deadline_seconds=bad)
must(start(user, deadline_seconds=60) and start(user, deadline_seconds=86400), "the limits themselves are fine")
must(len(Check.objects.rows) == 6, "only valid starts stored: %d" % len(Check.objects.rows))

reset()
plugin("scriptexecution")
register()
for kind in (dict(active=False), dict(installer=True), dict(agent=object()), dict(blocked=True)):
    person = User("p%d" % len(UserManager.rows), **{("active" if k == "active" else k): v for k, v in kind.items()})
    if "active" in kind:
        person.is_active = False
    must(raises(rc.ResultCheckRefused, start, person).code == "user", f"{kind} is refused")
must(not Check.objects.rows, "no check for a refused person")

user = fresh()
for i in range(20):
    start(user)
must(raises(rc.ResultCheckRefused, start, user).code == "too_many_open", "the 21st open check is refused")
must(len(Check.objects.rows) == 20, "cap holds")
other_person = new_user("other")
must(start(other_person), "the cap is per person")
check_row(Check.objects.rows[0].pk).status = "closed"
must(start(user), "a closed check frees a place")
source = (APP / "result_checks.py").read_text(encoding="utf-8")
must("select_for_update()" in source and "transaction.atomic()" in source and source.index("select_for_update()") < source.index("MAX_OPEN_PER_USER:"), "the cap is counted under a row lock inside a transaction")


# ================================================================================ run_check
def answer_for(states):
    return lambda job_ref, ids, user: {i: {"state": states.get(i, "running"), "exit_code": 0 if states.get(i) == "done" else (1 if states.get(i) == "failed" else None), "hostname": "H-" + i} for i in ids}


user = fresh()
READER["answer"] = answer_for({"a1": "done", "a2": "failed", "a3": "offline"})
cid = start(user)
NOW[0] += timedelta(seconds=60)
must(rc.run_check(cid) == "closed", "all terminal: closed")
must(len(READER["calls"]) == 1, "the reader is called once")
job_ref, ids, who = READER["calls"][0]
must(who is user and job_ref == {"script": 7} and ids == ["a1", "a2", "a3"], "called as the starter with a copy of job_ref")
must(job_ref is not check_row(cid).job_ref, "job_ref is a copy")
row = check_row(cid)
must(row.status == "closed" and row.closed_at == NOW[0] and row.notice_sent is True and row.running_until is None, "closed row")
st = items_of(cid)
must((st["a1"].state, st["a1"].exit_code, st["a1"].hostname) == ("done", 0, "H-a1") and st["a2"].state == "failed" and st["a2"].exit_code == 1 and st["a3"].state == "offline", "items updated")
must(len(NOTICES) == 1, "exactly one notice")
notice = NOTICES[0]
must(notice["recipients"] == [user] and notice["client_id"] == f"result-check:{cid}" and notice["source"] == "core" and notice["title"] == "", "recipient, key, source")
must(notice["message"] == "Run script: 1 done, 1 failed, 1 offline" and notice["level"] == "warning", notice["message"])
must(notice["action_label"] == "See results" and notice["action_route"] == f"/results/{cid}" and notice["action_route"].startswith("/"), "route")
closed_audit = [a for a in AUDITS if a["action"] == "custom:result-check-closed"]
must(len(closed_audit) == 1 and closed_audit[0]["object_id"] == cid, "one closed audit row")
must(all(h not in repr(closed_audit[0]["metadata"]) for h in ("H-a1", "'a1'", "'a2'")), "no hostnames or endpoint ids in the audit row")
must(closed_audit[0]["metadata"]["done"] == 1 and closed_audit[0]["metadata"]["failed"] == 1 and closed_audit[0]["metadata"]["offline"] == 1, "counts in the audit row")
must(rc.run_check(cid) == "skipped" and len(NOTICES) == 1 and len(READER["calls"]) == 1, "a closed check is never run or notified twice")

# everything done: success level
user = fresh()
READER["answer"] = answer_for({"a1": "done", "a2": "done", "a3": "done"})
cid = start(user)
rc.run_check(cid)
must(NOTICES[0]["level"] == "success" and NOTICES[0]["message"] == "Run script: 3 done, 0 failed, 0 offline", "success level when all are done")

# still running keeps the check open and sets the next check in 60 seconds
user = fresh()
READER["answer"] = answer_for({"a1": "done"})
cid = start(user)
NOW[0] += timedelta(seconds=60)
must(rc.run_check(cid) == "open", "open while something runs")
row = check_row(cid)
must(row.status == "open" and row.next_check_at == NOW[0] + timedelta(seconds=60) and row.running_until is None and row.queued_until is None, "rescheduled, leases cleared")
must(not NOTICES, "no notice while open")
must(items_of(cid)["a1"].state == "done" and items_of(cid)["a2"].state == "running", "partial results kept")
READER["calls"].clear()
NOW[0] += timedelta(seconds=60)
READER["answer"] = answer_for({"a1": "done", "a2": "done", "a3": "failed"})
rc.run_check(cid)
must(READER["calls"][0][1] == ["a2", "a3"], "only the running ones are asked again")
must(len(NOTICES) == 1 and check_row(cid).status == "closed", "closes when nothing runs")

# deadline: still running becomes no_result, with the extra clause
user = fresh()
READER["answer"] = answer_for({"a1": "done"})
cid = start(user, deadline_seconds=120)
NOW[0] += timedelta(seconds=120)
must(rc.run_check(cid) == "closed", "closed at the deadline")
must({k: v.state for k, v in items_of(cid).items()} == {"a1": "done", "a2": "no_result", "a3": "no_result"}, "running items become no_result")
must(NOTICES[0]["message"] == "Run script: 1 done, 0 failed, 0 offline, 2 no result" and NOTICES[0]["level"] == "warning", NOTICES[0]["message"])

# a gone reader still closes at the deadline
user = fresh()
cid = start(user, deadline_seconds=120)
rc._READERS.clear()
NOW[0] += timedelta(seconds=60)
must(rc.run_check(cid) == "open" and not NOTICES and not READER["calls"], "a missing reader leaves items running")
NOW[0] += timedelta(seconds=61)
must(rc.run_check(cid) == "closed" and all(i.state == "no_result" for i in items_of(cid).values()), "and the check still closes at its deadline")
user = fresh()
cid = start(user, deadline_seconds=300)
ENABLED["scriptexecution"] = False
NOW[0] += timedelta(seconds=60)
must(rc.run_check(cid) == "open" and not READER["calls"], "a disabled module's reader is not called")
ENABLED["scriptexecution"] = True

# strict handling of a bad reader answer
user = fresh()
cid = start(user, endpoint_ids=["a1", "a2", "a3", "a4", "a5", "a6"])
READER["answer"] = lambda j, ids, u: {
    "a1": {"state": "finished", "exit_code": 0, "hostname": "x"},          # unknown state
    "a2": {"state": "done", "exit_code": "0", "hostname": "x"},            # exit code not an int
    "a3": {"state": "done", "exit_code": True, "hostname": "x"},           # a bool is not an int
    "a4": {"state": "done", "exit_code": 0, "hostname": 5},                # hostname not text
    "a5": "done",                                                          # not a dict
    "zzz": {"state": "done", "exit_code": 0, "hostname": "unknown id"},    # unknown id ignored
}
NOW[0] += timedelta(seconds=60)
must(rc.run_check(cid) == "open", "bad entries leave the check open")
must(all(i.state == "running" for i in items_of(cid).values()) and "zzz" not in items_of(cid), "bad entries and unknown ids change nothing")
for answer in (None, [], "text", 5):
    READER["answer"] = answer
    NOW[0] += timedelta(seconds=60)
    must(rc.run_check(cid) == "open" and all(i.state == "running" for i in items_of(cid).values()), f"answer {answer!r} leaves all running")
READER["answer"] = None
READER["raises"] = True
NOW[0] += timedelta(seconds=60)
must(rc.run_check(cid) == "open" and all(i.state == "running" for i in items_of(cid).values()), "a raising reader leaves items running")
must(check_row(cid).running_until is None and check_row(cid).next_check_at == NOW[0] + timedelta(seconds=60), "retries next minute")
READER["raises"] = False
READER["answer"] = lambda j, ids, u: {"a1": {"state": "done", "exit_code": 2 ** 40, "hostname": "x"}, "a2": {"state": "done"}}
NOW[0] += timedelta(seconds=60)
rc.run_check(cid)
must(items_of(cid)["a1"].state == "running" and items_of(cid)["a2"].state == "done" and items_of(cid)["a2"].exit_code is None, "an exit code beyond the column and a missing exit code")
READER["answer"] = lambda j, ids, u: {i: {"state": "done", "exit_code": None, "hostname": "h\x00ost\n" + "x" * 400} for i in ids}
NOW[0] += timedelta(seconds=60)
rc.run_check(cid)
must(len(items_of(cid)["a3"].hostname) == 255 and items_of(cid)["a3"].hostname.startswith("host"), "hostname cleaned and cut to 255")

# 1000 endpoints rotate: at most 500 asked, never-checked first, then the longest ago
user = fresh()
ids1000 = ["e%04d" % i for i in range(1000)]
cid = start(user, endpoint_ids=ids1000)
asked: list = []
READER["answer"] = lambda j, ids, u: (asked.append(list(ids)), {i: {"state": "running"} for i in ids})[1]
for _ in range(4):
    NOW[0] += timedelta(seconds=60)
    rc.run_check(cid)
must(all(len(a) == 500 for a in asked), "at most 500 ids a call")
must(set(asked[0]) | set(asked[1]) == set(ids1000) and not set(asked[0]) & set(asked[1]), "the second call asks the 500 never checked: none starves")
must(set(asked[2]) == set(asked[0]) and set(asked[3]) == set(asked[1]), "then the ones checked longest ago come first")

# inactive or blocked starter: closes silently with one audit row, reader never called
for change in ("inactive", "blocked", "installer"):
    user = fresh()
    READER["answer"] = answer_for({"a1": "done"})
    cid = start(user)
    {"inactive": lambda: setattr(user, "is_active", False), "blocked": lambda: setattr(user, "block_dashboard_login", True), "installer": lambda: setattr(user, "is_installer_user", True)}[change]()
    NOW[0] += timedelta(seconds=60)
    must(rc.run_check(cid) == "closed" and not NOTICES and not READER["calls"], f"{change} starter: closed, no notice, no reader call")
    must(len([a for a in AUDITS if a["action"] == "custom:result-check-closed"]) == 1, "one audit row")
    must(all(i.state == "no_result" for i in items_of(cid).values()), "items end no_result")

# a notice that cannot be stored does not stop the close and is never repeated
user = fresh()
READER["answer"] = answer_for({"a1": "done", "a2": "done", "a3": "done"})
NOTICE_FAIL["on"] = True
cid = start(user)
must(rc.run_check(cid) == "closed" and check_row(cid).status == "closed" and check_row(cid).notice_sent is False, "closed even when the notice store is down")
NOTICE_FAIL["on"] = False
must(rc.run_check(cid) == "skipped" and not NOTICES, "and a closed check is not run again")

# a duplicate delivery runs nothing twice: the lease is the claim
user = fresh()
READER["answer"] = answer_for({})
cid = start(user)
calls_at: list = []


def reentrant(job_ref, ids, who):
    calls_at.append(rc.run_check(cid, now=NOW[0]))  # a second delivery arrives while the first one is running the reader
    return {}


READER["answer"] = reentrant
NOW[0] += timedelta(seconds=60)
rc.run_check(cid)
must(calls_at == ["skipped"] and len(READER["calls"]) == 1, "the duplicate found the lease live and did nothing")
row = check_row(cid)
row.running_until = NOW[0] + timedelta(seconds=100)
READER["calls"].clear()
must(rc.run_check(cid) == "skipped" and not READER["calls"], "a live lease blocks a run")
row.running_until = NOW[0] - timedelta(seconds=1)
READER["answer"] = answer_for({})
must(rc.run_check(cid) == "open" and len(READER["calls"]) == 1, "a lapsed lease is claimed again (a task that died)")

# ================================================================================ queue_due_checks
user = fresh()
cids = [start(user, label="c%d" % i) if i < 20 else start(new_user("p%d" % i), label="c%d" % i) for i in range(25)]
NOW[0] += timedelta(seconds=61)
must(rc.queue_due_checks() == 20 and len(SENT) == 20, "at most 20 of 25 due checks are queued")
must(all(check_row(c).queued_until == NOW[0] + timedelta(seconds=300) for c in SENT), "each queued check holds a 5 minute lease")
SENT_FIRST = list(SENT)
SENT.clear()
must(rc.queue_due_checks() == 5 and len(SENT) == 5 and not set(SENT) & set(SENT_FIRST), "the next tick queues only the rest: live leases are skipped")
SENT.clear()
must(rc.queue_due_checks() == 0 and not SENT, "everything leased: nothing queued")
NOW[0] += timedelta(seconds=301)
must(rc.queue_due_checks() == 20, "after the lease lapses the checks are queued again")
SENT.clear()
for c in cids:
    check_row(c).queued_until = None
BROKER["down"] = True
must(rc.queue_due_checks() == 0 and not SENT, "a raising broker queues nothing and never raises")
must(all(check_row(c).queued_until is None for c in cids), "the lease is cleared when the broker raises, so the next tick retries")
BROKER["down"] = False
must(rc.queue_due_checks() == 20, "retried when the broker is back")
# not yet due and closed checks are not queued
reset()
plugin("scriptexecution")
register()
user = new_user()
cid = start(user)
must(rc.queue_due_checks() == 0, "a check that is not due yet is not queued")
NOW[0] += timedelta(seconds=61)
check_row(cid).status = "closed"
must(rc.queue_due_checks() == 0, "a closed check is not queued")
# never raises on a database fault
broken = Check.objects.filter
Check.objects.filter = lambda **kw: (_ for _ in ()).throw(RuntimeError("db down"))
must(rc.queue_due_checks() == 0, "never raises")
Check.objects.filter = broken

# retention
reset()
plugin("scriptexecution")
register()
user = new_user()
old, young, still_open = (check_row(start(user)) for _ in range(3))
for r in (old, young):
    r.status = "closed"
old.closed_at = NOW[0] - timedelta(days=31)
young.closed_at = NOW[0] - timedelta(days=29)
still_open.created_at = NOW[0] - timedelta(days=90)
rc.queue_due_checks()
remaining = {r.pk for r in Check.objects.rows}
must(old.pk not in remaining and young.pk in remaining and still_open.pk in remaining, "a 31-day-old closed check goes, a 29-day-old one and an open one stay")
must(not [i for i in Item.objects.rows if i.result_check_id == old.pk] and [i for i in Item.objects.rows if i.result_check_id == young.pk], "items go with the check")
reset()
plugin("scriptexecution")
register()
for i in range(250):
    c = Check(user=new_user("u%d" % i), status="closed", closed_at=NOW[0] - timedelta(days=40), next_check_at=NOW[0], deadline_at=NOW[0])
    Check.objects.rows.append(c)
rc.queue_due_checks()
must(len(Check.objects.rows) == 50, f"at most 200 deleted a tick: {len(Check.objects.rows)}")

# the task wrapper and the tick step, by source
tasks_source = (APP / "tasks.py").read_text(encoding="utf-8")
must('name="tec_tac.run_result_check"' in tasks_source and "acks_late=True" in tasks_source and "ignore_result=True" in tasks_source
     and "soft_time_limit=100" in tasks_source and "time_limit=120" in tasks_source, "the task is declared with its limits")
body = tasks_source[tasks_source.index("def run_result_check"):]
body = body[:body.index("@app.task")]
must("from .result_checks import run_check" in body and "return run_check(check_id)" in body, "the task delegates to run_check")
tick = (APP / "management" / "commands" / "tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
must(tick.count("from tec_tac.result_checks import") == 1 and "from tec_tac.result_checks import queue_due_checks" in tick, "the tick imports only queue_due_checks")
step = tick[tick.index("from tec_tac.result_checks import"):]
step = step[:step.index("sweep_state =")]
must("reader" not in "".join(line for line in step.splitlines(True) if not line.strip().startswith("#")).lower(), "the tick step's code never mentions a reader")
must("except Exception:" in step and "logger" in step.lower() and "self.stdout" not in step, "the tick step is guarded and writes nothing")
must('"TEC-TAC scheduler tick: checked={checked} queued={queued} skipped={skipped} cleaned={cleaned} session_history_cleanup={session_cleanup} session_expiry_sweep={sweep_state}'
     ' sweep_revoked={sweep_revoked}' in tick.replace('"\n', " ") or "TEC-TAC scheduler tick: checked={checked} queued={queued} skipped={skipped} cleaned={cleaned}" in tick, "the tick's output format is unchanged")
queue_src = source[source.index("def queue_due_checks"):source.index("# ----", source.index("def queue_due_checks"))]
must("reader" not in queue_src.replace("a reader or any module code", ""), "queue_due_checks never calls a reader")
must(tasks_source.count("\r") == 0, "tasks.py keeps LF")

# no output text anywhere
models_source = (APP / "models.py").read_text(encoding="utf-8")
for cls in ("class TecTacResultCheck(", "class TecTacResultCheckItem("):
    section = models_source[models_source.index(cls):]
    section = section[:section.index("def __str__")]
    fields = [line.split("=")[0].strip() for line in section.replace("\r", "").splitlines() if " = models." in line]
    must(fields and not any(any(w in f.lower() for w in ("output", "stdout", "stderr", "text", "body", "result")) and f != "result_check" for f in fields), f"no output text field on {cls}: {fields}")
must(sorted(i for i in ("endpoint_id", "hostname", "state", "exit_code", "checked_at")) == sorted(Item.fields.keys() - {"result_check_id"}), "the item holds exactly the five documented fields")

# the capability
reset()
rc.register_core_result_checks_capability()
must(CAPS and CAPS[-1]["id"] == "core.result_checks" and CAPS[-1]["version"] == "1.0.0" and CAPS[-1]["module_id"] == "core" and CAPS[-1]["operations"] == ("register_reader", "start"), "capability registered")
must(CAPS[-1]["metadata"]["requires_framework"] == ">=1.18.44" and CAPS[-1]["metadata"]["stores_output"] is False, "metadata")
apps_source = (APP / "apps.py").read_bytes().decode("utf-8")
must("register_core_result_checks_capability()" in apps_source and b"\r\n" in (APP / "apps.py").read_bytes(), "apps.py registers it guarded and keeps CRLF")
guard = apps_source[apps_source.index("from .result_checks import register_core_result_checks_capability") - 60:]
must("try:" in guard[:200] and "except Exception:" in guard[:500], "its own try block")

# ================================================================================ the read route
user = fresh("starter")
rival = new_user("rival")
boss = new_user("boss")
boss.is_superuser = True
READER["answer"] = answer_for({"a1": "done", "a2": "failed"})
ids = ["host%03d" % i for i in range(130)]
cid = start(user, endpoint_ids=ids, label="Run script", job_ref={"secret": "ref"})
READER["answer"] = lambda j, i, u: {x: {"state": "done" if n % 2 else "failed", "exit_code": 0 if n % 2 else 3, "hostname": "PC-" + x} for n, x in enumerate(i)}
NOW[0] += timedelta(seconds=60)
rc.run_check(cid)   # asks 500: all 130 answered
NOW[0] += timedelta(seconds=1)


def get(who, check, **query):
    request = SimpleNamespace(user=who, query_params=query)
    return views.ResultCheckView().get(request, check)


NOT_FOUND = {"detail": "Not found."}
good = get(user, cid)
must(good.status_code == 200, good.data)
body = good.data
must(set(body) == {"id", "label", "status", "created_at", "closed_at", "deadline_at", "summary", "message", "items", "count", "page", "page_size", "next_page"}, sorted(body))
must("detail" not in body and "error" not in body and body["message"] == "Run script: 65 done, 65 failed, 0 offline", "success body uses message: " + body["message"])
must(body["summary"] == {"total": 130, "done": 65, "failed": 65, "offline": 0, "running": 0, "no_result": 0} and body["status"] == "closed", body["summary"])
must(body["count"] == 130 and body["page"] == 1 and body["page_size"] == 50 and len(body["items"]) == 50 and body["next_page"] == 2, "first page")
must(set(body["items"][0]) == {"endpoint_id", "hostname", "state", "exit_code"}, "item keys")
must([i["hostname"] for i in body["items"]] == sorted(i["hostname"] for i in body["items"]), "sorted by hostname")
flat = repr(body)
for secret in ("secret", READER_ID, "scriptexecution", "job_ref", "reader_id", "module_id", "stdout", "output"):
    must(secret not in flat, f"{secret!r} never in the answer")
p3 = get(user, cid, page="3").data
must(len(p3["items"]) == 30 and p3["next_page"] is None and p3["page"] == 3, "last page, next_page null at the end")
p2 = get(user, cid, page="2", page_size="100").data
must(len(p2["items"]) == 30 and p2["next_page"] is None and p2["page_size"] == 100, "page 2 of 100")
must(len(get(user, cid, page_size="100").data["items"]) == 100 and get(user, cid, page_size="100").data["next_page"] == 2, "page size 100")
for bad in ({"page": "0"}, {"page": "-1"}, {"page": "x"}, {"page_size": "0"}, {"page_size": "101"}, {"page_size": "abc"}, {"page": "1.5"}):
    response = get(user, cid, **bad)
    must(response.status_code == 400 and "detail" in response.data, f"bad value {bad} is 400")
# an open check shows a "still checking" sentence
user2 = new_user("second")
open_id = start(user2, endpoint_ids=["x1", "x2"])
open_body = get(user2, open_id).data
must(open_body["status"] == "open" and open_body["message"] == "Still checking: 0 of 2 endpoints have a result so far." and open_body["closed_at"] is None, open_body["message"])
# the same 404 for everyone else
anon = SimpleNamespace(is_active=False, is_authenticated=False)
inactive_starter = new_user("gone")
gid = start(inactive_starter)
inactive_starter.is_active = False
unknown = uuid.uuid4()
responses = [get(rival, cid), get(boss, cid), get(anon, cid), get(user, unknown), get(rival, unknown), get(inactive_starter, gid), get(boss, open_id)]
for response in responses:
    must(response.status_code == 404 and response.data == NOT_FOUND, f"identical 404: {response.status_code} {response.data}")
must(get(rival, cid, page="zzz").status_code == 404 and get(user, unknown, page="zzz").status_code == 404, "a bad page does not reveal that a check exists")
old = check_row(cid)
old.closed_at = NOW[0] - timedelta(days=31)
must(get(user, cid).status_code == 404 and get(user, cid).data == NOT_FOUND, "a check older than retention is 404 before the tick deletes it")
old.closed_at = NOW[0] - timedelta(days=29)
must(get(user, cid).status_code == 200, "inside retention is readable")

view_source = (APP / "result_check_views.py").read_text(encoding="utf-8")
must("permission_classes = [SessionAuthenticated]" in view_source and "from .session_security import SessionAuthenticated" in view_source, "session guard")
must("is_superuser" not in view_source and "is_effective_superuser" not in view_source, "no superuser exception")
must("job_ref" not in view_source and "reader_id" not in view_source and "module_id" not in view_source, "the view never reads job_ref, reader id or module id")

# urls.py, openapi.py
urls = (APP / "urls.py").read_text(encoding="utf-8")
must(urls.count('"ui/result-checks/<uuid:check_id>/"') == 1 and urls.count('name="tec-tac-ui-result-check"') == 1, "the path exists once with its name")
must("from .result_check_views import ResultCheckView" in urls and "ResultCheckView.as_view()" in urls, "urls imports the view")
openapi = (APP / "openapi.py").read_text(encoding="utf-8")
must('"tec_tac.result_check_views": "Tec-Tac · UI Runtime"' in openapi, "OpenAPI group")

# contracts.py by ast (no Django needed)
contracts_bytes = (APP / "contracts.py").read_bytes()
must(b"\r\n" in contracts_bytes and contracts_bytes.count(b"\n") == contracts_bytes.count(b"\r\n"), "contracts.py keeps CRLF")
tree = ast.parse(contracts_bytes.decode("utf-8"))
values = {}
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("CORE_CONTRACTS", "HTTP_CONTRACT_DETAILS", "RULES"):
        values[node.targets[0].id] = ast.literal_eval(node.value)
rows = {(r["import_path"], r["name"]): r for r in values["CORE_CONTRACTS"] if r["area"] == "result-checks"}
must(set(rows) == {("tec_tac.result_checks", "register_reader"), ("tec_tac.result_checks", "start"), ("tec_tac.result_checks", "ResultCheckRefused")}, sorted(rows))
must(rows[("tec_tac.result_checks", "register_reader")]["audience"] == "provider/backend" and rows[("tec_tac.result_checks", "start")]["audience"] == "consumer/backend", "audiences")
reg_text, start_text = rows[("tec_tac.result_checks", "register_reader")]["purpose"], rows[("tec_tac.result_checks", "start")]["purpose"]
for needle in ("1.18.44", "500", "idempotent and read-only", "no trusted global read", "Fail closed", "ResultCheckRegistrationError"):
    must(needle in reg_text, f"register_reader text names {needle}")
for needle in ("1.18.44", "1000", "2 KiB", "20 open checks", "AD-26", "ResultCheckRefused", "never output text"):
    must(needle in start_text, f"start text names {needle}")
detail = values["HTTP_CONTRACT_DETAILS"]["/api/tfd/ui/result-checks/<uuid:check_id>/"]["GET"]
must(detail["added"].startswith("1.18.44") and "page_size" in detail["query"] and "404" in detail["errors"] and "next_page" in detail["response"], "http detail")
must(any(r.startswith("Result checks (core.result_checks 1.0.0, Core 1.18.44)") for r in values["RULES"]), "rule sentence")
for name in ("result-checks.md",):
    must((ROOT / "docs" / name).is_file() and b"\r" not in (ROOT / "docs" / name).read_bytes(), "docs/result-checks.md exists with LF")
capabilities_doc = (ROOT / "docs" / "capabilities.md").read_bytes()
must(b"`core.result_checks` 1.0.0 (Core 1.18.44" in capabilities_doc and capabilities_doc.count(b"\n") == capabilities_doc.count(b"\r\n"), "capabilities.md line, CRLF kept")

# migration (by ast) and models agree on names
mig = (APP / "migrations" / "0048_result_checks.py").read_text(encoding="utf-8")
must('("tec_tac", "0047_published_installer_mtime")' in mig and "0046" not in mig.split("dependencies")[1].split("operations")[0], "migration depends on 0047 (and the user model)")
ast.parse(mig)
for name in ("tectac_rescheck_due_idx", "tectac_rescheck_user_idx", "tectac_rescheck_closed_idx", "tectac_rescheckitem_unique", "tectac_rescheckitem_state_idx"):
    must(name in mig and name in models_source, f"{name} in the model and the migration")
    must(len(name) <= 30 or name.endswith("unique"), f"{name} fits Django's index name limit")
must("class TecTacResultCheck(" in models_source and b"\r\n" in (APP / "models.py").read_bytes(), "models.py keeps CRLF")
print("result checks 1.18.44 regression: PASS")
