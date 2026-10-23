#!/usr/bin/env python3
"""1.17.76 regression: agent.command is rebuilt on Tactical's own view (POST agents/{agent_id}/cmd/), no copy of send_raw_cmd's steps remains, and the call runs
as the Communicator service user (Johan, 23 October 2026). Runs without Django: system_commands.py is loaded alone with small fakes.

Covered: no nats_cmd, AgentHistory or asyncio in system_commands.py; the view dispatch with fakes (string agent id, body, service user, status mapping), the service user's fail-closed checks, one row only, the 2000-per-run cap; the route takes
the STRING agent id (resolved from the number, fail closed when it is missing, short or broken); the reply maps timeout/natsdown to unreachable and cuts at 1 MiB; the
claim survives a cache flush through the durable audit lookup and fails closed when that lookup raises; the row has no min_flags (no can_send_cmd forced) and
declaring_module widens only for the registered agent.command row.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "framwork" / "tec_tac"
FAILED = []


def must(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        FAILED.append(label)


store = {}


class FakeCache:
    def add(self, key, value, timeout=None):
        if key in store:
            return False
        store[key] = value
        return True

    def delete(self, key):
        store.pop(key, None)

    def incr(self, key):
        store[key] += 1
        return store[key]


cache_mod = types.ModuleType("django.core.cache")
cache_mod.cache = FakeCache()
sys.modules.update({"django": types.ModuleType("django"), "django.core": types.ModuleType("django.core"), "django.core.cache": cache_mod})
spec = importlib.util.spec_from_file_location("tec_tac_system_commands", ROOT / "system_commands.py")
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)

src = (ROOT / "system_commands.py").read_text(encoding="utf-8")
code = "\n".join(line.split("#")[0] for line in src.splitlines())
must("nats_cmd" not in code.replace('"""', "") .split('class CommandRefused')[1] and "AgentHistory" not in code.split('class CommandRefused')[1] and "import asyncio" not in src,
     "no copy of send_raw_cmd's steps (nats_cmd, AgentHistory, asyncio) remains in the code")
for path in ROOT.glob("*.py"):
    must("nats_cmd(" not in path.read_text(encoding="utf-8") or path.name in ("agents_adapter.py",) or "rawcmd" not in path.read_text(encoding="utf-8"), f"{path.name} has no rawcmd send")

# availability and the service user (fakes for Tactical's accounts models, urls and http)
class Field:
    def __init__(self, name, kind="BooleanField"):
        self.name, self.kind = name, kind

    def get_internal_type(self):
        return self.kind


class Meta:
    @staticmethod
    def get_fields():
        return [Field("id", "AutoField"), Field("name", "CharField"), Field("can_send_cmd"), Field("can_view_clients"), Field("is_superuser")]


class RoleObj:
    _meta = Meta()
    pk = 1

    def __init__(self, name):
        self.name, self.can_send_cmd, self.can_view_clients, self.is_superuser = name, True, False, False


STATE = {"role": None, "user": None}


class First:
    def __init__(self, value):
        self.value = value

    def first(self):
        return self.value


class RoleMgr:
    CREATED = []

    @staticmethod
    def filter(name):
        return First(STATE["role"])

    @staticmethod
    def get_or_create(name, defaults=None):  # 1.17.76: the run must never call this
        RoleMgr.CREATED.append(name)
        raise AssertionError("the service role is created at run time")


class UserObj:
    def __init__(self, username, email="", block_dashboard_login=True, role=None, is_active=True):
        self.username, self.block_dashboard_login, self.role, self.role_id, self.is_active = username, block_dashboard_login, role, role.pk, is_active
        self.is_superuser = self.is_staff = self.is_installer_user = False
        self._usable = True

    def set_unusable_password(self):
        self._usable = False

    def has_usable_password(self):
        return self._usable

    def save(self):
        STATE["user"] = self
        UserObj.SAVED.append(self)

    SAVED = []


class UserQ:
    @staticmethod
    def first():
        return STATE["user"]


class UserMgr:
    @staticmethod
    def filter(username):
        return First(STATE["user"])


class Role:
    objects = RoleMgr
    _meta = Meta()


class User:
    objects = UserMgr

    def __new__(cls, **kw):
        return UserObj(**kw)


accounts, accounts_models = types.ModuleType("accounts"), types.ModuleType("accounts.models")
accounts_models.Role, accounts_models.User = Role, User
django_http, django_urls = types.ModuleType("django.http"), types.ModuleType("django.urls")


class HttpRequest:
    pass


django_http.HttpRequest = HttpRequest
MATCH = types.SimpleNamespace(func=types.SimpleNamespace(__name__="send_raw_cmd"), args=(), kwargs={"agent_id": "x"})
django_urls.resolve = lambda path: MATCH
sys.modules.update({"accounts": accounts, "accounts.models": accounts_models, "django.http": django_http, "django.urls": django_urls})
sys.modules["agents"] = types.ModuleType("agents")
agm = types.ModuleType("agents.models")
agm.Agent = object
sys.modules["agents.models"] = agm

must(sc.available() is True and sc.OWNER_VIEW_DISPATCH_SIGNED is True, "available() is True with the signed dispatch")
sc.OWNER_VIEW_DISPATCH_SIGNED = False
must(sc.available() is False, "available() is False when the flag is switched off (fail closed)")
sc.OWNER_VIEW_DISPATCH_SIGNED = True

# the dispatcher fake: the view is called with the right string agent id, shell, timeout and rendered command
SEEN = []
ANSWER = {"status": 200, "body": b'"hello"'}


def fake_dispatch(match, request):
    import json as _j
    SEEN.append((request.path, _j.loads(request._body), request._force_auth_user, match.func.__name__))
    return types.SimpleNamespace(status_code=ANSWER["status"], content=ANSWER["body"])


sc._dispatch_view = fake_dispatch
call = {"shell": "powershell", "command": "Get-Date", "timeout": 20}
AID = "x" * 20 + "ABCDEFG"
STATE["role"] = RoleObj(sc.SERVICE_ROLE)  # what migration 0038 makes; the run never creates it
STATE["user"] = UserObj(sc.SERVICE_USERNAME, role=STATE["role"])
STATE["user"].set_unusable_password()
out = sc._send(AID, call, "johan")
path, body, forced, fname = SEEN[0]
must(out == "hello" and path == f"/agents/{AID}/cmd/" and fname == "send_raw_cmd", "the view is called on the STRING agent id and answers its text")
must(body == {"shell": "powershell", "cmd": "Get-Date", "timeout": 20, "custom_shell": None, "run_as_user": False}, "the body holds shell, rendered command, timeout, no custom shell, no run_as_user")
must(forced.username == sc.SERVICE_USERNAME, "the view runs as the service user, not the owner")
ANSWER.update(status=400, body=b'"Unable to contact the agent"')
must(sc._send(AID, call, "johan") == "timeout" and sc.interpret_reply("timeout")[0] == "unreachable", "HTTP 400 'Unable to contact the agent' maps to unreachable")
ANSWER.update(status=403, body=b'{"detail":"no"}')
try:
    sc._send(AID, call, "johan")
    must(False, "another status raises")
except RuntimeError:
    must(True, "any other status raises (the caller records failed and keeps the claim)")
ANSWER.update(status=200, body=b'"ok"')
MATCH.func.__name__ = "other_view"
try:
    sc._send(AID, call, "johan")
    must(False, "a route that is not send_raw_cmd is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable", "a route that is not send_raw_cmd is refused")
MATCH.func.__name__ = "send_raw_cmd"

# 1.17.76 (AD-50): a missing service user or role refuses function_unavailable and NOTHING is created or dispatched at run time
n_seen = len(SEEN)
STATE["role"] = STATE["user"] = None
UserObj.SAVED.clear()
try:
    sc._service_user()
    must(False, "a missing service user is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable" and "not installed" in exc.detail, "a missing service user refuses function_unavailable with a plain reason")
must(STATE["user"] is None and STATE["role"] is None and not RoleMgr.CREATED and not UserObj.SAVED, "nothing is created at run time (the migration makes the user)")
try:
    sc._send(AID, call, "johan")
    must(False, "_send with no service user refuses")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable" and len(SEEN) == n_seen, "a missing service user: function_unavailable and no dispatch")
STATE["role"] = RoleObj(sc.SERVICE_ROLE)  # what migration 0038 makes
STATE["role"].pk = 1
inst = UserObj(sc.SERVICE_USERNAME, role=STATE["role"])
inst.set_unusable_password()
STATE["user"] = inst
UserObj.SAVED.clear()
_inst_user = inst
out = sc._send(AID, call, "johan")
must(out == "ok" and SEEN[-1][2] is inst, "with the installed service user the view is dispatched through it")

# the service user is refused when it holds more than the Communicator may
user = sc._service_user()
must(user.username == sc.SERVICE_USERNAME and not user.has_usable_password() and user.block_dashboard_login, "the service user cannot sign in")
for attr in ("is_superuser", "is_staff", "is_installer_user"):
    setattr(user, attr, True)
    try:
        sc._service_user()
        must(False, f"{attr} refuses")
    except sc.CommandRefused as exc:
        must(exc.reason == "function_unavailable", f"a service user with {attr} is refused")
    setattr(user, attr, False)
user.is_active = False
try:
    sc._service_user()
    must(False, "inactive refuses")
except sc.CommandRefused:
    must(True, "an inactive service user is refused")
user.is_active = True
user._usable = True
try:
    sc._service_user()
    must(False, "usable password refuses")
except sc.CommandRefused:
    must(True, "a service user with a usable password is refused")
user._usable = False
for flag in ("can_view_clients", "is_superuser"):
    setattr(STATE["role"], flag, True)
    try:
        sc._service_user()
        must(False, f"role {flag} refuses")
    except sc.CommandRefused:
        must(True, f"a role with {flag} beyond can_send_cmd is refused")
    setattr(STATE["role"], flag, False)
STATE["role"].can_send_cmd = False
try:
    sc._service_user()
    must(False, "role without can_send_cmd refuses")
except sc.CommandRefused:
    must(True, "a role that lost can_send_cmd is refused")
STATE["role"].can_send_cmd = True
must(sc._service_user() is user, "the untouched service user passes")

# no other row can use the service path
try:
    sc.run_one(definition=types.SimpleNamespace(function="agent.reboot"), run=None, verified=None, owner=None, provenance={}, extra={}, agent_pk=5, call=call)
    must(False, "another row is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "wrong_kind", "run_one refuses any row but agent.command (wrong_kind)")

# the per-run cap
store.clear()
for n in range(1, sc.MAX_COMMANDS_PER_RUN + 1):
    last = sc.count_run("run-1")
must(last == sc.MAX_COMMANDS_PER_RUN == 2000, "a run may send 2000 commands")
try:
    sc.count_run("run-1")
    must(False, "the 2001st is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "too_many_commands", "the 2001st command of a run is refused too_many_commands")
must(sc.count_run("run-2") == 1, "another run counts from one")

# the string agent id
agents = types.ModuleType("agents")
models = types.ModuleType("agents.models")
ROWS = {5: "x" * 20 + "ABCDEFG", 6: "short", 7: "x" * 20 + "a/b"}


class Q:
    def __init__(self, pk):
        self.pk = pk

    def values_list(self, name, flat=False):
        return self

    def first(self):
        return ROWS.get(self.pk)


class Mgr:
    @staticmethod
    def filter(pk):
        return Q(pk)


models.Agent = types.SimpleNamespace(objects=Mgr)
sys.modules.update({"agents": agents, "agents.models": models})
must(sc.route_agent_id(5) == ROWS[5], "the route takes Tactical's string agent id, resolved from the number")
for pk in (6, 7, 99):
    try:
        sc.route_agent_id(pk)
        must(False, f"agent {pk} is refused")
    except sc.CommandRefused as exc:
        must(exc.reason == "bad_agents", f"agent {pk} (short, with a slash or missing) is refused bad_agents")

# the reply
must(sc.interpret_reply("timeout")[0] == "unreachable" and sc.interpret_reply("natsdown")[0] == "unreachable" and sc.interpret_reply(None)[0] == "unreachable", "bare timeout/natsdown/None read unreachable")
must(sc.interpret_reply("hello") == ("ran", "hello", False), "the answer text is the output")
big = sc.interpret_reply("x" * (sc.MAX_OUTPUT_BYTES + 5))
must(big[0] == "ran" and big[2] is True and len(big[1]) == sc.MAX_OUTPUT_BYTES, "the output is cut at 1 MiB and says so")

# the durable claim
seen = {"rows": set()}
sc._already_recorded = lambda a, c: (a, c) in seen["rows"]
must(sc.claim(5, "c1") is True, "a first claim succeeds")
seen["rows"].add((5, "c1"))
store.clear()  # the cache is flushed
must(sc.claim(5, "c1") is False, "after a cache flush the strict audit row still refuses the same command_id")
store.clear()


def broken(a, c):
    raise RuntimeError("db down")


sc._already_recorded = broken
try:
    sc.claim(5, "c2")
    must(False, "a failed lookup refuses")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable", "a failed durable lookup refuses the call (fail closed)")

# AD-50: the Communicator rights attested at creation (an owner with communicator.send and NOT can_send_cmd is accepted; Core never asks for can_send_cmd)
sc._TEMPLATES.clear()
sc.REGISTRANTS = set(getattr(sc, "REGISTRANTS", ())) | {"communicator"}
H = "a" * 64
sc._TEMPLATES["communicator.notice"] = {"id": "communicator.notice", "module_id": "communicator", "right": sc.RIGHT_SEND, "shell": "cmd", "slots": {}, "timeout": 20, "text": "echo hi", "file": None, "hash": H}
sc._TEMPLATES["communicator.restart"] = {"id": "communicator.restart", "module_id": "communicator", "right": sc.RIGHT_REBOOT, "shell": "cmd", "slots": {}, "timeout": 20, "text": "shutdown /r", "file": None, "hash": H}
sc._load = lambda record: (record["text"], record["hash"])
base = {"allowed_templates": ["communicator.notice"], "template_hashes": {"communicator.notice": H}, "max_timeout": 20}
def refused(fn, reason=None):
    try:
        fn()
    except (ValueError, sc.CommandRefused) as exc:
        return reason is None or getattr(exc, "reason", None) == reason
    return False
must(refused(lambda: sc.parameters(base)), "parameters without rights are refused when the schedule is made")
must(refused(lambda: sc.parameters({**base, "rights": []})) and refused(lambda: sc.parameters({**base, "rights": ["communicator.reboot"]})) and refused(lambda: sc.parameters({**base, "rights": ["can_send_cmd"]})),
     "rights must be known Communicator rights and include communicator.send")
cleaned = sc.parameters({**base, "rights": ["communicator.send"]})
must(cleaned["rights"] == ["communicator.send"], "an owner with communicator.send (and no Tactical can_send_cmd anywhere) is accepted")
good = {"agent_id": 7, "command_id": "c-1", "template_id": "communicator.notice", "params": {}}
before = len(SEEN)
call2, pk = sc.resolve(good, cleaned)
must(pk == 7 and sc._send(AID, call2, "johan") == "ok" and SEEN[-1][2] is _inst_user and len(SEEN) == before + 1, "that run is dispatched through the service user")
must(refused(lambda: sc.parameters({**base, "allowed_templates": ["communicator.restart"], "template_hashes": {"communicator.restart": H}, "rights": ["communicator.send"]})),
     "a restart template needs communicator.reboot in the rights at creation")
forged = {**cleaned, "allowed_templates": ["communicator.restart"], "template_hashes": {"communicator.restart": H}}
before = len(SEEN)
must(refused(lambda: sc.resolve({**good, "template_id": "communicator.restart"}, forged), "permission_lost") and len(SEEN) == before, "no Communicator right for the template: permission_lost and no dispatch")
must(refused(lambda: sc.resolve(good, {k: v for k, v in cleaned.items() if k != "rights"}), "permission_lost"), "stored parameters with no rights: permission_lost (fail closed)")
reboot = sc.parameters({**base, "allowed_templates": ["communicator.restart"], "template_hashes": {"communicator.restart": H}, "rights": ["communicator.reboot", "communicator.send"]})
must(sc.resolve({**good, "template_id": "communicator.restart"}, reboot)[0]["template_id"] == "communicator.restart", "communicator.reboot holders may use the restart template")
ra = src.split("def run_one")[1]
must(ra.index("_service_user()") < ra.index("count_run(") < ra.index("claim("), "run_one reads and checks the service user BEFORE the count, the claim and the audit row")
must("get_or_create" not in code and "set_unusable_password" not in code and "Role.objects.create" not in code, "system_commands.py has no code that creates the service user or role")
mig = (ROOT / "migrations" / "0038_communicator_service_user.py").read_text(encoding="utf-8")
must(all(x in mig for x in (sc.SERVICE_USERNAME, sc.SERVICE_ROLE, sc.SERVICE_FLAG, "make_password(None)", "block_dashboard_login=True", "RunPython")), "migration 0038 makes the role and the user with the same names")
must("entry_time__gte" in src and 'action="run"' in src, "the durable claim lookup is time-windowed and filtered by action")
cx = (ROOT / "contracts.py").read_text(encoding="utf-8")
must("then can_send_cmd as stored at creation" not in cx and "can_send_cmd is not checked (AD-50)" in cx, "the contract text matches the code (no can_send_cmd check)")

# the wiring
sa = (ROOT / "system_actions.py").read_text(encoding="utf-8")
must('min_flags=(), accepts="command"' in sa, "agent.command has no Tactical minimum flag (Communicator rights decide, Johan 23 October 2026)")
must('verified.held_at_creation("can_send_cmd")' not in sa and "for flag in definition.permissions" in sa, "no forced can_send_cmd re-check at run time")
must("definition.function == \"agent.command\" and definition.module_id == entry.owner_module" not in sa, "declaring_module no longer needs the registered definition")
# -2 (after review): declaring_module is static (exact id <owner>.command, no registry), run on the real function text with _ACTIONS empty
i = sa.index("def declaring_module"); j = sa.index("def get_system_action")
ns = {"SYSTEM_FUNCTIONS": {"agent.command": types.SimpleNamespace(callers=("communicator",), owner_module="remote-background")}, "_ACTIONS": {}}
exec(sa[i:j], ns)
dm = ns["declaring_module"]
must(dm("communicator", "remote-background.command") == "remote-background", "declaring_module: exact id, _ACTIONS empty, no registration needed")
must(dm("communicator", "remote-background.other") == "communicator" and dm("communicator", "remote-backgroundX.command") == "communicator" and dm("other", "remote-background.command") == "other", "declaring_module: a look-alike id or a non-caller is not widened")
must("_ACTIONS" not in sa[i:j].split('"""')[2], "declaring_module reads no registry")

# -2: the audit lookup is read ONCE per run (one query), bounded, windowed and fail closed
queries = []


class FakeQS:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, **kw):
        queries.append(kw)
        return self

    def values_list(self, *a):
        return self

    def __getitem__(self, sl):
        return self.rows[sl]


fake_logs = types.ModuleType("logs"); fake_models = types.ModuleType("logs.models")
fake_models.AuditLog = types.SimpleNamespace(objects=FakeQS([(5, "old"), (6, "x")]))
sys.modules["logs"], sys.modules["logs.models"] = fake_logs, fake_models
fake_tz = types.ModuleType("django.utils"); fake_tz.timezone = types.SimpleNamespace(now=lambda: __import__("datetime").datetime(2026, 10, 23))
sys.modules["django.utils"] = fake_tz
real_ar = importlib.import_module  # keep the import machinery untouched
del sc.__dict__["_already_recorded"]  # the earlier fakes replaced it; reload the real one from source
_ns = dict(sc.__dict__)
exec(src[src.index("_RUN = threading.local()"):src.index("def claim(")], _ns)
sc._RUN, sc._RECORDED, sc._recent_recorded, sc._already_recorded = _ns["_RUN"], _ns["_RECORDED"], _ns["_recent_recorded"], _ns["_already_recorded"]
sc._RUN.run_id = "run-A"
res = [sc._already_recorded(5, "old"), sc._already_recorded(6, "x"), sc._already_recorded(5, "new"), sc._already_recorded(7, "x")]
sc._RUN.run_id = None
must(res == [True, True, False, False] and len(queries) == 1, "the audit lookup is one query for the whole run, not one per send")
must(all("entry_time__gte" in q for q in queries) and sc.CLAIM_LOOKUP_DAYS == 7, "the lookup is windowed to 7 days")
sc._ns_cap = _ns["CLAIM_PREFETCH_MAX"]
fake_models.AuditLog.objects = FakeQS([(1, "c")] * (sc._ns_cap + 1))
try:
    _ns["_recent_recorded"]()
    must(False, "more rows than the cap refuses (fail closed)")
except RuntimeError:
    must(True, "more rows than the cap refuses (fail closed)")

# -2: migration 0038 on a fake apps registry; a failure is logged with its type, not swallowed silently
import logging as _lg

dj = types.ModuleType("django"); dj_db = types.ModuleType("django.db")


class _Atomic:
    def __init__(self, using=None): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False


dj_db.transaction = types.SimpleNamespace(atomic=_Atomic)
dj_db.migrations = types.SimpleNamespace(Migration=object, RunPython=types.SimpleNamespace(noop=None))
dj_db.migrations.RunPython = type("RunPython", (), {"noop": None, "__init__": lambda self, *a: None})
dj_auth = types.ModuleType("django.contrib.auth.hashers"); dj_auth.make_password = lambda p: "!"
for k, v in {"django": dj, "django.db": dj_db, "django.contrib": types.ModuleType("django.contrib"), "django.contrib.auth": types.ModuleType("django.contrib.auth"), "django.contrib.auth.hashers": dj_auth}.items():
    sys.modules[k] = v
spec = importlib.util.spec_from_file_location("mig0038", ROOT / "migrations" / "0038_communicator_service_user.py")
mg = importlib.util.module_from_spec(spec); spec.loader.exec_module(mg)


class _Field:
    def __init__(self, name): self.name = name
    def get_internal_type(self): return "BooleanField"


class _Mgr:
    def __init__(self, rows, log): self.rows, self.log = rows, log
    def using(self, db): return self
    def filter(self, **kw): self.f = kw; return self
    def first(self): return None
    def exists(self): return False
    def create(self, **kw): self.log.append(kw); return kw


created = []
role_model = types.SimpleNamespace(_meta=types.SimpleNamespace(get_fields=lambda: [_Field(mg.FLAG), _Field("can_run_scripts")]), objects=_Mgr([], created))
user_model = types.SimpleNamespace(objects=_Mgr([], created))
apps = types.SimpleNamespace(get_model=lambda app, name: {"Role": role_model, "User": user_model}[name])
editor = types.SimpleNamespace(connection=types.SimpleNamespace(alias="default"))
mg.create_service_user(apps, editor)
must(len(created) == 2 and created[0]["name"] == mg.ROLE and created[0][mg.FLAG] is True and created[0]["can_run_scripts"] is False and created[1]["username"] == mg.USERNAME and created[1]["block_dashboard_login"] is True and created[1]["is_superuser"] is False, "migration 0038: role has only can_send_cmd; user has no sign-in and no admin flags")
role_model.objects.first = lambda: types.SimpleNamespace()
n = len(created); role_model.objects.exists = lambda: True; user_model.objects.exists = lambda: True
mg.create_service_user(apps, editor)
must(len(created) == n, "migration 0038: existing rows are never changed")
records = []


class _H(_lg.Handler):
    def emit(self, r): records.append(r)


mg.logger.addHandler(_H()); mg.logger.setLevel(_lg.DEBUG)
broken = types.SimpleNamespace(get_model=lambda a, n: (_ for _ in ()).throw(LookupError("no accounts")))
mg.create_service_user(broken, editor)
must(any("LookupError" in r.getMessage() for r in records), "migration 0038: a failure is logged with the exception type and does not abort the migration")
role_model._meta.get_fields = lambda: [_Field("other")]
records.clear(); n = len(created); role_model.objects.first = lambda: None; user_model.objects.exists = lambda: False
mg.create_service_user(apps, editor)
must(len(created) == n and any("has no can_send_cmd" in r.getMessage() for r in records), "migration 0038: a Tactical without the flag is skipped and logged")


print("PASS" if not FAILED else f"FAIL: {len(FAILED)} check(s)")
sys.exit(1 if FAILED else 0)
