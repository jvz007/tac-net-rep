#!/usr/bin/env python3
"""1.17.17 regression: a scheduled action may be gated by a Tactical role flag, or by any of several entries (patching 0.5.0).

``register_scheduled_action(permission=...)`` takes a Tec-Tac code (as before), ``None``, a Tactical flag written
``tactical:can_manage_winupdates``, or a list or tuple of those (any-of, at most 8, no duplicates). Registration checks the shape
only. An unknown flag is caught at use and fails closed. The real scheduler.py, tasks.py, rbac.py and scheduler_views.py run here
against stubs (Django is not installed), so the real ``_can_use_action`` is what proves the rules. tests/scheduler-one-off-run-1.17.16.py
stubs scheduler_views and cannot. The shared harness ends at the marker line below; tests/scheduler-one-off-run-now-1.17.17.py reuses it.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
PRELUDE = Path(__file__).resolve().parent / "scheduler-one-off-run-1.17.16.py"
_text = PRELUDE.read_text(encoding="utf-8")
G = globals()
# the in-memory Schedule and Run models, the Django stubs and the fake queue of the 1.17.16 test (everything before its permission stubs)
exec(compile(_text[: _text.index("PERMS = {}  # username")], str(PRELUDE), "exec"), G)
must, mod, mods, pkg, AUDITS, QUEUED, Schedule, Run = (G[k] for k in ("must", "mod", "mods", "pkg", "AUDITS", "QUEUED", "Schedule", "Run"))


# ------------------------------------------------------------------------------------------------ stubs for the real views and rbac
class _Spec:
    def __call__(self, *a, **k):
        return lambda obj: obj


class APIView:
    pass


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


class DRFError(Exception):
    pass


class PermissionDenied(DRFError):
    pass


class NotFound(DRFError):
    pass


class RoleField:
    def __init__(self, kind):
        self.kind = kind

    def get_internal_type(self):
        return self.kind


class FieldDoesNotExist(Exception):
    pass


class Role:
    FIELDS = {"can_manage_winupdates": "BooleanField", "can_reboot_agents": "BooleanField", "can_view_clients": "ManyToManyField",
              "can_do_server_maint": "BooleanField", "is_superuser": "BooleanField", "name": "CharField"}

    class _meta:
        @staticmethod
        def get_field(name):
            if name not in Role.FIELDS:
                raise FieldDoesNotExist(name)
            return RoleField(Role.FIELDS[name])


GRANTS = set()  # (role id, extension permission code)


class _Grants:
    def __init__(self, rows):
        self.rows = rows

    def exists(self):
        return bool(self.rows)


class ExtensionRolePermission:
    class objects:
        @staticmethod
        def filter(*, role_id, codename, granted):
            return _Grants([1] if (role_id, codename) in GRANTS and granted else [])


def _get_or_404(model, **kw):
    for row in model.objects.rows:
        if str(row.pk) == str(kw["pk"]):
            return row
    raise NotFound("no schedule")


def _safe_role(user):
    try:
        return user.get_and_set_role_cache()
    except Exception:
        return None


mods["tec_tac.models"].ExtensionRolePermission = ExtensionRolePermission
mod("accounts")
mod("accounts.models", Role=Role)
mod("tec_tac.registry", get_plugins=lambda: (SimpleNamespace(plugin_type="extension", permission_groups=(("Patching", ("patching.run", "alerts.view")),)),))
mod("drf_spectacular")
mod("drf_spectacular.utils", extend_schema=_Spec(), extend_schema_view=_Spec())
mod("rest_framework")
mod("rest_framework.response", Response=Response)
mod("rest_framework.views", APIView=APIView)
mod("rest_framework.exceptions", NotFound=NotFound, PermissionDenied=PermissionDenied)
mod("django.shortcuts", get_object_or_404=_get_or_404)
mod("django.utils.dateparse", parse_datetime=lambda v: None, parse_time=lambda v: None)
mods["django.db"].connection = SimpleNamespace(vendor="sqlite")
mods["django.db.models"].OuterRef = mods["django.db.models"].Subquery = lambda *a, **k: None
mod("tec_tac.session_security", SessionAuthenticated=object)
mod("tec_tac.resources_adapter", TacticalResourceAdapterError=type("TacticalResourceAdapterError", (Exception,), {}))
mod("tec_tac.views", _role_for_user=_safe_role)
audit_stub = mod("tec_tac.audit", record=lambda **kw: AUDITS.append(kw) or {"recorded": True}, service_audit_actor=lambda **kw: {"service": kw})
pkg.audit = audit_stub
sys.modules.update(mods)


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, APP / file)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


load("tec_tac.scheduler_targets", "scheduler_targets.py")
load("tec_tac.scheduler_timing", "scheduler_timing.py")
sched = load("tec_tac.scheduler", "scheduler.py")
sched._zone = lambda value: None
tasks = load("tec_tac.tasks_real", "tasks.py")
rbac = load("tec_tac.rbac", "rbac.py")
sv = load("tec_tac.scheduler_views", "scheduler_views.py")
# the target scope is item E's business and has its own tests: these two stand in for a user with unrestricted Tactical scope
sv._can_access_target_scope = lambda user, targets: True
sv._canonicalize_endpoint_targets_for_user = lambda user, targets: targets


class Granted:
    def __init__(self, rid=1, **flags):
        self.id = rid
        self.is_superuser = flags.pop("is_superuser", False)
        self.can_do_server_maint = flags.pop("can_do_server_maint", False)
        self.__dict__.update(flags)


class User:
    def __init__(self, username, role=None, *, superuser=False, installer=False, active=True, boom=False):
        self.pk = self.id = sum(map(ord, username))
        self.username = username
        self.is_authenticated, self.is_active, self.is_superuser, self.is_installer_user = True, active, superuser, installer
        self._role, self._boom = role, boom

    def get_and_set_role_cache(self):
        if self._boom:
            raise RuntimeError("role lookup down")
        return self._role


CONTEXTS = []


def handler(context):
    CONTEXTS.append(context)
    return {"ok": True}


def execute(r):
    return tasks.execute_schedule_run(SimpleNamespace(request=SimpleNamespace(retries=0)), str(r.id))


def reset():
    del Schedule.objects.rows[:], Run.objects.rows[:], QUEUED[:], AUDITS[:], CONTEXTS[:]


# ---- harness end (tests/scheduler-one-off-run-now-1.17.17.py reads up to this line)

logging.disable(logging.NOTSET)  # the prelude silences logging; this test reads the fail-closed log lines


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


capture = Capture()
logging.getLogger("tec_tac.scheduler").addHandler(capture)
logging.getLogger("tec_tac.scheduler").setLevel(logging.DEBUG)
logging.getLogger("tec_tac.scheduler").propagate = False

FLAG = "tactical:can_manage_winupdates"
tech = User("tech", Granted(1, can_manage_winupdates=True))
plain = User("plain", Granted(2))
coded = User("coded", Granted(3))
GRANTS.add((3, "patching.run"))
both = User("both", Granted(4, can_manage_winupdates=True))
GRANTS.add((4, "alerts.view"))
manager = User("manager", Granted(5, can_do_server_maint=True))
root = User("root", None, superuser=True)
role_root = User("role_root", Granted(6, is_superuser=True))
installer = User("installer", Granted(7, can_manage_winupdates=True), installer=True)
no_role = User("no_role", None)
broken = User("broken", boom=True)
ALL = (tech, plain, coded, both, manager, root, role_root, installer, no_role, broken)


def reg(action_id="patching.scan", permission=None, **kw):
    return sched.register_scheduled_action(id=action_id, module_id=action_id.split(".")[0], label=action_id, handler=handler,
                                           target_types=("none",), permission=permission, **kw)


def allowed(action, *users):
    return [u.username for u in users if sv._can_use_action(u, action)]


def bad_shape(permission, part=""):
    try:
        reg("patching.bad", permission)
    except sched.SchedulerError as exc:
        must(part in str(exc), (permission, str(exc)))
        must("patching.bad" not in sched._ACTIONS, "a refused registration leaves nothing registered")
        return
    raise AssertionError(f"permission accepted: {permission!r}")


# ------------------------------------------------------------------------------------------------ single Tactical flag
single = reg("patching.single", FLAG)
must(single.permission == FLAG and single.permission_any == () and single.permission_entries == (FLAG,), single)
# a holder passes; a role without the flag, no role, an installer user and a failed lookup are refused; managers pass
must(allowed(single, *ALL) == ["tech", "both", "manager", "root", "role_root"], allowed(single, *ALL))

# ------------------------------------------------------------------------------------------------ any-of
anyof = reg("patching.anyof", ["patching.run", FLAG])
must(anyof.permission == f"patching.run{sched.PERMISSION_ANY_JOIN}{FLAG}" and anyof.permission_any == ("patching.run", FLAG), anyof)
must(allowed(anyof, *ALL) == ["tech", "coded", "both", "manager", "root", "role_root"], allowed(anyof, *ALL))  # tech: the second entry
two_codes = reg("patching.two", ("patching.run", "alerts.view"))
must(allowed(two_codes, *ALL) == ["coded", "both", "manager", "root", "role_root"], allowed(two_codes, *ALL))
tuple_form = reg("patching.tuple", (FLAG, "tactical:can_reboot_agents"))
must(allowed(tuple_form, tech, plain) == ["tech"], "a tuple works like a list")
# a list of one entry reads as that entry
one = reg("patching.one", [FLAG])
must(one.permission == FLAG and one.permission_any == (), one)
# the order of the entries does not change who passes
must(allowed(reg("patching.rev", [FLAG, "patching.run"]), *ALL) == allowed(anyof, *ALL), "order is not significant")

# ------------------------------------------------------------------------------------------------ managers only
open_action = reg("patching.open", None)
must(open_action.permission is None and open_action.permission_entries == (), open_action)
must(allowed(open_action, *ALL) == ["manager", "root", "role_root"], "no entry at all means managers only")
must(allowed(reg("patching.blank", ""), *ALL) == ["manager", "root", "role_root"], "an empty text is still managers only")

# ------------------------------------------------------------------------------------------------ fail closed, logged, never blocking
del capture.records[:]
unknown = reg("patching.unknown", "tactical:can_do_nothing")
must(allowed(unknown, tech, plain, no_role) == [], "an unknown Tactical flag refuses everyone but the managers")
must(allowed(unknown, root, manager) == ["root", "manager"], "managers still pass")
must(any("does not exist" in r.getMessage() and "tactical:can_do_nothing" in r.getMessage() for r in capture.records), "the unknown flag is logged")
must(allowed(reg("patching.notflag", "tactical:can_view_clients"), tech) == [], "a Role field that is not a boolean flag fails closed")
must(allowed(reg("patching.unreg", "no.such.code"), coded) == [], "an unknown Tec-Tac code fails closed, as before")
# an error on one entry never blocks another
must(allowed(reg("patching.mixed1", ["tactical:can_do_nothing", "patching.run"]), coded, tech) == ["coded"], "bad first entry, good second")
must(allowed(reg("patching.mixed2", ["no.such.code", FLAG]), tech) == ["tech"], "bad code, good flag")
orig = sv.has_extension_permission
sv.has_extension_permission = lambda user, code: (_ for _ in ()).throw(RuntimeError("db down"))
must(allowed(reg("patching.mixed3", ["patching.run", FLAG]), tech, coded) == ["tech"], "a failing code check does not block the flag, and does not raise")
sv.has_extension_permission = orig

# ------------------------------------------------------------------------------------------------ registration shapes
for bad, part in (("tactical:", "tactical:"), ("tactical:not_a_flag", "tactical:"), ("tactical:Can_Manage", "tactical:"), ("tactical:can_", "tactical:"),
                  ("tactical:can_x y", "tactical:"), ("tactical:can_x\n", "tactical:"), ([], "empty"), ((), "empty"), ([5], "non-empty text"), ([None], "non-empty text"),
                  (["", "patching.run"], "non-empty text"), (["   "], "non-empty text"), ([f"a.b{i}" for i in range(9)], "more than 8"),
                  (["patching.run", "patching.run"], "repeats"), ([FLAG, FLAG], "repeats"), (5, "text, a list"), ({"a": 1}, "text, a list"), (b"x", "text, a list"),
                  (["patching.run", ["x"]], "non-empty text"), (["tactical:nope", "patching.run"], "tactical:")):
    bad_shape(bad, part)
reg("patching.eight", [f"a.b{i}" for i in range(8)])  # eight is the limit

# ------------------------------------------------------------------------------------------------ idempotent, compatible
again = reg("patching.single", FLAG)
must(again == single, "the same registration again is idempotent")
must(reg("patching.anyof", ("patching.run", FLAG)) == anyof, "a list and a tuple of the same entries are the same action")
try:
    reg("patching.single", "patching.run")
    raise AssertionError("a different permission for a registered action must be refused")
except sched.SchedulerError as exc:
    must("already registered" in str(exc), exc)
# an existing string-permission action is as it was
legacy = reg("patching.legacy", "patching.run")
must(legacy.permission == "patching.run" and legacy.permission_any == () and allowed(legacy, coded, tech, plain) == ["coded"], legacy)
# positional construction and equality of the earlier nine fields still work
old_style = sched.ScheduledAction("x.y", "x", "X", handler, "", ("none",), "x.use", False, 60)
must(old_style.permission_any == () and old_style == sched.ScheduledAction("x.y", "x", "X", handler, "", ("none",), "x.use", False, 60), old_style)
must(old_style != sched.ScheduledAction("x.y", "x", "X", handler, "", ("none",), "x.use", False, 60, ("a.b", "c.d")), "permission_any takes part in equality")
must(sched.get_scheduled_action("tec-tac.scheduler-test").permission is None, "the framework test action is unchanged")

# ------------------------------------------------------------------------------------------------ serialize_action
must(sched.serialize_action(single)["permission"] == FLAG and sched.serialize_action(single)["permission_any"] == [], sched.serialize_action(single))
shown = sched.serialize_action(anyof)
must(shown["permission"] == anyof.permission and shown["permission_any"] == ["patching.run", FLAG], shown)
must(sched.serialize_action(open_action)["permission"] is None and sched.serialize_action(open_action)["permission_any"] == [], "None")
must(list(sched.serialize_action(legacy)) == ["id", "module_id", "label", "description", "target_types", "permission", "permission_any", "dangerous", "timeout_seconds"],
     "the old keys keep their order and the new key follows permission")

# ------------------------------------------------------------------------------------------------ the browser lists follow the same rule (AD-12)
listing = sv.SchedulerActionListView().get(SimpleNamespace(user=tech)).data
ids = {a["id"] for a in listing["actions"]}
must("patching.single" in ids and "patching.anyof" in ids and "patching.legacy" not in ids and "patching.open" not in ids, ids)
must(listing["manage"] is False, listing)
permitted = sv.SchedulerRunListView._permitted_action_ids(tech)
must({"patching.single", "patching.anyof"} <= permitted and "patching.legacy" not in permitted, "run history visibility")
must("patching.single" not in {a["id"] for a in sv.SchedulerActionListView().get(SimpleNamespace(user=plain)).data["actions"]}, "denied means hidden")
for who, ok in ((tech, True), (plain, False)):
    try:
        sv._require_action(who, "patching.single")
        must(ok, "refused user got through")
    except PermissionDenied:
        must(not ok, "holder was refused")

# ------------------------------------------------------------------------------------------------ one-off start and the AD-13 re-check
reset()
try:
    sched.start_one_off_run(user=plain, owner_module="patching", action_id="patching.single", targets=None)
    raise AssertionError("a user without the flag must be refused")
except sched.SchedulerNotAllowed:
    pass
must(not Schedule.objects.rows and not Run.objects.rows and not QUEUED, "a refused start creates nothing")
run = sched.start_one_off_run(user=tech, owner_module="patching", action_id="patching.single", targets=None)
must(run.status == "queued" and QUEUED == [str(run.id)], run.__dict__)
# the owner still holds the flag: the handler runs
must(execute(run) == {"ok": True} and run.status == "succeeded" and len(CONTEXTS) == 1, run.__dict__)
# the flag is removed between start and run: skipped, audited, the handler never called
reset()
tech_role = tech._role
run = sched.start_one_off_run(user=tech, owner_module="patching", action_id="patching.single", targets=None)
del AUDITS[:]
tech_role.can_manage_winupdates = False
out = execute(run)
must(run.status == "skipped" and run.error_type == "AuthorizationRevoked" and "no longer has permission" in run.error, run.__dict__)
must(not CONTEXTS and isinstance(out, str) and out.startswith("run skipped"), (out, CONTEXTS))
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "deny" and AUDITS[0]["object_id"] == str(run.id), AUDITS)
tech_role.can_manage_winupdates = True
# any-of: the owner keeps one of two entries, so the run goes ahead; with both gone it is skipped
dual = User("dual", Granted(8, can_manage_winupdates=True))
GRANTS.add((8, "patching.run"))
reset()
run = sched.start_one_off_run(user=dual, owner_module="patching", action_id="patching.anyof", targets=None)
dual._role.can_manage_winupdates = False
must(execute(run) == {"ok": True} and run.status == "succeeded", "the code entry still holds")
reset()
run = sched.start_one_off_run(user=dual, owner_module="patching", action_id="patching.anyof", targets=None)
GRANTS.discard((8, "patching.run"))
must(execute(run).startswith("run skipped") and run.status == "skipped", "both entries gone: skipped")
# a user-owned schedule is re-checked the same way (_runtime_authorization_error)
user_schedule = Schedule.objects.create(name="u", module_id="patching", action_id="patching.single", owner_type="user", created_by=tech, targets={"type": "none"})
must(sched._runtime_authorization_error(user_schedule) is None, "holder")
tech_role.can_manage_winupdates = False
must(sched._runtime_authorization_error(user_schedule) == "Schedule owner no longer has permission to run this action.", "flag removed")
tech_role.can_manage_winupdates = True
# an installer user never passes for a one-off run, even with the flag set on the role
reset()
try:
    sched.start_one_off_run(user=installer, owner_module="patching", action_id="patching.single", targets=None)
    raise AssertionError("an installer user must be refused")
except sched.SchedulerNotAllowed:
    pass

# ------------------------------------------------------------------------------------------------ the public contract and docs name the forms
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
for needle in ("tactical:can_manage_winupdates", "permission_any", "any-of"):
    must(needle in contracts, f"contracts.py names {needle}")
for doc in ("docs/scheduler.md", "docs/module-scheduling.md"):
    text = (ROOT / doc).read_text(encoding="utf-8")
    must("tactical:can_manage_winupdates" in text and "any-of" in text, f"{doc} documents the forms")

print("[TEST] PASS scheduler tactical permission 1.17.17")
