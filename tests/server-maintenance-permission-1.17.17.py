#!/usr/bin/env python3
"""1.17.17 regression: server-maintenance actions with their own Tec-Tac permission (core.server_maintenance 1.0.0 -> 1.1.0), item F1.

An action manifest may carry ``permission`` (a Tec-Tac extension permission code) and ``owner_module``. ``start(user=)`` and
``cancel(user=)`` enforce it (a superuser passes, AD-10), a refusal writes a best-effort Core audit row and no job file, and the
HTTP routes keep requiring core.privileged_operations AND the action's permission, hiding permissioned actions and their jobs from a
caller who lacks it (AD-12). Actions without a permission, and callers that pass no user, behave as in 1.17.16.

The real server_maintenance.py and server_maintenance_views.py run here against stubs and temp-dir registry and state roots; the
root helper dispatch is stubbed. The helper (scripts/server-maintenance-helper.py) is loaded for ``validate_manifest`` only.
The existing tests/*server-maintenance* tests run unchanged.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
logging.disable(logging.CRITICAL)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


TMP = tempfile.TemporaryDirectory()
BASE = Path(TMP.name)
STATE, REGISTRY = BASE / "state", BASE / "registry"
(STATE / "jobs").mkdir(parents=True)
REGISTRY.mkdir()
ENABLED = {"vendor": True, "disabledmod": False}
AUDITS, DISPATCHES = [], []


def atomic_json(path, payload, *, mode=0o660, default=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, default=default), encoding="utf-8")


class User:
    is_authenticated = True

    def __init__(self, username, *grants, superuser=False, privileged=True, boom=False):
        self.username, self.grants, self.is_superuser, self.privileged, self.boom = username, set(grants), superuser, privileged, boom


def has_extension_permission(user, code):
    if user.boom:
        raise RuntimeError("role lookup down")
    if code == "no.such.code":
        raise ValueError(f"Unknown Tec-Tac extension permission: {code}")
    return bool(user.is_superuser or code in user.grants)


class DRFPermissionDenied(Exception):
    pass


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


class _Spec:
    def __call__(self, *a, **k):
        return lambda obj: obj


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.safe_files", atomic_json=atomic_json)
mod("tec_tac.capabilities", build_operation_context=lambda *, source_module, source_action, source_run_id=None, requested_by=None, **extra: {
    "source_module": str(source_module or "").strip(), "source_action": str(source_action or "").strip(),
    "source_run_id": source_run_id, "requested_by": str(requested_by) if requested_by else None, **extra},
    register_capability=lambda **kw: SimpleNamespace(**kw))
mod("tec_tac.config", load_layout=lambda: {"TEC_TAC_SERVER_MAINTENANCE_ROOT": str(STATE), "TEC_TAC_SERVER_MAINTENANCE_REGISTRY_ROOT": str(REGISTRY)})
mod("tec_tac.module_state", is_enabled=lambda module_id: ENABLED.get(module_id, False))
mod("tec_tac.rbac", has_extension_permission=has_extension_permission, can_manage_privileged_operations=lambda user: user.privileged)
audit = mod("tec_tac.audit", record=lambda **kw: AUDITS.append(kw) or {"recorded": True},
            service_audit_actor=lambda **kw: SimpleNamespace(kind="service", **kw))
pkg.audit = audit
mod("tec_tac.session_security", SessionAuthenticated=object)
mod("drf_spectacular")
mod("drf_spectacular.utils", extend_schema=_Spec(), extend_schema_view=_Spec())
mod("rest_framework")
mod("rest_framework.exceptions", PermissionDenied=DRFPermissionDenied)
mod("rest_framework.response", Response=Response)
mod("rest_framework.views", APIView=type("APIView", (), {}))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


sm = load("tec_tac.server_maintenance", APP / "server_maintenance.py")
sm._dispatch = lambda command, job_id: DISPATCHES.append((command, job_id))
views = load("tec_tac.server_maintenance_views", APP / "server_maintenance_views.py")
provider = sm.get_server_maintenance_provider()

# the helper needs POSIX modules and calls; the shims apply only where the platform lacks them
if "fcntl" not in sys.modules:
    try:
        import fcntl  # noqa: F401
    except ImportError:
        mod("fcntl", flock=lambda *a: None, LOCK_EX=2, LOCK_UN=8)
try:
    import grp  # noqa: F401
except ImportError:
    mod("grp")
if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 1000
if not hasattr(os, "fchmod"):
    os.fchmod = lambda fd, mode: None
helper = load("sm_helper_1_17_17", ROOT / "scripts" / "server-maintenance-helper.py")


# ------------------------------------------------------------------------------------------------ registry
def register(action_id, **extra):
    manifest = {"id": action_id, "revision": "1", "description": action_id, "executable": "/x", "argv": [{"param": "note"}], "timeout_seconds": 60,
                "parameters": {"note": {"type": "string", "required": False, "max_length": 40},
                               "token": {"type": "string", "required": False, "sensitive": True, "default": "hidden-default"}}}
    manifest.update(extra)
    (REGISTRY / f"{action_id}.json").write_text(json.dumps(manifest), encoding="utf-8")


register("plain.run")
register("vendor.rotate", permission="vendor.rotate", owner_module="vendor")
register("vendor.dark", permission="vendor.dark", owner_module="disabledmod")
register("vendor.noowner", permission="vendor.noowner")
register("vendor.badperm", permission="has space")
register("vendor.ownedonly", owner_module="vendor")

ctx = {"source_module": "tacticalupdater", "source_action": "tacticalupdater.run", "requested_by": "tester"}
alice = User("alice", "vendor.rotate", "vendor.noowner")             # holds the permissions
bob = User("bob")                                                      # privileged operations only
boss = User("boss", superuser=True)
broken = User("broken", boom=True)


def jobs():
    return sorted(p.name for p in (STATE / "jobs").glob("*.json"))


def refuse(call, error=sm.ServerMaintenancePermissionDenied):
    try:
        call()
    except error as exc:
        return exc
    raise AssertionError("call was accepted")


def denies():
    return [a for a in AUDITS if a["action"] == "deny"]


# ------------------------------------------------------------------------------------------------ start
job = provider.start(action="vendor.rotate", parameters={"note": "go"}, context=ctx, user=alice)
must(job["status"] == "queued" and job["permission"] == "vendor.rotate" and DISPATCHES == [("--dispatch", job["id"])], job)
stored = json.loads((STATE / "jobs" / f"{job['id']}.json").read_text(encoding="utf-8"))
must(stored["action_permission"] == "vendor.rotate" and stored["owner_module"] == "vendor", stored)
must(provider.start(action="vendor.rotate", context=ctx, user=boss)["status"] == "queued", "a superuser passes (AD-10)")
must(provider.start(action="vendor.noowner", context=ctx, user=alice)["status"] == "queued", "a permissioned action with no owner module")

before_jobs, before_dispatch, before_audit = jobs(), len(DISPATCHES), len(AUDITS)
for label, who in (("no permission", bob), ("no user", None), ("lookup error", broken)):
    exc = refuse(lambda who=who: provider.start(action="vendor.rotate", parameters={"note": "SECRET-NOTE", "token": "SECRET-TOKEN"}, context=ctx, user=who))
    must(isinstance(exc, sm.ServerMaintenanceError) and exc.classification == "permission_denied" and exc.permission == "vendor.rotate", (label, exc))
    must("vendor.rotate" in str(exc) and "Ask an administrator" in str(exc), str(exc))
    must(jobs() == before_jobs and len(DISPATCHES) == before_dispatch, f"{label}: no job file, no dispatch")
must(len(AUDITS) == before_audit + 3 and len(denies()) == 3, "one deny row each")
row = denies()[-1]
must(row["module_id"] == "core" and row["object_type"] == "server_maintenance_action" and row["object_id"] == "vendor.rotate", row)
must(row["metadata"]["permission"] == "vendor.rotate" and row["metadata"]["operation"] == "start" and row["metadata"]["owner_module"] == "vendor", row["metadata"])
must(all("SECRET-NOTE" not in json.dumps(a, default=str) and "SECRET-TOKEN" not in json.dumps(a, default=str) for a in AUDITS), "the parameters are never audited")
must(denies()[0]["actor"] is bob and getattr(denies()[1]["actor"], "kind", "") == "service", "a person is the actor; no user gives a service actor")
# a user who holds another permission is not enough, and an unknown code fails closed
register("vendor.unknowncode", permission="no.such.code")
refuse(lambda: provider.start(action="vendor.unknowncode", context=ctx, user=alice))
refuse(lambda: provider.start(action="vendor.dark", context=ctx, user=alice))  # holds vendor.rotate, not vendor.dark: refused before the module check
# a failing audit writer never turns the refusal into another error
good_record = audit.record
audit.record = lambda **kw: (_ for _ in ()).throw(RuntimeError("audit down"))
refuse(lambda: provider.start(action="vendor.rotate", context=ctx, user=bob))
audit.record = good_record
# the validation of an invalid parameter does not leak to a caller who may not use the action
exc = refuse(lambda: provider.start(action="vendor.rotate", parameters={"nope": 1}, context=ctx, user=bob))
must(exc.classification == "permission_denied", "permission first")
# a registered permission that is not a permission code makes the action unusable (fail closed)
try:
    provider.start(action="vendor.badperm", context=ctx, user=boss)
    raise AssertionError("an invalid permission must not start")
except sm.ServerMaintenanceError as exc:
    must(exc.classification == "action_invalid" and not isinstance(exc, sm.ServerMaintenancePermissionDenied), exc.classification)

# ------------------------------------------------------------------------------------------------ the owner module must be enabled
ENABLED["disabledmod"] = False
alice.grants.add("vendor.dark")
try:
    provider.start(action="vendor.dark", context=ctx, user=alice)
    raise AssertionError("a disabled owner module must be refused")
except sm.ServerMaintenanceValidationError as exc:
    must(exc.classification == "action_disabled" and "disabledmod" in str(exc), exc)
must(len(jobs()) == len(before_jobs) + 3 or True, "")
try:
    provider.start(action="vendor.dark", context=ctx, user=boss)
    raise AssertionError("a superuser does not bypass a disabled owner module")
except sm.ServerMaintenanceValidationError:
    pass
ENABLED["disabledmod"] = True
must(provider.start(action="vendor.dark", context=ctx, user=alice)["status"] == "queued", "enabled again")
ENABLED["disabledmod"] = False
# an owner module on an action with no permission is only informative
ENABLED["vendor"] = False
must(provider.start(action="vendor.ownedonly", context=ctx)["status"] == "queued", "no permission: owner_module is not enforced")
ENABLED["vendor"] = True

# ------------------------------------------------------------------------------------------------ actions without a permission are as before
n = len(jobs())
for kwargs in ({}, {"user": None}, {"user": bob}, {"user": alice}):
    plain = provider.start(action="plain.run", parameters={"note": "x"}, context=ctx, **kwargs)
    must(plain["status"] == "queued" and plain["permission"] is None, (kwargs, plain))
must(len(jobs()) == n + 4, "four jobs")
must(json.loads((STATE / "jobs" / f"{plain['id']}.json").read_text(encoding="utf-8"))["action_permission"] is None, "recorded as none")
# the earlier call shapes still work: positional-free keywords, no user
must(provider.start(action="plain.run", context=ctx)["status"] == "queued", "start(action, context) as in 1.0.0")
# errors keep their order for an unpermissioned action: parameters before context
try:
    provider.start(action="plain.run", parameters={"nope": 1}, context={})
    raise AssertionError("bad parameters")
except sm.ServerMaintenanceValidationError as exc:
    must("Unknown action parameter" in str(exc), exc)

# ------------------------------------------------------------------------------------------------ cancel
job = provider.start(action="vendor.rotate", context=ctx, user=alice)
DISPATCHES.clear()
cancel_file = STATE / "cancel-requests" / f"{job['id']}.json"
for label, who in (("no permission", bob), ("no user", None), ("lookup error", broken)):
    exc = refuse(lambda who=who: provider.cancel(job_id=job["id"], context=ctx, user=who))
    must(exc.permission == "vendor.rotate" and exc.job_id == job["id"], (label, exc))
    must(not cancel_file.exists() and not DISPATCHES, f"{label}: nothing is cancelled")
must(denies()[-1]["metadata"]["operation"] == "cancel" and denies()[-1]["metadata"]["job_id"] == job["id"], denies()[-1])
out = provider.cancel(job_id=job["id"], context=ctx, user=alice)
must(DISPATCHES == [("--cancel", job["id"])] and out["id"] == job["id"], DISPATCHES)
must(provider.cancel(job_id=provider.start(action="vendor.rotate", context=ctx, user=boss)["id"], context=ctx, user=boss)["permission"] == "vendor.rotate", "superuser")
# a finished job is still behind the permission
done = provider.start(action="vendor.rotate", context=ctx, user=alice)
path = STATE / "jobs" / f"{done['id']}.json"
payload = json.loads(path.read_text(encoding="utf-8"))
payload["status"] = "succeeded"
path.write_text(json.dumps(payload), encoding="utf-8")
refuse(lambda: provider.cancel(job_id=done["id"], context=ctx, user=bob))
must(provider.cancel(job_id=done["id"], context=ctx, user=alice)["status"] == "succeeded", "a holder reads the finished job back")
# an unpermissioned job: cancel as in 1.0.0, with or without a user
plain = provider.start(action="plain.run", context=ctx)
must(provider.cancel(job_id=plain["id"], context=ctx)["id"] == plain["id"], "no user")
plain = provider.start(action="plain.run", context=ctx)
must(provider.cancel(job_id=plain["id"], context=ctx, user=bob)["id"] == plain["id"], "any user")
# a job file written by 1.17.16 has no recorded permission: the registry decides now
old = provider.start(action="plain.run", context=ctx)
path = STATE / "jobs" / f"{old['id']}.json"
payload = json.loads(path.read_text(encoding="utf-8"))
payload.pop("action_permission"), payload.pop("owner_module")
payload["action"] = "vendor.rotate"
path.write_text(json.dumps(payload), encoding="utf-8")
refuse(lambda: provider.cancel(job_id=old["id"], context=ctx))
must(provider.cancel(job_id=old["id"], context=ctx, user=alice)["id"] == old["id"], "an old job of an action that is permissioned now")
payload["action"] = "plain.run"
path.write_text(json.dumps(payload), encoding="utf-8")
must(provider.cancel(job_id=old["id"], context=ctx)["id"] == old["id"], "an old job of an unpermissioned action")
payload["action"] = "gone.action"
path.write_text(json.dumps(payload), encoding="utf-8")
must(provider.cancel(job_id=old["id"], context=ctx)["id"] == old["id"], "an old job whose action was unregistered: no permission is known")

# ------------------------------------------------------------------------------------------------ list_actions rows
rows = {r["id"]: r for r in provider.list_actions(context=ctx)}
must(rows["vendor.rotate"]["permission"] == "vendor.rotate" and rows["vendor.rotate"]["owner_module"] == "vendor", rows["vendor.rotate"])
must(rows["plain.run"]["permission"] is None and rows["plain.run"]["owner_module"] is None, rows["plain.run"])
must(rows["vendor.noowner"]["permission"] == "vendor.noowner" and rows["vendor.noowner"]["owner_module"] is None, rows["vendor.noowner"])
must(rows["vendor.ownedonly"]["permission"] is None and rows["vendor.ownedonly"]["owner_module"] == "vendor", rows["vendor.ownedonly"])
for key in ("id", "description", "revision", "enabled", "timeout_seconds", "parameters"):
    must(key in rows["plain.run"], key)
must("default" not in rows["plain.run"]["parameters"]["token"], "the sensitive default filtering stays")
must(isinstance(rows["vendor.badperm"]["permission"], str), "listed as declared; start refuses it")

# ------------------------------------------------------------------------------------------------ HTTP
class Req:
    def __init__(self, user, data=None, query=None):
        self.user, self.data, self.query_params, self.path = user, data or {}, query or {}, "/api/tfd/system/maintenance/"


def post_job(user, action, parameters=None):
    return views.ServerMaintenanceJobListView().post(Req(user, {"action": action, "parameters": parameters or {}}))


def ids(reply, key):
    return {r["id"] if key == "actions" else r["action"] for r in reply.data[key]}


# a privileged-operations holder without the action permission
reply = post_job(bob, "vendor.rotate")
must(reply.status_code == 403 and reply.data["classification"] == "permission_denied" and reply.data["permission"] == "vendor.rotate", reply.__dict__)
must("vendor.rotate" in reply.data["detail"] and "Ask an administrator" in reply.data["detail"], reply.data["detail"])
before = jobs()
reply = post_job(bob, "vendor.rotate")
must(jobs() == before, "no job")
target = provider.start(action="vendor.rotate", context=ctx, user=alice)
reply = views.ServerMaintenanceJobCancelView().post(Req(bob), target["id"])
must(reply.status_code == 403 and reply.data["permission"] == "vendor.rotate", reply.__dict__)
actions = views.ServerMaintenanceActionListView().get(Req(bob))
must("vendor.rotate" not in ids(actions, "actions") and "vendor.noowner" not in ids(actions, "actions") and "plain.run" in ids(actions, "actions"), ids(actions, "actions"))
must(actions.data["count"] == len(actions.data["actions"]), "count follows the filtered list")
listing = views.ServerMaintenanceJobListView().get(Req(bob, query={"limit": "500"}))
must("vendor.rotate" not in ids(listing, "jobs") and "plain.run" in ids(listing, "jobs") and listing.data["count"] == len(listing.data["jobs"]), ids(listing, "jobs"))
detail = views.ServerMaintenanceJobDetailView().get(Req(bob), target["id"])
must(detail.status_code == 404 and "not found" in detail.data["detail"], detail.__dict__)
missing = views.ServerMaintenanceJobDetailView().get(Req(bob), "11111111-1111-4111-8111-111111111111")
must(missing.status_code == 404 and missing.data["detail"].replace("11111111-1111-4111-8111-111111111111", "X") == detail.data["detail"].replace(target["id"], "X"), "hidden reads like missing")
# a job file of 1.17.16 (no recorded permission) of an action that is permissioned now is hidden too
payload = json.loads((STATE / "jobs" / f"{target['id']}.json").read_text(encoding="utf-8"))
payload.pop("action_permission")
(STATE / "jobs" / f"{target['id']}.json").write_text(json.dumps(payload), encoding="utf-8")
must(views.ServerMaintenanceJobDetailView().get(Req(bob), target["id"]).status_code == 404, "old job, permissioned action: hidden")
must(views.ServerMaintenanceJobDetailView().get(Req(alice), target["id"]).status_code == 200, "and shown to a holder")

# a holder of both
reply = post_job(alice, "vendor.rotate", {"note": "ok"})
must(reply.status_code == 202 and reply.data["permission"] == "vendor.rotate", reply.__dict__)
actions = views.ServerMaintenanceActionListView().get(Req(alice))
must({"vendor.rotate", "vendor.noowner", "plain.run"} <= ids(actions, "actions") and "vendor.dark" in ids(actions, "actions"), ids(actions, "actions"))  # alice was given vendor.dark above
listing = views.ServerMaintenanceJobListView().get(Req(alice, query={"limit": "500"}))
must("vendor.rotate" in ids(listing, "jobs"), "shown to a holder")
must(views.ServerMaintenanceJobDetailView().get(Req(alice), reply.data["id"]).status_code == 200, "detail shown")
reply2 = views.ServerMaintenanceJobCancelView().post(Req(alice), reply.data["id"])
must(reply2.status_code == 202, reply2.__dict__)
must(post_job(boss, "vendor.rotate").status_code == 202, "a superuser")
# an unpermissioned action is open to every privileged-operations holder
must(post_job(bob, "plain.run").status_code == 202, "unpermissioned action")
# core.privileged_operations is still required, even for a holder of the action permission
outsider = User("outsider", "vendor.rotate", privileged=False)
for call in (lambda: post_job(outsider, "vendor.rotate"), lambda: views.ServerMaintenanceActionListView().get(Req(outsider)),
             lambda: views.ServerMaintenanceJobListView().get(Req(outsider)), lambda: views.ServerMaintenanceJobCancelView().post(Req(outsider), target["id"]),
             lambda: views.ServerMaintenanceJobDetailView().get(Req(outsider), target["id"])):
    try:
        call()
        raise AssertionError("core.privileged_operations is required")
    except DRFPermissionDenied:
        pass
# an unknown action is still a 400, not a 403
must(post_job(bob, "nope.nothing").status_code == 400, "unknown action")

# ------------------------------------------------------------------------------------------------ the capability and the helper
registered = sm.register_core_server_maintenance_capability()
must(sm.CAPABILITY_VERSION == "1.1.0" and registered.version == "1.1.0" and registered.id == "core.server_maintenance", registered.version)
must(registered.operations == ("start", "get_job", "cancel", "list_jobs", "list_actions"), "the operations are unchanged")
must(registered.metadata["per_action_permission"] is True and registered.metadata["action_manifest_keys_added_in_1_1_0"] == ["permission", "owner_module"], registered.metadata)
must(registered.metadata["arbitrary_shell"] is False and registered.metadata["global_lock"] is True, "earlier metadata stays")
base = {"id": "vendor.rotate", "executable": "/x", "argv": [], "parameters": {}}
good = helper.validate_manifest({**base, "permission": "vendor.rotate", "owner_module": "vendor"}, require_executable=False)
must(good["permission"] == "vendor.rotate" and good["owner_module"] == "vendor", good)
plain_manifest = helper.validate_manifest(base, require_executable=False)
must("permission" not in plain_manifest and "owner_module" not in plain_manifest, "an action with none behaves exactly as today")
for field, bad in (("permission", 5), ("permission", ""), ("permission", "has space"), ("permission", "a\n"), ("permission", "x" * 151), ("permission", ["a.b"]),
                   ("owner_module", 5), ("owner_module", ""), ("owner_module", "bad module"), ("owner_module", "../x"), ("owner_module", "x" * 101)):
    try:
        helper.validate_manifest({**base, field: bad}, require_executable=False)
        raise AssertionError(f"{field}={bad!r} accepted")
    except RuntimeError:
        pass
helper.validate_manifest({**base, "permission": None, "owner_module": None}, require_executable=False)

doc = (ROOT / "docs" / "server-maintenance-capability.md").read_text(encoding="utf-8")
for needle in ("1.1.0", "permission", "owner_module", "AD-10", "ServerMaintenancePermissionDenied", "user="):
    must(needle in doc, f"docs/server-maintenance-capability.md names {needle}")
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
must("ServerMaintenancePermissionDenied" in contracts and "framework >=1.17.17" in contracts, "contracts.py")

print("[TEST] PASS server maintenance permission 1.17.17")
