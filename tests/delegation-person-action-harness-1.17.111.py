#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""Shared stub harness for the 1.17.111 person-action delegation tests (exec'd by them, like delegated-targets-harness-1.17.74.py, which it follows).

On top of scheduler-completion-harness-1.17.61.py it adds the REAL ``system_action_confirmation.py`` and ``delegation.py``, Maintenance (the owner module the allow-list names),
WAPM (the provider of the person action ``wapm.profile-install``, which its signed manifest lists under ``scheduler_person_actions``) and Advanced Patch Management with its
Tactical-function action ``patchmanagement.install`` (the system-action path that must stay as it was). Module code is compiled under each module's folder, so the real frame walk
names the caller. The permission check is the REAL ``delegation._holds_permission`` over a stub ``tec_tac.rbac``. No Django, no database, no network.

Run on its own, this file only builds the harness and prints nothing.
"""
from __future__ import annotations

import dataclasses  # noqa: F401 - used by the tests that exec this file
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"
deleg = load("tec_tac.delegation", "delegation.py")
assert deleg.DECISION_RECORDED is True
deleg._secret = lambda: b"test-secret-key"
CLOCK = [1_000_000.0]
deleg._clock = lambda: CLOCK[0]
conf._clock = lambda: CLOCK[0]

ACTION = "wapm.profile-install"  # the person action AD-43 lets Maintenance start unattended
OTHER_ACTION = "wapm.profile-reboot"  # a person action of the same module that Core does NOT allow to be delegated
INSTALL = "patchmanagement.install"  # the Tactical-function action: the system-action path
BOTH = ("can_manage_winupdates", "can_run_bulk")
PERMISSION = "wapm.manage"
roots: dict = {}
mods: dict = {}
alice, bob, carol = User("alice"), User("bob"), User("carol")
CALLS: list = []
PERSON_LISTED: dict = {}  # module id -> the ids its signed manifest lists under scheduler_person_actions
EXT_PERMS: dict = {}  # username -> the extension permission codes the person holds
MANAGERS: set = set()  # usernames that are native scheduler managers (the strict check must not read this)
sched._manifest_person_actions = lambda module_id: tuple(PERSON_LISTED.get(module_id, ()))
sys.modules["tec_tac.rbac"].has_extension_permission = lambda user, code: code in EXT_PERMS.get(user.username, ())  # the real _holds_permission reads this, never the manager shortcut
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: user.username in MANAGERS or PERMISSION in EXT_PERMS.get(user.username, ())  # the bypass the strict check must never use

HANDLER_SRC = (
    "def handler(context):\n"
    "    CALLS.append(dict(context.get('parameters') or {}))\n"
    "    return {'ok': True}\n"
    "def describe(sa, request, **kw):\n    return sa.describe_delegation(request, **kw)\n"
    "def register(sa, request, **kw):\n    return sa.register_delegation_grant(request, **kw)\n"
    "def remove(sa, **kw):\n    return sa.remove_delegation_grant(**kw)\n"
    "def issue(sa, context, **kw):\n    return sa.issue_delegation_ticket(context, **kw)\n"
    "def start(sa, ticket, **kw):\n    return sa.start_delegated_run(ticket, **kw)\n"
    "def resolve(sa, ticket, **kw):\n    return sa.resolve_delegated_targets(ticket, **kw)\n"
)


class RealRequest:
    def __init__(self, user, session=True):
        self.user = user
        self.tec_tac_session = object() if session else None


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
sched._verified_person = lambda request: request.user if isinstance(request, RealRequest) and request.tec_tac_session is not None else (_ for _ in ()).throw(sched.SchedulerNotAllowed("no person"))
deleg._person_covers = lambda person, action, targets: True
real_queue = deleg._queue
ROWS = {pk: dict(agent_id=str(pk), hostname=f"h{pk}", platform="windows", client_id=client, site_id=site) for pk, client, site in ((1, 10, 100), (2, 10, 101), (3, 20, 200), (4, 30, 300))}
TARGETS = {"type": "profile", "ids": [7]}
GK = "profile:7"
CONFIRMED = {"profile_id": 7, "dry_run": False, "note": "nightly"}
PARAMS = {sa.PARAMETERS_KEY: CONFIRMED}


def fresh(*, delegable=("maintenance",)):
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    PERSON_LISTED.clear()
    EXT_PERMS.clear()
    MANAGERS.clear()
    CALLS.clear()
    sa._clear_for_tests()
    sched._ACTIONS.clear()
    deleg.PERSON_ACTION_DELEGATION.clear()
    deleg.PERSON_ACTION_DELEGATION.update({"maintenance": (ACTION,)})
    roots["maintenance"] = plugin("maintenance", category="core", system_actions=[])
    roots["wapm"] = plugin("wapm", category="premium", system_actions=[])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=[INSTALL])
    roots["patching"] = plugin("patching", system_actions=[])
    HONOURED["patchmanagement"] = "patching"
    PERSON_LISTED["wapm"] = (ACTION, OTHER_ACTION)
    for name in ("maintenance", "wapm", "patchmanagement"):
        mods[name] = compile_as(roots[name] / "apps.py", HANDLER_SRC, sa=sa, CALLS=CALLS)
    handler = mods["wapm"]["handler"]
    sched.register_scheduled_action(id=ACTION, module_id="wapm", label="WAPM profile install", handler=handler, target_types=("none", "endpoint", "profile"), permission=PERMISSION, timeout_seconds=600, delegable_to=delegable)
    sched.register_scheduled_action(id=OTHER_ACTION, module_id="wapm", label="WAPM profile reboot", handler=handler, target_types=("none", "endpoint", "profile"), permission=PERMISSION, timeout_seconds=600)
    sched.register_scheduled_action(id=INSTALL, module_id="patchmanagement", label="APM install", handler=mods["patchmanagement"]["handler"], target_types=("none", "endpoint", "profile"), timeout_seconds=600)
    sched.register_scheduled_action(id="maintenance.profile-run", module_id="maintenance", label="Maintenance profile run", handler=lambda context: {"ok": True}, target_types=("none",), timeout_seconds=600)
    sa.register_system_action(INSTALL, "patchmanagement", "Advanced Patch Management install", "winupdate.install", BOTH, delegable_to=("maintenance",))
    for user in (alice, bob, carol):
        user.is_active = True
        user.is_installer_user = False
        FLAGS[user.username] = set(BOTH)
        SCOPE[user.username] = {1, 2, 3, 4}
        EXT_PERMS[user.username] = {PERMISSION}
    AGENT_ROWS.update({pk: dict(row) for pk, row in ROWS.items()})
    for who in ("alice", "bob", "carol"):
        DESCRIPTORS[who] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {1, 2}
    CLOCK[0] = 1_000_000.0
    deleg._queue = real_queue


def call(module, name, *args, **kw):
    return mods[module][name](sa, *args, **kw)


def describe(user=alice, *, caller="maintenance", **over):
    kw = dict(owner_module="maintenance", provider_module="wapm", action_id=ACTION, targets=TARGETS, parameters=PARAMS)
    kw.update(over)
    return call(caller, "describe", RealRequest(user), **kw)


def register(token, user=alice, *, caller="maintenance", **over):
    kw = dict(owner_module="maintenance", grant_key=GK, provider_module="wapm", action_id=ACTION, targets=TARGETS, parameters=PARAMS, confirmation_id=token)
    kw.update(over)
    return call(caller, "register", RealRequest(user), **kw)


def save_grant(user=alice, **over):
    return register(describe(user, **{k: v for k, v in over.items() if k in ("targets", "parameters", "action_id", "provider_module")})["confirmation_id"], user, **over)


def refused(call_, reason, kind=deleg.DelegationRefused):
    try:
        call_()
    except kind as exc:
        must(getattr(exc, "reason", None) == reason, (reason, getattr(exc, "reason", None), str(exc)))
        return exc
    raise AssertionError(f"accepted instead of {reason}")


def deny_rows():
    return [a for a in AUDITS if a["action"] == "deny"]


def grants():
    return Grant.objects.rows


def live_context(module="maintenance", action="maintenance.profile-run"):
    run = make_run(action, module, owner="module", status="running", targets={"type": "none"})
    return rc.issue_run_context({"run_id": str(run.id)}, run_id=run.id), run


def ticket(key=GK):
    context, _run = live_context()
    return call("maintenance", "issue", context, grant_key=key)
