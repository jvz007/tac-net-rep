#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""Shared stub harness for the 1.17.74 delegated-targets tests (exec'd by them, like system-writes-harness-1.17.70.py, which it follows).

On top of scheduler-completion-harness-1.17.61.py it adds: the REAL ``system_action_confirmation.py`` and ``delegation.py``, Maintenance (a core module that may be
delegated to), Windows Patching and the premium replacement ``patchmanagement`` of ``patching`` (the provider of the delegated install, a task row) and a handler compiled under
each module's folder, so the real frame walk names the caller. No Django, no database, no network.

Run on its own, this file only builds the harness and prints nothing.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"
deleg = load("tec_tac.delegation", "delegation.py")
deleg._secret = lambda: b"test-secret-key"
CLOCK = [1_000_000.0]
deleg._clock = lambda: CLOCK[0]
conf._clock = lambda: CLOCK[0]

ACTION = "patchmanagement.install"  # the delegable task row: the install of the honoured replacement (also its Scheduler action)
BOTH = ("can_manage_winupdates", "can_run_bulk")
BASE = 1000
roots: dict = {}
mods: dict = {}
alice, bob = User("alice"), User("bob")
CFG = {"action_id": ACTION, "agents": []}
HANDLER_SRC = (
    "def handler(context):\n"
    "    CFG['last'] = sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
    "    return CFG['last']\n"
    "def write_handler(context):\n"
    "    return sa.run_system_write(context, action_id=CFG['action_id'], changes=[])\n"
    "def describe(sa, request, **kw):\n    return sa.describe_delegation(request, **kw)\n"
    "def register(sa, request, **kw):\n    return sa.register_delegation_grant(request, **kw)\n"
    "def remove(sa, **kw):\n    return sa.remove_delegation_grant(**kw)\n"
    "def issue(sa, context, **kw):\n    return sa.issue_delegation_ticket(context, **kw)\n"
    "def start(sa, ticket, **kw):\n    return sa.start_delegated_run(ticket, **kw)\n"
    "def resolve(sa, ticket, **kw):\n    return sa.resolve_delegated_targets(ticket, **kw)\n"
)
AUTO_TARGETS = lambda: {"type": "endpoint", "ids": [str(i) for i in CFG["agents"]]}  # noqa: E731 - the schedule targets exactly the endpoints in play


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
sched._verified_person = lambda request: request.user
deleg._person_covers = lambda person, action, targets: True
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: True
real_queue = deleg._queue
TARGETS = {"type": "profile", "ids": [7]}
GK = "profile:7"


def fresh(agents=3, *, register=True, delegable=("maintenance",)):
    """A clean world: ``agents`` endpoints that exist, Maintenance (core), Windows Patching and Advanced Patch Management (the honoured replacement) with
    ``patchmanagement.install`` registered as a delegable task row."""
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    sched._ACTIONS.clear()
    roots["maintenance"] = plugin("maintenance", category="core", system_actions=[])
    roots["patching"] = plugin("patching", system_actions=["patching.scan"])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=[ACTION])
    HONOURED["patchmanagement"] = "patching"
    for name in ("maintenance", "patchmanagement"):
        mods[name] = compile_as(roots[name] / "apps.py", HANDLER_SRC, sa=sa, CFG=CFG)
    sched.register_scheduled_action(id=ACTION, module_id="patchmanagement", label="APM install", handler=mods["patchmanagement"]["handler"], target_types=("none", "endpoint", "profile"), timeout_seconds=600)
    sched.register_scheduled_action(id="maintenance.profile-run", module_id="maintenance", label="Maintenance profile run", handler=lambda context: {"ok": True}, target_types=("none",), timeout_seconds=600)
    for user in (alice, bob):
        user.is_active = True
        FLAGS[user.username] = set(BOTH)
        SCOPE[user.username] = set(range(BASE, BASE + 41000))
    CFG.update(action_id=ACTION, agents=list(range(BASE, BASE + agents)))
    if register:
        sa.register_system_action(ACTION, "patchmanagement", "APM install", "winupdate.install", BOTH, delegable_to=delegable)
    # the delegation stand-ins: endpoints 1000.. in two clients, a module-owned profile target
    AGENT_ROWS.update({BASE + i: dict(agent_id=str(BASE + i), hostname=f"h{i}", platform="windows", client_id=10 if i < 2 else 20, site_id=100 + i) for i in range(agents)})
    for who in ("alice", "bob"):
        DESCRIPTORS[who] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {BASE, BASE + 1}
    CLOCK[0] = 1_000_000.0
    deleg._queue = real_queue


def start(agents=None, *, handler=ACTION, module="patchmanagement", retries=0, **kw):
    """A person-started run (manual) of the install handler. Returns ``(run, what the handler returned or raised)``."""
    if agents is not None:
        CFG["agents"] = list(agents)
    run = make_run(handler, module, user=alice, owner="user", retries=retries, manual=True, **kw)
    return run, go(run, retries=0)


def deny_reasons():
    return [a["metadata"]["reason"] for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def run_rows():
    return [a for a in AUDITS if a["action"] == "run" and a["object_type"] == "system_action"]


def group_marks(run):
    return [m for m in run.system_action_marks if m.get("kind") != "plan"]


# ---- delegation helpers (the path of delegation-run-1.17.68.py, with Advanced Patch Management as the provider and its install as the action)
def save_grant(user=alice, key=GK, targets=None, action_id=ACTION, provider="patchmanagement", **kw):
    request = RealRequest(user)
    base = dict(owner_module="maintenance", provider_module=provider, action_id=action_id, targets=targets or TARGETS, parameters=None)
    token = mods["maintenance"]["describe"](sa, request, **base)["confirmation_id"]
    return mods["maintenance"]["register"](sa, request, grant_key=key, confirmation_id=token, **base, **kw)


def live_context(module="maintenance", action="maintenance.profile-run"):
    run = make_run(action, module, owner="module", status="running", targets={"type": "none"})
    return rc.issue_run_context({"run_id": str(run.id)}, run_id=run.id), run


def ticket(key=GK):
    context, _run = live_context()
    return mods["maintenance"]["issue"](sa, context, grant_key=key)


def delegated_start(token, *, agents=None, action_id=ACTION, caller="patchmanagement"):
    return mods[caller]["start"](sa, token, action_id=action_id, agent_ids=agents if agents is not None else [BASE, BASE + 1])


def resolve(token, ids, *, action_id=ACTION, caller="patchmanagement"):
    return mods[caller]["resolve"](sa, token, action_id=action_id, endpoint_ids=ids)


def delegation_refused(call, reason):
    try:
        call()
    except deleg.DelegationRefused as exc:
        must(exc.reason == reason and isinstance(exc, sched.SchedulerNotAllowed) and isinstance(exc, sched.SchedulerPermanentError), (reason, exc.reason, str(exc)))
        return exc
    raise AssertionError(f"accepted instead of {reason}")
