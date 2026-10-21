#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.68 regression (S4): how Maintenance's unattended patch step starts Advanced Patch Management's scheduled install.

The real delegation.py, system_actions.py, system_action_confirmation.py, scheduler.py, scheduler_run_context.py and tasks.py on the stub harness of
scheduler-completion-harness-1.17.61.py. Module code is compiled under stub plugin folders, so the real frame walk decides who is calling.

Covered. (1) The whole path: a person confirms and saves a grant, Maintenance's LIVE run issues a ticket, the provider starts the delegated run, the provider's own handler calls the
unchanged run_system_action and the install is queued exactly once, with the person's owner DISABLED, demoted and out of the role scope. (2) The ticket: only from a context Core issued
for a run that is going and only for the run's module; signed, expired after 24 hours, a tampered or foreign ticket is refused; editing, re-saving, switching off or removing
the grant revokes it. (3) The start: only the provider the grant names, only for the action the grant holds, only while the provider still names the owner in delegable_to,
still lists the action, both modules are enabled and the replacement is honoured; endpoints inside the grant's targets AND the person's stored scope or nothing starts
(outside_grant), numbers shaped and counted before any lookup; the created schedule and run carry exactly what was confirmed; one strict audit row with no endpoint id; every
refusal one deny row with a reason; a queue fault leaves nothing behind; a strict audit failure starts nothing; the same ticket and endpoints never start a second install.
(4) The exemption: the delegated one-off is unattended ONLY while its marker (signed for that very schedule) verifies and its grant is unchanged; a copied marker, a plain
one-off, the switched-off amendment and an edited grant keep every re-check (CQ50). (5) wrong_module of run_system_action is unchanged.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"
deleg = load("tec_tac.delegation", "delegation.py")
assert deleg.DECISION_RECORDED is True  # AD-43 is signed: the module default is the live state this test pins; the switched-off behaviour is tested by setting the flag False explicitly
deleg._secret = lambda: b"test-secret-key"
CLOCK = [1_000_000.0]
deleg._clock = lambda: CLOCK[0]
conf._clock = lambda: CLOCK[0]

BOTH = ("can_manage_winupdates", "can_run_bulk")
INSTALL, SCAN = "patchmanagement.install", "patchmanagement.scan"
alice, bob = User("alice"), User("bob")
roots = {}
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: True


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
sched._verified_person = lambda request: request.user
deleg._person_covers = lambda person, action, targets: True

MODULE_SRC = (
    "def describe(sa, request, **kw):\n    return sa.describe_delegation(request, **kw)\n"
    "def register(sa, request, **kw):\n    return sa.register_delegation_grant(request, **kw)\n"
    "def remove(sa, **kw):\n    return sa.remove_delegation_grant(**kw)\n"
    "def issue(sa, context, **kw):\n    return sa.issue_delegation_ticket(context, **kw)\n"
    "def start(sa, ticket, **kw):\n    return sa.start_delegated_run(ticket, **kw)\n"
    "def handler(context):\n    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
)
CFG = {"action_id": INSTALL, "agents": [1, 2]}
mods = {}
ROWS = {pk: dict(agent_id=str(pk), hostname=f"h{pk}", platform="windows", client_id=client, site_id=site) for pk, client, site in ((1, 10, 100), (2, 10, 101), (3, 20, 200), (4, 30, 300))}
TARGETS = {"type": "profile", "ids": [7]}
GK = "profile:7"


def fresh():
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    sched._ACTIONS.clear()
    roots["maintenance"] = plugin("maintenance", category="core", system_actions=[])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=[INSTALL, SCAN])
    roots["patching"] = plugin("patching", system_actions=[])
    HONOURED["patchmanagement"] = "patching"
    for name in ("maintenance", "patchmanagement"):
        mods[name] = compile_as(roots[name] / "apps.py", MODULE_SRC, sa=sa, CFG=CFG)
    sched.register_scheduled_action(id=INSTALL, module_id="patchmanagement", label="APM install", handler=mods["patchmanagement"]["handler"], target_types=("none", "endpoint", "profile"), timeout_seconds=600)
    sched.register_scheduled_action(id=SCAN, module_id="patchmanagement", label="APM scan", handler=mods["patchmanagement"]["handler"], target_types=("none", "endpoint"), timeout_seconds=600)
    sched.register_scheduled_action(id="patchmanagement.plain", module_id="patchmanagement", label="APM plain", handler=lambda context: {"ok": True}, target_types=("none", "endpoint"), timeout_seconds=600)
    sched.register_scheduled_action(id="maintenance.profile-run", module_id="maintenance", label="Maintenance profile run", handler=lambda context: {"ok": True}, target_types=("none",), timeout_seconds=600)
    sa.register_system_action(INSTALL, "patchmanagement", "Advanced Patch Management install", "winupdate.install", BOTH, delegable_to=("maintenance",))
    sa.register_system_action(SCAN, "patchmanagement", "Advanced Patch Management scan", "winupdate.scan", BOTH)
    for user in (alice, bob):
        user.is_active = True
        FLAGS[user.username] = set(BOTH)
        SCOPE[user.username] = {1, 2, 3, 4}
    AGENT_ROWS.update({pk: dict(row) for pk, row in ROWS.items()})
    DESCRIPTORS["alice"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    DESCRIPTORS["bob"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {1, 2}
    CLOCK[0] = 1_000_000.0
    CFG.update(action_id=INSTALL, agents=[1, 2])
    deleg._queue = real_queue


real_queue = deleg._queue


def save_grant(user=alice, key=GK, targets=None, **kw):
    request = RealRequest(user)
    base = dict(owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=targets or TARGETS, parameters=None)
    token = mods["maintenance"]["describe"](sa, request, **base)["confirmation_id"]
    return mods["maintenance"]["register"](sa, request, grant_key=key, confirmation_id=token, **base, **kw)


def live_context(module="maintenance", action="maintenance.profile-run"):
    run = make_run(action, module, owner="module", status="running", targets={"type": "none"})
    return rc.issue_run_context({"run_id": str(run.id)}, run_id=run.id), run


def ticket(key=GK):
    context, _run = live_context()
    return mods["maintenance"]["issue"](sa, context, grant_key=key)


def start(token, *, agents=None, action_id=INSTALL, caller="patchmanagement"):
    return mods[caller]["start"](sa, token, action_id=action_id, agent_ids=agents if agents is not None else [1, 2])


def refused(call, reason):
    try:
        call()
    except deleg.DelegationRefused as exc:
        must(exc.reason == reason and isinstance(exc, sched.SchedulerNotAllowed) and isinstance(exc, sched.SchedulerPermanentError), (reason, exc.reason, str(exc)))
        return exc
    raise AssertionError(f"accepted instead of {reason}")


def deny_rows():
    return [a for a in AUDITS if a["action"] == "deny"]


def delegated_runs():
    return [r for r in Run.objects.rows if r.owner_module == "patchmanagement"]


def one_deny(reason):
    rows = deny_rows()
    must(len(rows) == 1 and rows[0]["metadata"]["reason"] == reason and rows[0]["metadata"]["requested_by"] == "delegation", (reason, rows))
    must(not any(x in repr(rows[0]["metadata"].values()) for x in ("[1, 2]", "[1, 4]", "agent_ids")), "no endpoint in a deny row")


# ---- (1) the whole path, with the owner disabled
fresh()
save_grant()
token = ticket()
del AUDITS[:]
run = start(token)
must(run.status == "queued" and QUEUED_IDS == [str(run.id)] and run.owner_module == "patchmanagement" and run.owner_type == "module" and run.manual is True, run.__dict__)
schedule = run.schedule
must(schedule.owner_module == "patchmanagement" and schedule.owner_key.startswith("one-off:") and schedule.enabled is False and schedule.schedule_type == "once", schedule.__dict__)
must(schedule.created_by is alice and schedule.created_by_username == "alice" and schedule.confirmed_by_username == "alice", "created by the person who confirmed")
must(schedule.targets == {"type": "endpoint", "ids": ["1", "2"]} and run.targets_snapshot == schedule.targets, "exactly the endpoints passed")
must(schedule.creation_scope == Grant.objects.rows[0].creation_scope and schedule.creation_scope["captured_for"] == "alice", "the grant's stored scope travels with the run")
must(deleg.MARKER_KEY in schedule.parameters and run.parameters_snapshot == schedule.parameters and schedule.action_id == INSTALL and schedule.module_id == "patchmanagement", schedule.parameters)
rows = [a for a in AUDITS if a["object_type"] == "scheduler_run"]
must(len(rows) == 1 and rows[0]["action"] == "add" and rows[0]["strict"] is True and rows[0]["actor"] is alice and rows[0]["object_id"] == str(run.id), rows)
meta = rows[0]["metadata"]
must(meta["owner_module"] == "maintenance" and meta["provider_module"] == "patchmanagement" and meta["grant_key"] == GK and meta["creator"] == "alice" and meta["total_agents"] == 2 and meta["groups"] == 1 and meta["requested_by"] == "delegation", meta)
must(not any(x in repr(meta) for x in ("'1'", "'2'", "[1, 2]", "agent_ids")), "no endpoint id in the audit row")
# Alice leaves the business: disabled, demoted, scope gone. The work she did is not undone.
alice.is_active = False
FLAGS["alice"] = set()
SCOPE["alice"] = set()
DESCRIPTORS["alice"] = {"mode": "none", "unrestricted": False, "whole_client_ids": [], "site_ids": []}
must(sched._is_unattended_scheduled_run(run) is True, "the delegated one-off is unattended")
out = go(run)
must(isinstance(out, dict) and out["outcome"] == "queued" and out["agents"] == 2, out)
must(len(TASK_CALLS) == 1 and TASK_CALLS[0][0] == "install" and sorted(TASK_CALLS[0][1][0]) == [1, 2], TASK_CALLS)
run_row = [a for a in AUDITS if a["action"] == "run"][0]
must(run_row["strict"] is True and run_row["metadata"]["creator"] == "alice" and run_row["metadata"]["owner_module"] == "patchmanagement" and run_row["metadata"]["total_agents"] == 2, run_row)
must(run.status == "succeeded", run.status)
print("       a person confirms once, Maintenance's live run issues a ticket, the provider starts the run and the install is queued once, with the person's account disabled and demoted")

# ---- (2) the ticket
fresh()
save_grant()
plain_context = {"run_id": "x"}
for label, bad in (("a plain dict", plain_context), ("a copy", None)):
    context, mrun = live_context()
    target = plain_context if label == "a plain dict" else dict(context)
    refused(lambda target=target: mods["maintenance"]["issue"](sa, target, grant_key=GK), "context_invalid")
context, mrun = live_context()
refused(lambda: mods["patchmanagement"]["issue"](sa, context, grant_key=GK), "wrong_module")  # the context is maintenance's
refused(lambda: sa.issue_delegation_ticket(context, grant_key=GK), "caller_unverified")
refused(lambda: mods["maintenance"]["issue"](sa, context, grant_key="BAD KEY"), "bad_grant_key")
refused(lambda: mods["maintenance"]["issue"](sa, context, grant_key="profile:9"), "grant_missing")
mrun.status = "succeeded"
refused(lambda: mods["maintenance"]["issue"](sa, context, grant_key=GK), "context_invalid")  # a finished run cannot issue one
context, mrun = live_context()
Grant.objects.rows[0].enabled = False
refused(lambda: mods["maintenance"]["issue"](sa, context, grant_key=GK), "grant_disabled")
Grant.objects.rows[0].enabled = True
good = mods["maintenance"]["issue"](sa, context, grant_key=GK)
must(isinstance(good, str) and good.count(".") == 1, good)
refused(lambda: start("garbage"), "ticket_invalid")
refused(lambda: start(good[:-3] + "000"), "ticket_invalid")  # a tampered signature
refused(lambda: start(None), "ticket_invalid")
refused(lambda: start(good.split(".")[0] + "." + "0" * 64), "ticket_invalid")
foreign = deleg._sign(b"tec-tac-delegation-confirmation-v1|", {"g": "x"})  # signed with the right secret, but a confirmation is not a ticket
refused(lambda: start(foreign), "ticket_invalid")
deleg._secret = lambda: b"another-secret"
other_token = ticket_ = None
deleg._secret = lambda: b"test-secret-key"
CLOCK[0] += deleg.TICKET_TTL_SECONDS - 1
must(start(good).status == "queued", "valid just before 24 hours")
CLOCK[0] += 2
refused(lambda: start(good, agents=[1]), "ticket_expired")
fresh()
save_grant()
t1 = ticket()
save_grant()  # the person saves the profile again
refused(lambda: start(t1), "grant_changed")
t2 = ticket()
Grant.objects.rows[0].enabled = False
refused(lambda: start(t2), "grant_disabled")
Grant.objects.rows[0].enabled = True
Grant.objects.rows[0].updated_at = NOW[0]
refused(lambda: start(t2), "grant_changed")
t3 = ticket()
call = mods["maintenance"]["remove"]
call(sa, owner_module="maintenance", grant_key=GK)
refused(lambda: start(t3), "grant_missing")
print("       a ticket comes only from a live run of the owner module; a forged, tampered, foreign or expired one is refused; editing, switching off or removing the grant revokes it")

# ---- (3) the start
fresh()
save_grant()
t = ticket()
refused(lambda: sa.start_delegated_run(t, action_id=INSTALL, agent_ids=[1, 2]), "caller_unverified")
del AUDITS[:]
refused(lambda: start(t, caller="maintenance"), "wrong_module")
one_deny("wrong_module")
del AUDITS[:]
refused(lambda: start(t, action_id=SCAN), "unknown_action")
refused(lambda: start(t, action_id="patchmanagement.nothing"), "unknown_action")
sa._ACTIONS[INSTALL] = sa.SystemActionDefinition(INSTALL, "patchmanagement", "x", "winupdate.install", BOTH, "agents", False, None, True, ())
refused(lambda: start(t), "not_delegable")  # the provider stopped naming maintenance
sa._ACTIONS[INSTALL] = sa.SystemActionDefinition(INSTALL, "patchmanagement", "Advanced Patch Management install", "winupdate.install", BOTH, "agents", False, None, True, ("maintenance",))
plugin("patchmanagement", category="premium", replaces="patching", system_actions=[SCAN])
refused(lambda: start(t), "action_not_declared")
plugin("patchmanagement", category="premium", replaces="patching", system_actions=[INSTALL, SCAN])
mods["patchmanagement"] = compile_as(roots["patchmanagement"] / "apps.py", MODULE_SRC, sa=sa, CFG=CFG)
ENABLED["maintenance"] = False
refused(lambda: start(t), "module_disabled")  # the owner module is not enabled
ENABLED["maintenance"] = True
HONOURED.clear()
refused(lambda: start(t), "replacement_not_honoured")
HONOURED["patchmanagement"] = "patching"
for bad in ([], "12", [True], [1.5], [0], {1: 2}):
    refused(lambda bad=bad: start(t, agents=bad), "bad_agents" if bad not in ([],) else "agent_count")
refused(lambda: start(t, agents=list(range(1, sa.MAX_AGENTS + 2))), "agent_count")
refused(lambda: start(t, agents=[1, 4]), "outside_grant")  # 4 is not a target of the grant
refused(lambda: start(t, agents=[1, 999]), "outside_grant")
RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {1, 2, 3}
refused(lambda: start(t, agents=[1, 3]), "outside_grant")  # 3 is a target but outside the scope the person had when they saved it (client 20)
RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {1, 2}
RESOLVED_MODULE_TARGETS.clear()
refused(lambda: start(t), "targets_unresolved")
RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {1, 2}
Grant.objects.rows[0].creation_scope = {}
refused(lambda: start(t), "creation_scope_unavailable")
Grant.objects.rows[0].creation_scope = Grant.objects.rows[0].creation_scope or creation_scope.capture(alice)
must(not delegated_runs() and not QUEUED_IDS, "nothing was started by any refusal")
must(all(r["metadata"]["requested_by"] == "delegation" and "reason" in r["metadata"] for r in deny_rows()) and len(deny_rows()) >= 15, "one deny row per refusal")
must(not any(any(x in repr(r["metadata"]) for x in ("[1, 4]", "[1, 3]", "999", "agent_ids")) for r in deny_rows()), "no endpoint in any deny row")
print("       the provider only, for the action the grant holds, while it is still delegable, declared, enabled and honoured; endpoints must lie inside the grant AND the stored scope; each refusal is one deny row")

# a queue fault, a strict audit failure and a retry
fresh()
save_grant()
t = ticket()
deleg._queue = lambda run: (_ for _ in ()).throw(RuntimeError("broker down"))
try:
    start(t)
    raise AssertionError("a queue fault must raise")
except sched.SchedulerTransientError as exc:
    must("could not be queued" in str(exc) and "broker" not in str(exc), exc)
must(not [s for s in Schedule.objects.rows if s.owner_module == "patchmanagement"], "the schedule that has no use is removed")
deleg._queue = real_queue
AUDIT_FAIL["strict"] = True
try:
    start(t)
    raise AssertionError("a strict audit failure must stop it")
except sched.SchedulerTransientError as exc:
    must("could not be written" in str(exc), exc)
AUDIT_FAIL["strict"] = False
must(not QUEUED_IDS, "nothing was queued")
first = start(t)
again = start(t)
must(again is first and len([s for s in Schedule.objects.rows if s.owner_module == "patchmanagement"]) == 1 and len(QUEUED_IDS) == 1, "the same ticket and the same endpoints name the same run: a retry never starts a second install")
del AUDITS[:]
refused(lambda: start(t, agents=[1]), "ticket_used")  # one ticket starts one run; another endpoint subset on it is refused
must(len(QUEUED_IDS) == 1 and len([s for s in Schedule.objects.rows if s.owner_module == "patchmanagement"]) == 1, "nothing more was started")
one_deny("ticket_used")
must(start(ticket(), agents=[1]) is not first and len(QUEUED_IDS) == 2, "a new ticket (a new live run) is a new call")
print("       a queue fault leaves nothing behind, a strict audit failure starts nothing, and the same ticket with the same endpoints never starts a second run")

# ---- (4) the exemption holds only for a valid marker and an unchanged grant
fresh()
save_grant()
run = start(ticket())
must(sched._is_unattended_scheduled_run(run) is True and deleg.run_is_validly_delegated(run) is True, "valid")
sched.AD13_CONDITION_2_AMENDED = False
must(sched._is_unattended_scheduled_run(run) is False, "the switched-off amendment keeps every re-check, delegated or not")
sched.AD13_CONDITION_2_AMENDED = True
# a plain one-off the provider starts for the person keeps every re-check
plain = sched.start_one_off_run(user=alice, owner_module="patchmanagement", action_id="patchmanagement.plain", targets={"type": "endpoint", "ids": ["1"]})
must(sched._is_unattended_scheduled_run(plain) is False, "an ordinary one-off is never unattended")
# a copied marker is bound to the schedule it was made for
plain.parameters_snapshot = dict(run.parameters_snapshot)
plain.schedule.parameters = dict(run.parameters_snapshot)
must(deleg.run_is_validly_delegated(plain) is False and sched._is_unattended_scheduled_run(plain) is False, "a marker copied to another schedule means nothing")
tampered = dict(run.parameters_snapshot)
_m = tampered[deleg.MARKER_KEY]
tampered[deleg.MARKER_KEY] = _m[:-1] + ("0" if _m[-1] != "0" else "1")  # always a change (a fixed "00" was a no-op one time in 256)
run.parameters_snapshot = tampered
must(deleg.run_is_validly_delegated(run) is False and sched._is_unattended_scheduled_run(run) is False, "a tampered marker")
run.parameters_snapshot = dict(run.schedule.parameters)
must(deleg.run_is_validly_delegated(run) is True, "restored")
run.manual = False
must(deleg.run_is_validly_delegated(run) is True, "manual or not does not matter for the delegated one-off")
run.owner_module = "patching"
must(deleg.run_is_validly_delegated(run) is False, "another module's run")
run.owner_module = "patchmanagement"
# editing the grant before the run executes: the exemption is gone and the ordinary one-off re-check applies
alice.is_active = False
save_grant(user=bob)  # bob edits the profile; the digest changes
must(deleg.run_is_validly_delegated(run) is False and sched._is_unattended_scheduled_run(run) is False, "an edited grant revokes the run that has not executed yet")
out = go(run)
must(run.status == "skipped" and run.error_type == "AuthorizationRevoked" and not TASK_CALLS, (run.status, run.error, out))
fresh()
save_grant()
run = start(ticket())
Grant.objects.rows[0].enabled = False
must(deleg.run_is_validly_delegated(run) is False, "a switched-off grant")
Grant.objects.rows.clear()
must(deleg.run_is_validly_delegated(run) is False, "a removed grant")
real_open = deleg._open
deleg._open = lambda prefix, token: (_ for _ in ()).throw(RuntimeError("secret unreadable"))
must(deleg.run_is_validly_delegated(run) is False and sched._is_unattended_scheduled_run(run) is False, "any doubt keeps the re-check")
deleg._open = real_open
tasks_src = (APP / "tasks.py").read_text(encoding="utf-8")
must("from .scheduler import _is_unattended_scheduled_run" in tasks_src and "if _is_unattended_scheduled_run(run):" in tasks_src, "the worker asks the one helper before the one-off re-check")
print("       the delegated one-off is unattended only with a valid marker and an unchanged grant; a copied or tampered marker, a plain one-off, an edited or removed grant and the switched-off amendment keep every re-check")

# ---- (5) wrong_module of run_system_action is unchanged
fresh()
save_grant()
run = start(ticket())
other = compile_as(roots["maintenance"] / "calls.py", "def go(context):\n    return sa.run_system_action(context, action_id='patchmanagement.install', agent_ids=[1, 2])\n", sa=sa)
context = rc.issue_run_context({"run_id": str(run.id)}, run_id=run.id)
run.status = "running"
try:
    other["go"](context)
    raise AssertionError("the module that is not the run's module must be refused")
except sa.SystemActionRefused as exc:
    must(exc.reason == "wrong_module", exc.reason)
must(run.status == "running", "a wrong module does not end another module's run")
print("       run_system_action still answers only the module that owns the run: wrong_module is unchanged")
print("PASS delegation run 1.17.68")
