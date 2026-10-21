#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.63 regression (CQ179 b, Johan 20 October 2026): run_system_action for a SCHEDULED run of an unattended action.

The real system_actions.py, scheduler.py, scheduler_run_context.py, caller_identity.py and tasks.py on the stub harness of
scheduler-completion-harness-1.17.61.py; module code is compiled under stub plugin folders so the real frame walk names the caller.

Covered. A scheduled run of an unattended action sends when its creator was demoted, lost the scope, was deactivated, or the user row is gone
(the stored name is in the audit row, the actor is then a Core service actor); the audit rows carry run_kind, creator and confirmed_by. The
same action run by a person (a manual run, a one-off run) and every ordinary action keep owner_inactive, permission_lost, out_of_scope and
owner_refused. Everything else still refuses an unattended run: a disabled module, a replacement not honoured, an action no longer listed in
the signed manifest (action_not_declared) or never registered (unknown_action), a wrong module (the run is kept), parameters, bad numbers,
0 and 2001 endpoints (2000 runs), an endpoint outside the snapshot (outside_targets, never widened), a module-owned target type
(targets_unresolved). A vanished target is reported as vanished_targets while the rest runs. A duplicate delivery sends once, a stuck mark
is an unknown outcome, and a duplicate or late complete_pending_run is a no-op or refused.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True  # these tests prove the post-amendment behaviour; scheduler-unattended-gate-1.17.63-1.py proves the gate

MARKER = "SECRET-MARKER-9c1b"
BOTH = ("can_manage_winupdates", "can_run_bulk")
IDS = [987654311, 987654312, 987654313]
SCAN = "patching.scan"
CFG = {"action_id": SCAN, "agents": IDS, "parameters": None}
LEAK = {}


def AUTO_TARGETS():
    return {"type": "endpoint", "ids": [str(i) for i in CFG["agents"]] if isinstance(CFG["agents"], (list, tuple, set)) else []}



alice, bob, carol = User("alice"), User("bob"), User("carol")
roots = {}


def setup_world():
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    roots["patching"] = plugin("patching", system_actions=["patching.scan", "patching.install", "patching.handler", "patching.send_then_pend"])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.scan", "patchmanagement.handler", "patchmanagement.send_then_pend"])
    roots["other"] = plugin("other", system_actions=["other.thing", "other.handler", "other.send_then_pend"])
    for who in ("alice", "bob", "carol"):
        FLAGS[who] = set(BOTH)
        SCOPE[who] = set(IDS) | {5000 + i for i in range(2100)}


HANDLER_SRC = (
    "def handler(context):\n"
    "    LEAK['context'] = context\n"
    "    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'], parameters=CFG.get('parameters'))\n"
    "def send_then_pend(context):\n"
    "    sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
    "    return PENDING('module', 'job-1')\n"
    "def complete(sched_, run_id, ext, outcome):\n"
    "    return sched_.complete_pending_run(run_id, external_job_id=ext, outcome=outcome)\n"
)
MODS = {}


def build_modules():
    names = dict(sa=sa, CFG=CFG, LEAK=LEAK, PENDING=sched.pending_completion)
    for module in ("patching", "patchmanagement", "other"):
        MODS[module] = compile_as(roots[module] / "handlers.py", HANDLER_SRC, **names)
        for fn, flag in (("handler", True), ("plain", False), ("send_then_pend", True)):
            aid = f"{module}.{fn}"
            if aid not in sched._ACTIONS:
                sched.register_scheduled_action(
                    id=aid, module_id=module, label=aid, handler=MODS[module]["send_then_pend" if fn == "send_then_pend" else "handler"],
                    target_types=("none",), timeout_seconds=600, unattended=flag,
                )


def fresh():
    reset()
    setup_world()
    HONOURED["patchmanagement"] = "patching"
    sched._ACTIONS.clear()
    build_modules()
    CFG.update(action_id=SCAN, agents=list(IDS), parameters=None)
    LEAK.clear()
    for user in (alice, bob, carol):
        user.is_active = True
    sa.register_system_action("patching.scan", "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
    sa.register_system_action("patching.install", "patching", "Scheduled patch install", "winupdate.install", BOTH)
    sa.register_system_action("patchmanagement.scan", "patchmanagement", "APM scheduled scan", "winupdate.scan", BOTH)
    for module in ("patching", "patchmanagement"):  # an unattended scheduled action needs a system action of the same id (1.17.63-1)
        for fn in ("handler", "send_then_pend"):
            sa.register_system_action(f"{module}.{fn}", module, f"{module}.{fn}", "winupdate.scan", BOTH)


def start(handler="patching.handler", *, owner_user=alice, owner="user", manual=False, name="auto", confirmed="", targets=None):
    """A queued run. ``owner`` is user (a scheduled run of a user-owned schedule), one-off, or module. ``name`` is the stored creator name."""
    run = make_run(handler, handler.split(".")[0], user=owner_user, owner=owner, targets=targets)
    stored = (owner_user.username if owner_user is not None else "alice") if name == "auto" else name
    run.schedule.created_by_username = stored
    run.schedule.confirmed_by_username = confirmed
    run.manual = manual
    return run, go(run)


def deny_rows():
    return [a for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def run_rows():
    return [a for a in AUDITS if a["action"] == "run"]


def reason_of(out):
    if isinstance(out, sa.SystemActionRefused):
        return out.reason
    rows = deny_rows()
    if isinstance(out, str) and out.startswith("run no longer active") and len(rows) == 1:
        return rows[0]["metadata"]["reason"]
    return None


def refused(run, out, reason, *, ended=True):
    must(reason_of(out) == reason, (reason, out, AUDITS))
    must(not TASK_CALLS and not run_rows(), f"{reason}: nothing was sent and no 'run' row")
    must(len(deny_rows()) == 1, (reason, AUDITS))
    row = deny_rows()[0]
    must(row["metadata"]["reason"] == reason and row["metadata"]["requested_by"] == "scheduler", row)
    must(MARKER not in repr(AUDITS) and not any(str(i) in repr(AUDITS) for i in IDS), "no id or parameter in the audit trail")
    if ended:
        must(run.status == "skipped" and run.error_type == "SystemActionRefused", (reason, run.__dict__))
    return row


def sent_once(out, run, agents=3):
    must(out["outcome"] == "queued" and out["agents"] == agents, out)
    must(len(TASK_CALLS) == 1 and run.status == "succeeded" and len(run_rows()) == 1 and not deny_rows(), (TASK_CALLS, AUDITS))
    return run_rows()[0]


# ---- (1) an unattended scheduled run does not look at the creator's rights again
fresh()
FLAGS["alice"] = set()  # demoted: no Tactical flag left
SCOPE["alice"] = set()  # and no scope
alice.is_active = False  # and deactivated
run, out = start(confirmed="bob")
row = sent_once(out, run)
must(TASK_CALLS == [("scan", (IDS,), {})] and not SCOPE_CALLS, (TASK_CALLS, SCOPE_CALLS))
must(row["actor"] is alice and row["strict"] is True and row["object_id"] == SCAN, row)
meta = row["metadata"]
must(meta["run_kind"] == "scheduled" and meta["creator"] == "alice" and meta["confirmed_by"] == "bob", meta)
must("vanished_targets" not in meta and "vanished_targets" not in out, "nothing vanished: no key")
alice.is_active = True
print("       a demoted, scope-less, deactivated creator's scheduled unattended run still sends; the row names the creator and confirmer, run_kind scheduled")

fresh()
run, out = start(owner_user=None, name="alice")  # the creator's user row is gone; only the stored name is left
row = sent_once(out, run)
must(getattr(row["actor"], "kind", None) == "service" and row["metadata"]["creator"] == "alice" and row["metadata"]["run_kind"] == "scheduled", row)
print("       a deleted creator: the actor is a Core service actor and the stored name is in the metadata")

fresh()
run, out = start(owner_user=None, name="")  # no person and no name at all
must(isinstance(out, sa.SystemActionRefused) and out.reason in ("owner_refused", "context_invalid", "no_owner") or (isinstance(out, str) and reason_of(out) is not None), out)
must(not TASK_CALLS and not run_rows(), "no creator name: nothing is sent")
print("       no creator at all: nothing is sent")

# ---- (2) a person-started run, and any ordinary action, keep every re-check
for label, kwargs, action in (("manual", dict(manual=True), "patching.handler"), ("manual ordinary", dict(manual=True), "patching.plain")):  # 1.17.65: an ordinary SCHEDULED run is exempt too (see the next block)
    fresh()
    FLAGS["alice"].discard("can_run_bulk")
    run, out = start(action, **kwargs)
    refused(run, out, "permission_lost")
    fresh()
    SCOPE["alice"] = set()
    run, out = start(action, **kwargs)
    refused(run, out, "out_of_scope")
    fresh()
    alice.is_active = False
    run, out = start(action, **kwargs)
    must(reason_of(out) == "owner_refused" and run.status == "skipped" and not TASK_CALLS, (label, out, run.__dict__))
    fresh()
    carol.is_installer_user = True
    run, out = start(action, owner_user=carol, **kwargs)
    carol.is_installer_user = False
    refused(run, out, "owner_inactive")
print("       a manual run of the flagged action and of an ordinary action still refuse permission_lost, out_of_scope and owner_refused")

fresh()  # 1.17.65 (wide rule): the flag no longer matters; an ordinary scheduled run of a demoted, scope-less, deactivated creator still sends
FLAGS["alice"] = set()
SCOPE["alice"] = set()
alice.is_active = False
run, out = start("patching.plain")
sent_once(out, run)
alice.is_active = True
print("       an ordinary (unflagged) scheduled run is not re-checked either (the unattended flag has no effect)")

fresh()
FLAGS["alice"].discard("can_manage_winupdates")
run, out = start(owner="one-off")
refused(run, out, "permission_lost")
fresh()
SCOPE["alice"] = set()
run, out = start(owner="one-off")
refused(run, out, "out_of_scope")
fresh()
alice.is_active = False
run, out = start(owner="one-off")
must(run.status == "skipped" and run.error_type == "AuthorizationRevoked" and not TASK_CALLS and not run_rows(), run.__dict__)
alice.is_active = True
fresh()
run, out = start(owner="one-off")
row = sent_once(out, run)
must(row["metadata"]["run_kind"] == "person" and row["metadata"]["creator"] == "alice", row["metadata"])
print("       a one-off run keeps every re-check; its audit row says run_kind person")

# ---- (3) everything else still refuses an unattended run
fresh()
ENABLED["patching"] = False
run, out = start()
must(isinstance(out, sa.SystemActionRefused) and out.reason == "caller_unverified" and not TASK_CALLS and not run_rows(), out)  # a disabled module is not even a verified caller
fresh()
real_enabled = sa._enabled_now
sa._enabled_now = lambda module_id: False  # the module is disabled between the caller check and the module check
run, out = start()
refused(run, out, "module_disabled")
sa._enabled_now = real_enabled
fresh()
sa._enabled_now = lambda module_id: (_ for _ in ()).throw(OSError("state unreadable"))
run, out = start()
refused(run, out, "module_disabled")
sa._enabled_now = real_enabled

fresh()
HONOURED.clear()
CFG["action_id"] = "patchmanagement.scan"
run, out = start("patchmanagement.handler")
refused(run, out, "replacement_not_honoured")

fresh()
PLUGINS["patching"].system_actions = ("patching.install",)  # the signed manifest no longer lists the scan
run, out = start()
row = refused(run, out, "action_not_declared")
must(row["metadata"]["run_kind"] == "scheduled" and row["metadata"]["creator"] == "alice", row["metadata"])
fresh()
PLUGINS["patching"].system_actions = ()
run, out = start()
refused(run, out, "action_not_declared")
fresh()
STATE_FAULT["registry"] = True
run, out = start()
must(reason_of(out) is not None and not TASK_CALLS, ("an unreadable manifest list refuses", out))
STATE_FAULT["registry"] = False
fresh()
CFG["action_id"] = "patching.nope"
run, out = start()
refused(run, out, "unknown_action")
print("       a disabled module, a replacement not honoured, an action no longer in the signed manifest and an unknown action are refused")

fresh()
run, out = start("other.handler")  # another module's run tries patching's action
must(isinstance(out, sa.SystemActionRefused) and out.reason == "wrong_module" and run.status == "failed" and not TASK_CALLS and not run_rows(), (out, run.__dict__))
must(len(deny_rows()) == 1 and deny_rows()[0]["metadata"]["reason"] == "wrong_module", AUDITS)
print("       a wrong module is refused with one deny row")

fresh()
CFG["parameters"] = {"x": MARKER}
run, out = start()
refused(run, out, "bad_parameters")
fresh()
CFG["agents"] = [True, 5]
run, out = start()
refused(run, out, "bad_agents")
fresh()
CFG["agents"] = []
run, out = start(targets={"type": "endpoint", "ids": [str(IDS[0])]})
refused(run, out, "agent_count")
fresh()
CFG["agents"] = [6000 + i for i in range(40001)]
run, out = start()
refused(run, out, "agent_count")
fresh()
CFG["agents"] = [6000 + i for i in range(2000)]
run, out = start()
must(out["agents"] == 2000 and len(TASK_CALLS) == 1 and len(TASK_CALLS[0][1][0]) == 2000, "2000 endpoints still run")
print("       parameters, bad numbers, 0 and 40001 endpoints are refused; 2000 still runs")

# ---- (4) the snapshot is never widened; a vanished target is reported
fresh()
CFG["agents"] = [IDS[0], IDS[1]]
run, out = start(targets={"type": "endpoint", "ids": [str(IDS[0])]})
row = refused(run, out, "outside_targets")
fresh()
CFG["agents"] = list(IDS)
EXISTING_AGENTS = {IDS[0], IDS[1]}  # the third target no longer exists
run, out = start(targets={"type": "endpoint", "ids": [str(i) for i in IDS]})
refused(run, out, "outside_targets")
must("1 target(s) of this schedule no longer exist." in run.error, run.error)
fresh()
EXISTING_AGENTS = {IDS[0], IDS[1]}
CFG["agents"] = [IDS[0], IDS[1]]
run, out = start(targets={"type": "endpoint", "ids": [str(i) for i in IDS]})
row = sent_once(out, run, agents=2)
must(out["vanished_targets"] == 1 and row["metadata"]["vanished_targets"] == 1, (out, row["metadata"]))
fresh()
run, out = start(targets={"type": "profile", "profile_id": 5})
refused(run, out, "targets_unresolved")
fresh()
CLIENT_AGENTS[7] = set(IDS)
run, out = start(targets={"type": "client", "ids": [7]})
sent_once(out, run)
print("       an endpoint outside the snapshot is refused; a vanished target is reported and the rest runs; a module-owned type is unresolved")

# ---- (5) at most once, duplicates and late completion
fresh()
run, out = start()
sent_once(out, run)
run.status, run.finished_at, run.result = "queued", None, {}  # a duplicate delivery of the same run
again = go(run)
must(again["outcome"] == "queued" and again.get("duplicate") is True and len(TASK_CALLS) == 1 and len(run_rows()) == 1, (again, TASK_CALLS))
print("       a duplicate delivery sends nothing again and writes no second row")

fresh()
run = make_run("patching.handler", "patching", user=alice, owner="user", targets=AUTO_TARGETS())
run.schedule.created_by_username = "alice"
import hashlib

digest = hashlib.sha256((f"{run.id}|{SCAN}|" + ",".join(str(i) for i in IDS)).encode("ascii")).hexdigest()[:32]
run.system_action_marks = [{"action_id": SCAN, "targets_digest": digest, "state": "claiming", "agents": 3}]
out = go(run)
must(isinstance(out, (sa.SystemActionOutcomeUnknown, str)) and run.status == "failed" and run.error_type == "OutcomeUnknown" and not TASK_CALLS, (out, run.__dict__))
unknown = [a for a in AUDITS if a["action"] == "custom:outcome-unknown"]
must(len(unknown) == 1 and unknown[0]["metadata"]["run_kind"] == "scheduled" and unknown[0]["metadata"]["creator"] == "alice", unknown)
print("       a mark stuck at claiming is an unknown outcome, never sent again, and the row names the creator")

fresh()
run, out = start("patching.send_then_pend")
must(run.status == "running" and len(TASK_CALLS) == 1 and run.completion_state, (run.status, run.__dict__))
MODS["patching"]["complete"](sched, run.id, "job-1", "succeeded")
must(run.status == "succeeded", run.status)
finished = run.finished_at
MODS["patching"]["complete"](sched, run.id, "job-1", "succeeded")  # a duplicate completion is a no-op
must(run.finished_at == finished and run.status == "succeeded", "the second completion changed nothing")
for who, outcome in (("patching", "failed"), ("other", "succeeded")):
    try:
        MODS[who]["complete"](sched, run.id, "job-1", outcome)
        raise AssertionError(f"{who} completed a finished run with {outcome}")
    except sched.SchedulerCompletionRefused:
        pass
must(run.status == "succeeded", "a late or foreign completion never changes a finished run")
must(len(TASK_CALLS) == 1, "nothing was sent again")
print("       a duplicate completion is a no-op; a conflicting, late or foreign completion is refused")

# ---- (6) the source and the contract
src = (APP / "system_actions.py").read_text(encoding="utf-8")
run_body = src.split("def _run(", 1)[1]
must('_refuse("action_not_declared", **common)' in run_body and run_body.index("_declared_now(definition.module_id, definition.id)") < run_body.index("entry = SYSTEM_FUNCTIONS.get(definition.function)"), "the manifest check runs before the function is looked up")
must("action_not_declared" in sa.REASONS, "the reason exists")
meta = sa.system_actions_contract_metadata()
must("action_not_declared" in meta["refusal_reasons"] and meta["version"] == "1.3.0", "the reasons list grows; the capability version is 1.3.0 since 1.17.70 (additive; 1.2.0 since 1.17.68, 1.1.0 since 1.17.66)")
body = src.split("def _run(", 1)[1]
must(body.count("if not unattended:") == 1 and body.count("if unattended:") == 1, "the skipped checks sit in exactly two guarded blocks")
guarded = body.split("if unattended:", 1)[1].split("# (6)", 1)[0]
must("owner_inactive" in guarded and "permission_lost" in guarded, "owner_inactive and permission_lost are the skipped re-reads")
must('_refuse("out_of_scope", **common)' in body.split("if not unattended:", 1)[1].split("# (6b)", 1)[0], "out_of_scope is the third skipped re-read")
for kept in ("module_disabled", "replacement_not_honoured", "wrong_module", "unknown_action", "bad_parameters", "outside_targets", "targets_unresolved"):
    must(f'_refuse("{kept}"' in body, f"{kept} is still checked for every run")
print("       the source: the manifest check comes before the function lookup, only three re-reads are skipped, every other check stays")
print("PASS system actions unattended 1.17.63")
