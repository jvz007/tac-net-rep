#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.61 regression (R-20): run_system_action re-checks the owner, the scope and the module at EVERY run, sends at most once and audits.

The real system_actions.py, scheduler.py, scheduler_run_context.py, caller_identity.py and tasks.py on the stub harness; module code is
compiled under stub plugin folders so the real frame walk names the caller; ``winupdate.tasks`` is a stub that records ``.delay``.
Covered: the happy path sends one task with the right numbers and writes one strict audit row naming the owner; an owner who is gone,
inactive, an installer user, or who lost either minimum flag is refused; one agent outside the scope refuses the whole call and a scheduler
manager gets no bypass; a module disabled between the checks, a replacement no longer honoured, a wrong calling module, a copied, hand-built
or foreign context, a module-owned run with no owner, an unknown action, counts 0 and 2001, bad numbers and parameters are refused; a missing
Tactical function fails closed; a retry never sends again; a mark stuck at claiming fails the run as outcome-unknown; a failed audit write
sends nothing; every refusal writes exactly one deny row and no ids, hostnames or parameters; a refusal for an unplaced caller does not end
another module's run.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

MARKER = "SECRET-MARKER-5d0e"
BOTH = ("can_manage_winupdates", "can_run_bulk")
IDS = [987654311, 987654312, 987654313]
SCAN = "patching.scan"
CFG = {"action_id": SCAN, "agents": IDS, "parameters": None}
LEAK = {}

alice, bob, carol, dave = User("alice"), User("bob"), User("carol", installer=True), User("dave")
roots = {}


def setup_world():
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    roots["patching"] = plugin("patching", system_actions=["patching.scan", "patching.install"])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.scan", "patchmanagement.install"])
    roots["checks"] = plugin("checks", system_actions=[])
    for who in ("alice", "bob", "carol", "dave"):
        FLAGS[who] = set(BOTH)
        SCOPE[who] = set(IDS) | {5000 + i for i in range(2100)}
    SCOPE["bob"] = set()  # a scheduler manager with no Tactical scope


HANDLER_SRC = (
    "def handler(context):\n"
    "    LEAK['context'] = context\n"
    "    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'], parameters=CFG.get('parameters'))\n"
    "def pending_handler(context):\n"
    "    LEAK['pending_context'] = context\n"
    "    return PENDING('module', 'job-1')\n"
    "def thief(context):\n"
    "    return sa.run_system_action(LEAK['pending_context'], action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
    "def with_copy(context):\n"
    "    return sa.run_system_action(dict(context), action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
    "def with_built(context):\n"
    "    return sa.run_system_action({'run_id': context['run_id'], 'module_id': 'patching'}, action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
    "def with_forged(context):\n"
    "    return sa.run_system_action(FORGED(dict(context)), action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
    "def with_old(context):\n"
    "    return sa.run_system_action(LEAK['context'], action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
)


def build_modules():
    from tec_tac.scheduler_run_context import SchedulerRunContext

    names = dict(sa=sa, CFG=CFG, LEAK=LEAK, PENDING=sched.pending_completion, FORGED=SchedulerRunContext)
    mods_ = {name: compile_as(roots[name] / "handlers.py", HANDLER_SRC, **names) for name in ("patching", "patchmanagement", "checks")}
    for module, ns in mods_.items():
        for fn in ("handler", "pending_handler", "thief", "with_copy", "with_built", "with_forged", "with_old"):
            aid = f"{module}.{fn}"
            if aid not in sched._ACTIONS:
                sched.register_scheduled_action(id=aid, module_id=module, label=aid, handler=ns[fn], target_types=("none",), timeout_seconds=600)
    return mods_


def fresh(register=True):
    reset()
    setup_world()
    HONOURED["patchmanagement"] = "patching"
    build_modules()
    CFG.update(action_id=SCAN, agents=list(IDS), parameters=None)
    LEAK.clear()
    for flag in ("alice", "bob", "carol", "dave"):
        USERS_BY = {u.username: u for u in USERS.values()}
        USERS_BY[flag].is_active = True
    if register:
        sa.register_system_action("patching.scan", "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
        sa.register_system_action("patching.install", "patching", "Scheduled patch install", "winupdate.install", BOTH)
        sa.register_system_action("patchmanagement.scan", "patchmanagement", "APM scheduled scan", "winupdate.scan", BOTH)


def start(handler="patching.handler", owner_user=alice, owner="user", retries=0):
    run = make_run(handler, handler.split(".")[0], user=owner_user, owner=owner, retries=retries)
    return run, go(run)


def deny_rows():
    return [a for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def refusal_reason(out):
    """The reason a run was refused. When the run was ended ``skipped`` the worker answers 'run no longer active', so the deny row names it."""
    if isinstance(out, sa.SystemActionRefused):
        return out.reason
    rows = deny_rows()
    if isinstance(out, str) and out.startswith("run no longer active") and len(rows) == 1:
        return rows[0]["metadata"]["reason"]
    return None


def assert_refused(run, out, reason, *, ended=True, owner="alice"):
    must(refusal_reason(out) == reason, (reason, out))
    must(isinstance(out, str) if ended else isinstance(out, sa.SystemActionRefused), (reason, ended, out))
    must(not TASK_CALLS, f"{reason}: nothing was sent")
    rows = deny_rows()
    must(len(rows) == 1, f"{reason}: exactly one deny row, got {AUDITS}")
    row = rows[0]
    must(row["module_id"] == "core" and row["metadata"]["reason"] == reason and row["metadata"]["requested_by"] == "scheduler", row)
    must(set(row["metadata"]) <= {"reason", "requested_by", "owner_module", "run_id"}, row["metadata"])
    text = repr(AUDITS) + repr(run.__dict__)
    must(MARKER not in text and not any(str(i) in text for i in IDS), f"{reason}: no id, hostname or parameter in the audit trail or the run")
    must(not [a for a in AUDITS if a["action"] == "run"], f"{reason}: no 'run' row")
    if ended:
        must(run.status == "skipped" and run.error_type == "SystemActionRefused" and run.error and run.finished_at, (reason, run.__dict__))
    else:
        must(run.status == "failed" and run.error_type == "SystemActionRefused", (reason, run.__dict__))
    if owner:
        must(getattr(row["actor"], "username", None) == owner, f"{reason}: the owner is the actor: {row['actor']}")


# ---- the happy path
fresh()
run, out = start()
must(out == {"outcome": "queued", "agents": 3, "message": "Queued in Tactical; the result shows in each endpoint's update list."}, out)
must(TASK_CALLS == [("scan", (IDS,), {})], TASK_CALLS)
must(run.status == "succeeded" and run.result == out and run.schedule.last_run_at is not None, run.__dict__)
must("done" not in out["message"].lower() and "completed" not in out["message"].lower(), "the result never says done")
must(len(run.system_action_marks) == 1 and run.system_action_marks[0]["state"] == "sent" and run.system_action_marks[0]["task_id"].startswith("celery-scan"), run.system_action_marks)
rows = [a for a in AUDITS if a["action"] == "run"]
must(len(rows) == 1 and not deny_rows(), AUDITS)
row = rows[0]
must(row["actor"] is alice and row["module_id"] == "core" and row["object_type"] == "system_action" and row["object_id"] == SCAN and row["strict"] is True, row)
meta = row["metadata"]
must(meta["requested_by"] == "scheduler" and meta["run_id"] == str(run.id) and meta["owner_module"] == "patching" and meta["function"] == "winupdate.scan"
     and meta["agent_count"] == 3 and len(meta["targets_digest"]) == 32 and meta["schedule_id"] == str(run.schedule.id), meta)
must(set(meta) == {"requested_by", "run_id", "schedule_id", "owner_module", "function", "agent_count", "targets_digest"}, set(meta))
must(not any(str(i) in repr(AUDITS) for i in IDS), "no endpoint number in the audit row")
must(SCOPE_CALLS == [("alice", IDS)], SCOPE_CALLS)
print("       the happy path: one task with the right numbers, one strict audit row naming the owner, a plain 'queued' result")

# ids are distinct and sorted; a one-off run and a user-owned schedule both work
fresh()
CFG["agents"] = [IDS[2], IDS[0], IDS[0], IDS[1]]
run, out = start(owner="one-off")
must(out["agents"] == 3 and TASK_CALLS == [("scan", (IDS,), {})], (out, TASK_CALLS))
print("       duplicate numbers are merged and sorted; a module's one-off run works like a user-owned schedule")

# the honoured replacement can run its own scan
fresh()
CFG["action_id"] = "patchmanagement.scan"
run, out = start("patchmanagement.handler")
must(out["outcome"] == "queued" and TASK_CALLS == [("scan", (IDS,), {})], (out, TASK_CALLS))
print("       the honoured replacement runs its own scan")

# ---- the owner is read again
fresh()
dave.is_active = False
run, out = start(owner_user=dave)
must(refusal_reason(out) == "owner_refused" and run.status == "skipped" and not TASK_CALLS, (out, run.__dict__))
must(len(deny_rows()) == 1 and deny_rows()[0]["metadata"]["reason"] == "owner_refused", AUDITS)
dave.is_active = True

fresh()
run, out = start(owner_user=carol)  # an installer user owning a user schedule
assert_refused(run, out, "owner_inactive", owner="carol")

fresh()
alice.is_active = False
run, out = start(owner="one-off")  # a one-off run is skipped by the worker before the handler, and nothing is sent either way
must(run.status == "skipped" and run.error_type == "AuthorizationRevoked" and not TASK_CALLS and not [a for a in AUDITS if a["action"] == "run"], run.__dict__)
alice.is_active = True
print("       an owner who is inactive or an installer user is refused (and the worker's one-off check stops a one-off run first)")

for flag in BOTH:
    fresh()
    FLAGS["alice"].discard(flag)
    run, out = start()
    assert_refused(run, out, "permission_lost")
fresh()
FLAGS["alice"] = set()
run, out = start()
assert_refused(run, out, "permission_lost")
fresh()
FLAGS["alice"] = set(BOTH)
run, out = start()
must(out["outcome"] == "queued", "the flags are back: it runs")
print("       an owner who lost either minimum flag is refused at the run; the flag is read fresh on every run")

# ---- scope: one agent outside refuses the whole call; no bypass for a manager
fresh()
SCOPE["alice"].discard(IDS[1])
run, out = start()
assert_refused(run, out, "out_of_scope")
must(SCOPE_CALLS == [("alice", IDS)], "the whole list is checked at once; nothing is narrowed")
fresh()
run, out = start(owner_user=bob)  # bob manages the Scheduler (the stub scope check passes) but has no Tactical scope
assert_refused(run, out, "out_of_scope", owner="bob")
fresh()
CFG["agents"] = [IDS[0], 999999999999]  # an endpoint that does not exist
run, out = start()
assert_refused(run, out, "out_of_scope")
print("       one endpoint outside the owner's scope refuses the whole call; a scheduler manager with no scope is refused; a missing endpoint is refused")

# ---- the module, the replacement, the caller
fresh()
ENABLED["patching"] = False
run, out = start()
must(isinstance(out, sa.SystemActionRefused) and out.reason == "caller_unverified" and not TASK_CALLS, out)  # a disabled module is not even a verified caller
fresh()
real_enabled = sa._enabled_now
sa._enabled_now = lambda module_id: False  # the module is disabled between the caller check and the module check
run, out = start()
assert_refused(run, out, "module_disabled")
sa._enabled_now = real_enabled
fresh()
sa._enabled_now = lambda module_id: (_ for _ in ()).throw(OSError("state unreadable"))
run, out = start()
assert_refused(run, out, "module_disabled")
sa._enabled_now = real_enabled
print("       a disabled owning module is refused; the module state is read at the run and a fault refuses")

fresh()
CFG["action_id"] = "patchmanagement.scan"
HONOURED.clear()  # registered while honoured, no longer honoured now
run, out = start("patchmanagement.handler")
assert_refused(run, out, "replacement_not_honoured")
print("       a replacement's action is refused once the replacement is no longer honoured")

fresh()
run, out = start("checks.handler")  # checks owns this run but not the action
assert_refused(run, out, "wrong_module", ended=False)
fresh()
CFG["action_id"] = "patchmanagement.scan"
run, out = start("patching.handler")  # patching's own run asks for another module's action
assert_refused(run, out, "wrong_module", ended=False)
print("       a handler that runs another module's action is refused (wrong_module)")

# a leaked context used by another module: refused, and the victim run is NOT ended
fresh()
victim, _ = start("patching.pending_handler")
must(victim.status == "running", victim.__dict__)
del AUDITS[:]
thief_run, out = start("checks.thief")
must(isinstance(out, sa.SystemActionRefused) and out.reason == "wrong_module" and not TASK_CALLS, out)
must(victim.status == "running" and victim.error == "", "another module cannot end a run it does not own")
rows = deny_rows()
must(len(rows) == 1 and rows[0]["metadata"]["reason"] == "wrong_module", AUDITS)
print("       a context leaked to another module is refused and cannot end the owner's run")

# context checks
for handler, reason in (("patching.with_copy", "context_invalid"), ("patching.with_built", "context_invalid"), ("patching.with_forged", "context_invalid")):
    fresh()
    run, out = start(handler)
    must(isinstance(out, sa.SystemActionRefused) and out.reason == reason and not TASK_CALLS, (handler, out))
    rows = deny_rows()
    must(len(rows) == 1 and rows[0]["metadata"]["reason"] == reason and rows[0]["metadata"].get("run_id") is None, (handler, AUDITS))
    must(MARKER not in repr(AUDITS), handler)
fresh()
first, _ = start("patching.handler")  # a context of an earlier, finished run
second, out = start("patching.with_old")
must(isinstance(out, sa.SystemActionRefused) and out.reason == "context_invalid" and len(TASK_CALLS) == 1, (out, TASK_CALLS))
print("       a copied, hand-built, forged or finished-run context is refused (context_invalid)")

# no person behind the run
fresh()
run, out = start(owner="module")
assert_refused(run, out, "no_owner", owner=None)
must(getattr(deny_rows()[0]["actor"], "service", None) == "scheduler", "a Core service actor is the actor when there is no owner")
print("       a module-owned run with no person behind it is refused (no_owner)")

# unknown action
for action in ("patching.nope", None, 5, "", "winupdate.scan", "PATCHING.SCAN"):
    fresh()
    CFG["action_id"] = action
    run, out = start()
    must(refusal_reason(out) == "unknown_action" and not TASK_CALLS and run.status == "skipped", (action, out))
    must(len(deny_rows()) == 1, AUDITS)
print("       an unregistered action id is refused (unknown_action)")

# counts and shapes
for agents, reason in (([], "agent_count"), (list(range(5000, 7001)), "agent_count"), ("987654311", "bad_agents"), (None, "bad_agents"), ({IDS[0]: 1}, "bad_agents"),
                       (["987654311"], "bad_agents"), ([True], "bad_agents"), ([0], "bad_agents"), ([-4], "bad_agents"), ([1.5], "bad_agents"), ([[IDS[0]]], "bad_agents"),
                       ([2 ** 63], "bad_agents")):
    fresh()
    CFG["agents"] = agents
    run, out = start()
    assert_refused(run, out, reason)
    must(not SCOPE_CALLS, "the count and shape are judged before any lookup")
fresh()
CFG["agents"] = list(range(5000, 7000))  # exactly 2000
run, out = start()
must(out["agents"] == 2000 and TASK_CALLS[0][1][0] == list(range(5000, 7000)), "2000 is allowed and nothing is truncated")
print("       0 and 2001 endpoints, and malformed numbers, are refused before any lookup; 2000 is allowed whole")

fresh()
CFG["parameters"] = {"x": MARKER}
run, out = start()
assert_refused(run, out, "bad_parameters")
fresh()
CFG["parameters"] = {}
run, out = start()
must(out["outcome"] == "queued", "an empty parameter object is the same as none")

# a missing Tactical function fails closed
fresh()
install_winupdate_stub(scan=False)
run, out = start()
assert_refused(run, out, "function_unavailable")
fresh()
for name in ("winupdate", "winupdate.tasks"):
    sys.modules.pop(name, None)
run, out = start()
assert_refused(run, out, "function_unavailable")
install_winupdate_stub()
fresh()
sys.modules["winupdate.tasks"].bulk_check_for_updates_task = lambda pks: None  # a function with no .delay is not a Celery task
run, out = start()
assert_refused(run, out, "function_unavailable")
print("       a missing Tactical module, function or a non-task callable fails closed (function_unavailable)")

# defence in depth: an install that re-approves is refused for a replacement at run time even if the registry were bypassed
fresh()
sa._ACTIONS["patchmanagement.install"] = sa.SystemActionDefinition("patchmanagement.install", "patchmanagement", "APM install", "winupdate.install", BOTH, "agents", False, None, True)
CFG["action_id"] = "patchmanagement.install"
run, out = start("patchmanagement.handler")
assert_refused(run, out, "reapproves_by_policy")
fresh()
CFG["action_id"] = "patching.install"
run, out = start()
must(out["outcome"] == "queued" and TASK_CALLS == [("install", (IDS,), {})], "Windows Patching may run install")
print("       install is refused for a replacement at run time and runs for Windows Patching")

# ---- at most once
fresh()
run, out = start()
must(out["outcome"] == "queued" and len(TASK_CALLS) == 1)
run.status, run.finished_at, run.result = "queued", None, {}  # a retry or a duplicate delivery of the same run
again = go(run)
must(again["outcome"] == "queued" and again.get("duplicate") is True and len(TASK_CALLS) == 1, (again, TASK_CALLS))
must(len([a for a in AUDITS if a["action"] == "run"]) == 1, "a duplicate delivery writes no second 'run' row")
CFG["agents"] = IDS[:2]  # another list in the same run is another send
run.status, run.finished_at = "queued", None
third = go(run)
must(third["outcome"] == "queued" and len(TASK_CALLS) == 2 and len(run.system_action_marks) == 2, (third, TASK_CALLS))
print("       a retry after a successful send sends nothing again; another endpoint list in the same run is its own send")

fresh()
run = make_run("patching.handler", "patching", user=alice, owner="user")
digest = sa._digest(run.id, SCAN, IDS)
run.system_action_marks = [{"action_id": SCAN, "targets_digest": digest, "state": "claiming", "agents": 3}]
out = go(run)
must(out == "run no longer active: failed" and not TASK_CALLS, out)
must(run.status == "failed" and run.error_type == "OutcomeUnknown" and "may already have been sent" in run.error, run.__dict__)
unknown = [a for a in AUDITS if a["action"] == "custom:outcome-unknown"]
must(len(unknown) == 1 and unknown[0]["actor"] is alice and not [a for a in AUDITS if a["action"] == "run"], AUDITS)
must(not any(str(i) in repr(AUDITS) for i in IDS))
print("       a mark stuck at 'claiming' fails the run as outcome-unknown and is never sent")

fresh()
DELAY_FAIL["raise"] = True
run, out = start()
must(out == "run no longer active: failed" and run.status == "failed" and run.error_type == "OutcomeUnknown" and not TASK_CALLS, (out, run.__dict__))
must(run.system_action_marks[0]["state"] == "claiming", "a send that raised stays unknown")
DELAY_FAIL["raise"] = False
run.status, run.finished_at, run.error, run.error_type = "queued", None, "", ""
again = go(run)
must(again == "run no longer active: failed" and run.error_type == "OutcomeUnknown" and not TASK_CALLS, "never sent again after an unknown outcome")
print("       a send that raised is an unknown outcome and is never repeated")

# ---- the audit row is written before the send; if it cannot be written nothing is sent
fresh()
AUDIT_FAIL["strict"] = True
run, out = start()
must(isinstance(out, sched.SchedulerTransientError) and not TASK_CALLS and run.status == "failed", (out, run.__dict__))
must(run.system_action_marks[0]["state"] == "aborted", run.system_action_marks)
fresh()
AUDIT_FAIL["strict"] = True
run, out = start(retries=1)
must(out == "retried" and run.status == "queued" and not TASK_CALLS, (out, run.__dict__))
AUDIT_FAIL["strict"] = False
out = go(run, retries=1)
must(out["outcome"] == "queued" and len(TASK_CALLS) == 1 and run.system_action_marks[0]["state"] == "sent", (out, TASK_CALLS))
must(len([a for a in AUDITS if a["action"] == "run"]) == 1, "one row, one send")
print("       an audit row that cannot be written means nothing is sent; the retry then sends once")

# ---- the order of marks and writes: mark, then audit, then send
fresh()
order = []
real_claim, real_record, real_delay = sa._claim_mark, sa._audit().record, sys.modules["winupdate.tasks"].bulk_check_for_updates_task.delay
sa._claim_mark = lambda *a, **k: (order.append("mark"), real_claim(*a, **k))[1]
sys.modules["tec_tac.audit"].record = lambda **kw: (order.append(kw["action"]), real_record(**kw))[1]
sys.modules["winupdate.tasks"].bulk_check_for_updates_task.delay = lambda *a, **k: (order.append("send"), real_delay(*a, **k))[1]
run, out = start()
sa._claim_mark = real_claim
sys.modules["tec_tac.audit"].record = real_record
must(order == ["mark", "run", "send"], order)
print("       the order is mark, strict audit row, send")

# ---- every refusal writes exactly one deny row (marker test over all reasons seen above is in assert_refused); a refused run does not run twice
fresh()
FLAGS["alice"].discard("can_run_bulk")
run, out = start()
rows_after_first = len(AUDITS)
must(go(run) == "run already skipped" and len(AUDITS) == rows_after_first, "a finished refusal is not repeated")
print("       a refused run is not run or audited again")

# ---- the module code is the only caller that reaches the function; a call from a test file is refused
fresh()
issued = {}
sched.register_scheduled_action(id="patching.capture", module_id="patching", label="capture", target_types=("none",), timeout_seconds=600,
                                handler=lambda context: issued.setdefault("c", context) and sched.pending_completion("module", "job-1"))
run = make_run("patching.capture", "patching", user=alice, owner="user")
go(run)
try:
    sa.run_system_action(issued["c"], action_id=SCAN, agent_ids=IDS)
    raise AssertionError("a call from outside every module ran")
except sa.SystemActionRefused as exc:
    must(exc.reason == "caller_unverified" and not TASK_CALLS and run.status == "running", exc.reason)
print("       a call from a test file (outside every module) is refused and leaves the run alone")

print("PASS system actions run 1.17.61")
