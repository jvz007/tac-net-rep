#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.67 regression (held Medium of the 1.17.66 review): the group plan is fixed on the first attempt, so a retry never sends an endpoint twice.

The real system_actions.py, scheduler.py, scheduler_run_context.py, caller_identity.py and tasks.py on the stub harness (as the 1.17.66 group
test). Covered: a run stores one plan mark per call (kind plan, id ranges, the digest of every group) and it counts toward the 105-mark limit;
4500 endpoints in 3 groups where group 1 was sent and the audit write of group 2 failed: a retry with the same list sends groups 2 and 3 once and
not group 1; a retry whose list gained an id, lost an id of group 1 or lost an id of group 3 ends the run failed as OutcomeUnknown with one
outcome-unknown row, sends nothing new and sends no endpoint twice; when nothing was sent yet (the first audit write failed, every mark aborted) a
changed list is planned again and sent once; two calls with no endpoint in common in one handler both send; an overlapping second call after a
sent group is refused; five full calls of 20 groups still fit; a hand-built mark without a kind stays a group mark.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

BOTH = ("can_manage_winupdates", "can_run_bulk")
BASE = 1000
SCAN = "patching.scan"
CFG = {"action_id": SCAN, "agents": []}
WIDE = {"type": "endpoint", "ids": [str(i) for i in range(BASE, BASE + 200000)]}
AUTO_TARGETS = lambda: WIDE  # noqa: E731 - the schedule targets are wide here: this test is about the plan, not the target check
alice = User("alice")
roots = {}
HANDLER_SRC = (
    "def handler(context):\n"
    "    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
    "def two_calls(context):\n"
    "    first = sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
    "    second = sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['second'])\n"
    "    return {'first': first, 'second': second}\n"
)


def fresh(count=0):
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    roots["patching"] = plugin("patching", system_actions=[SCAN])
    FLAGS["alice"] = set(BOTH)
    SCOPE["alice"] = set(range(BASE, BASE + 200000))
    ns = compile_as(roots["patching"] / "handlers.py", HANDLER_SRC, sa=sa, CFG=CFG)
    for name in ("handler", "two_calls"):
        if f"patching.{name}" not in sched._ACTIONS:
            sched.register_scheduled_action(id=f"patching.{name}", module_id="patching", label=name, handler=ns[name], target_types=("none",), timeout_seconds=600)
    sa.register_system_action(SCAN, "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
    CFG["agents"] = list(range(BASE, BASE + count))
    CFG["second"] = []
    sys.modules["winupdate.tasks"].bulk_check_for_updates_task.delay = FakeTacticalTask("scan").delay  # a fresh stub every time


def sent_groups():
    return [list(call[1][0]) for call in TASK_CALLS]


def run_rows():
    return [a for a in AUDITS if a["action"] == "run" and a["object_type"] == "system_action"]


def group_marks(run):
    return [m for m in run.system_action_marks if m.get("kind") != "plan"]


def plan_marks(run):
    return [m for m in run.system_action_marks if m.get("kind") == "plan"]


def no_endpoint_twice():
    flat = [i for g in sent_groups() for i in g]
    must(len(flat) == len(set(flat)), "an endpoint was sent twice")


real_record = sys.modules["tec_tac.audit"].record
calls = {"strict": 0, "fail_on": 0}


def flaky(**kw):
    if kw.get("strict"):
        calls["strict"] += 1
        if calls["strict"] == calls["fail_on"]:
            raise RuntimeError("audit store down")
    return real_record(**kw)


sys.modules["tec_tac.audit"].record = flaky


def attempt_one(fail_on, action="patching.handler", count=4500):
    """Group 1 is sent (when fail_on is 2) and the audit write of group `fail_on` fails: a transient failure, the run is queued again."""
    fresh(count)
    calls.update(strict=0, fail_on=fail_on)
    run = make_run(action, "patching", user=alice, owner="user", retries=2, manual=True)
    out = go(run)
    must(out == "retried" and run.status == "queued", (out, run.__dict__))
    calls["fail_on"] = 0  # the store is back
    return run


def retry(run, retries=1):
    run.status, run.finished_at = "queued", None
    return go(run, retries=retries)


def must_be_unknown(run, out, sent_before):
    must(out == "run no longer active: failed" and run.status == "failed" and run.error_type == "OutcomeUnknown", (out, run.__dict__))
    must(len(TASK_CALLS) == sent_before, ("something new was sent", len(TASK_CALLS), sent_before))
    must("endpoint list changed" in run.error and "did not send again" in run.error, run.error)
    must(len([a for a in AUDITS if a["action"] == "custom:outcome-unknown"]) == 1, "one outcome-unknown row")
    must(not any(str(BASE + i) in run.error or str(BASE + i) in repr([a for a in AUDITS if a["action"] == "custom:outcome-unknown"]) for i in (0, 1, 2, 2000, 4499)), "counts only, no endpoint id")
    no_endpoint_twice()


# ---- the plan mark: one per call, the groups' digests and the ranges, not the ids
fresh(4500)
run = make_run("patching.handler", "patching", user=alice, owner="user", manual=True)
out = go(run)
must(out["outcome"] == "queued" and len(group_marks(run)) == 3 and len(plan_marks(run)) == 1, run.system_action_marks)
plan = plan_marks(run)[0]
must(plan["action_id"] == SCAN and plan["state"] == "plan" and plan["ids"] == [[BASE, BASE + 4499]] and len(plan["group_digests"]) == 3, plan)
must(plan["group_digests"] == [m["targets_digest"] for m in group_marks(run)] and plan["targets_digest"] not in plan["group_digests"], plan)
must(sa.MAX_MARKS_PER_RUN == 105, sa.MAX_MARKS_PER_RUN)
must(not [a for a in AUDITS if a["object_type"] == "system_action" and "plan" in repr(a["metadata"])], "a plan mark carries no audit row")
print("       one plan mark per call: id ranges and the digest of each group; no audit row; the limit is 105")

# ---- a retry with the same list: groups 2 and 3 once, group 1 not again
run = attempt_one(2)
must([m["state"] for m in group_marks(run)] == ["sent", "aborted"] and len(plan_marks(run)) == 1, run.system_action_marks)
out = retry(run)
must(out["outcome"] == "queued" and out["groups"] == {"total": 3, "sent": 3, "failed": 0, "not_started": 0}, out)
flat = [i for g in sent_groups() for i in g]
must(len(TASK_CALLS) == 3 and flat == list(range(BASE, BASE + 4500)), "group 1 once, groups 2 and 3 once")
must(len(plan_marks(run)) == 1, "the plan is reused, not written again")
print("       (d) the same list: groups 2 and 3 are sent once, group 1 is not sent again")

# ---- a changed list after a group was sent: refused, nothing new sent, no endpoint twice
for label, change in (
    ("(a) the list gained an id", lambda ids: ids + [BASE + 4500]),
    ("(b) lost an id of group 1", lambda ids: [i for i in ids if i != BASE + 7]),
    ("(c) lost an id of group 3", lambda ids: [i for i in ids if i != BASE + 4400]),
    ("an id of group 2 moved", lambda ids: [i for i in ids if i != BASE + 2500] + [BASE + 9000]),
):
    run = attempt_one(2)
    must(len(TASK_CALLS) == 1, "group 1 was sent")
    CFG["agents"] = change(CFG["agents"])
    out = retry(run)
    must_be_unknown(run, out, 1)
    again = retry(run, retries=0)  # a later delivery changes nothing either
    must(len(TASK_CALLS) == 1, "still nothing new")
    print(f"       {label}: the run ends failed as OutcomeUnknown, nothing new was sent")

# ---- the list changed before the first group was sent: all marks aborted, so it is planned again and sent once
run = attempt_one(1)
must(not TASK_CALLS and [m["state"] for m in group_marks(run)] == ["aborted"] and len(plan_marks(run)) == 1, run.system_action_marks)
CFG["agents"] = CFG["agents"] + [BASE + 4500]  # 4501 ids: 3 groups
out = retry(run)
must(out["outcome"] == "queued" and out["agents"] == 4501 and len(TASK_CALLS) == 3, out)
flat = [i for g in sent_groups() for i in g]
must(flat == list(range(BASE, BASE + 4501)), "every endpoint of the new list once")
must(len(plan_marks(run)) == 1 and plan_marks(run)[0]["ids"] == [[BASE, BASE + 4500]], plan_marks(run))
must(len(group_marks(run)) == 3 and all(m["state"] == "sent" for m in group_marks(run)), "the old aborted group mark went with the old plan")
print("       a changed list when nothing was sent yet is planned again and sent once")

# ---- two calls with no endpoint in common in one handler both send
fresh(2500)
CFG["second"] = list(range(BASE + 10000, BASE + 10100))
run = make_run("patching.two_calls", "patching", user=alice, owner="user", manual=True)
out = go(run)
must(out["first"]["outcome"] == "queued" and out["second"]["outcome"] == "queued" and len(TASK_CALLS) == 3, out)
must(len(plan_marks(run)) == 2 and len(group_marks(run)) == 3, run.system_action_marks)
no_endpoint_twice()
print("       two disjoint calls in one run are two plans and both send")

# ---- an overlapping second call after a sent group is refused
fresh(2500)
CFG["second"] = list(range(BASE + 2400, BASE + 2600))  # shares BASE+2400..2499 with the first call
run = make_run("patching.two_calls", "patching", user=alice, owner="user", manual=True)
out = go(run)
must(out == "run no longer active: failed" and run.error_type == "OutcomeUnknown" and len(TASK_CALLS) == 2, (out, run.__dict__))
must("endpoint list changed" in run.error, run.error)
no_endpoint_twice()
print("       an overlapping second call after a sent group is refused: no endpoint is sent twice")

# ---- the plan counts toward the limit: five full calls fit, a sixth is refused before anything is sent
fresh(40000)
run = make_run("patching.handler", "patching", user=alice, owner="user", manual=True)
out = go(run)
must(out["outcome"] == "queued" and len(group_marks(run)) == 20 and len(plan_marks(run)) == 1, out)
fresh()
HANDLER5 = ("def five(context):\n    out = []\n    for n in range(5):\n        out.append(sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=list(range(BASE0 + n * 40000, BASE0 + n * 40000 + 40000))))\n    return out\n"
            "def six(context):\n    out = []\n    for n in range(6):\n        out.append(sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=list(range(BASE0 + n * 40000, BASE0 + n * 40000 + 40000))))\n    return out\n")
ns = compile_as(roots["patching"] / "five.py", HANDLER5, sa=sa, CFG=CFG, BASE0=BASE)
for name in ("five", "six"):
    sched.register_scheduled_action(id=f"patching.{name}", module_id="patching", label=name, handler=ns[name], target_types=("none",), timeout_seconds=600)
SCOPE["alice"] = set(range(BASE, BASE + 300000))
WIDE_BIG = {"type": "endpoint", "ids": [str(i) for i in range(BASE, BASE + 300000)]}
AUTO_TARGETS = lambda: WIDE_BIG  # noqa: E731
run = make_run("patching.five", "patching", user=alice, owner="user", manual=True)
out = go(run)
must(run.status == "succeeded" and len(TASK_CALLS) == 100 and len(run.system_action_marks) == 105, (type(out), len(TASK_CALLS), run.__dict__))
fresh()
run = make_run("patching.six", "patching", user=alice, owner="user", manual=True)
out = go(run)
must(len(TASK_CALLS) == 100 and run.status == "skipped" and run.error_type == "SystemActionRefused" and len(run.system_action_marks) == 105, (len(TASK_CALLS), run.__dict__))
print("       five full calls (100 group marks and 5 plan marks) fit in the 105; a sixth is refused with nothing sent")

# ---- a hand-built mark without a kind stays a group mark; the plan is added next to it
fresh(3)
run = make_run("patching.handler", "patching", user=alice, owner="user", manual=True)
digest = sa._digest(run.id, SCAN, CFG["agents"])
run.system_action_marks = [{"action_id": SCAN, "targets_digest": digest, "state": "claiming", "agents": 3}]
out = go(run)
must(out == "run no longer active: failed" and not TASK_CALLS and run.error_type == "OutcomeUnknown", (out, run.__dict__))
must(run.system_action_marks[0].get("kind") is None and run.system_action_marks[0]["state"] == "claiming", "the old mark is a group mark and untouched")
print("       a mark without a kind is a group mark")

# ---- the source: the group list comes from the stored plan
src = (APP / "system_actions.py").read_text(encoding="utf-8")
must("def _claim_plan(" in src and "_locked_run(run_id)" in src.split("def _claim_plan(")[1].split("def _claim_mark(")[0], "the plan is claimed under the same row lock")
must('digests = list(plan.get("group_digests") or digests)' in src and "MAX_MARKS_PER_RUN = 105" in src, "groups cut from the stored plan")
sys.modules["tec_tac.audit"].record = real_record
print("PASS system actions groups 1.17.67")
