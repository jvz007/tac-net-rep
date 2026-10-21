#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.66 regression (CQ178): a system action of more than 2000 endpoints is split into groups of at most 2000, never refused for its size.

The real system_actions.py, scheduler.py, scheduler_run_context.py, caller_identity.py and tasks.py on the stub harness; module code is compiled
under a stub plugin folder so the real frame walk names the caller. Covered: 2000 is one group; 2001 and 4500 split into 2 and 3 groups with no id
twice and none lost, in order; 20 groups (40 000) run and 40 001 is refused whole with nothing sent; one bad endpoint in the LAST group refuses the
whole call before group 1 is sent; an audit write that fails on group 2 sends nothing for group 2, and the retry sends group 2 once while group 1
is not sent again; a crash while sending group 2 leaves the run failed as OutcomeUnknown, group 3 is not started and nothing is ever sent again;
a duplicate delivery changes nothing; each group has its own strict audit row naming the group, the groups and the total, and no row holds an
endpoint id; the result and the failure text carry the counts of groups done, failed and not started.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

BOTH = ("can_manage_winupdates", "can_run_bulk")
BASE = 1000
SCAN = "patching.scan"
CFG = {"action_id": SCAN, "agents": []}
AUTO_TARGETS = lambda: {"type": "endpoint", "ids": [str(i) for i in CFG["agents"]]}  # noqa: E731 - the schedule targets exactly what the handler sends
alice = User("alice")
roots = {}
HANDLER_SRC = (
    "def handler(context):\n"
    "    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
)


def fresh(count=0):
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    roots["patching"] = plugin("patching", system_actions=[SCAN])
    FLAGS["alice"] = set(BOTH)
    SCOPE["alice"] = set(range(BASE, BASE + 41000))
    ns = compile_as(roots["patching"] / "handlers.py", HANDLER_SRC, sa=sa, CFG=CFG)
    if "patching.handler" not in sched._ACTIONS:
        sched.register_scheduled_action(id="patching.handler", module_id="patching", label="h", handler=ns["handler"], target_types=("none",), timeout_seconds=600)
    sa.register_system_action(SCAN, "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
    CFG["agents"] = list(range(BASE, BASE + count))
    sys.modules["winupdate.tasks"].bulk_check_for_updates_task.delay = FakeTacticalTask("scan").delay  # a fresh stub every time


def start(retries=0):
    run = make_run("patching.handler", "patching", user=alice, owner="user", retries=retries, manual=True)
    return run, go(run, retries=0)


def group_marks(run):  # 1.17.67: a call also leaves one plan mark (kind "plan")
    return [m for m in run.system_action_marks if m.get("kind") != "plan"]


def sent_groups():
    return [list(call[1][0]) for call in TASK_CALLS]


def run_rows():
    return [a for a in AUDITS if a["action"] == "run" and a["object_type"] == "system_action"]


def no_ids_in_audit(count):
    text = repr(AUDITS)
    return not any(str(BASE + i) in text for i in (0, 1, 2, count - 1) if count)


# ---- 2000 is one group
fresh(2000)
run, out = start()
must(out["outcome"] == "queued" and out["agents"] == 2000 and out["groups"] == {"total": 1, "sent": 1, "failed": 0, "not_started": 0}, out)
must(len(TASK_CALLS) == 1 and sent_groups()[0] == list(range(BASE, BASE + 2000)), "one group, nothing truncated")
must(len(run_rows()) == 1 and run_rows()[0]["metadata"]["group"] == 1 and run_rows()[0]["metadata"]["groups"] == 1 and run_rows()[0]["metadata"]["total_agents"] == 2000, run_rows())
print("       2000 endpoints are one group, sent whole")

# ---- 2001 and 4500 split; no id twice, none lost, in order
for count, sizes in ((2001, [2000, 1]), (4500, [2000, 2000, 500]), (6000, [2000, 2000, 2000])):
    fresh(count)
    run, out = start()
    groups = sent_groups()
    flat = [i for g in groups for i in g]
    must(out["outcome"] == "queued" and out["agents"] == count and [len(g) for g in groups] == sizes, (count, out, [len(g) for g in groups]))
    must(flat == list(range(BASE, BASE + count)) and len(set(flat)) == len(flat), "no id twice, none lost, in order")
    must(out["groups"] == {"total": len(sizes), "sent": len(sizes), "failed": 0, "not_started": 0}, out)
    must(out["summary"] == f"{count} endpoint(s) in {len(sizes)} group(s): {len(sizes)} sent, 0 failed, 0 not started.", out["summary"])
    rows = run_rows()
    must([r["metadata"]["group"] for r in rows] == list(range(1, len(sizes) + 1)) and all(r["metadata"]["groups"] == len(sizes) and r["metadata"]["total_agents"] == count for r in rows), rows)
    must([r["metadata"]["agent_count"] for r in rows] == sizes and all(r["strict"] is True for r in rows), "one strict row per group")
    must(len({r["metadata"]["targets_digest"] for r in rows}) == len(sizes), "each group has its own digest")
    must(len(group_marks(run)) == len(sizes) and all(m["state"] == "sent" for m in group_marks(run)), run.system_action_marks)
    must(no_ids_in_audit(count) and not any("agents" in r["metadata"] and isinstance(r["metadata"]["agents"], list) for r in rows), "no endpoint id in any audit row")
print("       2001, 4500 and 6000 endpoints split into 2, 3 and 3 groups: no id twice, none lost, one strict audit row and one mark per group")

# ---- the ceiling: 20 groups run, 40 001 is refused whole
fresh(40000)
run, out = start()
must(out["outcome"] == "queued" and len(TASK_CALLS) == 20 and out["groups"]["total"] == 20 and len(group_marks(run)) == 20, (out.get("groups"), len(TASK_CALLS)))
fresh(40001)
run, out = start()
must(isinstance(out, str) or isinstance(out, Exception), out)
must(not TASK_CALLS and not run_rows() and [a["metadata"]["reason"] for a in AUDITS if a["action"] == "deny"] == ["agent_count"], AUDITS)
must(run.status == "skipped" and run.error_type == "SystemActionRefused" and not run.system_action_marks, run.__dict__)
print("       40 000 endpoints run as 20 groups; 40 001 is refused whole with nothing sent and no mark")

# ---- one bad endpoint in the last group refuses the whole call before group 1 is sent
fresh(4500)
reset_targets = {"type": "endpoint", "ids": [str(i) for i in range(BASE, BASE + 4499)]}  # the last endpoint is not one of the schedule's targets
run = make_run("patching.handler", "patching", user=alice, owner="user", manual=True, targets=reset_targets)
out = go(run)
must(not TASK_CALLS and not run_rows() and not run.system_action_marks, "nothing was sent and no mark was written")
must([a["metadata"]["reason"] for a in AUDITS if a["action"] == "deny"] == ["outside_targets"], AUDITS)
fresh(4500)
SCOPE["alice"].discard(BASE + 4499)
run, out = start()
must(not TASK_CALLS and not run_rows() and [a["metadata"]["reason"] for a in AUDITS if a["action"] == "deny"] == ["out_of_scope"], AUDITS)
print("       a bad endpoint in the last group (outside the targets, or outside the scope) refuses the whole call before group 1 is sent")

# ---- an audit write that fails on group 2: nothing for group 2, the retry sends it once, group 1 is not sent again
fresh(4500)
real_record = sys.modules["tec_tac.audit"].record
calls = {"strict": 0, "fail_on": 2}


def flaky(**kw):
    if kw.get("strict"):
        calls["strict"] += 1
        if calls["strict"] == calls["fail_on"]:
            raise RuntimeError("audit store down")
    return real_record(**kw)


sys.modules["tec_tac.audit"].record = flaky
run = make_run("patching.handler", "patching", user=alice, owner="user", retries=2, manual=True)
out = go(run)
must(out == "retried" and run.status == "queued", (out, run.__dict__))
must(len(TASK_CALLS) == 1 and len(sent_groups()[0]) == 2000, "only group 1 was sent")
states = [m["state"] for m in group_marks(run)]
must(states == ["sent", "aborted"], states)
calls["fail_on"] = 0  # the store is back
out = go(run, retries=1)
must(out["outcome"] == "queued" and out["groups"] == {"total": 3, "sent": 3, "failed": 0, "not_started": 0}, out)
flat = [i for g in sent_groups() for i in g]
must(len(TASK_CALLS) == 3 and flat == list(range(BASE, BASE + 4500)) and len(set(flat)) == 4500, "every group once: group 1 was not sent again, group 2 was sent on the retry")
must([m["state"] for m in group_marks(run)] == ["sent", "sent", "sent"], run.system_action_marks)
must(len(run_rows()) == 3, "one strict row per group, none for the aborted attempt")
sys.modules["tec_tac.audit"].record = real_record
print("       an audit write that fails on group 2 sends nothing for it; the retry sends group 2 and 3 once and does not send group 1 again")

# ---- a crash while sending group 2: unknown, group 3 not started, never sent again
fresh(4500)
sent_calls = []


def crash_on_second(*args, **kwargs):
    if len(sent_calls) == 1:
        raise RuntimeError("broker unreachable")
    sent_calls.append(args)
    return SimpleNamespace(id="celery-x")


sys.modules["winupdate.tasks"].bulk_check_for_updates_task.delay = crash_on_second
run, out = start()
must(out == "run no longer active: failed" and run.status == "failed" and run.error_type == "OutcomeUnknown", (out, run.__dict__))
must(len(sent_calls) == 1, "group 1 was sent; group 2 raised; group 3 was never started")
must("2 sent" not in run.error and "1 sent, 1 failed, 1 not started" in run.error, run.error)
states = [m["state"] for m in group_marks(run)]
must(states == ["sent", "claiming"], states)
must(len(run_rows()) == 2, "group 3 has no audit row")
must(len([a for a in AUDITS if a["action"] == "custom:outcome-unknown"]) == 1, AUDITS)
# a retry, a duplicate delivery or a late completion never sends again
sys.modules["winupdate.tasks"].bulk_check_for_updates_task.delay = FakeTacticalTask("scan").delay
before = (len(AUDITS), list(run.system_action_marks), run.status, run.error)
run.status, run.finished_at = "queued", None
again = go(run)
must(again == "run no longer active: failed" and not TASK_CALLS, again)
run.status, run.finished_at = "failed", NOW[0]  # the run is over: a late delivery changes nothing
late = go(run)
must(not TASK_CALLS and len(group_marks(run)) == 2 and run.status == "failed", (late, run.__dict__))
print("       a crash in group 2 leaves it OutcomeUnknown, group 3 is not started and nothing is sent again")

# ---- a duplicate delivery after a full success changes nothing
fresh(4500)
run, out = start()
audits_after = len(AUDITS)
run.status, run.finished_at, run.result = "queued", None, {}
again = go(run)
must(again["outcome"] == "queued" and again.get("duplicate") is True and len(TASK_CALLS) == 3 and len(AUDITS) == audits_after, (again, len(TASK_CALLS)))
must(again["groups"] == {"total": 3, "sent": 3, "failed": 0, "not_started": 0}, again)
print("       a duplicate delivery sends nothing and writes nothing")

# ---- the source: the groups are cut from the sorted ids and the digest is per group
src = (APP / "system_actions.py").read_text(encoding="utf-8")
must("MAX_AGENTS_PER_GROUP = 2000" in src and "MAX_GROUPS = 20" in src and "MAX_AGENTS = MAX_AGENTS_PER_GROUP * MAX_GROUPS" in src, "the constants")
must("_digest(run.id, definition.id, group)" in src, "each group has its own digest")
meta = sa.system_actions_contract_metadata()
must(meta["max_agents"] == 40000 and meta["max_agents_per_group"] == 2000 and meta["max_groups"] == 20 and (tuple(int(x) for x in meta["version"].split("-")[0].split(".")) >= (1, 3, 0)), meta)  # 1.17.68: 1.2.0; 1.17.70: 1.3.0; 1.17.74: 1.4.0 (>= so a -N rebuild passes)
print("PASS system actions groups 1.17.66")
