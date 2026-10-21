#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.71 regression (held MEDIUM of the 1.17.70 review): a retry of a system WRITE run is bound to its decisions.

Before 1.17.71 the run key and the group marks covered the update numbers only. A first attempt that audited one set of decisions and failed at its
audit row could be retried with the same updates and OTHER decisions, and the retry then wrote the other decisions under a mark made for the first.

Covered. (1) The same updates with other decisions on a retry after an aborted first attempt: refused with decisions_changed, the run ends skipped
(SystemActionRefused), one deny row, nothing written, no closing row, no update number in the message. (2) The same updates with the same decisions
still write once. (3) Two groups: group 1 written, group 2's audit row fails, the retry brings other decisions: OutcomeUnknown, nothing more is written
and the message says the decisions changed. (4) _digest and _plan_digest without decisions return the 1.17.70 strings (task rows unchanged); with
decisions they change when one action changes and do not change with the input order. (5) A disjoint second call of the same run still works.
(6) The refusal text is in REASONS and in the write refusal_reasons list. (7) A plan stored by 1.17.70 (no ids_key) is refused on retry with other
decisions and ends outcome-unknown when a group was sent.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

H = Path(__file__).resolve().parent / "system-writes-harness-1.17.70.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

TEXT = "This run already tried these updates with other decisions, so Core wrote nothing new. Start a new run if you want the new decisions."


def first_attempt_fails(count, decisions):
    """A queued run whose first attempt fails at its strict audit row: its mark is aborted, nothing is written. Returns ``(run, nums)``."""
    fresh(count)
    nums = sorted(UPD)
    AUDIT_FAIL["strict"] = True
    CFG["changes"] = decisions(nums)
    run = make_run(HANDLER, "patchmanagement", user=alice, owner="user", retries=2, manual=True)
    run.parameters_snapshot = dict(CONFIRMED)
    out = go(run)
    must(out == "retried" and run.status == "queued" and not SER_CALLS, (out, run.status))
    must([m["state"] for m in group_marks(run)] == ["aborted"], run.system_action_marks)
    AUDIT_FAIL["strict"] = False
    return run, nums


# ---- (1) the same updates with other decisions: refused, nothing written
run, nums = first_attempt_fails(5, decide)
CFG["changes"] = decide(nums, "ignore")
out = go(run, retries=1)  # the refusal ends the run itself; the worker then only reports that it is no longer active
must(run.status == "skipped" and run.error_type == "SystemActionRefused" and run.error == TEXT, (run.status, run.error_type, run.error))
must(not SER_CALLS and all(UPD[n]["action"] == "nothing" for n in nums), "no decision changed and nothing was saved")
must(deny_reasons() == ["decisions_changed"], deny_reasons())
must(not closing_rows(), "no closing row")
must(not any(str(n) in run.error for n in nums), "no update number in the message")
must(len(before_rows()) == 0, "no write audit row for the refused retry")
print("       a retry with the same updates and other decisions is refused as decisions_changed and writes nothing")

# ---- (2) the same decisions on the retry: written once
run, nums = first_attempt_fails(5, decide)
CFG["changes"] = decide(nums)
out = go(run, retries=1)
must(isinstance(out, dict) and out["outcome"] == "written" and out["written"] == 5 and len(SER_CALLS) == 5, out)
must(current(nums) == {n: "approve" for n in nums} and [m["state"] for m in group_marks(run)] == ["sent"] and not deny_reasons(), run.system_action_marks)
print("       the same updates with the same decisions still write once after a failed audit row")

# ---- (3) two groups: group 1 written, group 2's audit row fails, the retry brings other decisions
real_group_size = sa.MAX_AGENTS_PER_GROUP
real_record = sys.modules["tec_tac.audit"].record
FAIL = {"on": True}


def flaky(**kw):
    meta = kw.get("metadata") or {}
    if FAIL["on"] and kw.get("strict") and meta.get("group") == 2 and meta.get("phase") == "before_write":
        raise RuntimeError("audit store down")
    return real_record(**kw)


try:
    sa.MAX_AGENTS_PER_GROUP = 2
    fresh(5)
    nums = sorted(UPD)
    sys.modules["tec_tac.audit"].record = flaky
    CFG["changes"] = decide(nums)
    run = make_run(HANDLER, "patchmanagement", user=alice, owner="user", retries=2, manual=True)
    run.parameters_snapshot = dict(CONFIRMED)
    out = go(run)
    must(out == "retried" and len(SER_CALLS) == 2, (out, SER_CALLS))
    must([m["state"] for m in group_marks(run)] == ["sent", "aborted"], run.system_action_marks)
    FAIL["on"] = False
    saved = len(SER_CALLS)
    CFG["changes"] = decide(nums, "ignore")
    out = go(run, retries=1)
    must(run.status == "failed" and run.error_type == "OutcomeUnknown", (run.status, run.error_type, run.error))
    must("decisions changed" in run.error and "did not write again" in run.error, run.error)
    must(len(SER_CALLS) == saved and not any(str(n) in run.error for n in nums), "nothing more was written, no number in the message")
    must(current(nums[:2]) == {nums[0]: "approve", nums[1]: "approve"} and all(UPD[n]["action"] == "nothing" for n in nums[2:]), current(nums))
finally:
    sys.modules["tec_tac.audit"].record = real_record
    sa.MAX_AGENTS_PER_GROUP = real_group_size
    FAIL["on"] = False
print("       part sent, then the same updates with other decisions: the run ends outcome-unknown and nothing more is written")

# ---- (4) the digests
must(sa._digest("run1", "act", [1, 2, 3]) == hashlib.sha256(b"run1|act|1,2,3").hexdigest()[:32], "the task digest is the 1.17.70 string")
must(sa._plan_digest("run1", "act", [1, 2, 3]) == hashlib.sha256(b"run1|act|plan|1,2,3").hexdigest()[:32], "the plan digest is the 1.17.70 string")
a = {1: "approve", 2: "ignore", 3: "approve"}
b = {3: "approve", 1: "approve", 2: "ignore"}  # the same pairs, other input order
c = {1: "approve", 2: "approve", 3: "approve"}  # one action differs
must(sa._digest("run1", "act", [1, 2, 3], a) == sa._digest("run1", "act", [1, 2, 3], b), "the order of the mapping does not matter")
must(sa._digest("run1", "act", [1, 2, 3], a) != sa._digest("run1", "act", [1, 2, 3], c), "one action changes the group digest")
must(sa._digest("run1", "act", [1, 2, 3], a) != sa._digest("run1", "act", [1, 2, 3]), "a write digest differs from the ids-only digest")
must(sa._plan_digest("run1", "act", [1, 2, 3], a) == sa._plan_digest("run1", "act", [1, 2, 3], b), "the plan digest ignores the order too")
must(sa._plan_digest("run1", "act", [1, 2, 3], a) != sa._plan_digest("run1", "act", [1, 2, 3], c), "one action changes the plan digest")
must(sa._plan_digest("run1", "act", [1, 2, 3], a) != sa._plan_digest("run1", "act", [1, 2, 3]), "a write plan digest differs from the ids-only digest")
print("       the digests are unchanged for a task and cover the decisions for a write")

# ---- (5) a disjoint second call of the same run still works
fresh(6)
nums = sorted(UPD)
run, out = start(decide(nums[:3]))
must(out["outcome"] == "written" and out["written"] == 3, out)
run.status, run.finished_at, run.result = "queued", None, {}
CFG["changes"] = decide(nums[3:], "ignore")
out = go(run)
must(isinstance(out, dict) and out["outcome"] == "written" and out["written"] == 3 and len(SER_CALLS) == 6, out)
must(current(nums) == {**{n: "approve" for n in nums[:3]}, **{n: "ignore" for n in nums[3:]}} and not deny_reasons(), current(nums))
print("       a second call of the same run with other update numbers still works")

# ---- (6) the reason is listed
must(sa.REASONS["decisions_changed"] == TEXT, sa.REASONS.get("decisions_changed"))
meta = sa.system_actions_contract_metadata()
must("decisions_changed" in meta["write"]["refusal_reasons"] and set(meta["refusal_reasons"]) == set(sa.REASONS), meta["write"]["refusal_reasons"])
must((tuple(int(x) for x in meta["version"].split("-")[0].split(".")) >= (1, 3, 0)) if "version" in meta else True, "core.system_actions is 1.3.0 or later (1.4.0 since 1.17.74)")
print("       decisions_changed is in REASONS and in the write refusal reasons; core.system_actions is 1.3.0 or later")

# ---- (7) a plan written by 1.17.70 (no ids_key; targets_digest is the ids-only digest)
fresh(4)
nums = sorted(UPD)
run = make_run(HANDLER, "patchmanagement", user=alice, owner="user", retries=0, manual=True)
run.parameters_snapshot = dict(CONFIRMED)
old_group = sa._digest(run.id, WRITE, nums)
run.system_action_marks = [
    {"action_id": WRITE, "kind": "plan", "targets_digest": sa._plan_digest(run.id, WRITE, nums), "ids": sa._ranges_of(nums), "group_digests": [old_group],
     "group_size": sa.MAX_AGENTS_PER_GROUP, "state": "plan"},
    {"action_id": WRITE, "targets_digest": old_group, "state": "sent", "agents": 4},
]
CFG["changes"] = decide(nums, "ignore")
out = go(run)
must(run.status == "failed" and run.error_type == "OutcomeUnknown" and not SER_CALLS, (run.status, run.error_type, run.error))
fresh(4)
nums = sorted(UPD)
run = make_run(HANDLER, "patchmanagement", user=alice, owner="user", retries=0, manual=True)
run.parameters_snapshot = dict(CONFIRMED)
old_group = sa._digest(run.id, WRITE, nums)
run.system_action_marks = [
    {"action_id": WRITE, "kind": "plan", "targets_digest": sa._plan_digest(run.id, WRITE, nums), "ids": sa._ranges_of(nums), "group_digests": [old_group],
     "group_size": sa.MAX_AGENTS_PER_GROUP, "state": "plan"},
    {"action_id": WRITE, "targets_digest": old_group, "state": "aborted", "agents": 4},
]
CFG["changes"] = decide(nums)
out = go(run)
must(run.status == "skipped" and run.error_type == "SystemActionRefused" and run.error == TEXT and deny_reasons() == ["decisions_changed"], (run.status, run.error))
must(not SER_CALLS, "a plan from 1.17.70 is never written again with decisions Core cannot compare")
print("       a plan stored by 1.17.70 is refused or ends outcome-unknown on a retry, never written again")

print("PASS system writes retry 1.17.71")
