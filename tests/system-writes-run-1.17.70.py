#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.70 regression (CQ203, AD-45): run_system_write, the second kind of system action, on the REAL system_actions.py and system_writes.py.

Covered: decisions are written with the update, the decision before and the decision after in a STRICT audit row that exists BEFORE the first save, and
only the action column is saved; a failing audit row writes nothing and aborts the mark, the retry writes once; a retry or duplicate delivery never writes
twice; a failed save ends the run OutcomeUnknown and is never repeated; 2000 per group (4500 split 2000, 2000, 500; 40 000 are 20 groups; 40 001 is refused
untruncated); audit rows of at most 500 changes; every refusal writes nothing and one deny row (update outside the targets, endpoint outside the owner's scope
for a person-started run, outside the stored scope for an unattended run on a module-owned target type, unknown update, an action outside allowed_actions,
'inherit', an extra key such as installed, a duplicate update, bad shapes, the wrong calling module, an unverified caller, a disabled module, an action not
declared, a replacement that is no longer honoured, a missing flag, no confirmed parameters, a task row (wrong_kind) and run_system_action on the write row
(wrong_kind)); no id is named in a message; a decision a person changed in between is not overwritten and is counted; a no-op is counted and not written; a
row that vanished is counted; rows are read under a lock; the closing row carries the counts and the decisions actually saved; a closing row that cannot be
written does not undo the write.
"""
from __future__ import annotations

from pathlib import Path

H = Path(__file__).resolve().parent / "system-writes-harness-1.17.70.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input


def nothing_written(run, reason, *, kept=False):
    """The call was refused: no save, no write audit row, one deny row with ``reason``, no decision changed, no mark, and no update number in the text."""
    must(not SER_CALLS and not before_rows() and not closing_rows(), "nothing was written and no write audit row exists")
    must(deny_reasons() == [reason], (reason, deny_reasons()))
    must(all(UPD[n]["action"] == "nothing" for n in UPD), "no decision changed")
    if not kept:
        must(run.status == "skipped" and run.error_type == "SystemActionRefused", (run.status, run.error_type, run.error))
    must(not group_marks(run), run.system_action_marks)
    must(not any(str(UBASE + i) in run.error for i in range(5)), "no update number in the message")


# ---- decisions are written; the strict row comes first; only the action column is saved
fresh(5)
nums = sorted(UPD)
seen = {}
HOOKS["after_save"] = lambda pk: seen.setdefault("rows_at_first_save", (len(before_rows()), [a["strict"] for a in before_rows()]))
changes = decide(nums[:3]) + decide(nums[3:], "ignore")
run, out = start(changes)
must(out["outcome"] == "written" and out["changes"] == 5 and out["written"] == 5 and out["unchanged"] == 0 and out["changed_meanwhile"] == 0, out)
must(out["groups"] == {"total": 1, "sent": 1, "failed": 0, "not_started": 0} and "duplicate" not in out and "5 update decision(s)" in out["summary"], out)
must(run.status == "succeeded", (run.status, run.error))
must(current(nums) == {nums[0]: "approve", nums[1]: "approve", nums[2]: "approve", nums[3]: "ignore", nums[4]: "ignore"}, current(nums))
must(all(d == {"action": a} for (_pk, d), a in zip(SER_CALLS, ["approve"] * 3 + ["ignore"] * 2)) and [pk for pk, _ in SER_CALLS] == nums, SER_CALLS)
must(all(UPD[n]["installed"] is False and UPD[n]["kb"] == f"KB{i}" for i, n in enumerate(nums)), "installed and kb were never touched")
must(seen["rows_at_first_save"] == (1, [True]), f"the strict audit row exists before the first save: {seen}")
row = before_rows()[0]
meta = row["metadata"]
must(row["strict"] is True and row["module_id"] == "core" and row["object_id"] == WRITE, row)
must(meta["changes"] == [[nums[0], "nothing", "approve"], [nums[1], "nothing", "approve"], [nums[2], "nothing", "approve"], [nums[3], "nothing", "ignore"], [nums[4], "nothing", "ignore"]], meta["changes"])
must(meta["run_id"] == str(run.id) and meta["schedule_id"] == str(run.schedule.id) and meta["action_id"] == WRITE and meta["owner_module"] == "patchmanagement", meta)
must(meta["kind"] == "write" and meta["phase"] == "before_write" and meta["requested_by"] == "scheduler" and meta["group"] == 1 and meta["groups"] == 1, meta)
must(meta["run_kind"] == "person" and meta["creator"] == "alice" and "confirmed_by" in meta and meta["allowed_actions"] == ["approve", "ignore"], meta)
must(meta["targets_digest"] == group_marks(run)[0]["targets_digest"] and meta["total_changes"] == 5 and meta["change_count"] == 5 and meta["part"] == 1 and meta["parts"] == 1, meta)
close = closing_rows()
must(len(close) == 1 and close[0]["strict"] is True and close[0]["metadata"]["phase"] == "closed", close)
cm = close[0]["metadata"]
must((cm["written"], cm["unchanged"], cm["changed_meanwhile"], cm["vanished"]) == (5, 0, 0, 0) and cm["saved"] == [[n, UPD[n]["action"]] for n in nums], cm)
must(cm["targets_digest"] == meta["targets_digest"] and cm["changed_meanwhile_ids"] == [], cm)
must([m["state"] for m in group_marks(run)] == ["sent"], run.system_action_marks)
must(LOCKED == nums, f"every row is read under a lock: {LOCKED}")
print("       decisions are written with before and after in a strict row that exists before the first save; only the action column is saved; the closing row counts")

# ---- a failing audit row writes nothing and aborts the mark; the retry writes once
fresh(5)
nums = sorted(UPD)
AUDIT_FAIL["strict"] = True
CFG["changes"] = decide(nums)
run = make_run(HANDLER, "patchmanagement", user=alice, owner="user", retries=2, manual=True)
run.parameters_snapshot = dict(CONFIRMED)
out = go(run)
must(out == "retried" and run.status == "queued", (out, run.status))
must(not SER_CALLS and all(UPD[n]["action"] == "nothing" for n in nums) and not LOCKED, "nothing was written, no row was even locked")
must([m["state"] for m in group_marks(run)] == ["aborted"], run.system_action_marks)
AUDIT_FAIL["strict"] = False
out = go(run, retries=1)
must(out["outcome"] == "written" and out["written"] == 5 and len(SER_CALLS) == 5, out)
must([m["state"] for m in group_marks(run)] == ["sent"], run.system_action_marks)
print("       a failing audit row writes nothing and aborts the mark; the retry writes once")

# ---- the second chunk's audit row fails: still nothing is written (every row comes before the write)
fresh(700)
nums = sorted(UPD)
real_record = sys.modules["tec_tac.audit"].record
calls = {"n": 0}


def flaky(**kw):
    if kw.get("strict"):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("audit store down")
    return real_record(**kw)


sys.modules["tec_tac.audit"].record = flaky
CFG["changes"] = decide(nums)
run = make_run(HANDLER, "patchmanagement", user=alice, owner="user", retries=2, manual=True)
run.parameters_snapshot = dict(CONFIRMED)
out = go(run)
sys.modules["tec_tac.audit"].record = real_record
must(out == "retried" and not SER_CALLS and all(UPD[n]["action"] == "nothing" for n in nums), "no decision was written")
must(len(before_rows()) == 1 and [m["state"] for m in group_marks(run)] == ["aborted"], (len(before_rows()), run.system_action_marks))
print("       when the second audit chunk cannot be written, no decision is written")

# ---- at most once: a duplicate delivery never writes twice
fresh(4)
nums = sorted(UPD)
run, out = start(decide(nums))
rows_after, saves = len(AUDITS), len(SER_CALLS)
run.status, run.finished_at, run.result = "queued", None, {}
again = go(run)
must(again["outcome"] == "written" and again.get("duplicate") is True and len(SER_CALLS) == saves and len(AUDITS) == rows_after, again)
must(again["written"] == 0 and again["groups"] == {"total": 1, "sent": 1, "failed": 0, "not_started": 0}, again)
print("       a duplicate delivery writes nothing and adds no audit row")

# ---- a failed save is outcome-unknown and is never repeated
fresh(4)
nums = sorted(UPD)
HOOKS["serializer_fail"] = True
run, out = start(decide(nums))
must(run.status == "failed" and run.error_type == "OutcomeUnknown" and "may already have been sent" in run.error, (run.status, run.error_type, run.error))
must([m["state"] for m in group_marks(run)] == ["claiming"] and len(before_rows()) == 1 and not closing_rows(), run.system_action_marks)
HOOKS["serializer_fail"] = False
run.status, run.finished_at = "queued", None
go(run)
must(not SER_CALLS and run.status == "failed", "never written again")
must(len([a for a in AUDITS if a["action"] == "custom:outcome-unknown"]) >= 1, "an outcome-unknown row")
print("       a failed save ends the run OutcomeUnknown and Core never writes that group again")

# ---- groups: 2000 per group, 20 groups at most, 40 001 refused untruncated
fresh(4500)
nums = sorted(UPD)
run, out = start(decide(nums))
must(out["outcome"] == "written" and out["written"] == 4500 and out["groups"] == {"total": 3, "sent": 3, "failed": 0, "not_started": 0}, out)
must([m["agents"] for m in group_marks(run)] == [2000, 2000, 500] and len(SER_CALLS) == 4500 and len({pk for pk, _ in SER_CALLS}) == 4500, "no update twice, none lost")
sizes = [r["metadata"]["change_count"] for r in before_rows()]
must(sizes == [500] * 9 and max(sizes) <= 500, sizes)
must([r["metadata"]["group"] for r in before_rows()] == [1] * 4 + [2] * 4 + [3] and all(r["metadata"]["groups"] == 3 for r in before_rows()), "rows name their group")
must(len(closing_rows()) == 3 and [c["metadata"]["written"] for c in closing_rows()] == [2000, 2000, 500], "one closing row per group")
must(len({r["metadata"]["targets_digest"] for r in before_rows()}) == 3, "each group has its own digest")
print("       4500 updates split into groups of 2000, 2000 and 500; audit rows hold at most 500 changes; one closing row per group")

fresh(40000, agents=50)
nums = sorted(UPD)
run, out = start(decide(nums))
must(out["outcome"] == "written" and out["written"] == 40000 and out["groups"]["total"] == 20 and len(group_marks(run)) == 20 and len(SER_CALLS) == 40000, out["groups"])
print("       40 000 updates run as 20 groups")

fresh(5)
over = [{"update_id": UBASE + i, "action": "approve"} for i in range(40001)]
run, out = start(over)
nothing_written(run, "bad_changes")
must("40000" in run.error, run.error)
print("       40 001 changes are refused whole and untruncated")

# ---- the endpoint checks
fresh(6, agents=3)
nums = sorted(UPD)
CFG["agents"] = [BASE, BASE + 1]  # the schedule's targets leave out the third endpoint
run, out = start(decide(nums))
nothing_written(run, "outside_targets")
fresh(6, agents=3)
nums = sorted(UPD)
SCOPE["alice"].discard(BASE + 2)
run, out = start(decide(nums))
nothing_written(run, "out_of_scope")
print("       an update on an endpoint outside the targets, or outside a person-started run's role scope, refuses the whole call")

# an unattended run on a module-owned target type: judged by the stored creation-time scope, never the module's resolver alone
ROWS = {BASE: dict(agent_id="a1", hostname="h1", platform="windows", client_id=10, site_id=100), BASE + 1: dict(agent_id="a2", hostname="h2", platform="windows", client_id=10, site_id=100),
        BASE + 2: dict(agent_id="a3", hostname="h3", platform="windows", client_id=20, site_id=200)}


def unattended(updates, agents, resolver, stored=True):
    fresh(updates, agents=agents)
    AGENT_ROWS.update({pk: dict(r) for pk, r in ROWS.items()})
    DESCRIPTORS["alice"] = {"mode": "mixed", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    RESOLVED_MODULE_TARGETS[("patchmanagement", "profile")] = set(resolver)
    run = make_run(HANDLER, "patchmanagement", user=alice, owner="user", manual=False, targets={"type": "profile", "ids": [7]})
    run.parameters_snapshot = dict(CONFIRMED)
    run.schedule.creation_scope = creation_scope.capture(alice) if stored else {}
    SCOPE["alice"] = set()  # the live scope is irrelevant for an unattended run
    CFG["changes"] = decide(sorted(UPD))
    return run, go(run)


run, out = unattended(6, 3, {BASE, BASE + 1, BASE + 2})
nothing_written(run, "out_of_scope")  # endpoint BASE+2 is client 20, outside the stored scope
run, out = unattended(4, 2, {BASE, BASE + 1})
must(isinstance(out, dict) and out["outcome"] == "written" and out["written"] == 4 and len(SER_CALLS) == 4, out)
run, out = unattended(4, 2, {BASE, BASE + 1}, stored=False)
nothing_written(run, "creation_scope_unavailable")
run, out = unattended(4, 2, {BASE})  # the module's resolver names only one of the two endpoints the updates live on
nothing_written(run, "outside_targets")
print("       an unattended run on a module-owned target type is cut to the stored creation-time scope and to the resolver's endpoints, and refuses when there is no stored scope")


# ---- the changes
def bad(changes, reason, **kw):
    fresh(5)
    run, _out = start(changes(sorted(UPD)) if callable(changes) else changes, **kw)
    nothing_written(run, reason)


bad(lambda n: decide(n) + [{"update_id": 999999, "action": "approve"}], "unknown_update")
bad(lambda n: [{"update_id": 999999, "action": "approve"}], "unknown_update")
bad(lambda n: decide(n, "nothing"), "action_not_allowed")
bad(lambda n: decide(n[:2]) + decide(n[2:], "inherit"), "action_not_allowed")
bad(lambda n: decide(n, "Approve"), "action_not_allowed")
bad(lambda n: decide(n, "remove"), "action_not_allowed")
bad(lambda n: [{"update_id": n[0], "action": "approve", "installed": True}], "bad_changes")
bad(lambda n: [{"update_id": n[0], "action": "approve", "kb": "KB1"}], "bad_changes")
bad(lambda n: [{"update_id": n[0]}], "bad_changes")
bad(lambda n: [{"action": "approve"}], "bad_changes")
bad(lambda n: [{"update_id": n[0], "action": "approve"}, {"update_id": n[0], "action": "ignore"}], "bad_changes")
bad(lambda n: [{"update_id": n[0], "action": "approve"}, {"update_id": n[0], "action": "approve"}], "bad_changes")
bad(lambda n: [{"update_id": True, "action": "approve"}], "bad_changes")
bad(lambda n: [{"update_id": str(n[0]), "action": "approve"}], "bad_changes")
bad(lambda n: [{"update_id": float(n[0]), "action": "approve"}], "bad_changes")
bad(lambda n: [{"update_id": 0, "action": "approve"}], "bad_changes")
bad(lambda n: [{"update_id": -5, "action": "approve"}], "bad_changes")
bad(lambda n: [{"update_id": 2**63, "action": "approve"}], "bad_changes")
bad(lambda n: [{"update_id": n[0], "action": None}], "bad_changes")
bad(lambda n: [{"update_id": n[0], "action": ["approve"]}], "bad_changes")
bad(lambda n: [(n[0], "approve")], "bad_changes")
bad(lambda n: [], "bad_changes")
bad(lambda n: None, "bad_changes")
bad(lambda n: {"update_id": n[0], "action": "approve"}, "bad_changes")
bad(lambda n: "approve", "bad_changes")
print("       an unknown update, an action outside allowed_actions or 'inherit', an extra key such as installed, a duplicate and every bad shape refuse the whole call")

# the decisions are checked against what the person confirmed, so a narrower confirmation narrows the call
fresh(3)
run, out = start(decide(sorted(UPD), "ignore"), params={sa.PARAMETERS_KEY: {"allowed_actions": ["approve"]}})
nothing_written(run, "action_not_allowed")
fresh(3)
run, out = start(decide(sorted(UPD), "nothing"), params={sa.PARAMETERS_KEY: {"allowed_actions": ["nothing"]}})
must(out["written"] == 0 and out["unchanged"] == 3 and not SER_CALLS, out)  # every update is already 'nothing': counted, not written
for params in (None, {}, {sa.PARAMETERS_KEY: {}}, {sa.PARAMETERS_KEY: {"allowed_actions": []}}, {sa.PARAMETERS_KEY: {"allowed_actions": ["inherit"]}},
               {sa.PARAMETERS_KEY: {"allowed_actions": ["approve"], "installed": True}}):
    fresh(3)
    run, out = start(decide(sorted(UPD)), params=params)
    nothing_written(run, "bad_parameters")
print("       the allowed decisions come from the confirmed record only; none, empty or bad confirmed parameters refuse")

# ---- the common checks of a run
fresh(3)
ENABLED["patchmanagement"] = False
run, out = start(decide(sorted(UPD)))
nothing_written(run, "caller_unverified", kept=True)  # the frame walk already refuses a disabled module, before the module_disabled check is reached
fresh(3)
PLUGINS["patchmanagement"].system_actions = ()
run, out = start(decide(sorted(UPD)))
nothing_written(run, "action_not_declared", kept=True)
fresh(3)
HONOURED.pop("patchmanagement")
run, out = start(decide(sorted(UPD)))
nothing_written(run, "replacement_not_honoured")
fresh(3)
FLAGS["alice"] = {"can_run_bulk"}
run, out = start(decide(sorted(UPD)))
nothing_written(run, "permission_lost")
fresh(3)
alice.is_active = False
run, out = start(decide(sorted(UPD)))
alice.is_active = True
must(not SER_CALLS and not before_rows(), "an inactive owner writes nothing")
print("       a disabled module, an action no longer in the signed manifest, a replacement that is no longer honoured, a lost flag and an inactive owner write nothing")

# ---- who is calling
fresh(3)
other_ns = compile_as(roots["patching"] / "handlers.py", HANDLER_SRC, sa=sa, CFG=CFG)  # Windows Patching's code
sched.register_scheduled_action(id="patching.handler", module_id="patching", label="p", handler=other_ns["handler"], target_types=("none", "endpoint"), timeout_seconds=600)
run, out = start(decide(sorted(UPD)), handler="patching.handler")
must(not SER_CALLS and deny_reasons() == ["wrong_module"] and run.status != "skipped", (deny_reasons(), run.status))
fresh(3)
pm_ns = compile_as(roots["patchmanagement"] / "handlers.py", HANDLER_SRC, sa=sa, CFG=CFG)
sched.register_scheduled_action(id="patching.borrowed", module_id="patching", label="b", handler=pm_ns["handler"], target_types=("none", "endpoint"), timeout_seconds=600)
run, out = start(decide(sorted(UPD)), handler="patching.borrowed", module="patching")
must(not SER_CALLS and deny_reasons() == ["wrong_module"], deny_reasons())  # the caller is patchmanagement, the run belongs to patching
fresh(3)
LIBDIR = LIB / "nobody"
LIBDIR.mkdir(exist_ok=True)
stranger = compile_as(LIBDIR / "x.py", HANDLER_SRC, sa=sa, CFG=CFG)
sched.register_scheduled_action(id="patchmanagement.stranger", module_id="patchmanagement", label="s", handler=stranger["handler"], target_types=("none", "endpoint"), timeout_seconds=600)
run, out = start(decide(sorted(UPD)), handler="patchmanagement.stranger")
must(not SER_CALLS and deny_reasons() == ["caller_unverified"], deny_reasons())
fresh(3)
try:
    sa.run_system_write(object(), action_id=WRITE, changes=decide(sorted(UPD)))
    raise AssertionError("a context Core did not issue was accepted")
except sa.SystemActionRefused as exc:
    must(exc.reason == "context_invalid", exc.reason)
must(not SER_CALLS, "nothing written")
print("       another module's handler, a handler borrowed by another module's run, code that is no module and a context Core did not issue write nothing")

# ---- the two kinds
fresh(3)
plugin("patchmanagement", category="premium", replaces="patching", system_actions=[WRITE, "patchmanagement.install"])
sa.register_system_action("patchmanagement.install", "patchmanagement", "APM install", "winupdate.install", BOTH)
CFG["action_id"] = "patchmanagement.install"
run, out = start(decide(sorted(UPD)))  # run_system_write on a task row
nothing_written(run, "wrong_kind")
fresh(3)
CFG["action_id"] = WRITE
run, out = start(None, handler="patchmanagement.task_handler")  # run_system_action on the write row
nothing_written(run, "wrong_kind")
must(not TASK_CALLS, "no Tactical task was started")
print("       run_system_action on a write row and run_system_write on a task row are both wrong_kind, with nothing sent or written")

# ---- a decision a person changed in between is not overwritten
fresh(5)
nums = sorted(UPD)
HOOKS["before_lock"] = lambda: UPD[nums[1]].__setitem__("action", "ignore")  # a person decides after Core read the 'before'
run, out = start(decide(nums))
must(out["written"] == 4 and out["changed_meanwhile"] == 1 and out["unchanged"] == 0, out)
must(UPD[nums[1]]["action"] == "ignore" and nums[1] not in [pk for pk, _ in SER_CALLS], "the person's later decision wins")
must(closing_rows()[0]["metadata"]["changed_meanwhile"] == 1 and closing_rows()[0]["metadata"]["changed_meanwhile_ids"] == [nums[1]], closing_rows()[0]["metadata"])
must(closing_rows()[0]["metadata"]["saved"] == [[n, "approve"] for n in nums if n != nums[1]], closing_rows()[0]["metadata"]["saved"])
must("left alone" in out["summary"], out["summary"])
print("       a decision a person changed after Core read it is not overwritten, is counted as changed meanwhile and shows in the closing row")

# ---- a no-op is counted and not written
fresh(5)
nums = sorted(UPD)
UPD[nums[0]]["action"] = "approve"
UPD[nums[1]]["action"] = "approve"
run, out = start(decide(nums))
must(out["written"] == 3 and out["unchanged"] == 2 and [pk for pk, _ in SER_CALLS] == nums[2:], out)
must(before_rows()[0]["metadata"]["change_count"] == 3 and [c[0] for c in before_rows()[0]["metadata"]["changes"]] == nums[2:], "only real changes are in the 'before' row")
must(closing_rows()[0]["metadata"]["unchanged"] == 2, closing_rows()[0]["metadata"])
fresh(3)
nums = sorted(UPD)
for n in nums:
    UPD[n]["action"] = "ignore"
run, out = start(decide(nums, "ignore"))
must(out["written"] == 0 and out["unchanged"] == 3 and not SER_CALLS and not before_rows() and len(closing_rows()) == 1 and run.status == "succeeded", out)
print("       a change equal to the current decision is counted and not written; a group of only no-ops writes nothing and still closes")

# ---- a row that vanished between the read and the write is counted
fresh(4)
nums = sorted(UPD)
HOOKS["before_lock"] = lambda: UPD.pop(nums[0], None)
run, out = start(decide(nums))
must(out["written"] == 3 and nums[0] not in [pk for pk, _ in SER_CALLS] and closing_rows()[0]["metadata"]["vanished"] == 1, (out, closing_rows()[0]["metadata"]))
print("       an update that vanished before the locked write is counted and skipped")

# ---- an unreadable Tactical table refuses the whole call
fresh(3)
HOOKS["read_fail"] = True
run, out = start(decide(sorted(UPD)))
HOOKS["read_fail"] = False
nothing_written(run, "function_unavailable")
fresh(3)
saved_module = sys.modules.pop("winupdate.serializers")
must(writer.available() is False, "an unavailable serializer is reported")
run, out = start(decide(sorted(UPD)))
sys.modules["winupdate.serializers"] = saved_module
nothing_written(run, "function_unavailable")
print("       an unreadable update table or an unavailable serializer refuses the whole call")

# ---- a closing row that cannot be written does not undo the write
fresh(3)
nums = sorted(UPD)
real_record = sys.modules["tec_tac.audit"].record


def no_closing(**kw):
    if kw.get("action") == writer.CLOSING_ACTION:
        raise RuntimeError("audit store down")
    return real_record(**kw)


sys.modules["tec_tac.audit"].record = no_closing
run, out = start(decide(nums))
sys.modules["tec_tac.audit"].record = real_record
must(out["outcome"] == "written" and out["written"] == 3 and run.status == "succeeded" and len(before_rows()) == 1 and not closing_rows(), out)
must([m["state"] for m in group_marks(run)] == ["sent"], "the mark is sent: Core never writes this group again")
print("       a closing row that cannot be written is logged and the write stands; the 'before' row is the record")

# ---- the deny rows name a reason, the owner and no update
fresh(3)
run, out = start(decide(sorted(UPD), "nothing"))
row = next(a for a in AUDITS if a["action"] == "deny")
must(row["metadata"]["requested_by"] == "scheduler" and row["metadata"]["reason"] == "action_not_allowed" and not any(str(n) in repr(row["metadata"]) for n in UPD), row)
print("       a refusal writes one deny row with a reason and no update number")
print("PASS system writes run 1.17.70")
