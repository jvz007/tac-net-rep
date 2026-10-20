#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.61 regression (R-21): who may call complete_pending_run. Same technique as tests/event-jobs-caller-1.17.47.py.

Real frames are compiled under stub plugin folders, so the real frame walk of caller_identity decides. Covered: the owning module's own
code completes the run; another module, a test file, a library frame, a generated frame, a Core frame (the Scheduler), a functools.partial
run by Core, a disabled module and a legacy module are all refused with caller_unverified or wrong_module and change nothing; a registry
fault refuses (fail closed, no crash); a handler that completes its own run before it has returned finds no pending run (not_pending).
"""
from __future__ import annotations

import functools
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

alice = User("alice")
roots = {name: plugin(name, enabled=(name != "gamma"), legacy=(name == "oldmod")) for name in ("patching", "beta", "gamma", "oldmod")}
SRC = (
    "def complete(sched, run_id, ext):\n"
    "    return sched.complete_pending_run(run_id, external_job_id=ext, outcome='succeeded', result={'ok': True})\n"
)
patching = compile_as(roots["patching"] / "jobs.py", SRC)
beta = compile_as(roots["beta"] / "jobs.py", SRC)
gamma = compile_as(roots["gamma"] / "jobs.py", SRC)
oldmod = compile_as(roots["oldmod"] / "jobs.py", SRC)
core_frame = compile_as(APP / "scheduler.py", SRC + "def run_partial(fn):\n    return fn()\n")
lib = compile_as(LIB / "decorator.py", SRC)
generated = compile_as("<string>", SRC)
EARLY = {}


def early_handler(context):
    # module code finishing its own run before the handler has returned: the run is not pending yet
    try:
        patching["complete"](sched, context["run_id"], "job-1")
        EARLY["result"] = "accepted"
    except sched.SchedulerCompletionRefused as exc:
        EARLY["result"] = exc.reason
    return sched.pending_completion("module", "job-1")


sched.register_scheduled_action(id="patching.wait", module_id="patching", label="Wait", target_types=("none",), timeout_seconds=600,
                                handler=lambda context: sched.pending_completion("module", "job-1"))
sched.register_scheduled_action(id="patching.early", module_id="patching", label="Early", target_types=("none",), timeout_seconds=600, handler=early_handler)


def parked(action="patching.wait"):
    reset()
    run = make_run(action, "patching", user=alice)
    must(go(run) == "pending completion", run.__dict__)
    return run


def outcome_of(fn, run):
    try:
        fn(sched, run.id, "job-1")
    except sched.SchedulerCompletionRefused as exc:
        return exc.reason
    return "accepted"


def untouched(run):
    return run.status == "running" and run.completion_state == "pending" and run.result == {} and not run.schedule.last_run_at


run = parked()
must(outcome_of(patching["complete"], run) == "accepted" and run.status == "succeeded" and run.result == {"ok": True}, run.__dict__)
print("       the owning module's own code completes the run")

for name, fn, reason in (
    ("another module", beta["complete"], "wrong_module"),
    ("a library frame", lib["complete"], "caller_unverified"),
    ("a generated frame", generated["complete"], "caller_unverified"),
    ("a Core frame (the Scheduler)", core_frame["complete"], "caller_unverified"),
    ("a disabled module", gamma["complete"], "caller_unverified"),
    ("a legacy module", oldmod["complete"], "caller_unverified"),
):
    run = parked()
    must(outcome_of(fn, run) == reason and untouched(run), (name, reason))
    rows = [a for a in AUDITS if a["action"] == "custom:scheduler-completion-refused"]
    must(len(rows) == 1 and rows[0]["metadata"]["reason"] == reason and "result" not in repr(rows[0]["metadata"]), (name, AUDITS))
print("       another module, a library, a generated frame, a Core frame, a disabled and a legacy module are refused; one reason-code row each")

run = parked()
must(outcome_of(lambda s, r, e: s.complete_pending_run(r, external_job_id=e, outcome="succeeded"), run) == "caller_unverified" and untouched(run))
print("       a call from a test file (outside every module) is refused")

run = parked()
partial = functools.partial(sched.complete_pending_run, run.id, external_job_id="job-1", outcome="succeeded")
try:
    core_frame["run_partial"](partial)
    raise AssertionError("a partial run by Core completed the run")
except sched.SchedulerCompletionRefused as exc:
    must(exc.reason == "caller_unverified" and untouched(run), exc.reason)
own = functools.partial(patching["complete"], sched, run.id, "job-1")
core_frame["run_partial"](own)  # a partial of the owner's own function: the owner's frame is the caller
must(run.status == "succeeded", run.__dict__)
print("       a functools.partial of the provider run by Core is refused; a partial of the owner's own function is the owner's call")

run = parked()
STATE_FAULT["registry"] = True
must(outcome_of(patching["complete"], run) == "caller_unverified" and untouched(run), "a registry fault fails closed")
STATE_FAULT["registry"] = False
must(outcome_of(patching["complete"], run) == "accepted")
print("       a registry fault refuses (fail closed, no raise) and the next call is checked again")

reset()
run = make_run("patching.early", "patching", user=alice)
go(run)
must(EARLY["result"] == "not_pending" and run.status == "running" and run.completion_state == "pending", (EARLY, run.__dict__))
must(outcome_of(patching["complete"], run) == "accepted", "after the handler has returned the module can complete")
print("       completing before the handler has returned finds no pending run (not_pending); afterwards it works")

print("PASS scheduler completion caller 1.17.61")
