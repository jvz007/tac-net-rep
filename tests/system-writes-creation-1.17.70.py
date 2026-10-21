#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.70 regression (CQ203, AD-45): creating or editing a schedule for the write row winupdate.set_action.

The real system_action_confirmation.py, system_actions.py, scheduler.py (reconcile_schedule) and system_writes.py on the stub harness. Covered: the confirmed
parameters {allowed_actions} are validated by the row at creation (the confirmed record, never the caller); the confirmation id is bound to allowed_actions,
so an id made for one list does not open a schedule with another; the Yes or No text names the allowed decisions in plain words, says Tactical keeps them
after the module is removed and carries the dangerous line, but no re-approve warning and no script line; the script line of scripts.run is unchanged and
shows only for that row; a task row's text is unchanged; the flag of the row, the module being enabled and the replacement being honoured are checked at
creation; a person without can_manage_winupdates is refused; an allowed creation writes one strict audit row.
"""
from __future__ import annotations

from datetime import time
from pathlib import Path

H = Path(__file__).resolve().parent / "system-writes-harness-1.17.70.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"
conf._clock = lambda: 1_000_000.0

SCRIPT_FLAGS = ("can_run_bulk", "can_run_scripts")
bob = User("bob")
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: True
views._can_access_target_scope = lambda user, targets, **kw: True


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
_orig_save = Schedule.save


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    _orig_save(self, update_fields)


Schedule.save = _save
DAILY = {"schedule_type": "daily", "run_time": "03:00", "timezone": "UTC"}
KW = dict(schedule_type="daily", run_time=time(3, 0))
RUN = "scriptexecution.run"


def noop(context):
    return {"ok": True}


def world():
    fresh(0)
    mod("scripts")
    sys.modules["scripts"].__path__ = []
    mod("scripts.tasks", bulk_script_task=FakeTacticalTask("script"))
    plugin("scriptexecution", system_actions=[RUN])
    sa.register_system_action(RUN, "scriptexecution", "Scheduled script run", "scripts.run", SCRIPT_FLAGS)
    for aid, module in ((WRITE, "patchmanagement"), ("patching.scan", "patching"), (RUN, "scriptexecution")):
        if aid not in sched._ACTIONS:
            sched.register_scheduled_action(id=aid, module_id=module, label=aid, handler=noop, target_types=("none", "endpoint", "profile"), timeout_seconds=600)
    for who in ("alice", "bob"):
        FLAGS[who] = set(BOTH) | set(SCRIPT_FLAGS)
        SCOPE[who] = set(range(BASE, BASE + 41000))


def endpoints(count):
    return {"type": "endpoint", "ids": [str(BASE + i) for i in range(count)]}


def params(*decisions):
    return {sa.PARAMETERS_KEY: {"allowed_actions": list(decisions)}}


def describe(user=alice, action=WRITE, parameters=None, targets=None):
    return conf.describe_confirmation(user, action, targets if targets is not None else endpoints(3), parameters, DAILY)


def create(confirmation_id, user=alice, action=WRITE, parameters=None, key="rules"):
    return sched.reconcile_schedule(owner_module=action.split(".")[0], owner_key=key, action_id=action, targets=endpoints(3), parameters=parameters, **KW,
                                    confirmed_by_request=RealRequest(user), confirmation_id=confirmation_id)


def refused(call, reason):
    try:
        call()
    except conf.SystemActionCreationRefused as exc:
        must(exc.reason == reason, (reason, exc.reason, str(exc)))
        return exc
    raise AssertionError(f"accepted instead of {reason}")


# ---- the text
world()
got = describe(parameters=params("approve", "ignore"))
text = got["text"]
must(got["required"] is True and got["total"] == 3 and got["confirmation_id"], got)
must(text.startswith("Advanced Patch Management update decisions: decisions on the Windows updates of 3 endpoint(s), at most 40000 decisions each time, written in groups of at most 2000, every day at 03:00 (UTC)."), text)
must("approve or ignore" in text and "do nothing" not in text, text)
must("Tactical keeps the decisions even if the module is later removed" in text and "Core records the earlier and the new decision of every update in its own audit log" in text, text)
must("This action can change many endpoints at once." in text and text.endswith("Requested by alice. Do you want to continue?"), text)
must("Script number" not in text and sa.REAPPROVE_WARNING not in text, "no script line and no re-approve warning on a write row")
must("Core does not check your rights again when it runs" in text, text)
three = describe(parameters=params("approve", "ignore", "nothing"))["text"]
must("approve, ignore or do nothing" in three, three)
one = describe(parameters=params("nothing"))["text"]
must("to do nothing," in one, one)
print("       the Yes or No text names the allowed decisions in plain words, says Tactical keeps them, carries the dangerous line and no script or re-approve line")

# ---- the script line stays with scripts.run; a task row's text is unchanged
world()
script_params = {sa.PARAMETERS_KEY: {"script_pk": 7, "args": ["-Quiet"], "timeout": 120}}
script_text = describe(action=RUN, parameters=script_params)["text"]
must("Script number 7, 1 argument(s), time limit 120 seconds." in script_text and "Tactical keeps the decisions" not in script_text, script_text)
scan_text = describe(action="patching.scan")["text"]
must("Script number" not in scan_text and "decisions" not in scan_text, scan_text)
must(scan_text.startswith("Scheduled patch scan: 3 endpoint(s), sent to Tactical in 1 group(s) of at most 2000, every day at 03:00 (UTC)."), scan_text)
print("       the script line shows only for scripts.run; a task row's text is unchanged")

# ---- the parameters are validated at creation
world()
for bad in (None, {}, params(), params("inherit"), params("approve", "inherit"), params("approve", "approve"), params("Approve"), {sa.PARAMETERS_KEY: {"allowed_actions": ["approve"], "installed": True}},
            {sa.PARAMETERS_KEY: {"allowed_actions": "approve"}}, {sa.PARAMETERS_KEY: {"script_pk": 1}}, {sa.PARAMETERS_KEY: ["approve"]}):
    del AUDITS[:]
    refused(lambda bad=bad: describe(parameters=bad), "bad_parameters")
    must([a["metadata"]["reason"] for a in AUDITS if a["action"] == "deny"] == ["bad_parameters"], AUDITS)
must(not Schedule.objects.rows, "nothing created")
print("       missing, empty and bad parameters are refused at creation with one deny row")

# ---- the confirmation id is bound to allowed_actions
world()
wide = describe(parameters=params("approve", "ignore"))["confirmation_id"]
refused(lambda: create(wide, parameters=params("approve")), "confirmation_invalid")
refused(lambda: create(wide, parameters=params("approve", "ignore", "nothing")), "confirmation_invalid")
refused(lambda: create(None, parameters=params("approve", "ignore")), "confirmation_required")
refused(lambda: create(wide, user=bob, parameters=params("approve", "ignore")), "confirmation_invalid")
must(not Schedule.objects.rows, "nothing created by a refused call")
del AUDITS[:]
made = create(wide, parameters=params("approve", "ignore"))
must(made is not None and len(Schedule.objects.rows) == 1, "created with the id made for exactly this list")
sched_row = Schedule.objects.rows[0]
must(sched_row.parameters == params("approve", "ignore") and sched_row.module_id == "patchmanagement" and sched_row.action_id == WRITE, sched_row.__dict__)
strict_rows = [a for a in AUDITS if a.get("strict") and a["object_type"] == "scheduler_schedule"]
must(len(strict_rows) == 1 and strict_rows[0]["metadata"].get("total_agents") == 3 and strict_rows[0]["metadata"].get("groups") == 1, AUDITS)
print("       the confirmation id is bound to allowed_actions: an id for one list does not open a schedule with another; an allowed creation writes one strict row")

# ---- the same checks as every row, at creation
world()
FLAGS["alice"] = {"can_run_bulk"}
refused(lambda: describe(parameters=params("approve")), "not_permitted")
FLAGS["alice"] = set(BOTH)
ENABLED["patchmanagement"] = False
refused(lambda: describe(parameters=params("approve")), "module_disabled")
ENABLED["patchmanagement"] = True
HONOURED.pop("patchmanagement")
refused(lambda: describe(parameters=params("approve")), "replacement_not_honoured")
HONOURED["patchmanagement"] = "patching"
SCOPE["alice"] = set()
refused(lambda: describe(parameters=params("approve")), "out_of_scope")
SCOPE["alice"] = set(range(BASE, BASE + 41000))
must(describe(parameters=params("approve"))["required"] is True, "and it works again")
print("       the row's flag, the module being enabled, the replacement being honoured and the person's scope are checked at creation")
print("PASS system writes creation 1.17.70")
