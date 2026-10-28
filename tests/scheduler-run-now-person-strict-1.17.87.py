#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.87 regression (held Low of the 1.17.86 review): the real SchedulerRunNowView.post refuses a scheduler manager whose Tactical scope does not
cover the targets when the action is a declared person action (strict scope, no manager bypass), writes one deny row and queues nothing. An
undeclared action keeps the manager bypass. The test fails when ``strict=person_run`` is reverted in scheduler_views.py.
Harness of tests/scheduler-tactical-permission-1.17.17.py (real scheduler.py and scheduler_views.py on stubs)."""
from __future__ import annotations

from pathlib import Path

_here = Path(__file__).resolve().parent
_source = (_here / "scheduler-tactical-permission-1.17.17.py").read_text(encoding="utf-8")
_cut = _source.index("# ---- harness end")
exec(compile(_source[:_cut], str(_here / "scheduler-tactical-permission-1.17.17.py"), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
H = globals()
(must, sched, sv, Schedule, Run, User, PermissionDenied, Granted, QUEUED, handler, reset, GRANTS, SimpleNamespace, AUDITS) = (
    H[k] for k in ("must", "sched", "sv", "Schedule", "Run", "User", "PermissionDenied", "Granted", "QUEUED", "handler", "reset", "GRANTS", "SimpleNamespace", "AUDITS"))

# the real scope check runs: this user has a restricted Tactical scope, so a target of type "none" (needs unrestricted scope) is refused for them
ra = sys.modules["tec_tac.resources_adapter"]
ra.tactical_scope_unrestricted = lambda user: False
ra.canonical_agent_target_ids = lambda identifiers: list(identifiers)
Schedule.save = lambda self, update_fields=None: self in Schedule.objects.rows or Schedule.objects.rows.append(self)

DECLARED = {"patching": ("patching.scan",)}
sched._manifest_person_actions = lambda module_id: DECLARED.get(module_id, ())  # the signed manifest answer, replaced as 1.17.80 tests do
sched.register_scheduled_action(id="patching.scan", module_id="patching", label="Scan", handler=handler, target_types=("none",), permission="patching.run")
sched.register_scheduled_action(id="patching.plain", module_id="patching", label="Plain", handler=handler, target_types=("none",), permission="patching.run")
manager = User("manager", Granted(21, can_do_server_maint=True))
GRANTS.add((21, "patching.run"))


def run_now(user, schedule):
    try:
        return sv.SchedulerRunNowView().post(SimpleNamespace(user=user), str(schedule.pk))
    except PermissionDenied as exc:
        return exc


def module_schedule(action):
    return Schedule.objects.create(name=action, module_id="patching", action_id=action, owner_type="module", owner_module="patching", owner_key=action,
                                   targets={"type": "none"})


def deny_rows():
    return [a for a in AUDITS if a.get("action") == "deny" and a.get("object_type") == "scheduler_schedule"]


# declared person action: the manager is outside scope, so 403, no run, one deny row
reset()
s = module_schedule("patching.scan")
must(sched.manual_person_action(s) is True, "the action is declared")
reply = run_now(manager, s)
must(isinstance(reply, PermissionDenied) and "outside your Tactical scope" in str(reply), reply)
must(not Run.objects.rows and not QUEUED, "no run was created or queued")
rows = deny_rows()
must(len(rows) == 1 and rows[0]["metadata"]["reason"] == "outside_scope" and rows[0]["object_id"] == str(s.pk), rows)

# undeclared action: the manager bypass stays, the run is queued
reset()
s = module_schedule("patching.plain")
must(sched.manual_person_action(s) is False, "the action is not declared")
reply = run_now(manager, s)
must(getattr(reply, "status_code", None) == 202 and len(Run.objects.rows) == 1 and not deny_rows(), reply)
print("PASS scheduler run now strict scope 1.17.87")
