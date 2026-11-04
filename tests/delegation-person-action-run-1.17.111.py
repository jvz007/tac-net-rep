#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.111 regression (AD-43): the ticket and the delegated one-off run of a module's person action (wapm.profile-install, started for Maintenance's person).

The real delegation.py, system_actions.py, scheduler.py, scheduler_run_context.py and tasks.py on the stub harness of delegation-person-action-harness-1.17.111.py.

Covered. (1) issue_delegation_ticket, then start_delegated_run: the one-off has created_by the person who confirmed, targets exactly the endpoints passed, parameters the confirmed record
plus the signed marker, one strict audit row; the worker runs the provider's own handler with the person's account disabled. (2) An endpoint outside the grant or the stored scope is refused; a
second use of the ticket for other endpoints is ticket_used and the same endpoints answer the same run; a ticket made for another provider or action is refused. (3) resolve_delegated_targets
answers the covered endpoints, and one generic ticket_invalid otherwise. (4) verify_run_context gives user the person and unattended True; run_is_validly_delegated is False after a grant edit or
removal, after delegable_to or the manifest entry is gone, after the allow-list drops the pair, with the wrong action id and with a forged marker, and the owner re-check is then back.
"""
from __future__ import annotations

from pathlib import Path

HARNESS_111 = Path(__file__).resolve().parent / "delegation-person-action-harness-1.17.111.py"
exec(compile(HARNESS_111.read_text(encoding="utf-8"), str(HARNESS_111), "exec"), globals())  # noqa: S102 - the shared test harness, not user input


def start(token, *, agents=None, action_id=ACTION, caller="wapm"):
    return call(caller, "start", token, action_id=action_id, agent_ids=agents if agents is not None else [1, 2])


def resolve(token, ids, *, action_id=ACTION, caller="wapm"):
    return call(caller, "resolve", token, action_id=action_id, endpoint_ids=ids)


def wapm_runs():
    return [r for r in Run.objects.rows if r.owner_module == "wapm"]


# ---- (1) the whole path
fresh()
save_grant()
token = ticket()
del AUDITS[:]
run = start(token)
must(run.status == "queued" and QUEUED_IDS == [str(run.id)] and run.owner_module == "wapm" and run.owner_type == "module" and run.manual is True and run.action_id == ACTION, run.__dict__)
schedule = run.schedule
must(schedule.created_by is alice and schedule.created_by_username == "alice" and schedule.confirmed_by_username == "alice" and schedule.owner_key.startswith("one-off:") and schedule.enabled is False, "created by the person")
must(schedule.targets == {"type": "endpoint", "ids": ["1", "2"]} and run.targets_snapshot == schedule.targets, "exactly the endpoints passed")
must(schedule.parameters[sa.PARAMETERS_KEY] == CONFIRMED and set(schedule.parameters) == {sa.PARAMETERS_KEY, deleg.MARKER_KEY} and run.parameters_snapshot == schedule.parameters, schedule.parameters)
must(schedule.creation_scope == grants()[0].creation_scope and schedule.creation_scope["captured_for"] == "alice", "the grant's stored scope travels with the run")
rows = [a for a in AUDITS if a["object_type"] == "scheduler_run"]
must(len(rows) == 1 and rows[0]["strict"] is True and rows[0]["actor"] is alice and rows[0]["metadata"]["action_id"] == ACTION and rows[0]["metadata"]["requested_by"] == "delegation", rows)
must(not any(x in repr(rows[0]["metadata"]) for x in ("'1'", "[1, 2]", "agent_ids")), "no endpoint id in the audit row")
alice.is_active = False  # the person's account is disabled; the run that was confirmed goes on
FLAGS["alice"] = set()
EXT_PERMS["alice"] = set()
SCOPE["alice"] = set()
must(sched._is_unattended_scheduled_run(run) is True and deleg.run_is_validly_delegated(run) is True, "the delegated one-off is unattended")
out = go(run)
must(run.status == "succeeded" and CALLS == [schedule.parameters], (run.status, out, CALLS))
print("       a person confirms once, Maintenance's live run issues a ticket, WAPM starts the one-off and its own handler runs with the person's account disabled")

# ---- (2) the start
fresh()
save_grant()
t = ticket()
refused(lambda: sa.start_delegated_run(t, action_id=ACTION, agent_ids=[1, 2]), "caller_unverified")
refused(lambda: start(t, caller="maintenance"), "wrong_module")
refused(lambda: start(t, action_id=OTHER_ACTION), "unknown_action")
refused(lambda: start(t, action_id="wapm.nothing"), "unknown_action")
for bad in ([], "12", [True], [1.5], [0], {1: 2}):
    refused(lambda bad=bad: start(t, agents=bad), "bad_agents" if bad != [] else "agent_count")
refused(lambda: start(t, agents=[1, 4]), "outside_grant")
refused(lambda: start(t, agents=[1, 999]), "outside_grant")
RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {1, 2, 3}
refused(lambda: start(t, agents=[1, 3]), "outside_grant")  # 3 is a target but outside the scope the person had when they saved it
RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {1, 2}
sched._ACTIONS[ACTION] = dataclasses.replace(sched._ACTIONS[ACTION], delegable_to=())
refused(lambda: start(t), "not_delegable")
sched._ACTIONS[ACTION] = dataclasses.replace(sched._ACTIONS[ACTION], delegable_to=("maintenance",))
deleg.PERSON_ACTION_DELEGATION.clear()
refused(lambda: start(t), "not_delegable")  # the allow-list no longer names the pair
deleg.PERSON_ACTION_DELEGATION.update({"maintenance": (ACTION,)})
PERSON_LISTED["wapm"] = (OTHER_ACTION,)
refused(lambda: start(t), "action_not_declared")
PERSON_LISTED["wapm"] = (ACTION, OTHER_ACTION)
ENABLED["maintenance"] = False
refused(lambda: start(t), "module_disabled")
ENABLED["maintenance"] = True
ENABLED["wapm"] = False
refused(lambda: start(t), "caller_unverified")  # a disabled provider is not a caller at all
ENABLED["wapm"] = True
must(not wapm_runs() and not QUEUED_IDS, "nothing was started by any refusal")
must(all(r["metadata"]["requested_by"] == "delegation" and "reason" in r["metadata"] for r in deny_rows()), "one deny row per refusal")
first = start(t)
again = start(t)
must(again is first and len(QUEUED_IDS) == 1 and len([s for s in Schedule.objects.rows if s.owner_module == "wapm"]) == 1, "the same ticket and endpoints name the same run")
del AUDITS[:]
refused(lambda: start(t, agents=[1]), "ticket_used")
must(len(deny_rows()) == 1 and deny_rows()[0]["metadata"]["reason"] == "ticket_used" and len(QUEUED_IDS) == 1, "one deny row, nothing more started")
# a ticket is for one grant: a grant for another action id cannot start this one, and a grant for this action cannot start another
fresh()
save_grant()
t = ticket()
sched._ACTIONS[OTHER_ACTION] = dataclasses.replace(sched._ACTIONS[OTHER_ACTION], delegable_to=("maintenance",))
deleg.PERSON_ACTION_DELEGATION["maintenance"] = (ACTION, OTHER_ACTION)  # even if a future release allowed both, a ticket binds the action of its grant
refused(lambda: start(t, action_id=OTHER_ACTION), "unknown_action")
print("       the provider only, for the action the grant holds, while the pair is allowed, listed and enabled; endpoints inside the grant AND the stored scope; one ticket one run")

# ---- (3) resolve_delegated_targets
fresh()
save_grant()
t = ticket()
answer = resolve(t, [1, 2, 3, 999])
must(answer == {"agents": [{"agent_id": "1", "pk": 1}, {"agent_id": "2", "pk": 2}], "covered": 2, "not_covered": 2}, answer)
must(resolve(t, ["2", 1])["covered"] == 2, "agent id texts and numbers")
must(not wapm_runs(), "resolving starts nothing")
for label, fn in (
    ("garbage", lambda: resolve("garbage", [1])), ("another module", lambda: resolve(t, [1], caller="maintenance")), ("another action", lambda: resolve(t, [1], action_id=OTHER_ACTION)),
):
    del AUDITS[:]
    refused(fn, "ticket_invalid")
    must(len(deny_rows()) == 1 and deny_rows()[0]["metadata"]["reason"] == "ticket_invalid", label)
save_grant()  # an edit revokes the ticket: the same single generic refusal
del AUDITS[:]
refused(lambda: resolve(t, [1]), "ticket_invalid")
must(deny_rows()[0]["metadata"]["cause"] == "grant_changed", deny_rows())
print("       resolve_delegated_targets answers the covered endpoints and one generic ticket_invalid for any ticket problem")

# ---- (4) the exemption holds only while everything holds
fresh()
save_grant()
run = start(ticket())
run.status = "running"
v = rc.verify_run_context(rc.issue_run_context({"run_id": str(run.id)}, run_id=run.id), expected_module_id="wapm", expected_action_id=ACTION)
must(v.user is alice and v.unattended is True and v.creator_username == "alice", (v.user, v.unattended))
must([row["agent_id"] for row in v.resolved_endpoints()] == ["1", "2"], "the run reads its endpoints inside the stored scope")
run.status = "queued"


def revoked(label, setup):
    fresh()
    save_grant()
    r = start(ticket())
    setup()
    must(deleg.run_is_validly_delegated(r) is False and sched._is_unattended_scheduled_run(r) is False, label)
    return r


r = revoked("a grant edit", lambda: save_grant(user=bob))
alice.is_active = False
bob.is_active = False
EXT_PERMS["bob"] = set()
out = go(r)
must(r.status == "skipped" and r.error_type == "AuthorizationRevoked" and not CALLS, (r.status, r.error_type, out))  # the owner re-check is back
revoked("a removed grant", lambda: call("maintenance", "remove", owner_module="maintenance", grant_key=GK))
revoked("a switched-off grant", lambda: setattr(grants()[0], "enabled", False))
revoked("delegable_to gone", lambda: sched._ACTIONS.__setitem__(ACTION, dataclasses.replace(sched._ACTIONS[ACTION], delegable_to=())))
revoked("the manifest entry gone", lambda: PERSON_LISTED.__setitem__("wapm", ()))
revoked("the allow-list dropped the pair", lambda: deleg.PERSON_ACTION_DELEGATION.clear())
revoked("the owner module disabled", lambda: ENABLED.__setitem__("maintenance", False))
revoked("the provider module disabled", lambda: ENABLED.__setitem__("wapm", False))
revoked("the action no longer registered", lambda: sched._ACTIONS.pop(ACTION))
revoked("the wrong action id", lambda: setattr(Run.objects.rows[-1], "action_id", OTHER_ACTION))
fresh()
save_grant()
run = start(ticket())
must(deleg.run_is_validly_delegated(run) is True, "valid")
tampered = dict(run.parameters_snapshot)
marker = tampered[deleg.MARKER_KEY]
tampered[deleg.MARKER_KEY] = marker[:-1] + ("0" if marker[-1] != "0" else "1")
run.parameters_snapshot = tampered
must(deleg.run_is_validly_delegated(run) is False and sched._is_unattended_scheduled_run(run) is False, "a tampered marker")
run.parameters_snapshot = dict(run.schedule.parameters)
plain = make_run(OTHER_ACTION, "wapm", user=alice, owner="one-off", targets={"type": "endpoint", "ids": ["1"]})
plain.parameters_snapshot = dict(run.parameters_snapshot)
plain.schedule.parameters = dict(run.parameters_snapshot)
must(deleg.run_is_validly_delegated(plain) is False and sched._is_unattended_scheduled_run(plain) is False, "a marker copied to another schedule means nothing")
sched.AD13_CONDITION_2_AMENDED = False
must(sched._is_unattended_scheduled_run(run) is False, "the switched-off amendment keeps every re-check")
sched.AD13_CONDITION_2_AMENDED = True
deleg.DECISION_RECORDED = False
must(deleg.run_is_validly_delegated(run) is False, "the decision switch keeps every re-check")
deleg.DECISION_RECORDED = True
real_open = deleg._open
deleg._open = lambda prefix, token: (_ for _ in ()).throw(RuntimeError("secret unreadable"))
must(deleg.run_is_validly_delegated(run) is False, "any doubt keeps the re-check")
deleg._open = real_open
must(deleg.run_is_validly_delegated(run) is True, "restored")
print("       the delegated one-off is unattended only while grant, action id, delegable_to, manifest entry, allow-list and both modules hold; a forged or copied marker and any doubt keep every re-check")
print("PASS delegation person action run 1.17.111")
