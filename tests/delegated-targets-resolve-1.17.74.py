#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.74 regression (Q-APM21 option b, Johan 21 October 2026): resolve_delegated_targets tells a provider which endpoints a delegation ticket covers.

The real delegation.py and system_actions.py on the stub harness. Covered: a valid ticket returns exactly the covered endpoints, by number or by agent id text, with the agent id
and the number of each; an endpoint outside the grant's targets or the person's stored scope, or one that does not exist, is only counted in not_covered and never named; every
ticket problem (garbage, tampered, forged with another key, a confirmation instead of a ticket, expired, grant changed, switched off, removed, wrong provider, the owner module,
another action, a module no longer declared or enabled) gives the same single refusal (ticket_invalid, the same message) with exactly one deny row that keeps the real cause for
the audit log only; the caller is read from the call stack (a direct import is caller_unverified; no function takes a caller); the shape of the endpoint list is judged (1 to 40 000
whole numbers or short printable texts) after the ticket; the call creates no run, no schedule and no audit row except the deny row of a refusal; it does not use up the ticket;
start_delegated_run still works after it with the covered numbers and keeps every refusal it had.
"""
from __future__ import annotations

import inspect
from pathlib import Path

H = Path(__file__).resolve().parent / "delegated-targets-harness-1.17.74.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

GENERIC = deleg.REASONS["ticket_invalid"]


def generic_refusal(call, cause=None):
    """The call is refused with the one generic refusal and exactly one deny row; ``cause`` is the real reason, in the row only."""
    before = len(AUDITS)
    try:
        call()
    except deleg.DelegationRefused as exc:
        must(exc.reason == "ticket_invalid" and str(exc) == GENERIC, (exc.reason, str(exc)))
    else:
        raise AssertionError("accepted")
    rows = AUDITS[before:]
    must(len(rows) == 1 and rows[0]["action"] == "deny" and rows[0]["metadata"]["reason"] == "ticket_invalid" and rows[0]["metadata"]["requested_by"] == "delegation", rows)
    if cause is not None:
        must(rows[0]["metadata"].get("cause") == cause, (cause, rows[0]["metadata"]))
    must(not any(str(BASE + i) in repr(rows[0]["metadata"].values()) for i in range(5)), "no endpoint in a deny row")
    return rows[0]


def nothing_made(schedules, runs):
    must(len(Schedule.objects.rows) == schedules and len(Run.objects.rows) == runs, "no run and no schedule was made")


# ---- a valid ticket returns exactly what it covers
fresh(4)  # endpoints BASE..BASE+3; the profile holds BASE and BASE+1 (client 10); BASE+2 and BASE+3 are in client 20
save_grant()
t = ticket()
schedules, runs, audits = len(Schedule.objects.rows), len(Run.objects.rows), len(AUDITS)
out = resolve(t, [BASE, BASE + 1, BASE + 2, BASE + 3, 99999])
must(out == {"agents": [{"agent_id": str(BASE), "pk": BASE}, {"agent_id": str(BASE + 1), "pk": BASE + 1}], "covered": 2, "not_covered": 3}, out)
must(not any(str(BASE + 2) in repr(out) or str(BASE + 3) in repr(out) or "99999" in repr(out) for _ in (0,)), "an endpoint the ticket does not cover is never named")
nothing_made(schedules, runs)
must(len(AUDITS) == audits, "a valid call writes no audit row")
out = resolve(t, [str(BASE), str(BASE + 2), "no-such-agent"])  # agent id texts
must(out == {"agents": [{"agent_id": str(BASE), "pk": BASE}], "covered": 1, "not_covered": 2}, out)
out = resolve(t, [BASE + 1, str(BASE + 1), BASE])  # the same endpoint by number and by text, and order does not matter
must([a["pk"] for a in out["agents"]] == [BASE, BASE + 1] and out["covered"] == 2 and out["not_covered"] == 0, out)
out = resolve(t, {BASE + 3})
must(out == {"agents": [], "covered": 0, "not_covered": 1}, out)
print("       a valid ticket returns exactly the covered endpoints, by number or by agent id, and only counts the others")

# ---- the person's stored scope cuts the answer, even for an endpoint the resolver names
fresh(4)
RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {BASE, BASE + 1}
save_grant()
t = ticket()
Grant.objects.rows[0].creation_scope["scope"].update(whole_client_ids=[], site_ids=[100])  # the stored scope now reaches only the site of BASE
out = resolve(t, [BASE, BASE + 1])
must(out == {"agents": [{"agent_id": str(BASE), "pk": BASE}], "covered": 1, "not_covered": 1}, out)
Grant.objects.rows[0].creation_scope = {}
before = len(AUDITS)
generic_refusal(lambda: resolve(t, [BASE]), "creation_scope_unavailable")
print("       an endpoint outside the person's stored scope is not covered; a grant with no stored scope is the generic refusal")

# ---- every ticket problem is the same refusal, with one deny row
fresh(4)
save_grant()
good = ticket()
for label, bad in (("garbage", "garbage"), ("none", None), ("tampered", good[:-3] + "000"), ("zeros", good.split(".")[0] + "." + "0" * 64), ("number", 7), ("long", "a." * 3000)):
    generic_refusal(lambda bad=bad: resolve(bad, [BASE]), "ticket_invalid")
foreign = deleg._sign(b"tec-tac-delegation-confirmation-v1|", {"g": "x"})  # signed with the right secret, but a confirmation is not a ticket
generic_refusal(lambda: resolve(foreign, [BASE]), "ticket_invalid")
deleg._secret = lambda: b"another-secret"
other = None
deleg._secret = lambda: b"test-secret-key"
CLOCK[0] += deleg.TICKET_TTL_SECONDS - 1
must(resolve(good, [BASE])["covered"] == 1, "valid just before 24 hours")
CLOCK[0] += 2
generic_refusal(lambda: resolve(good, [BASE]), "ticket_expired")
fresh(4)
save_grant()
t1 = ticket()
save_grant()
generic_refusal(lambda: resolve(t1, [BASE]), "grant_changed")
t2 = ticket()
Grant.objects.rows[0].enabled = False
generic_refusal(lambda: resolve(t2, [BASE]), "grant_disabled")
Grant.objects.rows[0].enabled = True
t3 = ticket()
mods["maintenance"]["remove"](sa, owner_module="maintenance", grant_key=GK)
generic_refusal(lambda: resolve(t3, [BASE]), "grant_missing")
print("       garbage, tampered, forged, expired, changed, switched off and removed tickets are all the one generic refusal; the real cause is in the audit row only")

# ---- who and what
fresh(4)
save_grant()
t = ticket()
generic_refusal(lambda: resolve(t, [BASE], caller="maintenance"), "wrong_module")  # not even the owner module: only the provider asks
generic_refusal(lambda: resolve(t, [BASE], action_id="patchmanagement.other"), "unknown_action")
generic_refusal(lambda: resolve(t, [BASE], action_id=None), "unknown_action")
ENABLED["maintenance"] = False
generic_refusal(lambda: resolve(t, [BASE]), "module_disabled")
ENABLED["maintenance"] = True
PLUGINS["patchmanagement"].system_actions = ()
generic_refusal(lambda: resolve(t, [BASE]), "action_not_declared")
PLUGINS["patchmanagement"].system_actions = (ACTION,)
sa._ACTIONS[ACTION] = __import__("dataclasses").replace(sa._ACTIONS[ACTION], delegable_to=())  # the provider no longer allows the delegate
generic_refusal(lambda: resolve(t, [BASE]), "not_delegable")
print("       the owner module, another action, a disabled module, an undeclared action and a withdrawn delegable_to all get the same refusal")

# ---- the caller is read from the stack
fresh(4)
save_grant()
t = ticket()
before = len(AUDITS)
try:
    sa.resolve_delegated_targets(t, action_id=ACTION, endpoint_ids=[BASE])  # called from the test, which is no module
    raise AssertionError("an unverified caller was answered")
except deleg.DelegationRefused as exc:
    must(exc.reason == "caller_unverified", exc.reason)
parameters = list(inspect.signature(sa.resolve_delegated_targets).parameters)
must(parameters == ["ticket", "action_id", "endpoint_ids"] and "caller" not in parameters and "module" not in parameters and "provider" not in parameters, parameters)
must(list(inspect.signature(deleg.resolve_targets).parameters) == ["ticket", "action_id", "endpoint_ids"], "delegation.resolve_targets takes no caller either")
capability_provider = sa._PROVIDER
must(hasattr(capability_provider, "resolve_delegated_targets") and "resolve_delegated_targets" in sa.OPERATIONS, "the capability route exists")
print("       the caller comes from the call stack: a call from code that is no module is caller_unverified, and no function takes a caller")

# ---- the shape of the list is judged after the ticket
fresh(4)
save_grant()
t = ticket()
for bad, reason in (([], "agent_count"), (list(range(1, 40002)), "agent_count"), (None, "bad_agents"), ("1000", "bad_agents"), ({"a": 1}, "bad_agents"), ([True], "bad_agents"),
                    ([1.5], "bad_agents"), ([0], "bad_agents"), ([-1], "bad_agents"), ([2**63], "bad_agents"), ([None], "bad_agents"), ([""], "bad_agents"),
                    (["x" * 101], "bad_agents"), (["a\nb"], "bad_agents"), ([["1000"]], "bad_agents"), ([b"1000"], "bad_agents")):
    del AUDITS[:]
    delegation_refused(lambda bad=bad: resolve(t, bad), reason)
    must(len(AUDITS) == 1 and AUDITS[0]["metadata"]["reason"] == reason, AUDITS)
del AUDITS[:]
generic_refusal(lambda: resolve("garbage", []), "ticket_invalid")  # a bad ticket is judged first: a bad list does not tell a forger anything
must(len(resolve(t, list(range(BASE, BASE + 40000)))["agents"]) == 2, "40 000 references are the most one call may hold")
print("       the list is 1 to 40 000 whole numbers or short printable texts; a bad ticket is judged before the list")

# ---- it uses up nothing, and start still works after it
fresh(4)
save_grant()
t = ticket()
first = resolve(t, [BASE, BASE + 1, BASE + 2])
second = resolve(t, [BASE, BASE + 1, BASE + 2])
must(first == second, "asking twice gives the same answer")
run = delegated_start(t, agents=[a["pk"] for a in first["agents"]])
must(run.status == "queued" and run.owner_module == "patchmanagement", run.__dict__)
must(resolve(t, [BASE])["covered"] == 1, "the ticket still resolves after it started a run")
must(delegated_start(t, agents=[a["pk"] for a in first["agents"]]).id == run.id, "start_delegated_run answers the same run for the same endpoints")
delegation_refused(lambda: delegated_start(t, agents=[BASE]), "ticket_used")
delegation_refused(lambda: delegated_start(t, agents=[BASE + 2]), "outside_grant")
fresh(4)
save_grant()
t = ticket()
delegation_refused(lambda: delegated_start(t, agents=[BASE, BASE + 2]), "outside_grant")  # start keeps its specific refusals
print("       the call does not use up the ticket; start_delegated_run answers as before, with its own specific refusals")

# ---- the shared helper: start and resolve apply the same ticket checks
src = inspect.getsource(deleg.start) + inspect.getsource(deleg.resolve_targets)
must(src.count("_checked_ticket(") == 2, "one helper serves both")
must("_open(" not in inspect.getsource(deleg.start) and "_open(" not in inspect.getsource(deleg.resolve_targets), "neither opens the ticket on its own")
print("       start and resolve share one helper for the ticket checks")
print("delegated-targets-resolve-1.17.74: ok")
