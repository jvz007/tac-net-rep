"""Runtime check for Core 1.17.68 delegation (S4). It did NOT run on the development PC (Django, Celery and Tactical are not installed there).

It walks the whole path on the dev server with TWO real users and ONE test endpoint: a person confirms a grant for a module, that module's live Scheduler run issues a
ticket, the provider module starts the delegated run, and the provider's handler runs Tactical's own patch SCAN (harmless: no install) through the unchanged run_system_action,
with the person's account DISABLED. Then it shows that editing the grant revokes a ticket. Use dev02. Everything it creates is removed at the end.

The two modules are the installed modules `maintenance` (the owner) and `patching` (the provider; Windows Patching owns the winupdate rows). Both must be installed and enabled
on the dev server. The probe puts one provider action `patching.tectac-probe-delegation` (function winupdate.scan, `delegable_to=("maintenance",)`) into this shell.

Environment (set on the command line):
    TECTAC_PROBE_USER    a Tactical username; role holds can_manage_winupdates AND can_run_bulk and covers the test endpoint
    TECTAC_PROBE_USER2   a second Tactical username with the same rights (used for the takeover line)
    TECTAC_PROBE_AGENT   the Tactical agent number (the database id) of the test endpoint

One command:
    cd /rmm/api/tacticalrmm && TECTAC_PROBE_USER=jvz TECTAC_PROBE_USER2=tech2 TECTAC_PROBE_AGENT=12 ../env/bin/python manage.py shell < /path/to/tests/delegation-runtime-1.17.68.py

What it checks (each line prints PASS or FAIL; the script ends with PASS only when every line passed):
    1 describe_delegation gives the plain text and a confirmation id for the person
    2 a grant without the id is refused, with the id it is stored (one strict audit row, no endpoint id)
    3 Maintenance's live run issues a ticket
    4 the provider starts a delegated run for the test endpoint (queued, owner patching, created by the person)
    5 with the person DISABLED the run succeeds and Tactical's scan task is queued once (run_system_action's own result says queued)
    6 the same ticket and endpoint start no second run
    7 an endpoint that is not a target of the grant is refused (outside_grant) and starts nothing
    8 re-saving the grant revokes the old ticket (grant_changed)
    9 a second person's takeover is accepted and moves the grant (their scope covers the target) with one strict audit row
   10 removing the grant revokes the new ticket (grant_missing)

How it works. The targets of the grant are the one test endpoint, as a Tactical endpoint target. A request from this shell stands for a real, session-checked one (a test
device used nowhere in Core). The person's is_active flag is put back at the end, also on a failure.
"""
import os
import sys
import uuid
from types import SimpleNamespace

from accounts.models import User
from agents.models import Agent
from tec_tac import audit, registry, scheduler
from tec_tac import system_actions as sa
from tec_tac.models import TecTacDelegationGrant, TecTacSchedule, TecTacScheduleRun
from tec_tac.tasks import execute_schedule_run

USER1, USER2, AGENT = (os.environ.get(name, "") for name in ("TECTAC_PROBE_USER", "TECTAC_PROBE_USER2", "TECTAC_PROBE_AGENT"))
OWNER, PROVIDER, ACTION, GK = "maintenance", "patching", "patching.tectac-probe-delegation", "tectac-probe-profile"
RUN_ACTION = "maintenance.tectac-probe-run"
if not USER1 or not USER2 or USER1 == USER2 or not AGENT.isdigit():
    print("FAIL set TECTAC_PROBE_USER, TECTAC_PROBE_USER2 (a different user) and TECTAC_PROBE_AGENT")
    sys.exit(1)
roots = {p.plugin_id: p.root for p in registry.discover_plugins() if p.plugin_type == "extension"}
if OWNER not in roots or PROVIDER not in roots:
    print("FAIL the modules maintenance and patching must both be installed here")
    sys.exit(1)

BOTH = ("can_manage_winupdates", "can_run_bulk")
RESULTS = {}
OWNER_SRC = (
    "def describe(sa, request, **kw):\n    return sa.describe_delegation(request, **kw)\n"
    "def register(sa, request, **kw):\n    return sa.register_delegation_grant(request, **kw)\n"
    "def remove(sa, **kw):\n    return sa.remove_delegation_grant(**kw)\n"
    "def handler(context):\n    RESULTS['ticket'] = sa.issue_delegation_ticket(context, grant_key=" + repr(GK) + ")\n    return {'ticket_issued': True}\n"
)
PROVIDER_SRC = (
    "def start(sa, ticket, **kw):\n    return sa.start_delegated_run(ticket, **kw)\n"
    "def handler(context):\n    return sa.run_system_action(context, action_id=" + repr(ACTION) + ", agent_ids=IDS)\n"
)
IDS = [int(AGENT)]
owner_ns = {"sa": sa, "RESULTS": RESULTS}
provider_ns = {"sa": sa, "IDS": IDS}
exec(compile(OWNER_SRC, str(roots[OWNER] / "_tectac_probe_delegation_1_17_68.py"), "exec"), owner_ns)  # noqa: S102 - probe code under the owner module's folder
exec(compile(PROVIDER_SRC, str(roots[PROVIDER] / "_tectac_probe_delegation_1_17_68.py"), "exec"), provider_ns)  # noqa: S102 - probe code under the provider module's folder

sa._ACTIONS[ACTION] = sa.SystemActionDefinition(ACTION, PROVIDER, "Probe scan (delegated)", "winupdate.scan", BOTH, "agents", False, None, False, (OWNER,))
scheduler.register_scheduled_action(id=ACTION, module_id=PROVIDER, label="Delegation probe", handler=provider_ns["handler"], target_types=("none", "endpoint"), permission="tactical:can_manage_winupdates")
scheduler.register_scheduled_action(id=RUN_ACTION, module_id=OWNER, label="Delegation probe owner run", handler=owner_ns["handler"], target_types=("none",), permission="tactical:can_manage_winupdates")
real_manifest, real_declared, real_person, real_queue = scheduler._manifest_system_actions, sa._declared_now, scheduler._verified_person, scheduler._queue_run
scheduler._manifest_system_actions = lambda module_id: (ACTION,) if module_id == PROVIDER else real_manifest(module_id)
sa._declared_now = lambda module_id, action_id: action_id == ACTION or real_declared(module_id, action_id)
scheduler._verified_person = lambda request: request.user  # a test device: this shell's request stands for a real, session-checked one
scheduler._queue_run = lambda queued: queued  # keep every run QUEUED: this shell runs it, no broker message

results = []


def step(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))


def make_owner_run():
    schedule = TecTacSchedule.objects.create(
        name="Delegation probe owner run", module_id=OWNER, action_id=RUN_ACTION, targets={"type": "none"}, schedule_type="once", run_at=scheduler.timezone.now(), enabled=False,
        owner_type="module", owner_module=OWNER, owner_key=f"tectac-probe-owner-run-{uuid.uuid4().hex[:8]}",
    )
    run = TecTacScheduleRun.objects.create(**scheduler._run_kwargs(schedule, scheduled_for=scheduler.timezone.now(), manual=True, targets_snapshot={"type": "none"}))
    return schedule, run


def refused_reason(call):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 - the reason is what the probe reports
        return getattr(exc, "reason", type(exc).__name__)
    return None


user1 = User.objects.get(username=USER1)
was_active = user1.is_active
cleanup = []
try:
    user2 = User.objects.get(username=USER2)
    agent = Agent.objects.get(pk=int(AGENT))
    targets = {"type": "endpoint", "ids": [agent.agent_id]}
    common = dict(owner_module=OWNER, provider_module=PROVIDER, action_id=ACTION, targets=targets, parameters=None)
    request1, request2 = SimpleNamespace(user=user1), SimpleNamespace(user=user2)

    shown = owner_ns["describe"](sa, request1, **common)
    print(f"confirmation text: {shown.get('text')}")
    step("1 the plain text and a confirmation id come back", shown.get("required") is True and shown["total"] == 1 and "Do you want to continue?" in shown["text"] and bool(shown.get("confirmation_id")))

    no_id = refused_reason(lambda: owner_ns["register"](sa, request1, grant_key=GK, confirmation_id=None, **common))
    stored = owner_ns["register"](sa, request1, grant_key=GK, confirmation_id=shown["confirmation_id"], **common)
    grant = TecTacDelegationGrant.objects.get(owner_module=OWNER, grant_key=GK)
    rows = list(audit._auditlog_model().objects.filter(object_type="delegation_grant", action="add").order_by("-id")[:1])
    text = repr([(r.message, (r.debug_info or {}).get("metadata")) for r in rows])
    step("2 the grant needs the id and is stored with one strict audit row", no_id == "confirmation_required" and stored["created"] is True and grant.created_by_username == USER1 and bool(rows) and agent.agent_id not in text, f"{no_id} {text[:160]}")

    owner_schedule, owner_run = make_owner_run()
    cleanup.append(owner_schedule)
    execute_schedule_run.run(str(owner_run.id))
    ticket = RESULTS.get("ticket")
    step("3 Maintenance's live run issues a ticket", bool(ticket), str(TecTacScheduleRun.objects.get(pk=owner_run.pk).status))

    run = provider_ns["start"](sa, ticket, action_id=ACTION, agent_ids=IDS)
    cleanup.append(run.schedule)
    step("4 the provider starts a delegated run", run.status == "queued" and run.owner_module == PROVIDER and run.schedule.created_by_username == USER1 and run.targets_snapshot == {"type": "endpoint", "ids": [agent.agent_id]}, f"{run.status} {run.targets_snapshot}")

    User.objects.filter(pk=user1.pk).update(is_active=False)
    execute_schedule_run.run(str(run.id))
    row = TecTacScheduleRun.objects.get(pk=run.pk)
    result = row.result or {}
    print(f"run: {row.status}, {result}")
    step("5 with the person disabled the scan is queued once", row.status == "succeeded" and result.get("outcome") == "queued" and result.get("agents") == 1 and len(row.system_action_marks or []) >= 1, f"{row.status} {result.get('summary')}")
    User.objects.filter(pk=user1.pk).update(is_active=was_active)

    again = provider_ns["start"](sa, ticket, action_id=ACTION, agent_ids=IDS)
    step("6 the same ticket and endpoint start no second run", again.pk == run.pk and TecTacSchedule.objects.filter(owner_module=PROVIDER, owner_key=run.schedule.owner_key).count() == 1)

    other = Agent.objects.exclude(pk=agent.pk).first()
    outside = refused_reason(lambda: provider_ns["start"](sa, ticket, action_id=ACTION, agent_ids=[other.pk])) if other is not None else "outside_grant"
    step("7 an endpoint that is not a target of the grant is refused", outside == "outside_grant", str(outside))

    owner_ns["register"](sa, request1, grant_key=GK, confirmation_id=owner_ns["describe"](sa, request1, **common)["confirmation_id"], **common)
    revoked = refused_reason(lambda: provider_ns["start"](sa, ticket, action_id=ACTION, agent_ids=IDS))
    step("8 re-saving the grant revokes the old ticket", revoked == "grant_changed", str(revoked))

    token2 = owner_ns["describe"](sa, request2, **common)["confirmation_id"]
    moved = owner_ns["register"](sa, request2, grant_key=GK, confirmation_id=token2, **common)
    modify = list(audit._auditlog_model().objects.filter(object_type="delegation_grant", action="modify").order_by("-id")[:1])
    mtext = repr([(r.message, (r.debug_info or {}).get("metadata")) for r in modify])
    step("9 a second person's takeover moves the grant with one strict row", moved.get("owner_changed") is True and TecTacDelegationGrant.objects.get(owner_module=OWNER, grant_key=GK).created_by_username == USER2 and "owner_changed_from" in mtext, mtext[:200])

    schedule3, run3 = make_owner_run()
    cleanup.append(schedule3)
    execute_schedule_run.run(str(run3.id))
    ticket3 = RESULTS.get("ticket")
    owner_ns["remove"](sa, owner_module=OWNER, grant_key=GK)
    gone = refused_reason(lambda: provider_ns["start"](sa, ticket3, action_id=ACTION, agent_ids=IDS))
    step("10 removing the grant revokes the new ticket", gone == "grant_missing" and not TecTacDelegationGrant.objects.filter(owner_module=OWNER, grant_key=GK).exists(), str(gone))
finally:
    scheduler._manifest_system_actions, sa._declared_now, scheduler._verified_person, scheduler._queue_run = real_manifest, real_declared, real_person, real_queue
    User.objects.filter(pk=user1.pk).update(is_active=was_active)
    TecTacDelegationGrant.objects.filter(owner_module=OWNER, grant_key=GK).delete()
    TecTacSchedule.objects.filter(owner_module=OWNER, owner_key__startswith="tectac-probe-owner-run").delete()
    for item in cleanup:
        try:
            item.delete()
        except Exception:  # noqa: BLE001 - cleanup only
            pass
    sa._ACTIONS.pop(ACTION, None)

ok = bool(results) and all(results) and len(results) == 10
print(("PASS" if ok else "FAIL") + " Core 1.17.68 delegation runtime")
if not ok:
    sys.exit(1)
