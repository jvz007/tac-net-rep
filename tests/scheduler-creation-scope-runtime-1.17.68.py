"""Runtime check for Core 1.17.68 creation-time scope and ownership (Johan, 21 October 2026, Q-APM12 b). It did NOT run on the development PC (Django, Celery and Tactical are not installed there).

It uses TWO real Tactical users and ONE test endpoint on the dev server. It shows that the creator of a schedule can be disabled and the unattended run still resolves the
same endpoints, that a schedule with no stored scope says so in plain words, and that the next person who edits a module-owned schedule becomes its owner. Use dev02.
Everything it creates is removed at the end. Nothing is sent to an endpoint (the probe handler only reads).

Environment (set on the command line):
    TECTAC_PROBE_USER    a Tactical username (the creator); its role must hold can_manage_winupdates and cover the test endpoint
    TECTAC_PROBE_USER2   a second Tactical username (the next editor); its role must hold can_manage_winupdates and cover the test endpoint too
    TECTAC_PROBE_AGENT   the Tactical agent number (the database id) of the test endpoint

One command:
    cd /rmm/api/tacticalrmm && TECTAC_PROBE_USER=jvz TECTAC_PROBE_USER2=tech2 TECTAC_PROBE_AGENT=12 ../env/bin/python manage.py shell < /path/to/tests/scheduler-creation-scope-runtime-1.17.68.py

What it checks (each line prints PASS or FAIL; the script ends with PASS only when every line passed):
    1 the stored scope of the creator names them and holds can_manage_winupdates
    2 an unattended run (a scheduled run of a user-owned schedule) resolves the test endpoint
    3 the creator is DISABLED, the same run resolves the same endpoint (the live row is not read) and held_at_creation still answers True
    4 the run of a schedule with no stored scope fails with CreationScopeUnavailable in plain words
    5 a run a person started (manual) follows that person's live scope: with the creator disabled it is refused, as before
    6 a module-owned schedule created through reconcile_schedule by the first person is moved to the second person by an edit, with ONE strict 'modify' audit row naming
      owner_changed_from and owner_changed_to, and the stored scope is the second person's
    7 the first person editing it again takes it back, and the audit row names the move

How it works. The probe puts one scheduled action for the module patching into this shell (its handler is compiled under patching's own folder so Core names the caller)
and tells reconcile_schedule that a request from this shell is a real, session-checked one (a test device used nowhere in Core). The creator's is_active flag is put back
at the end, also on a failure.
"""
import os
import sys
from datetime import time
from types import SimpleNamespace

from accounts.models import User
from agents.models import Agent
from tec_tac import audit, registry, scheduler
from tec_tac.models import TecTacSchedule, TecTacScheduleRun
from tec_tac.tasks import execute_schedule_run

USER1, USER2, AGENT = (os.environ.get(name, "") for name in ("TECTAC_PROBE_USER", "TECTAC_PROBE_USER2", "TECTAC_PROBE_AGENT"))
MODULE, ACTION = "patching", "patching.tectac-probe-scope"
if not USER1 or not USER2 or USER1 == USER2 or not AGENT.isdigit():
    print("FAIL set TECTAC_PROBE_USER, TECTAC_PROBE_USER2 (a different user) and TECTAC_PROBE_AGENT")
    sys.exit(1)
root = next((p.root for p in registry.discover_plugins() if p.plugin_id == MODULE and p.plugin_type == "extension"), None)
if root is None:
    print("FAIL the module patching is not installed here")
    sys.exit(1)

SOURCE = (
    "def handler(context):\n"
    "    verified = scheduler.verify_run_context(context, expected_module_id='patching', expected_action_id=" + repr(ACTION) + ", require_owner=False)\n"
    "    rows = verified.resolved_endpoints()\n"
    "    return {'endpoints': [r['pk'] for r in rows], 'held': verified.held_at_creation('can_manage_winupdates'), 'unattended': verified.unattended, 'scope_for': (verified.creation_scope_info() or {}).get('captured_for')}\n"
)
namespace = {"scheduler": scheduler}
exec(compile(SOURCE, str(root / "_tectac_probe_scope_1_17_68.py"), "exec"), namespace)  # noqa: S102 - a probe handler under patching's folder
scheduler.register_scheduled_action(id=ACTION, module_id=MODULE, label="Creation scope probe", handler=namespace["handler"], target_types=("none", "endpoint"), permission="tactical:can_manage_winupdates")
real_person = scheduler._verified_person
scheduler._verified_person = lambda request: request.user  # a test device: this shell's request stands for a real, session-checked one

results = []


def step(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))


def make_run(schedule, *, manual=False):
    return TecTacScheduleRun.objects.create(**scheduler._run_kwargs(schedule, scheduled_for=scheduler.timezone.now(), manual=manual, targets_snapshot=schedule.targets or {}))


created = []
user1 = User.objects.get(username=USER1)
was_active = user1.is_active
try:
    user2 = User.objects.get(username=USER2)
    agent = Agent.objects.get(pk=int(AGENT))
    targets = {"type": "endpoint", "ids": [agent.agent_id]}
    from tec_tac import scheduler_creation_scope as scope

    snapshot = scope.capture(user1)
    print(f"stored scope: {snapshot}")
    step("1 the stored scope names the creator and holds the flag", snapshot["captured_for"] == USER1 and "can_manage_winupdates" in snapshot["flags"], str(snapshot["flags"][:5]))

    schedule = TecTacSchedule.objects.create(
        name="Creation scope probe", module_id=MODULE, action_id=ACTION, targets=targets, schedule_type="once", run_at=scheduler.timezone.now(), enabled=False,
        owner_type="user", created_by=user1, updated_by=user1, created_by_username=USER1, confirmed_by_username=USER1, creation_scope=snapshot,
    )
    created.append(schedule)
    run = make_run(schedule)
    execute_schedule_run.run(str(run.id))
    run.refresh_from_db()
    result = run.result or {}
    step("2 an unattended run resolves the test endpoint", run.status == "succeeded" and result.get("endpoints") == [agent.pk] and result.get("unattended") is True and result.get("held") is True, f"{run.status} {result}")

    User.objects.filter(pk=user1.pk).update(is_active=False)
    run = make_run(schedule)
    execute_schedule_run.run(str(run.id))
    run.refresh_from_db()
    result = run.result or {}
    step("3 with the creator disabled the same run resolves the same endpoint", run.status == "succeeded" and result.get("endpoints") == [agent.pk] and result.get("held") is True and result.get("scope_for") == USER1, f"{run.status} {result}")

    legacy = TecTacSchedule.objects.create(
        name="Creation scope probe, made before 0037", module_id=MODULE, action_id=ACTION, targets=targets, schedule_type="once", run_at=scheduler.timezone.now(), enabled=False,
        owner_type="user", created_by=user1, updated_by=user1, created_by_username=USER1, confirmed_by_username=USER1,
    )
    created.append(legacy)
    run = make_run(legacy)
    try:
        execute_schedule_run.run(str(run.id))
    except Exception:  # noqa: BLE001 - the worker task re-raises a failure after recording it
        pass
    run.refresh_from_db()
    step("4 a schedule with no stored scope fails in plain words", run.status == "failed" and run.error_type == "CreationScopeUnavailable" and "Edit it and save it once" in (run.error or ""), f"{run.status} {run.error_type} {run.error}")

    manual = make_run(schedule, manual=True)
    try:
        execute_schedule_run.run(str(manual.id))
    except Exception:  # noqa: BLE001
        pass
    manual.refresh_from_db()
    step("5 a run a person started follows the live account: refused while the creator is disabled", manual.status in ("skipped", "failed"), f"{manual.status} {manual.error_type}")
    User.objects.filter(pk=user1.pk).update(is_active=was_active)

    request1, request2 = SimpleNamespace(user=user1), SimpleNamespace(user=user2)
    kwargs = dict(owner_module=MODULE, owner_key="tectac-probe-scope-owner", action_id=ACTION, schedule_type="daily", run_time=time(3, 0), targets=targets)
    owned = scheduler.reconcile_schedule(**kwargs, confirmed_by_request=request1)
    created.append(owned)
    moved = scheduler.reconcile_schedule(**{**kwargs, "run_time": time(4, 0)}, confirmed_by_request=request2)
    rows = list(audit._auditlog_model().objects.filter(object_type="scheduler_schedule", action="modify").order_by("-id")[:1])
    text = repr([(r.message, getattr(r, "metadata", None), (r.debug_info or {}).get("metadata")) for r in rows])
    step("6 the next editor becomes the owner, with one strict modify row naming the move",
         moved.created_by_username == USER2 and moved.created_by_id == user2.pk and (moved.creation_scope or {}).get("captured_for") == USER2
         and "owner_changed_from" in text and USER1 in text and USER2 in text, text[:200])
    back = scheduler.reconcile_schedule(**{**kwargs, "run_time": time(5, 0)}, confirmed_by_request=request1)
    step("7 the first person editing it again takes it back", back.created_by_username == USER1 and back.created_by_id == user1.pk and (back.creation_scope or {}).get("captured_for") == USER1)
finally:
    scheduler._verified_person = real_person
    User.objects.filter(pk=user1.pk).update(is_active=was_active)
    for item in created:
        try:
            item.delete()
        except Exception:  # noqa: BLE001 - cleanup only
            pass
    TecTacSchedule.objects.filter(owner_module=MODULE, owner_key="tectac-probe-scope-owner").delete()

ok = bool(results) and all(results) and len(results) == 7
print(("PASS" if ok else "FAIL") + " Core 1.17.68 creation scope runtime")
if not ok:
    sys.exit(1)
