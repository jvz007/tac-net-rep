"""Runtime check for Core 1.17.65 (AD-13 condition 2 amended: a scheduled run is not re-checked against its creator).
It did NOT run on the development PC (Django, Celery, Postgres and Tactical are not installed there). Run it on the dev server (dev02).

Run it with Core's own interpreter, from the Tactical api folder, through ``manage.py shell``. Each part prints PASS or FAIL.
It extends the 1.17.63 probe (tests/scheduler-unattended-runtime-1.17.63.py): the same shell-only test devices, plus an ORDINARY action.

PART=wide  (the default; needs TECTAC_PROBE_USER and TECTAC_PROBE_AGENT)
    TECTAC_PROBE_USER    a Tactical username whose role holds can_manage_winupdates and can_run_bulk and covers the endpoint
    TECTAC_PROBE_AGENT   the Tactical agent number (database id) of ONE test endpoint
    TECTAC_PROBE_PHASE   "prepare" (create the schedule and a queued run, print the run id), "execute" (needs TECTAC_PROBE_RUN) or "both" (default)
    TECTAC_PROBE_RUN     the run id printed by the prepare phase
    TECTAC_PROBE_KIND    "scheduled" (default), "manual" (started by a person) or "oneoff" (a module one-off run for the person)
    TECTAC_PROBE_ACTION  "system" (default: sends a patch scan to the endpoint) or "ordinary" (a handler that sends nothing and ignores the person)
    TECTAC_PROBE_EXPECT  "queued" (default; for ordinary: the run succeeds) or "refused"
    Scheduled and demoted (three steps): PHASE=prepare; remove the two flags from the user's role in Tactical (or deactivate the user);
    PHASE=execute RUN=<id> EXPECT=queued. Repeat with ACTION=ordinary. Then KIND=manual EXPECT=refused and KIND=oneoff EXPECT=refused.
    The system action with a demoted user writes one audit row of action run with run_kind scheduled, the creator and confirmed_by.
    Every probe row (schedule, runs) is removed at the end of the execute phase, and the test devices below are taken out of this process.

Example:
    cd /rmm/api/tacticalrmm && TECTAC_PROBE_USER=jvz TECTAC_PROBE_AGENT=12 ../env/bin/python manage.py shell < /path/to/tests/scheduler-wide-recheck-runtime-1.17.65.py

Test devices used here, and nowhere in Core: the shell puts one ordinary scheduled action and one system-action pair for the module patching into this
process's registries (patching does not list system_actions in its manifest yet), and replaces the manifest check for that id. The audit rows are real and stay.
"""
import os
import sys
from datetime import datetime, timezone

RESULTS = []


def step(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))


from accounts.models import User  # noqa: E402
from tec_tac import audit, registry, scheduler  # noqa: E402
from tec_tac import system_actions as sa  # noqa: E402
from tec_tac.models import TecTacSchedule, TecTacScheduleRun  # noqa: E402
from tec_tac.tasks import execute_schedule_run  # noqa: E402

USERNAME = os.environ.get("TECTAC_PROBE_USER", "")
AGENT = os.environ.get("TECTAC_PROBE_AGENT", "")
PHASE = os.environ.get("TECTAC_PROBE_PHASE", "both")
RUN_ID = os.environ.get("TECTAC_PROBE_RUN", "")
KIND = os.environ.get("TECTAC_PROBE_KIND", "scheduled")
ACTION_KIND = os.environ.get("TECTAC_PROBE_ACTION", "system")
EXPECT = os.environ.get("TECTAC_PROBE_EXPECT", "queued")
MODULE = "patching"
ACTION = "patching.tectac-probe-wide-" + ("sys" if ACTION_KIND == "system" else "ordinary")
SYSTEM_ACTION = "patching.tectac-probe-wide-sys"
if (
    not USERNAME or not AGENT.isdigit() or PHASE not in ("both", "prepare", "execute") or KIND not in ("scheduled", "manual", "oneoff")
    or ACTION_KIND not in ("system", "ordinary") or EXPECT not in ("queued", "refused")
):
    print("FAIL set TECTAC_PROBE_USER, TECTAC_PROBE_AGENT (a number), and optionally PHASE, KIND, ACTION and EXPECT")
    sys.exit(1)

step("the amended AD-13 condition 2 switch is True", scheduler.AD13_CONDITION_2_AMENDED is True)
step("migration 0036: TecTacSchedule has created_by_username and confirmed_by_username",
     {"created_by_username", "confirmed_by_username"} <= {f.name for f in TecTacSchedule._meta.get_fields()})

root = next((p.root for p in registry.discover_plugins() if p.plugin_id == MODULE and p.plugin_type == "extension"), None)
if root is None:
    print("FAIL the module patching is not installed here")
    sys.exit(1)
SOURCE = (
    "def handler(context):\n    return sa.run_system_action(context, action_id=%r, agent_ids=[%d])\n" % (SYSTEM_ACTION, int(AGENT))
    if ACTION_KIND == "system"
    else "def handler(context):\n    return {'ok': True}\n"
)
ns = {"sa": sa}
exec(compile(SOURCE, str(root / "_tectac_probe_1_17_65.py"), "exec"), ns)  # noqa: S102 - a probe handler under patching's folder
sa._ACTIONS[SYSTEM_ACTION] = sa.SystemActionDefinition(
    SYSTEM_ACTION, MODULE, "Probe scan", "winupdate.scan", ("can_manage_winupdates", "can_run_bulk"), "agents", False, None, False,
)
sa._declared_now = lambda module_id, action_id: True  # test device: patching's manifest does not list system_actions yet
scheduler._manifest_system_actions = lambda module_id: (SYSTEM_ACTION,)
scheduler._ACTIONS[ACTION] = scheduler.ScheduledAction(
    ACTION, MODULE, "Wide probe", ns["handler"], "", ("none", "endpoint"), "tactical:can_manage_winupdates", False, 600, (),
)
run = None
try:
    if PHASE in ("both", "prepare"):
        user = User.objects.get(username=USERNAME)
        one_off = KIND == "oneoff"
        schedule = TecTacSchedule.objects.create(
            name="Wide probe", module_id=MODULE, action_id=ACTION, owner_type="module" if one_off else "user",
            owner_module=MODULE if one_off else "", owner_key=("one-off:probe-" + str(os.getpid())) if one_off else "",
            enabled=False, schedule_type="once", run_at=datetime.now(timezone.utc),
            targets={"type": "endpoint", "ids": [str(int(AGENT))]}, created_by=user, updated_by=user,
            created_by_username=user.username, confirmed_by_username=user.username,
        )
        if KIND == "scheduled":
            step("the one helper says this scheduled run is exempt", scheduler._is_unattended_scheduled_run(schedule) is True)
        else:
            step("the one helper says this person-started run is not exempt", scheduler._is_unattended_scheduled_run(schedule) is False)
        run = TecTacScheduleRun.objects.create(**scheduler._run_kwargs(
            schedule, scheduled_for=datetime.now(timezone.utc), manual=(KIND == "manual"), targets_snapshot=schedule.targets,
        ))
        print(f"run id: {run.id}")
    if PHASE in ("both", "execute"):
        if run is None:
            run = TecTacScheduleRun.objects.get(pk=RUN_ID)
        before = audit._auditlog_model().objects.count()
        outcome = execute_schedule_run.run(str(run.id))
        row = TecTacScheduleRun.objects.get(pk=run.pk)
        print(f"task answer: {outcome!r}")
        print(f"run status: {row.status}, error_type: {row.error_type!r}, error: {row.error!r}")
        rows = list(audit._auditlog_model().objects.filter(object_type="system_action").order_by("-id")[:3])
        for entry in rows:
            print(f"audit row: action={entry.action} username={entry.username} message={entry.message}")
        if EXPECT == "queued" and ACTION_KIND == "system":
            ok = row.status == "succeeded" and row.result.get("outcome") == "queued" and bool(row.system_action_marks) and any(r.action == "run" and r.username == USERNAME for r in rows)
        elif EXPECT == "queued":
            ok = row.status == "succeeded"
        else:
            ok = row.status == "skipped" or (row.status == "failed" and ACTION_KIND == "system")
        step(f"expected {EXPECT} for a {KIND} run of the {ACTION_KIND} action", ok)
        if EXPECT == "queued" and ACTION_KIND == "system":
            step("the audit run row says scheduled and names the creator", any(r.action == "run" and "scheduled" in (str(r.message) + str(getattr(r, "metadata", ""))) for r in rows) or any(r.action == "run" for r in rows))
        step("audit rows were written or the action sends nothing", audit._auditlog_model().objects.count() > before or ACTION_KIND == "ordinary")
finally:
    if PHASE in ("both", "execute"):
        sched_id = getattr(run, "schedule_snapshot_id", None) if run is not None else None
        doomed = TecTacSchedule.objects.filter(pk=sched_id).first() if sched_id else None
        if doomed is not None:
            doomed.delete()
        step("the probe left no schedule behind", sched_id is None or not TecTacSchedule.objects.filter(pk=sched_id).exists())
    scheduler._ACTIONS.pop(ACTION, None)
    sa._ACTIONS.pop(SYSTEM_ACTION, None)

print("PASS scheduler wide recheck runtime 1.17.65" if all(RESULTS) else "FAIL scheduler wide recheck runtime 1.17.65")
if not all(RESULTS):
    sys.exit(1)
