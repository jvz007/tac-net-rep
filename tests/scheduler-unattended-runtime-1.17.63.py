"""Runtime check for Core 1.17.63 (CQ179 b unattended runs, the creator names, CQ183 mixed-case ids and the job hook read budget).
It did NOT run on the development PC (Django, Celery, Postgres and Tactical are not installed there). Run it on the dev server (dev02).

Run it with Core's own interpreter, from the Tactical api folder, through ``manage.py shell``. Each part prints PASS or FAIL.

PART=unattended  (a demoted creator's scheduled unattended run still runs and the audit row names the creator; a manual run is still refused)
    TECTAC_PROBE_USER    a Tactical username whose role holds can_manage_winupdates and can_run_bulk and covers the endpoint
    TECTAC_PROBE_AGENT   the Tactical agent number (database id) of ONE test endpoint
    TECTAC_PROBE_PHASE   "prepare" (create the schedule and a queued run, print the run id), "execute" (needs TECTAC_PROBE_RUN) or "both" (default)
    TECTAC_PROBE_RUN     the run id printed by the prepare phase
    TECTAC_PROBE_KIND    "scheduled" (default: the run is a scheduled one) or "manual" (the run is marked as started by a person)
    TECTAC_PROBE_EXPECT  "queued" (default) or "refused"
    Scheduled and demoted (three steps): PHASE=prepare; remove can_run_bulk AND can_manage_winupdates from the user's role in Tactical (or deactivate
    the user); PHASE=execute RUN=<id> EXPECT=queued. Then the same with KIND=manual EXPECT=refused: the manual run is re-checked.

PART=hook  (a mixed-case module id, and a tick with 60 unfinished job files; no input needed)
    It uses a temporary job folder and removes its own database rows. It never touches a real job.

Example:
    cd /rmm/api/tacticalrmm && TECTAC_PROBE_PART=hook ../env/bin/python manage.py shell < /path/to/tests/scheduler-unattended-runtime-1.17.63.py
    cd /rmm/api/tacticalrmm && TECTAC_PROBE_PART=unattended TECTAC_PROBE_USER=jvz TECTAC_PROBE_AGENT=12 ../env/bin/python manage.py shell < /path/to/tests/scheduler-unattended-runtime-1.17.63.py

Test devices used here, and nowhere in Core: the shell puts one scheduled action flagged unattended and one system action definition for the module
patching into this process's registries (patching does not list system_actions in its manifest yet), and replaces the manifest check for that one
action. The audit rows are real and stay. The probe schedule and its runs are removed at the end of the execute phase.
"""
import json
import os
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

PART = os.environ.get("TECTAC_PROBE_PART", "hook")
RESULTS = []


def step(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))


if PART not in ("hook", "unattended"):
    print("FAIL set TECTAC_PROBE_PART to hook or unattended")
    sys.exit(1)

from tec_tac import audit, scheduler  # noqa: E402
from tec_tac import system_actions as sa  # noqa: E402
from tec_tac.models import TecTacSchedule, TecTacScheduleRun, TecTacServerJobHook  # noqa: E402

# ------------------------------------------------------------------------------------------------ the migration and the contract shapes
step("migration 0036: TecTacSchedule has created_by_username and confirmed_by_username",
     {"created_by_username", "confirmed_by_username"} <= {f.name for f in TecTacSchedule._meta.get_fields()})
step("ScheduledAction ends with the unattended field", scheduler.ScheduledAction.__dataclass_fields__ and list(scheduler.ScheduledAction.__dataclass_fields__)[-1] == "unattended")
step("the new refusal reason exists", "action_not_declared" in sa.REASONS)

if PART == "unattended":
    from accounts.models import User
    from tec_tac import registry
    from tec_tac.tasks import execute_schedule_run

    USERNAME = os.environ.get("TECTAC_PROBE_USER", "")
    AGENT = os.environ.get("TECTAC_PROBE_AGENT", "")
    PHASE = os.environ.get("TECTAC_PROBE_PHASE", "both")
    RUN_ID = os.environ.get("TECTAC_PROBE_RUN", "")
    KIND = os.environ.get("TECTAC_PROBE_KIND", "scheduled")
    EXPECT = os.environ.get("TECTAC_PROBE_EXPECT", "queued")
    MODULE, ACTION, SYSTEM_ACTION = "patching", "patching.tectac-probe-unattended", "patching.tectac-probe-unattended"
    if not USERNAME or not AGENT.isdigit() or PHASE not in ("both", "prepare", "execute") or KIND not in ("scheduled", "manual") or EXPECT not in ("queued", "refused"):
        print("FAIL set TECTAC_PROBE_USER, TECTAC_PROBE_AGENT (a number), and optionally PHASE, KIND and EXPECT")
        sys.exit(1)
    root = next((p.root for p in registry.discover_plugins() if p.plugin_id == MODULE and p.plugin_type == "extension"), None)
    if root is None:
        print("FAIL the module patching is not installed here")
        sys.exit(1)
    SOURCE = "def handler(context):\n    return sa.run_system_action(context, action_id=%r, agent_ids=[%d])\n" % (SYSTEM_ACTION, int(AGENT))
    ns = {"sa": sa}
    exec(compile(SOURCE, str(root / "_tectac_probe_1_17_63.py"), "exec"), ns)  # noqa: S102 - a probe handler under patching's folder
    sa._ACTIONS[SYSTEM_ACTION] = sa.SystemActionDefinition(
        SYSTEM_ACTION, MODULE, "Probe scan", "winupdate.scan", ("can_manage_winupdates", "can_run_bulk"), "agents", False, None, False,
    )
    sa._declared_now = lambda module_id, action_id: True  # test device: patching's manifest does not list system_actions yet
    scheduler._manifest_system_actions = lambda module_id: (ACTION,)  # same reason, for the 1.17.63-1 binding of the action id to the manifest
    scheduler.AD13_CONDITION_2_AMENDED = True  # 1.17.63-1: this probe proves the path that applies once the amended AD-13 condition 2 is recorded
    probe_action = scheduler.ScheduledAction(
        ACTION, MODULE, "Unattended probe", ns["handler"], "", ("none", "endpoint"), "tactical:can_manage_winupdates", False, 600, (), True,
    )
    scheduler._ACTIONS[ACTION] = probe_action
    run = None
    schedule = None
    try:
        if PHASE in ("both", "prepare"):
            user = User.objects.get(username=USERNAME)
            schedule = TecTacSchedule.objects.create(
                name="Unattended probe", module_id=MODULE, action_id=ACTION, owner_type="user", enabled=False, schedule_type="once",
                run_at=datetime.now(timezone.utc), targets={"type": "endpoint", "ids": [str(int(AGENT))]}, created_by=user, updated_by=user,
                created_by_username=user.username, confirmed_by_username=user.username,
            )
            step("the tick helper says this schedule is unattended", scheduler._is_unattended_scheduled_run(schedule) is True)
            data = scheduler.serialize_schedule(schedule)
            step("the serialized schedule names the creator and the confirmer", data["created_by_username"] == USERNAME and data["confirmed_by_username"] == USERNAME)
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
            if EXPECT == "queued":
                ok = (
                    row.status == "succeeded" and row.result.get("outcome") == "queued" and bool(row.system_action_marks)
                    and any(r.action == "run" and r.username == USERNAME for r in rows)
                )
            else:
                ok = row.status == "skipped" and row.error_type == "SystemActionRefused" and not row.system_action_marks
            step(f"expected {EXPECT} for a {KIND} run", ok)
            step("audit rows were written", audit._auditlog_model().objects.count() > before)
    finally:
        if PHASE in ("both", "execute"):
            sched_id = getattr(run, "schedule_snapshot_id", None) if run is not None else None
            doomed = TecTacSchedule.objects.filter(pk=sched_id).first() if sched_id else None
            if doomed is not None:
                doomed.delete()
        scheduler._ACTIONS.pop(ACTION, None)
        sa._ACTIONS.pop(SYSTEM_ACTION, None)

if PART == "hook":
    from tec_tac import event_jobs as ej
    from tec_tac import event_jobs_policy as policy
    from tec_tac import server_job_hooks as hooks
    from tec_tac import server_maintenance as sm

    # CQ183: a module id with capital letters
    try:
        spec = policy.clean_spec(id="securityWAF.server_job_finished", module_id="securityWAF", label="probe")
        step("securityWAF.server_job_finished is accepted by Core's id check", spec.id == "securityWAF.server_job_finished")
    except Exception as exc:
        step("securityWAF.server_job_finished is accepted by Core's id check", False, str(exc))
    for bad in ("securitywaf.x", "SecurityWAF.x", "securityWAF.X"):
        try:
            policy.clean_spec(id=bad, module_id="securityWAF", label="probe")
            step(f"{bad} is refused for securityWAF", False)
        except policy.EventJobPolicyError:
            step(f"{bad} is refused for securityWAF", True)

    # the read budget: 60 unfinished job files older than one finished job, in a temporary folder
    TMP = tempfile.mkdtemp(prefix="tectac-hookprobe-")
    real_root, real_read, real_has, real_status, real_blocked, real_publish = (
        sm._jobs_root, sm._read_job, ej.has_registered_event_job, ej.module_status_for_core, hooks._replacement_blocked, ej.publish_for_core,
    )
    ids = []
    published, reads = [], []
    try:
        now = datetime.now(timezone.utc)

        def write(job_id, status, age):
            record = {
                "schema": 1, "id": job_id, "action": "securityWAF.probe", "owner_module": "securityWAF", "status": status, "stage": "x",
                "created_at": now.isoformat(), "finished_at": now.isoformat() if status == "succeeded" else None, "context": {}, "parameters": {},
                "public_parameters": {}, "exit_result": {"success": status == "succeeded", "exit_code": 0, "signal": None, "timed_out": False}, "failure": None,
            }
            path = os.path.join(TMP, f"{job_id}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(record, handle)
            stamp = (now - timedelta(seconds=age)).timestamp()
            os.utime(path, (stamp, stamp))

        for n in range(60):
            job_id = str(uuid.uuid4())
            ids.append(job_id)
            write(job_id, "running", 5000 - n)
        finished = str(uuid.uuid4())
        ids.append(finished)
        write(finished, "succeeded", 10)
        sm._jobs_root = lambda: Path(TMP)
        sm._read_job = lambda job_id: reads.append(job_id) or real_read(job_id)
        ej.has_registered_event_job = lambda job_id, module_id: True
        ej.module_status_for_core = lambda module_id: ej.RUNNABLE
        hooks._replacement_blocked = lambda module_id: False
        ej.publish_for_core = lambda job_id, *, module_id, key, payload: published.append((job_id, module_id, key, payload)) or type("R", (), {"outcome": "queued", "reason": ""})()
        hooks._WAITING.clear()
        first = hooks.deliver_finished_server_jobs()
        step("tick 1: the finished job behind 60 unfinished files is handed over", first["delivered"] == 1 and len(published) == 1 and published[0][0] == "securityWAF.server_job_finished" and published[0][1] == "securityWAF", f"{first} {published}")
        step("tick 1 read 61 files, within the read budget", len(reads) == 61 and first["waiting"] == 60)
        del reads[:]
        second = hooks.deliver_finished_server_jobs()
        step("tick 2 reads none of the 60 unfinished files again", reads == [] and second["waiting"] == 60 and second["delivered"] == 0 and len(published) == 1, f"{second} reads={len(reads)}")
        step("the counts keys are the 1.17.62 keys", set(first) == {"checked", "delivered", "waiting", "skipped", "ignored", "duplicate", "retry", "abandoned", "unreadable", "errors"})
    finally:
        sm._jobs_root, sm._read_job, ej.has_registered_event_job, ej.module_status_for_core, hooks._replacement_blocked, ej.publish_for_core = (
            real_root, real_read, real_has, real_status, real_blocked, real_publish,
        )
        hooks._WAITING.clear()
        TecTacServerJobHook.objects.filter(job_id__in=ids).delete()
        shutil.rmtree(TMP, ignore_errors=True)
    step("the probe left no hook row behind", not TecTacServerJobHook.objects.filter(job_id__in=ids).exists())

print("PASS scheduler unattended runtime 1.17.63" if all(RESULTS) else "FAIL scheduler unattended runtime 1.17.63")
if not all(RESULTS):
    sys.exit(1)
