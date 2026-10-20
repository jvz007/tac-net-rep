"""Runtime check for Core 1.17.61 system actions (R-20). It did NOT run on the development PC (Django, Celery and Tactical are not installed there).

It queues a REAL patch scan on ONE endpoint through Tactical's own Celery task, as a real Tactical user, and shows that the owner's flags
are checked again at the run. Use one test endpoint on the dev server (dev02). Nothing else is touched.

Environment (set on the command line):
    TECTAC_PROBE_USER    a Tactical username whose role holds can_manage_winupdates AND can_run_bulk and covers the endpoint
    TECTAC_PROBE_AGENT   the Tactical agent number (the database id) of ONE test endpoint
    TECTAC_PROBE_PHASE   "both" (default: prepare and execute), "prepare" (create the run and print its id) or "execute" (needs TECTAC_PROBE_RUN)
    TECTAC_PROBE_RUN     the run id printed by the prepare phase
    TECTAC_PROBE_EXPECT  "queued" (default) or "refused": what this run should do. The script prints PASS or FAIL against it.

Happy path (one command):
    cd /rmm/api/tacticalrmm && TECTAC_PROBE_USER=jvz TECTAC_PROBE_AGENT=12 ../env/bin/python manage.py shell < /path/to/tests/system-actions-runtime-1.17.61.py

Refusal at run time (three steps): run with TECTAC_PROBE_PHASE=prepare; remove can_run_bulk from the user's role in Tactical; run with
TECTAC_PROBE_PHASE=execute TECTAC_PROBE_RUN=<id> TECTAC_PROBE_EXPECT=refused. The run ends skipped with a deny row and nothing is sent.
Remove can_run_bulk, not can_manage_winupdates: the probe's own Scheduler action needs only can_manage_winupdates, so the Scheduler's one-off check
passes and it is Core's system-action check that refuses. (Removing can_manage_winupdates is refused earlier, by the Scheduler, with a different
row; that is also correct, and the probe then reports FAIL only because it looks for the system-action row.)

How it works. Core's table names the real Tactical task (winupdate.tasks.bulk_check_for_updates_task). No module has registered a system action yet,
so this probe puts one definition for the module patching into this shell's registry and registers a scheduled action whose handler is
compiled under patching's own folder (as Core's stub tests do), because Core names the caller from the code file. That is a test device and is
used nowhere in Core. The task body runs in this process (execute_schedule_run.run), so the handler is known; the broker is not used for
the run itself, only by Tactical's own task, as in production. The audit rows are real and stay. The one-off schedule is removed at the end.
"""
import os
import sys

from accounts.models import User
from tec_tac import audit, registry, scheduler
from tec_tac import system_actions as sa
from tec_tac.models import TecTacSchedule, TecTacScheduleRun
from tec_tac.tasks import execute_schedule_run

USERNAME = os.environ.get("TECTAC_PROBE_USER", "")
AGENT = os.environ.get("TECTAC_PROBE_AGENT", "")
PHASE = os.environ.get("TECTAC_PROBE_PHASE", "both")
RUN_ID = os.environ.get("TECTAC_PROBE_RUN", "")
EXPECT = os.environ.get("TECTAC_PROBE_EXPECT", "queued")
MODULE = "patching"
ACTION = "patching.tectac-probe-scan"
SYSTEM_ACTION = "patching.tectac-probe"

if not USERNAME or not AGENT.isdigit() or PHASE not in ("both", "prepare", "execute") or EXPECT not in ("queued", "refused"):
    print("FAIL set TECTAC_PROBE_USER, TECTAC_PROBE_AGENT (a number), and optionally TECTAC_PROBE_PHASE and TECTAC_PROBE_EXPECT")
    sys.exit(1)

root = next((p.root for p in registry.discover_plugins() if p.plugin_id == MODULE and p.plugin_type == "extension"), None)
if root is None:
    print("FAIL the module patching is not installed here")
    sys.exit(1)

SOURCE = (
    "def handler(context):\n"
    f"    return sa.run_system_action(context, action_id={SYSTEM_ACTION!r}, agent_ids=[{int(AGENT)}])\n"
)
namespace = {"sa": sa}
exec(compile(SOURCE, str(root / "_tectac_probe_1_17_61.py"), "exec"), namespace)  # noqa: S102 - a probe handler under patching's folder
sa._ACTIONS[SYSTEM_ACTION] = sa.SystemActionDefinition(
    SYSTEM_ACTION, MODULE, "Probe scan", "winupdate.scan", ("can_manage_winupdates", "can_run_bulk"), "agents", False, None, False,
)
scheduler.register_scheduled_action(
    id=ACTION, module_id=MODULE, label="System action probe", handler=namespace["handler"], target_types=("none", "endpoint"),
    permission="tactical:can_manage_winupdates",
)

ok = True
run = None
try:
    if PHASE in ("both", "prepare"):
        user = User.objects.get(username=USERNAME)
        real_queue = scheduler._queue_run
        scheduler._queue_run = lambda queued: queued  # keep the run QUEUED: this shell runs it, no broker message
        try:
            run = scheduler.start_one_off_run(user=user, owner_module=MODULE, action_id=ACTION, name="System action probe",
                                              targets={"type": "endpoint", "ids": [str(int(AGENT))]})  # 1.17.62: a system action must target what it sends
        finally:
            scheduler._queue_run = real_queue
        print(f"run id: {run.id}")
    if PHASE in ("both", "execute"):
        if run is None:
            run = TecTacScheduleRun.objects.get(pk=RUN_ID)
        outcome = execute_schedule_run.run(str(run.id))
        row = TecTacScheduleRun.objects.get(pk=run.pk)
        print(f"task answer: {outcome!r}")
        print(f"run status: {row.status}, error_type: {row.error_type!r}, error: {row.error!r}")
        print(f"run result: {row.result}")
        print(f"marks: {row.system_action_marks}")
        rows = list(audit._auditlog_model().objects.filter(object_type="system_action").order_by("-id")[:3])
        for entry in rows:
            print(f"audit row: action={entry.action} username={entry.username} message={entry.message}")
        if EXPECT == "queued":
            ok = (
                row.status == "succeeded" and row.result.get("outcome") == "queued" and row.result.get("agents") == 1
                and bool(row.system_action_marks) and row.system_action_marks[0].get("state") == "sent"
                and any(r.action == "run" and r.username == USERNAME for r in rows)
            )
        else:
            ok = (
                row.status == "skipped" and row.error_type == "SystemActionRefused" and not row.system_action_marks
                and any(r.action == "deny" and r.username == USERNAME for r in rows)
            )
        print(("PASS" if ok else "FAIL") + f" expected {EXPECT}")
finally:
    if PHASE in ("both", "execute") and run is not None:
        schedule = TecTacSchedule.objects.filter(pk=getattr(run, "schedule_snapshot_id", None)).first()
        if schedule is not None:
            schedule.delete()

if not ok:
    sys.exit(1)
