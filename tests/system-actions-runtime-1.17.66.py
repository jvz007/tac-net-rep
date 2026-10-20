"""Runtime check for Core 1.17.66 system actions (groups, confirmation, creation controls). It did NOT run on the development PC (Django, Celery and Tactical are not installed there).

It scans TWO test endpoints on the dev server through Tactical's own Celery task, as a real Tactical user, in two groups of one endpoint (the group size is
lowered to 1 inside this shell only, so no 2001 endpoints are needed), and shows that the confirmation id is needed, is bound to the person and the
targets, and that the run reports its groups. A patch scan is harmless. Use dev02. Nothing else is touched.

Environment (set on the command line):
    TECTAC_PROBE_USER    a Tactical username whose role holds can_manage_winupdates AND can_run_bulk and covers BOTH endpoints
    TECTAC_PROBE_AGENT   the Tactical agent number (the database id) of the first test endpoint
    TECTAC_PROBE_AGENT2  the agent number of the second test endpoint (a different one)

One command:
    cd /rmm/api/tacticalrmm && TECTAC_PROBE_USER=jvz TECTAC_PROBE_AGENT=12 TECTAC_PROBE_AGENT2=13 ../env/bin/python manage.py shell < /path/to/tests/system-actions-runtime-1.17.66.py

What it checks (each line prints PASS or FAIL; the script ends with PASS only when every line passed):
    1 the confirmation text names the total, the groups and the timing, and a confirmation id comes back
    2 a one-off start with NO confirmation id is refused (SystemActionCreationRefused, confirmation_required) and creates nothing
    3 a one-off start with an id made for other endpoints is refused (confirmation_invalid)
    4 a one-off start with the right id queues the run
    5 the run succeeds with outcome queued, agents 2 and groups total 2, sent 2, failed 0, not_started 0, and a summary line
    6 two marks, both sent, and exactly two strict 'run' audit rows with group 1 and group 2 of 2 and no endpoint id in them
    7 one 'add' audit row for the one-off run names total_agents 2 and groups 2

How it works. Core's table names the real Tactical task. No module registers a system action yet, so this probe puts one definition for the module
patching into this shell's registry, tells the Scheduler that the manifest lists it, and registers a scheduled action whose handler is compiled under
patching's own folder (Core names the caller from the code file). That is a test device used nowhere in Core. The audit rows are real and stay. The
one-off schedule is removed at the end.
"""
import os
import sys

from accounts.models import User
from tec_tac import audit, registry, scheduler
from tec_tac import system_action_confirmation as confirmation
from tec_tac import system_actions as sa
from tec_tac.models import TecTacSchedule, TecTacScheduleRun
from tec_tac.tasks import execute_schedule_run

USERNAME = os.environ.get("TECTAC_PROBE_USER", "")
AGENT = os.environ.get("TECTAC_PROBE_AGENT", "")
AGENT2 = os.environ.get("TECTAC_PROBE_AGENT2", "")
MODULE = "patching"
ACTION = "patching.tectac-probe-groups"  # the scheduled action id equals the system action id

if not USERNAME or not AGENT.isdigit() or not AGENT2.isdigit() or AGENT == AGENT2:
    print("FAIL set TECTAC_PROBE_USER, TECTAC_PROBE_AGENT and TECTAC_PROBE_AGENT2 (two different numbers)")
    sys.exit(1)

root = next((p.root for p in registry.discover_plugins() if p.plugin_id == MODULE and p.plugin_type == "extension"), None)
if root is None:
    print("FAIL the module patching is not installed here")
    sys.exit(1)

IDS = [int(AGENT), int(AGENT2)]
SOURCE = (
    "def handler(context):\n"
    f"    return sa.run_system_action(context, action_id={ACTION!r}, agent_ids={IDS!r})\n"
)
namespace = {"sa": sa}
exec(compile(SOURCE, str(root / "_tectac_probe_1_17_66.py"), "exec"), namespace)  # noqa: S102 - a probe handler under patching's folder
sa._ACTIONS[ACTION] = sa.SystemActionDefinition(
    ACTION, MODULE, "Probe scan", "winupdate.scan", ("can_manage_winupdates", "can_run_bulk"), "agents", False, None, False,
)
scheduler.register_scheduled_action(
    id=ACTION, module_id=MODULE, label="System action groups probe", handler=namespace["handler"], target_types=("none", "endpoint"),
    permission="tactical:can_manage_winupdates",
)
real_manifest, real_declared, real_group = scheduler._manifest_system_actions, sa._declared_now, sa.MAX_AGENTS_PER_GROUP
scheduler._manifest_system_actions = lambda module_id: (ACTION,) if module_id == MODULE else real_manifest(module_id)
sa._declared_now = lambda module_id, action_id: action_id == ACTION or real_declared(module_id, action_id)
sa.MAX_AGENTS_PER_GROUP = 1  # this shell only: two endpoints make two groups

results = []


def step(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))


run = None
try:
    user = User.objects.get(username=USERNAME)
    targets = {"type": "endpoint", "ids": [str(i) for i in IDS]}
    when = {"schedule_type": "once", "run_at": "now"}
    shown = confirmation.describe_confirmation(user, ACTION, targets, None, when)
    print(f"confirmation text: {shown.get('text')}")
    step("1 the text names the total, the groups and the timing and an id comes back",
         shown.get("required") is True and shown["total"] == 2 and shown["groups"] == 2 and "2 endpoint(s)" in shown["text"] and "once, now" in shown["text"] and shown.get("confirmation_id"))

    before = TecTacSchedule.objects.filter(owner_module=MODULE, action_id=ACTION).count()
    try:
        scheduler.start_one_off_run(user=user, owner_module=MODULE, action_id=ACTION, targets=targets)
        step("2 no confirmation id is refused", False, "the run started")
    except confirmation.SystemActionCreationRefused as exc:
        step("2 no confirmation id is refused", exc.reason == "confirmation_required" and TecTacSchedule.objects.filter(owner_module=MODULE, action_id=ACTION).count() == before, exc.reason)

    other = confirmation.describe_confirmation(user, ACTION, {"type": "endpoint", "ids": [str(IDS[0])]}, None, when)["confirmation_id"]
    try:
        scheduler.start_one_off_run(user=user, owner_module=MODULE, action_id=ACTION, targets=targets, confirmation_id=other)
        step("3 an id made for other endpoints is refused", False, "the run started")
    except confirmation.SystemActionCreationRefused as exc:
        step("3 an id made for other endpoints is refused", exc.reason == "confirmation_invalid", exc.reason)

    real_queue = scheduler._queue_run
    scheduler._queue_run = lambda queued: queued  # keep the run QUEUED: this shell runs it, no broker message
    try:
        run = scheduler.start_one_off_run(user=user, owner_module=MODULE, action_id=ACTION, name="System action groups probe", targets=targets,
                                          confirmation_id=shown["confirmation_id"])
    finally:
        scheduler._queue_run = real_queue
    step("4 the right id queues the run", run is not None, str(getattr(run, "id", "")))

    outcome = execute_schedule_run.run(str(run.id))
    row = TecTacScheduleRun.objects.get(pk=run.pk)
    print(f"task answer: {outcome!r}")
    print(f"run status: {row.status}, error_type: {row.error_type!r}, error: {row.error!r}")
    print(f"run result: {row.result}")
    result = row.result or {}
    step("5 the run reports its groups",
         row.status == "succeeded" and result.get("outcome") == "queued" and result.get("agents") == 2
         and result.get("groups") == {"total": 2, "sent": 2, "failed": 0, "not_started": 0} and "2 sent" in str(result.get("summary")), str(result.get("summary")))

    marks = row.system_action_marks or []
    rows = list(audit._auditlog_model().objects.filter(object_type="system_action", action="run").order_by("-id")[:2])
    print(f"marks: {marks}")
    text = repr([(r.message, getattr(r, "metadata", None)) for r in rows])
    step("6 two marks sent, two strict run rows, no endpoint id",
         len(marks) == 2 and all(m.get("state") == "sent" for m in marks) and len(rows) == 2 and "group 1 of 2" in text and "group 2 of 2" in text
         and not any(f"'{i}'" in text for i in IDS))

    add_rows = list(audit._auditlog_model().objects.filter(object_type="scheduler_run", action="add").order_by("-id")[:1])
    add_text = repr([(r.message, getattr(r, "metadata", None)) for r in add_rows])
    step("7 the one-off audit row names total and groups", bool(add_rows) and "total_agents" in add_text and "groups" in add_text, add_text[:160])
finally:
    scheduler._manifest_system_actions, sa._declared_now, sa.MAX_AGENTS_PER_GROUP = real_manifest, real_declared, real_group
    if run is not None:
        schedule = TecTacSchedule.objects.filter(pk=getattr(run, "schedule_snapshot_id", None)).first()
        if schedule is not None:
            schedule.delete()

ok = bool(results) and all(results) and len(results) == 7
print(("PASS" if ok else "FAIL") + " Core 1.17.66 system actions runtime")
if not ok:
    sys.exit(1)
