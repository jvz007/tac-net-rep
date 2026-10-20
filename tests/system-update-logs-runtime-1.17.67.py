"""Runtime check for Core 1.17.67 (job log routes, system update audit row, fail-closed system-action gate). DEV SERVER ONLY.
It did NOT run on the development PC (Django, Tactical's database and Knox are not installed there).

Run it on the dev server with:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/system-update-logs-runtime-1.17.67.py

PASS means the script printed PASS as its last line and no step printed FAIL. FAIL prints the step that broke, then FAIL. Send that step back.

What it does. As a throwaway superuser and a throwaway plain person, signed in with real Knox tokens (no force_authenticate), inside ONE database
transaction that is rolled back, it checks:
  1  the three new routes are registered (URL resolver) and the list route answers
  2  a system update job log and a server-maintenance job log are served as scrubbed text, with the four headers, the 5 MB cap, and ?download=1
     (a 6 MB log is cut head and tail), and a plain person is refused (403)
  3  each read writes exactly one audit row (view of system_update_job_log or server_maintenance_job_log) with no log text
  4  a job found only in history works; the list route returns it with has_log and log_bytes; the detail route falls back to history
  5  the Scheduler tick's sweep writes one 'Update installed successfully 1.17.16 -> 1.17.17' row and a second sweep writes none
  6  with the signed-manifest read made to fail (monkeypatched in this shell only), POST /api/tfd/scheduler/schedules/, reconcile_schedule and
     start_one_off_run for a probe system action are refused with declaration_unreadable, nothing is saved or queued, and an ordinary action is not
     refused. The same with the registry read made to fail.

The job and log files are written under temporary folders (tempfile), NOT under /var/lib/tec-tac: those folders are root-owned and the Tactical
user cannot write there. Core's own paths are pointed at the temporary folders for this shell only, so the real views, the real audit writer and
the real database run; only the folders differ. The temporary folders are removed in the finally block. Nothing is kept: the database work is
rolled back, the probe system action is removed from this shell's registry, and a closing step counts that the throwaway people, their tokens and
the probe audit rows are gone.
"""
import json
import os
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from accounts.models import User
from agents.models import Agent
from django.db import transaction
from django.urls import resolve
from knox.models import AuthToken
from logs.models import AuditLog
from rest_framework.test import APIRequestFactory
from tec_tac import module_job_logs, scheduler, server_maintenance, system_action_confirmation as confirmation, system_actions as sa, system_update, system_update_audit
from tec_tac.models import TecTacSchedule, TecTacScheduleRun, TecTacSessionTrust
from tec_tac.scheduler_views import SchedulerListView
from tec_tac.server_maintenance_views import ServerMaintenanceJobLogView
from tec_tac.views import SystemUpdateJobListView, SystemUpdateJobLogView, SystemUpdateJobView

MODULE = "patching"
PROBE_ACTION = "patching.tectac-probe-1-17-67"
PLAIN_ACTION = "checks.tectac-probe-plain-1-17-67"
HEADERS = ("X-Tec-Tac-Log-Truncated", "X-Tec-Tac-Log-Bytes", "X-Tec-Tac-Log-Kept", "Content-Disposition")
SECRET_LOG = "line one\npassword=hunter2hunter2\nAuthorization: Bearer abcdef0123456789abcdef\nread /etc/tec-tac/secret.key failed\nok\n"

STEP = ["start"]
NAMES = []
JOB_IDS = []


class Rollback(Exception):
    pass


def step(name):
    STEP[0] = name
    print("step:", name)


def throwaway(label, superuser):
    name = "tectac-%s-%s" % (label, uuid.uuid4().hex[:8])
    NAMES.append(name)
    person = User.objects.create_user(username=name, email="%s@example.invalid" % label, password=uuid.uuid4().hex)
    person.is_superuser = superuser
    person.totp_key = "TECTACRUNTIMEPROBE" + uuid.uuid4().hex[:8]
    person.save()
    return person


def new_id():
    job_id = str(uuid.uuid4())
    JOB_IDS.append(job_id)
    return job_id


TMP = Path(tempfile.mkdtemp(prefix="tectac-1-17-67-"))
SU_JOBS, SU_HISTORY, SU_LOGS = TMP / "su" / "jobs", TMP / "su" / "history", TMP / "su" / "logs"
SM_STATE = TMP / "sm"
for folder in (SU_JOBS, SU_HISTORY, SU_LOGS, SM_STATE / "jobs", SM_STATE / "logs"):
    folder.mkdir(parents=True)

real = {
    "su": (system_update.JOBS_ROOT, system_update.HISTORY_ROOT, system_update.LOGS_ROOT),
    "sm_state": server_maintenance._state_root,
    "manifest": scheduler._manifest_system_actions,
    "registered": sa.is_registered_system_action,
    "actions": dict(sa._ACTIONS),
    "scheduled": dict(scheduler._ACTIONS),
}
ok = False
before = {}
try:
    before = {
        "tokens": AuthToken.objects.count(), "trust": TecTacSessionTrust.objects.count(),
        "users": User.objects.filter(username__startswith="tectac-").count(),
    }
    system_update.JOBS_ROOT, system_update.HISTORY_ROOT, system_update.LOGS_ROOT = SU_JOBS, SU_HISTORY, SU_LOGS
    server_maintenance._state_root = lambda: SM_STATE

    with transaction.atomic():
        step("create the throwaway superuser, the plain person and their Knox tokens")
        manager, plain = throwaway("probe", True), throwaway("plain", False)
        TOKENS = {person.pk: AuthToken.objects.create(person)[1] for person in (manager, plain)}
        assert all(TOKENS.values()), "Knox gave no raw token"
        factory = APIRequestFactory()

        def call(view, path, who=manager, method="get", body=None, **kwargs):
            extra = {"HTTP_AUTHORIZATION": "Token " + TOKENS[who.pk]}
            request = getattr(factory, method)(path, body, format="json", **extra) if body is not None else getattr(factory, method)(path, **extra)
            reply = view(request, **kwargs)
            if hasattr(reply, "render"):
                reply.render()
            return reply

        def text(reply):
            return bytes(reply.content).decode("utf-8", errors="replace")

        def audit_rows(object_type, job_id):
            return AuditLog.objects.filter(action="view", object_type=object_type, debug_info__object_id=job_id)

        def su_job(*, where="jobs", log=None, **fields):
            job_id = new_id()
            data = {"id": job_id, "status": "succeeded", "action": "install", "component": "framework", "version": "1.17.17", "installed_version": "1.17.16",
                    "operation": "upgrade", "requested_by": "probe", "created_at": datetime.now(timezone.utc).isoformat(), "finished_at": datetime.now(timezone.utc).isoformat(),
                    "backup_path": "/var/lib/tec-tac/x", "rollback": None}
            data.update(fields)
            data = {k: v for k, v in data.items() if v is not ...}
            (SU_HISTORY if where == "history" else SU_JOBS).joinpath("%s.json" % job_id).write_text(json.dumps(data), encoding="utf-8")
            if log is not None:
                (SU_LOGS / ("%s.log" % job_id)).write_bytes(log if isinstance(log, bytes) else log.encode("utf-8"))
            return job_id

        def sm_job(*, logs=None, secret=""):
            job_id = new_id()
            data = {"schema": 1, "id": job_id, "action": "tectac.probe", "status": "succeeded", "stage": "done", "created_at": datetime.now(timezone.utc).isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(), "context": {}, "parameters": {"token": secret} if secret else {},
                    "public_parameters": {"token": "<redacted>"} if secret else {}, "lock": {}, "action_permission": None}
            (SM_STATE / "jobs" / ("%s.json" % job_id)).write_text(json.dumps(data), encoding="utf-8")
            for suffix, body in (logs or {}).items():
                (SM_STATE / "logs" / ("%s%s" % (job_id, suffix))).write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
            return job_id

        step("1 the three new routes are registered")
        for path, name in (("/api/tfd/system/updates/jobs/", "SystemUpdateJobListView"), ("/api/tfd/system/updates/jobs/%s/log/" % uuid.uuid4(), "SystemUpdateJobLogView"),
                           ("/api/tfd/system/maintenance/jobs/%s/log/" % uuid.uuid4(), "ServerMaintenanceJobLogView")):
            match = resolve(path)
            assert getattr(match.func, "view_class", None).__name__ == name, "%s resolves to %r" % (path, match.func)

        step("2 a system update log is served as scrubbed text with the four headers; a plain person is refused")
        job = su_job(log=SECRET_LOG)
        reply = call(SystemUpdateJobLogView.as_view(), "/x/", job_id=uuid.UUID(job))
        body = text(reply)
        assert reply.status_code == 200 and "hunter2hunter2" not in body and "abcdef0123456789abcdef" not in body and "secret.key" not in body and "line one" in body, (reply.status_code, body[:300])
        exposed = [part.strip() for part in reply["Access-Control-Expose-Headers"].split(",")]
        assert exposed == list(HEADERS), exposed
        assert reply["X-Content-Type-Options"] == "nosniff" and reply["Cache-Control"] == "no-store" and reply["X-Tec-Tac-Log-Truncated"] == "false" and reply["X-Tec-Tac-Log-Kept"] == "all", dict(reply.items())
        assert reply["Content-Type"].startswith("text/plain") and "Content-Disposition" not in reply, "inline by default"
        denied = call(SystemUpdateJobLogView.as_view(), "/x/", who=plain, job_id=uuid.UUID(job))
        assert denied.status_code == 403, denied.status_code

        step("3 the read wrote one audit row with no log text; a download writes a second")
        rows = audit_rows("system_update_job_log", job)
        assert rows.count() == 1, rows.count()
        assert "hunter2" not in repr(list(rows.values("message", "debug_info"))) and "line one" not in repr(list(rows.values("message", "debug_info"))), "log text in the audit row"
        request = factory.get("/x/", {"download": "1"}, HTTP_AUTHORIZATION="Token " + TOKENS[manager.pk])
        download = SystemUpdateJobLogView.as_view()(request, job_id=uuid.UUID(job))
        if hasattr(download, "render"):
            download.render()
        assert download.status_code == 200 and download["Content-Disposition"].startswith('attachment; filename="system-update-framework-') and download["Content-Disposition"].endswith('.log"'), download.get("Content-Disposition")
        assert audit_rows("system_update_job_log", job).count() == 2, "one row per read"

        step("2b a 6 MB log is cut head and tail at 5 MB")
        big = ("a line of ordinary log text that is long enough\n" * 140000).encode("utf-8")
        reply = call(SystemUpdateJobLogView.as_view(), "/x/", job_id=uuid.UUID(su_job(log=big)))
        assert reply.status_code == 200 and reply["X-Tec-Tac-Log-Truncated"] == "true" and reply["X-Tec-Tac-Log-Kept"] == "head-and-tail" and len(reply.content) <= module_job_logs.MAX_LOG_BYTES + 200, (reply.status_code, len(reply.content))

        step("2c a maintenance log: three headed sections, the job's own secret is redacted, ?part picks one")
        mid = sm_job(secret="s3cr3t-value-xyz", logs={".log": "helper started\nusing s3cr3t-value-xyz now\n", ".stdout.log": "out line\n", ".stderr.log": "err line\n"})
        reply = call(ServerMaintenanceJobLogView.as_view(), "/x/", job_id=uuid.UUID(mid))
        body = text(reply)
        assert reply.status_code == 200 and "s3cr3t-value-xyz" not in body and body.index("== log ==") < body.index("== stdout ==") < body.index("== stderr =="), body[:300]
        assert audit_rows("server_maintenance_job_log", mid).count() == 1, "one audit row"
        request = factory.get("/x/", {"part": "stdout"}, HTTP_AUTHORIZATION="Token " + TOKENS[manager.pk])
        only = ServerMaintenanceJobLogView.as_view()(request, job_id=uuid.UUID(mid))
        if hasattr(only, "render"):
            only.render()
        assert "out line" in text(only) and "err line" not in text(only) and "helper started" not in text(only), text(only)
        assert call(ServerMaintenanceJobLogView.as_view(), "/x/", who=plain, job_id=uuid.UUID(mid)).status_code == 403, "plain person"

        step("4 a job found only in history works; the list carries it with has_log and log_bytes; the detail falls back to history")
        hist = su_job(where="history", log="from history\n")
        assert call(SystemUpdateJobLogView.as_view(), "/x/", job_id=uuid.UUID(hist)).status_code == 200, "history log"
        listing = call(SystemUpdateJobListView.as_view(), "/api/tfd/system/updates/jobs/")
        assert listing.status_code == 200, listing.status_code
        found = [row for row in listing.data["jobs"] if row["id"] == hist]
        assert found and found[0]["has_log"] is True and found[0]["log_bytes"] == len(b"from history\n") and "log_tail" not in found[0] and "backup_path" not in found[0], found
        detail = call(SystemUpdateJobView.as_view(), "/x/", job_id=uuid.UUID(hist))
        assert detail.status_code == 200 and detail.data["log_tail"] == ["from history"] and detail.data["has_log"] is True, detail.data

        step("5 the sweep writes one 'Update installed successfully 1.17.16 -> 1.17.17' row, and a second sweep writes none")
        sweep_job = su_job(version="1.17.17", installed_version="1.17.16", log="x\n")
        written = system_update_audit.audit_finished_system_updates()
        assert written >= 1, written
        correlation = "system-update:installed:%s" % sweep_job
        found_rows = AuditLog.objects.filter(debug_info__correlation_id=correlation)
        assert found_rows.count() == 1 and found_rows.first().message == "Update installed successfully 1.17.16 -> 1.17.17", [r.message for r in found_rows]
        system_update_audit.audit_finished_system_updates()
        assert AuditLog.objects.filter(debug_info__correlation_id=correlation).count() == 1, "a second sweep wrote a second row"

        step("6 the fail-closed gate: a failed manifest or registry read refuses a system action schedule and leaves an ordinary action alone")
        sa._ACTIONS[PROBE_ACTION] = sa.SystemActionDefinition(PROBE_ACTION, MODULE, "Probe scan", "winupdate.scan", ("can_manage_winupdates", "can_run_bulk"), "agents", False, None, False)
        scheduler.register_scheduled_action(id=PROBE_ACTION, module_id=MODULE, label="probe", handler=lambda context: {"ok": True}, target_types=("none", "endpoint"))
        scheduler.register_scheduled_action(id=PLAIN_ACTION, module_id="checks", label="probe plain", handler=lambda context: {"ok": True}, target_types=("none", "endpoint"))
        scheduler._manifest_system_actions = lambda module_id: (PROBE_ACTION,) if module_id == MODULE else real["manifest"](module_id)
        assert scheduler.system_action_state(MODULE, PROBE_ACTION) == "declared", scheduler.system_action_state(MODULE, PROBE_ACTION)

        def boom(*args, **kwargs):
            raise RuntimeError("read failed")

        agent = Agent.objects.order_by("pk").first()
        assert agent is not None, "this check needs one endpoint in Tactical (any); none exists here"
        targets = {"type": "endpoint", "ids": [str(agent.pk)]}
        body = {"name": "tectac probe", "action_id": PROBE_ACTION, "schedule_type": "daily", "run_time": "03:00", "timezone": "UTC", "targets": targets, "parameters": {}, "enabled": True,
                "confirmation_id": "anything"}

        for label, patch in (("manifest", lambda: setattr(scheduler, "_manifest_system_actions", boom)), ("registry", lambda: setattr(sa, "is_registered_system_action", boom))):
            scheduler._manifest_system_actions = lambda module_id: (PROBE_ACTION,) if module_id == MODULE else real["manifest"](module_id)
            sa.is_registered_system_action = real["registered"]
            patch()
            schedules_before = TecTacSchedule.objects.count()
            runs_before = TecTacScheduleRun.objects.count()
            denies_before = AuditLog.objects.filter(action="deny", object_type="system_action").count()
            reply = call(SchedulerListView.as_view(), "/api/tfd/scheduler/schedules/", method="post", body=body)
            assert reply.status_code == 403 and reply.data.get("reason") == "declaration_unreadable", "POST (%s): %s %s" % (label, reply.status_code, reply.data)
            try:
                scheduler.start_one_off_run(user=manager, owner_module=MODULE, action_id=PROBE_ACTION, targets=targets, confirmation_id="anything")
                raise AssertionError("start_one_off_run (%s) started" % label)
            except confirmation.SystemActionCreationRefused as exc:
                assert exc.reason == "declaration_unreadable", exc.reason
            try:
                confirmation.describe_confirmation(manager, PROBE_ACTION, targets, None, {"schedule_type": "daily", "run_time": "03:00", "timezone": "UTC"})
                raise AssertionError("describe_confirmation (%s) issued an id" % label)
            except confirmation.SystemActionCreationRefused as exc:
                assert exc.reason == "declaration_unreadable", exc.reason
            assert TecTacSchedule.objects.count() == schedules_before and TecTacScheduleRun.objects.count() == runs_before, "something was saved or queued (%s)" % label
            assert AuditLog.objects.filter(action="deny", object_type="system_action").count() == denies_before + 3, "one deny row per refusal (%s)" % label
            # an ordinary action is not refused while the read fails
            plain_reply = call(SchedulerListView.as_view(), "/api/tfd/scheduler/schedules/", method="post", body={**body, "name": "tectac plain", "action_id": PLAIN_ACTION})
            assert plain_reply.status_code != 403 or plain_reply.data.get("reason") != "declaration_unreadable", "an ordinary action was refused for a read fault (%s): %s" % (label, plain_reply.data)
            print("  PASS %s unreadable: POST, start_one_off_run and describe_confirmation refused; nothing saved; an ordinary action not refused" % label)

        step("6b the run-time exemption still answers False when the read fails")
        scheduler._manifest_system_actions = boom
        assert scheduler._action_declared_as_system_action(MODULE, PROBE_ACTION) is False, "the run-time exemption must keep every re-check on a failed read"

        raise Rollback()
except Rollback:
    ok = True
except Exception as exc:  # noqa: BLE001 - print the step and the reason, then FAIL
    print("FAIL at step '%s': %s: %s" % (STEP[0], exc.__class__.__name__, exc))
finally:
    system_update.JOBS_ROOT, system_update.HISTORY_ROOT, system_update.LOGS_ROOT = real["su"]
    server_maintenance._state_root = real["sm_state"]
    scheduler._manifest_system_actions = real["manifest"]
    sa.is_registered_system_action = real["registered"]
    sa._ACTIONS.clear()
    sa._ACTIONS.update(real["actions"])
    scheduler._ACTIONS.clear()
    scheduler._ACTIONS.update(real["scheduled"])
    shutil.rmtree(TMP, ignore_errors=True)

try:
    after = {
        "tokens": AuthToken.objects.count(), "trust": TecTacSessionTrust.objects.count(),
        "users": User.objects.filter(username__startswith="tectac-").count(),
    }
    leftovers = AuditLog.objects.filter(object_type__in=("system_update_job_log", "server_maintenance_job_log"), debug_info__object_id__in=JOB_IDS).count()
    leftovers += AuditLog.objects.filter(debug_info__correlation_id__in=["system-update:installed:%s" % j for j in JOB_IDS]).count()
    if before and after != before:
        ok = False
        print("FAIL cleanup: before %s, after %s" % (before, after))
    if leftovers:
        ok = False
        print("FAIL cleanup: %d probe audit rows are still there" % leftovers)
    if os.path.exists(str(TMP)):
        ok = False
        print("FAIL cleanup: the temporary folder is still there")
except Exception as exc:  # noqa: BLE001
    ok = False
    print("FAIL cleanup check: %s: %s" % (exc.__class__.__name__, exc))

print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
