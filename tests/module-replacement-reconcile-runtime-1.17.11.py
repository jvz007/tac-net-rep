"""Runtime check for Core 1.17.11 module replacement. It did NOT run on the development PC (Django is not installed there).

Run it on the dev server through Tactical's manage.py shell, so Django, Tactical's real AuditLog and the real Core code are loaded:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/module-replacement-reconcile-runtime-1.17.11.py

It proves what the stub tests (tests/module-replacement-conflict-1.17.11.py, tests/module-replacement-enable-1.17.11.py) cannot:
that the audit rows reach Tactical's AuditLog with the right action, actor, module and object, that the real Core job writer records a
queued reconcile job, and that the real sudo dispatch fails safely and is logged and not raised when the helper cannot run the job.

It prints PASS or FAIL for each step and exits with status 1 when any step fails. It works on a temporary extensions root and a
temporary jobs folder, with the module state held in memory, so no real module, job, state file or user is touched. The probe modules use their own ids (tectac-probe-replacement, tectac-probe-replaced) and only audit rows for those ids are deleted. It sets no module state
on the server and never dispatches a real job: the dispatch step uses a job id that does not exist, which the helper refuses. Audit rows it
writes are deleted at the end. The bootstrap drop (a replacement left out of what Core loads) needs a restart of Tactical and is
checked by hand: enable both Windows Patching and a replacement in module-state.json, restart, and read the log for
"Core does not load".
"""
import json
import sys
import tempfile
from pathlib import Path

from accounts.models import User
from logs.models import AuditLog
from tec_tac import module_manager, module_manager_v2 as v2, module_replacement as mr, module_state, registry

# Unique probe ids: the rows this script writes and deletes can never be a real module's audit rows.
REPL, OLD = "tectac-probe-replacement", "tectac-probe-replaced"
RESULTS = []
TMP = Path(tempfile.mkdtemp(prefix="tectac-runtime-replacement-"))
EXT, JOBS = TMP / "extensions", TMP / "jobs"
for folder in (EXT, JOBS):
    folder.mkdir()
STATE = {"schema": 1, "modules": {OLD: {"enabled": True}, REPL: {"enabled": True}}}
SAVED = (registry.EXTENSIONS_ROOT, module_state.load_state, v2.load_state, v2.JOBS_ROOT, module_manager.JOBS_ROOT)
MARK = "tectac-runtime-replacement"


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def manifest(module_id, **extra):
    folder = EXT / module_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "tec_tac.json").write_text(json.dumps({"id": module_id, "type": "extension", "version": "1.0.0", **extra}), encoding="utf-8")


def audit_rows():
    return AuditLog.objects.filter(object_type="module", debug_info__metadata__replacement=REPL)


def setup():
    registry.EXTENSIONS_ROOT = EXT
    module_state.load_state = v2.load_state = lambda: STATE
    v2.JOBS_ROOT = module_manager.JOBS_ROOT = JOBS
    manifest(OLD, category="core", capabilities={"patching.windows": "1.2.0"})
    manifest(REPL, replaces=OLD, capabilities={"patching.windows": "1.2.0"})


def teardown():
    registry.EXTENSIONS_ROOT, module_state.load_state, v2.load_state, v2.JOBS_ROOT, module_manager.JOBS_ROOT = SAVED
    audit_rows().delete()


def detect():
    assert mr.conflicted_replacements(mr.live_model()) == [(REPL, OLD)], mr.conflicted_replacements(mr.live_model())
    row = mr.replacement_status(REPL)
    assert row["conflict"] is True and row["honoured"] is False and row["reason"] == "target-enabled", row


def reconcile_audits_and_queues():
    original = v2._dispatch_v2
    dispatched = []
    v2._dispatch_v2 = dispatched.append
    try:
        rows = mr.reconcile_conflicts()
    finally:
        v2._dispatch_v2 = original
    assert len(rows) == 1 and rows[0]["queued"] is True, rows
    jobs = [json.loads(path.read_text(encoding="utf-8")) for path in JOBS.glob("*.json")]
    assert len(jobs) == 1 and dispatched == [jobs[0]["id"]], (jobs, dispatched)
    job = jobs[0]
    assert job["action"] == "disable" and job["plugin_id"] == REPL and job["reason"] == "replacement_conflict" and job["requested_by"] == "system", job
    row = audit_rows().filter(action="custom:module-replacement-conflict-resolved").first()
    assert row is not None, "no audit row"
    info = row.debug_info
    assert info["metadata"] == {"replacement": REPL, "replaced": OLD, "job_id": job["id"]}, info
    assert info["module_id"] == "core" and info["actor_kind"] == "service" and info["object_id"] == REPL, info
    assert row.username.startswith("service:"), row.username


def reconcile_limits():
    assert mr.reconcile_conflicts() == [], "a pending job and the hourly limit must stop a second job"
    assert len(list(JOBS.glob("*.json"))) == 1


def enable_audit_row():
    user = User(username=MARK)  # unsaved: nothing is written to Tactical's accounts table
    mr.audit_replaced_disabled(user, REPL, [OLD], "job-1")
    row = audit_rows().filter(action="custom:module-replacement-disabled").first()
    assert row is not None, "no audit row"
    assert row.username == MARK and row.debug_info["object_id"] == OLD and row.debug_info["metadata"]["job_id"] == "job-1", row.debug_info


def dispatch_fails_safely():
    for path in JOBS.glob("*.json"):
        path.unlink()
    original = v2._dispatch_v2

    def dispatch_unknown(job_id):
        return original("00000000-0000-4000-8000-000000000000")  # a job the helper does not have

    v2._dispatch_v2 = dispatch_unknown
    try:
        rows = mr.reconcile_conflicts()
    finally:
        v2._dispatch_v2 = original
    assert len(rows) == 1 and rows[0]["queued"] is False and rows[0]["error"], rows
    jobs = [json.loads(path.read_text(encoding="utf-8")) for path in JOBS.glob("*.json")]
    assert len(jobs) == 1 and jobs[0]["status"] == "dispatch_failed", jobs
    assert mr.reconcile_conflicts() == [], "a failing dispatch must not loop"


def snapshot_effective_state():
    from tec_tac.module_runtime import module_runtime_snapshot

    rows = {row["id"]: row for row in module_runtime_snapshot()}
    assert rows[REPL]["enabled"] is False and rows[REPL]["active"] is False, rows[REPL]
    assert rows[REPL]["replaces"] == OLD and rows[OLD]["replaces"] is None, rows


setup()
try:
    step("a replacement next to its enabled module is a conflict", detect)
    step("reconcile queues one disable job and writes the audit row", reconcile_audits_and_queues)
    step("a pending job and the hourly limit stop a second job", reconcile_limits)
    step("the enable audit row names the replaced module and the requesting user", enable_audit_row)
    step("a failing sudo dispatch is logged, recorded and not raised", dispatch_fails_safely)
    step("module_status reports the conflicted replacement as not enabled, with replaces", snapshot_effective_state)
finally:
    teardown()

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)
