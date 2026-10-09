"""Runtime check for Core 1.17.13 module hand-back and audit (the 1.17.12 script, corrected). It did NOT run on the development PC (Django is not installed there).

Run it on the dev server through Tactical's manage.py shell, so Django, Tactical's real AuditLog and the real Core code are loaded:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/module-replacement-handback-runtime-1.17.13.py

1.17.13: the probe capability is ``tectac-probe-replaced.windows``. The 1.17.12 script declared ``patching.windows`` on a core probe, which Core
refuses (a core module's capability must begin with its own id), so 4 of its 6 steps failed with RegistryError before they tested anything
(debug/command results 18-06.log). The replacement probe carries ``category: premium`` (AD-21). Two steps are new: the long-error row is
written once, found again by its correlation id even after the audit writer replaced the metadata, and a failed switch with no rollback
record says the outcome is not confirmed (the two findings held from the 1.17.12 review).

It proves what the stub tests (tests/module-replacement-handback-1.17.12.py, tests/module-replacement-audit-1.17.12.py) cannot:
that the AuditLog JSON lookup (action, object and metadata job_id) really finds a row and really misses another, that the queue-time
"asked to switch" row and the outcome rows reach Tactical's AuditLog with the right action, actor, module and object, that a second
sweep does not duplicate any of them, and that the real sudo dispatch of a hand-back job fails safely (recorded as dispatch_failed,
raised to the caller, no request row, no outcome row) when the helper cannot run the job.

It prints PASS or FAIL for each step and exits with status 1 when any step fails. It works on a temporary extensions root and a temporary
jobs folder, with the module state held in memory, so no real module, job, state file or user is touched. The probe modules use their own ids
(tectac-probe-replacement, tectac-probe-replaced) and only audit rows for those ids are deleted at the end. It never dispatches a real job:
the dispatch step uses a job id that does not exist, which the helper refuses. The root helper's own switch (one state write, rollback,
re-checked rules) runs only as root, so it is covered by tests/module-replacement-helper-handback-1.17.12.py on the stub side; to see it
for real, enable a replacement next to its replaced module on the dev server through the Modules page once the UI half ships, and read the
job and the audit rows it leaves.
"""
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from accounts.models import User
from logs.models import AuditLog
from tec_tac import module_manager, module_manager_v2 as v2, module_replacement as mr, module_state, registry

# Unique probe ids: the rows this script writes and deletes can never be a real module's audit rows.
REPL, OLD = "tectac-probe-replacement", "tectac-probe-replaced"
RESULTS = []
TMP = Path(tempfile.mkdtemp(prefix="tectac-runtime-handback-"))
EXT, JOBS = TMP / "extensions", TMP / "jobs"
for folder in (EXT, JOBS):
    folder.mkdir()
STATE = {"schema": 1, "modules": {OLD: {"enabled": False}, REPL: {"enabled": True}}}
SAVED = (registry.EXTENSIONS_ROOT, module_state.load_state, v2.load_state, v2.JOBS_ROOT, module_manager.JOBS_ROOT, v2._dispatch_v2)
MARK = "tectac-runtime-handback"
CAP = f"{OLD}.windows"  # a core module's capability must begin with its own id
NOW = datetime.now(timezone.utc)


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
    (folder / "tec_tac.json").write_text(json.dumps({"id": module_id, "type": "extension", "version": "1.0.0", **({"category": "premium"} if "replaces" in extra else {}), **extra}), encoding="utf-8")


def rows(action=None):
    found = AuditLog.objects.filter(object_type="module", debug_info__object_id__in=[REPL, OLD])
    return found.filter(action=action) if action else found


def job_file(job_id, **fields):
    body = {"id": job_id, "status": "succeeded", "requested_by": MARK, "finished_at": (NOW - timedelta(minutes=1)).isoformat(), **fields}
    (JOBS / f"{job_id}.json").write_text(json.dumps(body), encoding="utf-8")


def setup():
    registry.EXTENSIONS_ROOT = EXT
    module_state.load_state = v2.load_state = lambda: STATE
    v2.JOBS_ROOT = module_manager.JOBS_ROOT = JOBS
    manifest(OLD, category="core", capabilities={CAP: "1.2.0"})
    manifest(REPL, category="premium", replaces=OLD, capabilities={CAP: "1.2.0"})


def teardown():
    registry.EXTENSIONS_ROOT, module_state.load_state, v2.load_state, v2.JOBS_ROOT, module_manager.JOBS_ROOT, v2._dispatch_v2 = SAVED
    rows().delete()


def plan_is_read():
    model = mr.live_model()
    assert mr.hand_back_plan(model, REPL) == [OLD], mr.hand_back_plan(model, REPL)
    check = v2.validate_disable(REPL)
    assert check["valid"] is True and check["will_enable"] == [OLD], check
    row = {item["id"]: item for item in v2.installed_catalog_v2()}[REPL]
    assert row["will_enable"] == [OLD] and row["second_confirmation_required"] is False, row


def queued_row_reaches_auditlog():
    user = User(username=MARK)  # unsaved: nothing is written to Tactical's accounts table
    mr.audit_switch_queued(user, REPL, "job-q1", enabled=[OLD])
    row = rows("custom:module-replacement-switch-queued").first()
    assert row is not None, "no audit row"
    assert row.username == MARK and row.debug_info["object_id"] == REPL and row.debug_info["module_id"] == "core", row.debug_info
    assert row.debug_info["metadata"] == {"job_id": "job-q1", "disable": [], "enable": [OLD]}, row.debug_info
    assert "asked to switch" in row.message and "job job-q1 will enable" in row.message, row.message
    assert not rows("custom:module-replacement-disabled").exists(), "the request row must not claim a change"


def lookup_finds_and_misses():
    assert mr._audit_already_written("custom:module-replacement-switch-queued", REPL, "job-q1") is True, "the JSON lookup must find the row"
    assert mr._audit_already_written("custom:module-replacement-switch-queued", REPL, "job-other") is False, "another job id must miss"
    assert mr._audit_already_written("custom:module-replacement-switch-queued", OLD, "job-q1") is False, "another object must miss"
    assert mr._audit_already_written("custom:module-replacement-enabled", REPL, "job-q1") is False, "another action must miss"


def outcome_rows_written_once():
    job_file("job-h1", action="disable", plugin_id=REPL, enabled_modules=[OLD])
    job_file("job-e1", action="enable", plugin_id=OLD, disable_modules=[REPL], disabled_modules=[REPL], replacement_confirmed=True)
    job_file("job-r1", action="enable", plugin_id="tectac-probe-bystander", disabled_modules=[], reconciled_modules=[REPL])
    job_file("job-f1", status="failed", action="disable", plugin_id=REPL, enable_modules=[OLD], stage="rollback", rolled_back=True, error="Tactical graceful reload failed with status 1")
    job_file("job-old", action="disable", plugin_id=REPL, enabled_modules=[OLD], finished_at=(NOW - timedelta(days=9)).isoformat())
    (JOBS / "broken.json").write_text("{not json", encoding="utf-8")
    written = mr.audit_finished_jobs()
    assert written == 4, written
    back = rows("custom:module-replacement-enabled").get(debug_info__metadata__job_id="job-h1")
    assert back.debug_info["object_id"] == OLD and back.debug_info["metadata"]["replacement"] == REPL and back.debug_info["metadata"]["requested_by"] == MARK, back.debug_info
    assert back.username.startswith("service:") and back.debug_info["actor_kind"] == "service" and back.debug_info["module_id"] == "core", back.debug_info
    off = rows("custom:module-replacement-disabled").get(debug_info__metadata__job_id="job-e1")
    assert off.debug_info["object_id"] == REPL and off.debug_info["metadata"]["replaced"] == OLD, off.debug_info
    resolved = rows("custom:module-replacement-conflict-resolved").get(debug_info__metadata__job_id="job-r1")
    assert resolved.debug_info["object_id"] == REPL and resolved.debug_info["metadata"]["replaced"] == OLD, resolved.debug_info
    failed = rows("custom:module-replacement-switch-failed").get(debug_info__metadata__job_id="job-f1")
    assert "graceful reload" in failed.message and failed.debug_info["metadata"]["stage"] == "rollback", failed.message
    assert "put back as they were" in failed.message and failed.debug_info["metadata"]["rolled_back"] is True, failed.message
    assert failed.debug_info["correlation_id"] == "module-replacement:switch-failed:job-f1", failed.debug_info["correlation_id"]
    assert not rows().filter(debug_info__metadata__job_id="job-old").exists(), "a job older than 7 days is not audited"
    assert mr.audit_finished_jobs() == 0, "a second sweep must write nothing"
    assert rows().filter(debug_info__metadata__job_id__in=["job-h1", "job-e1", "job-r1", "job-f1"]).count() == 4, "no duplicate rows"


def reconcile_job_keeps_one_row():
    for path in JOBS.glob("*.json"):
        path.unlink()
    original = v2._dispatch_v2
    v2._dispatch_v2 = lambda job_id: None
    try:
        STATE["modules"][OLD]["enabled"] = True  # both enabled: the reconcile case
        queued = mr.reconcile_conflicts()
    finally:
        v2._dispatch_v2 = original
        STATE["modules"][OLD]["enabled"] = False
    assert len(queued) == 1 and queued[0]["queued"] is True, queued
    job = json.loads(next(JOBS.glob("*.json")).read_text(encoding="utf-8"))
    assert job["reason"] == "replacement_conflict" and "enable_modules" not in job, job
    assert rows("custom:module-replacement-conflict-resolved").filter(debug_info__metadata__job_id=job["id"]).count() == 1, "one queue-time row"
    # the job finishes, and the helper reports a reconciled list: still one row for this job
    job.update(status="succeeded", finished_at=NOW.isoformat(), reconciled_modules=[REPL])
    (JOBS / f"{job['id']}.json").write_text(json.dumps(job), encoding="utf-8")
    assert mr.audit_finished_jobs() == 0 and rows("custom:module-replacement-conflict-resolved").filter(debug_info__metadata__job_id=job["id"]).count() == 1


def long_error_row_is_written_once():
    marker = {"error": "value too large to store in audit log. Check documentation for configuring AUDIT_MAX_VALUE_BYTES", "original_bytes": 99999}
    job_file("job-long", status="failed", action="enable", plugin_id=OLD, disable_modules=[REPL], stage="runtime-sync", error="E" * 20000)  # no rolled_back
    assert mr.audit_finished_jobs() == 1, "one row for the failed job"
    row = rows("custom:module-replacement-switch-failed").get(debug_info__correlation_id="module-replacement:switch-failed:job-long")
    assert "The outcome is not confirmed" in row.message and "stage runtime-sync" in row.message and "put back" not in row.message, row.message
    assert len(row.message) < 800, len(row.message)  # the error is cut to 300 characters
    meta = row.debug_info["metadata"]
    assert len(meta.get("error", "")) <= 300 and meta.get("rolled_back", "missing") is None, meta
    # the audit writer replaces oversized metadata with its marker; the row must still be found, so no second row is written
    AuditLog.objects.filter(pk=row.pk).update(debug_info={**row.debug_info, "metadata": marker})
    assert mr._audit_already_written("custom:module-replacement-switch-failed", OLD, "job-long") is True, "found by correlation id after the marker"
    assert mr.audit_finished_jobs() == 0, "a second sweep writes nothing"
    assert rows("custom:module-replacement-switch-failed").filter(debug_info__correlation_id="module-replacement:switch-failed:job-long").count() == 1


def a_1_17_12_row_is_still_found():
    AuditLog.objects.create(username=f"service:{MARK}", action="custom:module-replacement-disabled", object_type="module", message="row written by 1.17.12",
                            debug_info={"source": "tec-tac", "module_id": "core", "object_id": REPL, "metadata": {"job_id": "job-1-17-12"}})
    assert mr._audit_already_written("custom:module-replacement-disabled", REPL, "job-1-17-12") is True, "found by metadata job id"
    job_file("job-1-17-12", action="enable", plugin_id=OLD, disable_modules=[REPL], disabled_modules=[REPL], replacement_confirmed=True)
    assert mr.audit_finished_jobs() == 0, "the sweep does not duplicate a 1.17.12 row"


def dispatch_fails_safely():
    for path in JOBS.glob("*.json"):
        path.unlink()
    before = rows().count()
    original = v2._dispatch_v2

    def dispatch_unknown(job_id):
        return original("00000000-0000-4000-8000-000000000000")  # a job the helper does not have

    v2._dispatch_v2 = dispatch_unknown
    try:
        v2.queue_set_enabled(REPL, False, requested_by=MARK, actor=User(username=MARK))
    except Exception:  # noqa: BLE001 - the dispatch error is re-raised as it came
        pass
    else:
        raise AssertionError("the dispatch of an unknown job must fail")
    finally:
        v2._dispatch_v2 = original
    jobs = [json.loads(path.read_text(encoding="utf-8")) for path in JOBS.glob("*.json")]
    assert len(jobs) == 1 and jobs[0]["status"] == "dispatch_failed" and jobs[0]["enable_modules"] == [OLD], jobs
    assert rows().count() == before, "a job that never started writes no request row"
    assert mr.audit_finished_jobs() == 0 and rows().count() == before, "and no outcome row"


setup()
try:
    step("the hand-back plan, validate_disable and the catalogue row name the replaced module", plan_is_read)
    step("the queue-time row is a request and reaches AuditLog without claiming a change", queued_row_reaches_auditlog)
    step("the AuditLog JSON lookup finds the row and misses another job, object or action", lookup_finds_and_misses)
    step("the sweep writes one outcome row per module and never a duplicate", outcome_rows_written_once)
    step("the reconcile job keeps its single row", reconcile_job_keeps_one_row)
    step("the long-error row is written once and found again by its correlation id; no rollback record means not confirmed", long_error_row_is_written_once)
    step("a row written by 1.17.12 (metadata job id only) is still found", a_1_17_12_row_is_still_found)
    step("a failing sudo dispatch of a hand-back job is recorded, raised and not audited", dispatch_fails_safely)
finally:
    teardown()

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)
