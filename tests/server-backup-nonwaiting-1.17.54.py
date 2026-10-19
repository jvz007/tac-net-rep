#!/usr/bin/env python3
"""1.17.54 (core.server_backup 1.10.0): non-waiting operations, plus the compatibility proof.

Plain Python, no Django. Runs where Core imports (it needs fcntl, so Linux or WSL).
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))

import tec_tac.capabilities as capabilities
import tec_tac.server_backup as sb

MARKER = "MARKER-SECRET-7f3a9"
CTX = {"source_module": "backups", "source_action": "test", "source_run_id": "run-1"}
LOCAL = {"id": "loc", "type": "local", "path": "/rmmbackups"}
PROVIDER = sb.get_server_backup_provider()

TMP = pathlib.Path(tempfile.mkdtemp(prefix="sb-nonwaiting-"))
(TMP / "jobs").mkdir()
(TMP / "logs").mkdir()


class Sandbox:
    """Point the module at a temp state root and fake the helper dispatch."""

    def __enter__(self):
        self.saved = (sb._state_root, sb._dispatch, sb._run, sb.time.sleep)
        sb._state_root = lambda: TMP
        self.dispatched = []
        sb._dispatch = lambda job_id: self.dispatched.append(job_id)

        def no_sleep(*_a, **_k):
            raise AssertionError("a start_ operation must never sleep")

        sb.time.sleep = no_sleep
        return self

    def __exit__(self, *_exc):
        sb._state_root, sb._dispatch, sb._run, sb.time.sleep = self.saved


def job_file(job_id):
    return TMP / "jobs" / f"{job_id}.json"


def forbid_read(job_id):
    raise AssertionError("a start_ operation must not read the job file")


def capture_twin(call):
    """Run a waiting method with _run faked; return (action, request)."""
    captured = {}
    saved = sb._run

    def fake_run(action, request, *, context, timeout=None):
        captured["action"], captured["request"] = action, request
        return {"ok": True, "backups": []}

    sb._run = fake_run
    try:
        call()
    finally:
        sb._run = saved
    return captured["action"], captured["request"]


DEST_PAIR = dict(backup_ref="bundle-1.tgz", destination=LOCAL, restore_mode="full", context=CTX)
CASES = {
    "start_create_backup": ("create_backup", "create_backup",
                            dict(backup_class="manual", destinations=[LOCAL], include_tactical=True, include_tec_tac=False, context=CTX)),
    "start_list_backups": ("list_backups", "list_backups", dict(destinations=[LOCAL], context=CTX)),
    "start_restore_backup": ("restore_backup", "restore_backup", dict(DEST_PAIR, overrides={"target.os": "audit-1"})),
    "start_validate_destination": ("validate_destination", "validate_destination", dict(destination=LOCAL, context=CTX)),
    "start_validate_restore": ("validate_restore", "validate_restore", dict(DEST_PAIR, overrides=["target.os"])),
}


def test_start_returns_at_once_and_matches_twin() -> None:
    for start_name, (twin_name, action, kwargs) in CASES.items():
        with Sandbox() as box:
            saved_read = sb._read_job
            sb._read_job = forbid_read
            try:
                started = getattr(PROVIDER, start_name)(**kwargs)
            finally:
                sb._read_job = saved_read
            assert set(started) == {"job_id", "status", "action"}, (start_name, started)
            assert started["status"] == "queued" and started["action"] == action, started
            assert box.dispatched == [started["job_id"]]
            payload = json.loads(job_file(started["job_id"]).read_text(encoding="utf-8"))
            assert payload["nonwaiting"] is True, start_name
            twin_action, twin_request = capture_twin(lambda: getattr(PROVIDER, twin_name)(**kwargs))
            assert twin_action == action
            assert payload["request"] == twin_request, (start_name, payload["request"], twin_request)


def test_bad_arguments_raise_the_twin_error() -> None:
    bad = {
        "start_create_backup": dict(CASES["start_create_backup"][2], backup_class="nope"),
        "start_list_backups": dict(destinations="not-a-list", context=CTX),
        "start_restore_backup": dict(DEST_PAIR, restore_mode="sideways"),
        "start_validate_destination": dict(destination={"id": "x", "type": "carrier-pigeon"}, context=CTX),
        "start_validate_restore": dict(DEST_PAIR, restore_mode="sideways"),
    }
    for start_name, kwargs in bad.items():
        twin_name = CASES[start_name][0]
        with Sandbox():
            messages = []
            for name in (twin_name, start_name):
                try:
                    getattr(PROVIDER, name)(**kwargs)
                except sb.ServerBackupError as exc:
                    messages.append(str(exc))
                else:
                    raise AssertionError(f"{name} accepted bad arguments")
            assert messages[0] == messages[1], messages


def write_job(action, *, nonwaiting, status="succeeded", result=None, error=None):
    job_id = str(uuid.uuid4())
    payload = {
        "id": job_id, "action": action, "status": status, "stage": "complete", "started_at": None,
        "finished_at": None, "error": error, "context": dict(CTX), "request": {}, "result": result,
    }
    if nonwaiting:
        payload["nonwaiting"] = True
    job_file(job_id).write_text(json.dumps(payload), encoding="utf-8")
    return job_id


OLD_KEYS = {"job_id", "source_run_id", "status", "action", "stage", "stage_label", "started_at", "finished_at", "error", "progress", "log_tail"}


def test_get_job_status_result_rule() -> None:
    with Sandbox():
        secret_result = {"ok": False, "reason": f"login failed password={MARKER}", "detail": f"token: {MARKER}", "nested": {"rows": [f"secret={MARKER}"]}, "count": 3}
        for status, error in (("succeeded", None), ("failed", "boom")):
            job_id = write_job("validate_destination", nonwaiting=True, status=status, result=secret_result, error=error)
            out = PROVIDER.get_job_status(job_id=job_id)
            assert MARKER not in json.dumps(out), out
            assert out["result"]["count"] == 3 and out["result"]["ok"] is False
            assert "<redacted>" in out["result"]["reason"] and "<redacted>" in out["result"]["nested"]["rows"][0]
        # A job without the flag: exactly the old key set, no result for a non-registered action.
        plain = write_job("validate_destination", nonwaiting=False, result=secret_result)
        out = PROVIDER.get_job_status(job_id=plain)
        assert set(out) == OLD_KEYS, set(out) ^ OLD_KEYS
        # The three registered actions: result returned as before, unscrubbed, flag or not.
        for action in ("list_registered_backups", "validate_registered_restore", "restore_registered_backup"):
            job_id = write_job(action, nonwaiting=False, result={"note": f"password={MARKER}"})
            out = PROVIDER.get_job_status(job_id=job_id)
            assert out["result"] == {"note": f"password={MARKER}"}, out
        # A start_ job with no result yet gets no result key.
        pending = write_job("create_backup", nonwaiting=True, status="running", result=None)
        assert "result" not in PROVIDER.get_job_status(job_id=pending)


def test_detail_scrubbed_in_waiting_validate_destination() -> None:
    with Sandbox():
        sb._run = lambda action, request, *, context, timeout=None: {"ok": True, "detail": f"password={MARKER}", "stage": "complete"}
        out = PROVIDER.validate_destination(destination=LOCAL, context=CTX)
        assert MARKER not in json.dumps(out) and out["stage"] == "complete"

        def failing(action, request, *, context, timeout=None):
            raise sb.ServerBackupError("failed", result={"ok": False, "detail": f"secret={MARKER}", "reason": "connection failed"})

        sb._run = failing
        try:
            PROVIDER.validate_destination(destination=LOCAL, context=CTX)
        except sb.ServerBackupError as exc:
            assert MARKER not in json.dumps(exc.result) and exc.result["reason"] == "connection failed"
        else:
            raise AssertionError("expected an error")
        # No detail key (an older helper): untouched, nothing invented.
        sb._run = lambda action, request, *, context, timeout=None: {"ok": True, "checks": {}}
        assert "detail" not in PROVIDER.validate_destination(destination=LOCAL, context=CTX)


def test_compatibility_waiting_operations_unchanged() -> None:
    calls = []
    with Sandbox():
        def fake_run(action, request, *, context, timeout=None):
            calls.append((action, request))
            return {"backups": [{"a": 1}], "ok": True}

        sb._run = fake_run
        PROVIDER.create_backup(backup_class="daily", destinations=[LOCAL], context=CTX)
        assert PROVIDER.list_backups(destinations=[LOCAL], context=CTX) == [{"a": 1}]
        PROVIDER.restore_backup(backup_ref=" r ", destination=LOCAL, restore_tec_tac=False, context=CTX)
        PROVIDER.validate_destination(destination=LOCAL, context=CTX)
        PROVIDER.validate_restore(backup_ref="r", destination=None, restore_mode="tactical", context=CTX)
    assert [name for name, _ in calls] == ["create_backup", "list_backups", "restore_backup", "validate_destination", "validate_restore"]
    assert calls[0][1] == {"backup_class": "daily", "destinations": [dict(LOCAL)], "include_tactical": True, "include_tec_tac": True}
    assert calls[2][1] == {"backup_ref": "r", "destination": dict(LOCAL), "restore_mode": "tactical", "overrides": {}}
    assert calls[3][1] == {"destination": dict(LOCAL)}
    assert calls[4][1] == {"backup_ref": "r", "destination": None, "restore_mode": "tactical", "overrides": []}
    # Waiting jobs carry no flag.
    with Sandbox():
        started = sb._start("create_backup", {}, context=CTX)
        assert "nonwaiting" not in json.loads(job_file(started["job_id"]).read_text(encoding="utf-8"))


def test_registration_and_versions() -> None:
    capabilities._clear_capabilities_for_tests()
    saved = sb._PROVIDER.health
    sb._PROVIDER.health = lambda: {"healthy": True}
    try:
        registration = sb.register_core_server_backup_capability()
        assert registration.version == "1.11.0"
        assert capabilities.get_capability("core.server_backup", version=">=1.6.0,<2.0.0") is PROVIDER
        operations = set(registration.operations)
        old = {"create_backup", "get_job_status", "list_backups", "restore_backup", "apply_retention", "validate_destination", "validate_restore", "store_secret", "delete_secret"}
        new = {"start_create_backup", "start_validate_restore", "start_validate_destination", "start_list_backups", "start_restore_backup", "get_status", "start_get_status", "start_apply_retention"}
        assert old <= operations and new <= operations and operations == old | new, operations
        for name in operations:
            assert callable(getattr(PROVIDER, name)), name
        meta = registration.metadata
        assert meta["dangerous_operations"] == ["restore_backup", "start_restore_backup", "start_apply_retention"]
    finally:
        sb._PROVIDER.health = saved
        capabilities._clear_capabilities_for_tests()


def test_get_status_core_side_and_health_untouched() -> None:
    with Sandbox():
        seen = {}

        def fake_run(action, request, *, context, timeout=None):
            seen.update(action=action, request=request)
            return {"ok": True, "destinations": [], "tactical_backup_schedule": {}}

        sb._run = fake_run
        PROVIDER.get_status(destinations=[LOCAL], context=CTX)
        assert seen == {"action": "get_status", "request": {"destinations": [dict(LOCAL)]}}
        PROVIDER.get_status(context=CTX)
        assert seen["request"] == {"destinations": []}
        try:
            PROVIDER.get_status(destinations=[{"id": "x", "type": "nope"}], context=CTX)
        except sb.ServerBackupError:
            pass
        else:
            raise AssertionError("get_status accepted a bad destination")
        assert sb._timeout_for("get_status") == 120
    # health() keeps its exact 1.17.53 shape and never touches the helper, a disk or a crontab.
    saved_layout = sb.load_layout
    saved_helper = sb.HELPER
    try:
        sb.load_layout = lambda: {"TACTICAL_ROOT": str(TMP / "rmm")}
        sb.HELPER = TMP / "missing-helper"
        sb._run = None
        health = PROVIDER.health()
    finally:
        sb.load_layout, sb.HELPER = saved_layout, saved_helper
    assert set(health) == {"healthy", "helper", "helper_available", "backup_script", "backup_script_available", "restore_script", "restore_script_available", "transports"}, health
    assert health["healthy"] is False and health["transports"] == sorted(sb.DESTINATION_TYPES)


if __name__ == "__main__":
    test_start_returns_at_once_and_matches_twin()
    test_bad_arguments_raise_the_twin_error()
    test_get_job_status_result_rule()
    test_detail_scrubbed_in_waiting_validate_destination()
    test_compatibility_waiting_operations_unchanged()
    test_registration_and_versions()
    test_get_status_core_side_and_health_untouched()
    print("[TEST] PASS core.server_backup non-waiting operations and compatibility")
