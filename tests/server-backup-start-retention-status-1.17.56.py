#!/usr/bin/env python3
"""1.17.56 (core.server_backup 1.11.0): start_apply_retention and start_get_status.

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

import tec_tac.server_backup as sb
from tec_tac import capabilities

MARKER = "MARKER-SECRET-56b1"
CTX = {"source_module": "backups", "source_action": "test", "source_run_id": "run-1"}
LOCAL = {"id": "loc", "type": "local", "path": "/rmmbackups"}
PROVIDER = sb.get_server_backup_provider()

TMP = pathlib.Path(tempfile.mkdtemp(prefix="sb-start-ret-"))
(TMP / "jobs").mkdir()
(TMP / "logs").mkdir()


class Sandbox:
    """Point the module at a temp state root; fake the helper dispatch; forbid waiting."""

    def __enter__(self):
        self.saved = (sb._state_root, sb._dispatch, sb._run, sb.time.sleep)
        sb._state_root = lambda: TMP
        self.dispatched = []
        sb._dispatch = lambda job_id: self.dispatched.append(job_id)

        def no_sleep(*_a, **_k):
            raise AssertionError("a start_ operation must never sleep")

        def no_run(*_a, **_k):
            raise AssertionError("this call must not wait on a job")

        sb.time.sleep = no_sleep
        sb._run = no_run
        return self

    def __exit__(self, *_exc):
        sb._state_root, sb._dispatch, sb._run, sb.time.sleep = self.saved


def job_file(job_id):
    return TMP / "jobs" / f"{job_id}.json"


def stored(job_id):
    return json.loads(job_file(job_id).read_text(encoding="utf-8"))


def capture_twin(call):
    """Run a waiting method with _run faked; return (action, request)."""
    captured = {}
    saved = sb._run

    def fake_run(action, request, *, context, timeout=None):
        captured["action"], captured["request"] = action, request
        return {"ok": True}

    sb._run = fake_run
    try:
        call()
    finally:
        sb._run = saved
    return captured["action"], captured["request"]


def policy(**over):
    base = {"destination": LOCAL, "keep_daily": 7, "keep_weekly": 4, "keep_monthly": 12, "keep_unclassified": 3}
    base.update(over)
    return base


OTHER = {"id": "b", "type": "local", "path": "/rmmbackups/b"}
GOOD_POLICIES = [
    [policy()],
    [policy(), policy(destination=OTHER, keep_daily=0)],
    [{"destination": LOCAL, "keep_daily": "5", "keep_weekly": 1, "keep_monthly": 1}],  # keep_unclassified omitted
    [],
]
BAD_POLICIES = [
    "nope",
    ["nope"],
    [{"keep_daily": 1}],
    [policy(keep_daily="x")],
    [policy(keep_weekly=-1)],
    [policy(keep_monthly=10001)],
    [policy(keep_unclassified=None)],
]


def test_start_get_status() -> None:
    with Sandbox() as box:
        started = PROVIDER.start_get_status(destinations=[LOCAL], context=CTX)
        assert started == {"job_id": started["job_id"], "status": "queued", "action": "get_status"}, started
        assert box.dispatched == [started["job_id"]]
        payload = stored(started["job_id"])
        assert payload["nonwaiting"] is True and payload["action"] == "get_status"
        twin = capture_twin(lambda: PROVIDER.get_status(destinations=[LOCAL], context=CTX))
        assert twin == ("get_status", payload["request"])
        started = PROVIDER.start_get_status(context=CTX)
        assert stored(started["job_id"])["request"] == {"destinations": []}
        try:
            PROVIDER.start_get_status(destinations=[{"id": "x", "type": "nope"}], context=CTX)
        except sb.ServerBackupError:
            pass
        else:
            raise AssertionError("start_get_status accepted a bad destination")


def test_start_apply_retention_matches_twin() -> None:
    for policies in GOOD_POLICIES:
        with Sandbox() as box:
            started = PROVIDER.start_apply_retention(policies=policies, context=CTX)
            assert set(started) == {"job_id", "status", "action"}
            assert started["status"] == "queued" and started["action"] == "apply_retention", started
            assert box.dispatched == [started["job_id"]]
            payload = stored(started["job_id"])
            assert payload["nonwaiting"] is True
            twin_action, twin_request = capture_twin(lambda p=policies: PROVIDER.apply_retention(policies=p, context=CTX))
            assert twin_action == "apply_retention" and payload["request"] == twin_request, (payload["request"], twin_request)
    with Sandbox():
        started = PROVIDER.start_apply_retention(policies=GOOD_POLICIES[2], context=CTX)
        row = stored(started["job_id"])["request"]["policies"][0]
        assert row["keep_unclassified"] == 10000 and row["keep_daily"] == 5, row


def test_bad_policies_refused_with_twin_text() -> None:
    for policies in BAD_POLICIES:
        before = set((TMP / "jobs").iterdir())
        messages = []
        for name in ("apply_retention", "start_apply_retention"):
            with Sandbox():  # _run raises if the call got past validation
                try:
                    getattr(PROVIDER, name)(policies=policies, context=CTX)
                except sb.ServerBackupError as exc:
                    messages.append(str(exc))
                else:
                    raise AssertionError(f"{name} accepted {policies!r}")
        assert messages[0] == messages[1], (policies, messages)
        assert set((TMP / "jobs").iterdir()) == before, "a refused call must create no job"


def write_job(action, *, status, result, error=None):
    job_id = str(uuid.uuid4())
    payload = {
        "id": job_id, "action": action, "status": status, "stage": "complete", "started_at": None, "finished_at": None,
        "error": error, "context": dict(CTX), "request": {}, "result": result, "nonwaiting": True,
    }
    job_file(job_id).write_text(json.dumps(payload), encoding="utf-8")
    return job_id


def test_get_job_status_returns_scrubbed_result() -> None:
    with Sandbox():
        cases = (
            ("get_status", {"ok": True, "destinations": [{"id": "loc", "free_bytes": 5}], "tactical_backup_schedule": {"present": False}, "note": f"password={MARKER}"}),
            ("apply_retention", {"ok": True, "deleted": [], "note": f"token: {MARKER}"}),
        )
        for action, result in cases:
            for status, error in (("succeeded", None), ("failed", "boom")):
                out = PROVIDER.get_job_status(job_id=write_job(action, status=status, result=result, error=error))
                assert MARKER not in json.dumps(out), out
                assert out["result"]["ok"] is True and out["action"] == action
                assert "<redacted>" in out["result"]["note"]


def test_waiting_twins_unchanged() -> None:
    calls = []
    saved = sb._run
    try:
        sb._run = lambda action, request, *, context, timeout=None: calls.append((action, request)) or {"ok": True}
        PROVIDER.apply_retention(policies=[policy()], context=CTX)
        PROVIDER.get_status(destinations=[LOCAL], context=CTX)
    finally:
        sb._run = saved
    assert [c[0] for c in calls] == ["apply_retention", "get_status"]
    assert sb._timeout_for("apply_retention") == 7200 and sb._timeout_for("get_status") == 120


def test_registration_and_compatibility() -> None:
    capabilities._clear_capabilities_for_tests()
    saved = sb._PROVIDER.health
    sb._PROVIDER.health = lambda: {"healthy": True}
    try:
        registration = sb.register_core_server_backup_capability()
        assert registration.version == "1.11.0" and sb.CAPABILITY_VERSION == "1.11.0"
        earlier = {
            "create_backup", "get_job_status", "list_backups", "restore_backup", "apply_retention", "validate_destination",
            "validate_restore", "store_secret", "delete_secret", "start_create_backup", "start_validate_restore",
            "start_validate_destination", "start_list_backups", "start_restore_backup", "get_status",
        }
        operations = set(registration.operations)
        assert len(earlier) == 15 and operations == earlier | {"start_get_status", "start_apply_retention"}, operations
        for name in operations:
            assert callable(getattr(PROVIDER, name)), name
        assert registration.metadata["dangerous_operations"] == ["restore_backup", "start_restore_backup", "start_apply_retention"]
        # Backups 0.8.0 pins >=1.6.0,<2.0.0 and still resolves; the rebuild pins >=1.11.0.
        assert capabilities.get_capability("core.server_backup", version=">=1.6.0,<2.0.0") is PROVIDER
        assert capabilities.get_capability("core.server_backup", version=">=1.11.0,<2.0.0") is PROVIDER
    finally:
        sb._PROVIDER.health = saved
        capabilities._clear_capabilities_for_tests()


def test_docs_and_notes() -> None:
    doc = (ROOT / "docs" / "server-backup-capability.md").read_text(encoding="utf-8")
    assert "Non-waiting retention and status (1.11.0)" in doc and "start_apply_retention" in doc and "start_get_status" in doc
    notes_path = ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.56.md"  # moved there by 1.17.57
    if not notes_path.exists():
        notes_path = ROOT / "RELEASE_NOTES_1.17.56.md"
    notes = notes_path.read_text(encoding="utf-8")
    assert "Module-facing change" in notes and ">=1.11.0" in notes
    def _at_least(text: str) -> bool:  # 1.17.57: at least 1.17.56, ignoring a -N rebuild suffix
        return tuple(int(x) for x in text.strip().split("-")[0].split(".")) >= (1, 17, 56)
    assert _at_least((ROOT / "VERSION").read_text(encoding="utf-8"))
    assert _at_least(json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))["version"])


if __name__ == "__main__":
    test_start_get_status()
    test_start_apply_retention_matches_twin()
    test_bad_policies_refused_with_twin_text()
    test_get_job_status_returns_scrubbed_result()
    test_waiting_twins_unchanged()
    test_registration_and_compatibility()
    test_docs_and_notes()
    print("[TEST] PASS core.server_backup 1.11.0 start_apply_retention and start_get_status")
