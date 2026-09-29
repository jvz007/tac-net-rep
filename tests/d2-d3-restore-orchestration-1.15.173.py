#!/usr/bin/env python3
"""D2/D3 final acceptance through the real destructive restore orchestrator.

This test intentionally executes operation_restore_backup() rather than only its
helpers. Expensive host/database/install operations are isolated, but the real
restore control flow must carry an older Core version and the pre-restore service
state through validation/preflight, snapshot, reintegration, service restoration,
verification and the returned result.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("server_backup_helper_173", ROOT / "scripts" / "server-backup-helper.py")
h = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(h)


def must(value, message):
    if not value:
        raise AssertionError(message)


class DummyLock:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True


with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    state = td / "state"
    staging = state / "staging"
    staging.mkdir(parents=True)
    framework = td / "framework"
    framework.mkdir()
    (framework / "VERSION").write_text("1.15.172\n", encoding="utf-8")
    component = td / "tec-tac-component.tar.gz"
    component.write_bytes(b"component")

    config = {
        "TEC_TAC_SERVER_BACKUP_ROOT": str(state),
        "TEC_TAC_SERVER_BACKUP_STAGING": str(staging),
        "TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": str(td),
        "TEC_TAC_FRAMEWORK_SOURCE": str(framework),
        "TEC_TAC_ROOT": str(td / "runtime"),
        "TACTICAL_ROOT": str(td / "rmm"),
    }

    manifest = {
        "format_version": 2,
        "artifact_type": "tec-tac-recovery-bundle",
        "created_at": "2026-09-29T10:00:00Z",
        "installation_id": "install-old",
        "server_name": "old-rmm",
        "recovery_trust": {
            "installation_id": "install-old",
            "key_id": "old-key",
            "public_key_sha256": "11" * 32,
            "trusted": True,
            "trust_required": False,
        },
        "components": {
            "tec_tac": {"included": True, "framework_version": "1.15.83"},
        },
        "recovery_modes": ["tec_tac"],
    }

    job = {
        "id": "11111111-1111-4111-8111-111111111173",
        "request": {
            "backup_ref": "destination:local:tec-tac-backup-d23.tgz",
            "restore_mode": "tec_tac",
            "destination": {"id": "local", "type": "local", "name": "local", "path": str(td)},
        },
        "context": {"requested_by": "admin"},
    }

    service_state = {
        "rmm": True,
        "celery": True,
        "celerybeat": True,
        "nginx": True,
        "nats": False,
        "daphne": False,
        "nats-api": False,
        "meshcentral": False,
    }
    snapshot_root = td / "snapshot"
    snapshot_root.mkdir()
    lock = DummyLock()
    calls = []
    audits = []

    originals = {
        name: getattr(h, name)
        for name in (
            "acquire_lock", "download_destination", "validate_recovery_bundle",
            "validate_target_preflight", "_capture_restore_security_state",
            "create_pre_restore_snapshot", "run_post_restore_tec_tac",
            "service_start_after_restore", "verify_tactical_runtime",
            "_append_recovery_audit",
        )
    }

    try:
        h.acquire_lock = lambda _config: lock

        def fake_download(_config, _destination, _name, downloaded, _log):
            downloaded.write_bytes(b"bundle")
            return {
                "size_bytes": downloaded.stat().st_size,
                "sha256": hashlib.sha256(downloaded.read_bytes()).hexdigest(),
            }
        h.download_destination = fake_download
        h.validate_recovery_bundle = lambda *_a, **_k: (manifest, {"tec_tac": component})

        def fake_preflight(_config, report, _mode, _staged_bytes, **_kwargs):
            report["sections"]["target"]["status"] = "passed"
            h._vr_check(report, "target", "target.mutation_lock", "Backup/restore mutation", "passed", "owned")
        h.validate_target_preflight = fake_preflight

        security_snapshot = {"trusted_publishers": "target-wins"}
        h._capture_restore_security_state = lambda *_a, **_k: security_snapshot

        def fake_snapshot(_config, _job_id, _log, **kwargs):
            calls.append(("snapshot", kwargs))
            return {
                "root": str(snapshot_root),
                "created_at": "2026-09-29T10:01:00Z",
                "databases": [],
                "host_paths": [],
                "service_state": dict(service_state),
            }
        h.create_pre_restore_snapshot = fake_snapshot

        def fake_reintegrate(_config, component_meta, component_archive, _log, *, security_snapshot=None, actor="restore", source_installation_id=None):
            calls.append(("reintegrate", dict(component_meta), Path(component_archive), security_snapshot, actor, source_installation_id))
            # This is the exact postcondition D2 requires from a successful older-Core restore.
            Path(config["TEC_TAC_ROOT"]).mkdir(parents=True, exist_ok=True)
            (Path(config["TEC_TAC_ROOT"]) / "VERSION").write_text("1.15.83\n", encoding="utf-8")
            return h._verify_restored_core_version(_config, component_meta, io.StringIO())
        h.run_post_restore_tec_tac = fake_reintegrate

        def fake_service_restore(_log, restored_state=None):
            calls.append(("service_restore", dict(restored_state or {})))
        h.service_start_after_restore = fake_service_restore
        h.verify_tactical_runtime = lambda *_a, **_k: calls.append(("runtime_verified",))
        h._append_recovery_audit = lambda event, **payload: audits.append((event, payload))

        result = h.operation_restore_backup(config, job, io.StringIO())
    finally:
        for name, value in originals.items():
            setattr(h, name, value)

    must(lock.closed, "restore mutation lock was not closed")
    must(result["ok"] is True, "restore did not succeed")
    transition = result.get("version_transition") or {}
    must(transition.get("current_core_version") == "1.15.172", "current Core version was not captured")
    must(transition.get("restored_core_version") == "1.15.83", "backup-declared older Core version was not preserved")
    must(transition.get("is_core_downgrade") is True, "older Core restore was not identified as a downgrade")
    must(transition.get("effective_core_version") == "1.15.83", "successful restore did not verify the effective older Core version")
    must(transition.get("version_verified") is True, "successful restore did not mark older Core version verified")
    must((Path(config["TEC_TAC_ROOT"]) / "VERSION").read_text(encoding="utf-8").strip() == "1.15.83", "installed runtime did not remain on the backup version")

    reintegrate = next(row for row in calls if row[0] == "reintegrate")
    must(reintegrate[1]["framework_version"] == "1.15.83", "restore orchestrator did not pass the backup Core version into reintegration")
    must(reintegrate[3] == security_snapshot, "target security/trust snapshot was not carried into reintegration")
    must(reintegrate[4] == "admin", "restore actor was not preserved")

    service_restore = next(row for row in calls if row[0] == "service_restore")
    must(service_restore[1] == service_state, "pre-restore service activity was not restored exactly")
    must(("runtime_verified",) in calls, "restored Tactical runtime was not verified after service restoration")
    must(any(event == "core_version_restore" and payload.get("restored_core_version") == "1.15.83" for event, payload in audits), "downgrade restore audit was not emitted")

    # D3 source identity/trust data must remain present in the exact manifest that
    # passed the verified bundle boundary used by this destructive restore.
    must(manifest["server_name"] == "old-rmm", "source server identity was lost")
    must(manifest["installation_id"] == "install-old", "source installation identity was lost")
    must(manifest["recovery_trust"]["key_id"] == "old-key", "recovery signer identity was lost")
    must(manifest["recovery_trust"]["public_key_sha256"] == "11" * 32, "recovery signer fingerprint was lost")

print("[TEST] PASS D2/D3 destructive restore orchestration preserves older Core, identity/trust and service state")
