#!/usr/bin/env python3
"""D3/AD-3 regression at the destructive restore operation boundary.

This test keeps host mutation stubbed, but executes operation_restore_backup() itself
through archive download and adjacent SHA-256 verification. It proves that a missing
companion is recorded in the recovery audit and that a mismatched companion aborts
before any restore mutation begins.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "server-backup-helper.py"
spec = importlib.util.spec_from_file_location("server_backup_helper_d3_restore", HELPER)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)

NAME = "tec-tac-backup-2026_09_30__08_45_00.tgz"
JOB_ID = "11111111-1111-4111-8111-111111111189"


def _config(state: pathlib.Path, backups: pathlib.Path) -> dict:
    return {
        "TEC_TAC_SERVER_BACKUP_ROOT": str(state),
        "TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": str(backups),
        "TACTICAL_ROOT": str(state / "tactical"),
        "TEC_TAC_ROOT": str(state / "tec-tac"),
        "TEC_TAC_FRAMEWORK_SOURCE": str(state / "framework"),
        "TEC_TAC_UI_SOURCE": str(state / "ui"),
    }


def _job(destination: dict) -> dict:
    return {
        "id": JOB_ID,
        "request": {
            "backup_ref": f"destination:local:{NAME}",
            "destination": destination,
            "restore_mode": "tec_tac",
        },
        "context": {"requested_by": "d3-regression"},
    }


def _install_safe_stubs(state: pathlib.Path, audit_events: list[tuple[str, dict]], mutation_calls: list[str]):
    original = {
        "validate_recovery_bundle": mod.validate_recovery_bundle,
        "_restore_version_transition": mod._restore_version_transition,
        "validate_target_preflight": mod.validate_target_preflight,
        "_capture_restore_security_state": mod._capture_restore_security_state,
        "create_pre_restore_snapshot": mod.create_pre_restore_snapshot,
        "run_post_restore_tec_tac": mod.run_post_restore_tec_tac,
        "service_start_after_restore": mod.service_start_after_restore,
        "verify_tactical_runtime": mod.verify_tactical_runtime,
        "_append_recovery_audit": mod._append_recovery_audit,
    }
    extracted = state / "fake-tec-tac.tar.gz"
    extracted.write_bytes(b"fixture")

    mod.validate_recovery_bundle = lambda downloaded, mode, stage, config=None: (
        {
            "format_version": 2,
            "installation_id": "source-installation",
            "core_version": "1.15.188",
            "components": {"tec_tac": {"included": True}},
            "recovery_modes": ["tec_tac"],
        },
        {"tec_tac": extracted},
    )
    mod._restore_version_transition = lambda config, manifest: {
        "source_core_version": "1.15.188",
        "target_core_version": "1.15.189",
        "is_core_downgrade": False,
    }
    mod.validate_target_preflight = lambda *a, **k: None
    mod._capture_restore_security_state = lambda *a, **k: None

    def snapshot(*a, **k):
        mutation_calls.append("snapshot")
        root = state / "snapshot"
        root.mkdir(exist_ok=True)
        return {"root": str(root), "created_at": "2026-09-30T06:45:00Z", "databases": [], "host_paths": [], "service_state": {}}

    mod.create_pre_restore_snapshot = snapshot

    def restore_core(*a, **k):
        mutation_calls.append("run_post_restore_tec_tac")
        return "1.15.189"

    mod.run_post_restore_tec_tac = restore_core
    mod.service_start_after_restore = lambda *a, **k: mutation_calls.append("service_start")
    mod.verify_tactical_runtime = lambda *a, **k: mutation_calls.append("verify_runtime")
    mod._append_recovery_audit = lambda event, **detail: audit_events.append((event, dict(detail)))
    return original


def _restore(original):
    for name, value in original.items():
        setattr(mod, name, value)


with tempfile.TemporaryDirectory(prefix="tectac-d3-restore-") as td:
    root = pathlib.Path(td)
    state = root / "state"
    backups = root / "backups"
    state.mkdir(); backups.mkdir()
    for child in ("jobs", "logs", "staging"):
        (state / child).mkdir()
    archive = backups / NAME
    archive.write_bytes(b"d3-ad3-archive-payload")
    destination = {"id": "local", "type": "local", "name": "Local", "path": str(backups)}
    config = _config(state, backups)

    # Missing companion: operation_restore_backup must continue, record the
    # explicit not-verified recovery audit, and return that state.
    audit_events: list[tuple[str, dict]] = []
    mutation_calls: list[str] = []
    original = _install_safe_stubs(state, audit_events, mutation_calls)
    try:
        result = mod.operation_restore_backup(config, _job(destination), io.StringIO())
    finally:
        _restore(original)
    assert result["ok"] is True
    assert result["archive_verification"]["status"] == "not_verified"
    not_verified = [detail for event, detail in audit_events if event == "restore_archive_not_verified"]
    assert len(not_verified) == 1, audit_events
    assert not_verified[0]["backup_ref"] == f"destination:local:{NAME}"
    assert "sha256 companion missing" in not_verified[0]["reason"]
    assert "run_post_restore_tec_tac" in mutation_calls

    # Mismatched companion: the real operation must stop at verification,
    # before snapshot/restore/service mutation is entered.
    wrong = "0" * 64
    (backups / f"{NAME}.sha256").write_text(f"{wrong}  {NAME}\n", encoding="utf-8")
    audit_events = []
    mutation_calls = []
    original = _install_safe_stubs(state, audit_events, mutation_calls)
    try:
        try:
            mod.operation_restore_backup(config, _job(destination), io.StringIO())
        except RuntimeError as exc:
            assert "SHA-256 companion mismatch" in str(exc), exc
        else:
            raise AssertionError("mismatched archive companion did not stop destructive restore")
    finally:
        _restore(original)
    assert mutation_calls == [], mutation_calls
    assert audit_events == [], audit_events

print("[TEST] PASS D3 destructive restore records missing hash and blocks mismatches")
