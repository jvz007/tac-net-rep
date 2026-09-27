#!/usr/bin/env python3
"""M7 regression: legacy retention policies must remain non-destructive."""
from __future__ import annotations

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))

import tec_tac.server_backup as sb


def test_provider_normalizes_legacy_policy() -> None:
    provider = sb.get_server_backup_provider()
    captured = {}
    old_run = sb._run
    try:
        def fake_run(action, request, *, context, timeout=None):
            captured["action"] = action
            captured["request"] = request
            return {"ok": True}

        sb._run = fake_run
        provider.apply_retention(
            policies=[{
                "destination": {"id": "legacy", "type": "local", "name": "legacy", "path": "/tmp"},
                "keep_daily": 14,
                "keep_weekly": 8,
                "keep_monthly": 12,
            }],
            context={"source_module": "backups"},
        )
    finally:
        sb._run = old_run

    policy = captured["request"]["policies"][0]
    assert captured["action"] == "apply_retention"
    assert policy["keep_unclassified"] == 10000, policy
    assert policy["keep_daily"] == 14
    assert policy["keep_weekly"] == 8
    assert policy["keep_monthly"] == 12


def test_helper_does_not_delete_legacy_unclassified() -> None:
    spec = importlib.util.spec_from_file_location("server_backup_helper_m7", ROOT / "scripts/server-backup-helper.py")
    helper = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(helper)

    class Lock:
        def close(self):
            pass

    deleted = []
    old_lock = helper.acquire_lock
    old_list = helper.list_destination
    old_delete = helper.delete_destination
    try:
        helper.acquire_lock = lambda config: Lock()
        helper.list_destination = lambda config, destination, log: [
            {
                "archive_name": f"legacy-{idx}.tgz",
                "backup_class": "unclassified",
                "sidecar_status": "missing",
                "modified_at": f"2026-09-{idx:02d}T00:00:00Z",
            }
            for idx in range(1, 8)
        ]
        helper.delete_destination = lambda config, destination, name, log: deleted.append(name)
        result = helper.operation_apply_retention(
            {"TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": "/tmp"},
            {"request": {"policies": [{
                "destination": {"id": "legacy", "type": "local", "name": "legacy", "path": "/tmp"},
                "keep_daily": 1,
                "keep_weekly": 1,
                "keep_monthly": 1,
            }]}},
            None,
        )
    finally:
        helper.acquire_lock = old_lock
        helper.list_destination = old_list
        helper.delete_destination = old_delete

    assert result["ok"] is True
    assert deleted == [], deleted


def test_explicit_unclassified_still_applies() -> None:
    spec = importlib.util.spec_from_file_location("server_backup_helper_m7_explicit", ROOT / "scripts/server-backup-helper.py")
    helper = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(helper)

    class Lock:
        def close(self):
            pass

    deleted = []
    old_lock = helper.acquire_lock
    old_list = helper.list_destination
    old_delete = helper.delete_destination
    try:
        helper.acquire_lock = lambda config: Lock()
        helper.list_destination = lambda config, destination, log: [
            {"archive_name": "new.tgz", "backup_class": "unclassified", "sidecar_status": "missing", "modified_at": "2026-09-27T00:00:00Z"},
            {"archive_name": "old.tgz", "backup_class": "unclassified", "sidecar_status": "missing", "modified_at": "2026-09-26T00:00:00Z"},
        ]
        helper.delete_destination = lambda config, destination, name, log: deleted.append(name)
        helper.operation_apply_retention(
            {"TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": "/tmp"},
            {"request": {"policies": [{
                "destination": {"id": "new", "type": "local", "name": "new", "path": "/tmp"},
                "keep_daily": 0,
                "keep_weekly": 0,
                "keep_monthly": 0,
                "keep_unclassified": 1,
            }]}},
            None,
        )
    finally:
        helper.acquire_lock = old_lock
        helper.list_destination = old_list
        helper.delete_destination = old_delete

    assert deleted == ["old.tgz"], deleted


if __name__ == "__main__":
    test_provider_normalizes_legacy_policy()
    test_helper_does_not_delete_legacy_unclassified()
    test_explicit_unclassified_still_applies()
    print("[TEST] PASS M7 legacy retention compatibility")
