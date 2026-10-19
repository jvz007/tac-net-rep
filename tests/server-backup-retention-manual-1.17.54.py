#!/usr/bin/env python3
"""1.17.54 (Backups R2): retention no longer raises KeyError for backup_class 'manual'.

The helper imports fcntl, pwd and grp, so this runs on Linux or WSL, not plain Windows.
"""
from __future__ import annotations

import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_helper(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/server-backup-helper.py")
    helper = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(helper)
    return helper


class Lock:
    def close(self):
        pass


def run_retention(rows, policy):
    helper = load_helper("server_backup_helper_manual")
    deleted = []
    helper.acquire_lock = lambda config: Lock()
    helper.list_destination = lambda config, destination, log: [dict(row) for row in rows]
    helper.delete_destination = lambda config, destination, name, log: deleted.append(name)
    job = {"request": {"policies": [dict(policy, destination={"id": "d", "type": "local", "name": "d", "path": "/tmp"})]}}
    result = helper.operation_apply_retention({"TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": "/tmp"}, job, None)
    return result, deleted


def row(name, cls, day):
    return {"archive_name": name, "backup_class": cls, "sidecar_status": "ok", "modified_at": f"2026-09-{day:02d}T00:00:00Z"}


MANUAL = [row("new-manual.tgz", "manual", 20), row("old-manual.tgz", "manual", 10)]
ZERO = {"keep_daily": 0, "keep_weekly": 0, "keep_monthly": 0}


def test_manual_counts_as_unclassified() -> None:
    result, deleted = run_retention(MANUAL, dict(ZERO, keep_unclassified=1))
    assert result["ok"] is True
    assert deleted == ["old-manual.tgz"], deleted
    assert result["deleted"] == [{"destination_id": "d", "backup_class": "unclassified", "archive_name": "old-manual.tgz"}], result


def test_legacy_policy_never_deletes_manual() -> None:
    result, deleted = run_retention(MANUAL, dict(ZERO))
    assert result["ok"] is True and deleted == [], (result, deleted)


def test_other_classes_unchanged() -> None:
    rows = [row(f"{cls}-{i}.tgz", cls, i) for cls in ("daily", "weekly", "monthly", "unclassified") for i in (1, 2, 3)]
    rows += [row("manual-1.tgz", "manual", 5), row("manual-2.tgz", "manual", 6)]
    result, deleted = run_retention(rows, dict(keep_daily=1, keep_weekly=2, keep_monthly=3, keep_unclassified=2))
    # daily keep 1 drops the two older; weekly keep 2 drops one; monthly keep 3 drops none.
    # unclassified pool = 3 unclassified + 2 manual, keep the newest 2 (both manual), drop the rest.
    assert deleted == ["daily-2.tgz", "daily-1.tgz", "weekly-1.tgz", "unclassified-3.tgz", "unclassified-2.tgz", "unclassified-1.tgz"], deleted
    assert {item["backup_class"] for item in result["deleted"]} == {"daily", "weekly", "unclassified"}


if __name__ == "__main__":
    test_manual_counts_as_unclassified()
    test_legacy_policy_never_deletes_manual()
    test_other_classes_unchanged()
    print("[TEST] PASS retention treats manual archives as unclassified")
