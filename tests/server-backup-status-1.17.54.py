#!/usr/bin/env python3
"""1.17.54 (Backups R3): get_status, free space per local destination and Tactical's cron entry.

The helper imports fcntl, pwd and grp, so this runs on Linux or WSL, not plain Windows.
"""
from __future__ import annotations

import collections
import importlib.util
import json
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
MARKER = "MARKER-SECRET-91c2"
TMP = pathlib.Path(tempfile.mkdtemp(prefix="sb-status-"))


def load_helper():
    spec = importlib.util.spec_from_file_location("server_backup_helper_status", ROOT / "scripts/server-backup-helper.py")
    helper = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(helper)
    return helper


class Log:
    def __init__(self):
        self.lines = []

    def write(self, text):
        self.lines.append(text)


Usage = collections.namedtuple("Usage", "total used free")
CONFIG = {"TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": str(TMP), "TACTICAL_USER": "tactical"}


def run(helper, destinations, crontab=(0, "", "")):
    calls = []

    def fake_capture(args, *, timeout=120):
        calls.append(list(args))
        if isinstance(crontab, Exception):
            raise crontab
        return crontab

    helper._capture_command = fake_capture
    log = Log()
    result = helper.operation_get_status(CONFIG, {"request": {"destinations": destinations}}, log)
    return result, calls, log


def test_free_space_and_parent_fallback() -> None:
    helper = load_helper()
    seen = []

    def fake_usage(path):
        seen.append(path)
        return Usage(1000, 400, 600)

    helper.shutil.disk_usage = fake_usage
    existing = TMP / "present"
    existing.mkdir()
    missing = TMP / "not-yet" / "deeper"
    dests = [
        {"id": "a", "type": "local", "path": str(existing)},
        {"id": "b", "type": "local", "path": str(missing)},
        {"id": "c", "type": "ftp", "host": "h", "username": "u", "remote_path": "/x", "tls_mode": "explicit"},
    ]
    result, _calls, _log = run(helper, dests)
    rows = result["destinations"]
    assert [r["id"] for r in rows] == ["a", "b"], rows
    assert rows[0] == {"id": "a", "path": str(existing.resolve()), "available": True, "free_bytes": 600, "total_bytes": 1000}
    assert seen == [str(existing.resolve()), str(TMP.resolve())], seen
    assert not missing.exists() and not (TMP / "not-yet").exists(), "get_status must create nothing"

    def broken(path):
        raise OSError("unreadable")

    helper.shutil.disk_usage = broken
    result, _calls, _log = run(helper, [dests[0]])
    assert result["destinations"][0]["available"] is False
    assert result["destinations"][0]["free_bytes"] is None and result["destinations"][0]["total_bytes"] is None


def test_allow_list_refuses_outside_path() -> None:
    helper = load_helper()
    try:
        run(helper, [{"id": "evil", "type": "local", "path": "/etc/ssh"}])
    except RuntimeError as exc:
        assert "allow-list" in str(exc)
    else:
        raise AssertionError("a path outside the allow-list was accepted")


def test_cron_schedule() -> None:
    helper = load_helper()
    helper.shutil.disk_usage = lambda path: Usage(1, 1, 0)
    line = "0 0 * * * /rmm/backup.sh --auto"
    text = f"# comment backup.sh --auto\nMAILTO=ops@example.com\n{line}\n5 4 * * * /usr/bin/other --token={MARKER}\n"
    result, calls, _log = run(helper, [], crontab=(0, text, ""))
    sched = result["tactical_backup_schedule"]
    assert sched["checked"] is True and sched["present"] is True
    assert sched["entries"] == [{"schedule": "0 0 * * *", "command": "/rmm/backup.sh --auto"}], sched
    assert sched["writes_to"] == ["/rmmbackups/daily", "/rmmbackups/weekly", "/rmmbackups/monthly"]
    assert calls == [["crontab", "-l", "-u", "tactical"]], calls
    assert MARKER not in json.dumps(result)

    result, _calls, _log = run(helper, [], crontab=(0, f"5 4 * * * /usr/bin/other {MARKER}\n", ""))
    assert result["tactical_backup_schedule"]["present"] is False and result["tactical_backup_schedule"]["checked"] is True
    assert MARKER not in json.dumps(result)

    result, _c, _l = run(helper, [], crontab=(0, "@daily /rmm/backup.sh --auto >/dev/null 2>&1\n", ""))
    assert result["tactical_backup_schedule"]["entries"][0]["schedule"] == "@daily"

    # A user with no crontab is a real answer, not a failure.
    result, _c, _l = run(helper, [], crontab=(1, "", "no crontab for tactical"))
    assert (result["tactical_backup_schedule"]["checked"], result["tactical_backup_schedule"]["present"]) == (True, False)

    for failure in (FileNotFoundError("crontab"), (1, "", f"crontab: permission problem {MARKER}")):
        result, _c, _l = run(helper, [], crontab=failure)
        sched = result["tactical_backup_schedule"]
        assert sched["checked"] is False and sched["present"] is None and sched["entries"] == [] and sched["reason"], sched
        assert MARKER not in json.dumps(result)


def test_crontab_is_called_with_a_list_never_a_shell() -> None:
    helper = load_helper()
    recorded = {}

    def fake_run(args, **kwargs):
        recorded["args"], recorded["kwargs"] = args, kwargs

        class Proc:
            returncode, stdout, stderr = 0, "", ""

        return Proc()

    helper.subprocess.run = fake_run
    helper._read_tactical_backup_schedule(CONFIG)
    assert recorded["args"] == ["crontab", "-l", "-u", "tactical"]
    assert not recorded["kwargs"].get("shell") and recorded["kwargs"].get("timeout")
    bad = helper._read_tactical_backup_schedule({"TACTICAL_USER": "tactical; rm -rf /"})
    assert bad["checked"] is False and bad["present"] is None


def test_job_schema_and_registration() -> None:
    helper = load_helper()
    assert "get_status" in helper.ALLOWED_ACTIONS and "get_status" in helper.OPERATIONS
    result, _c, log = run(helper, [], crontab=(0, "", ""))
    assert result["ok"] is True and result["destinations"] == []
    assert not any(MARKER in line for line in log.lines)


if __name__ == "__main__":
    test_free_space_and_parent_fallback()
    test_allow_list_refuses_outside_path()
    test_cron_schedule()
    test_crontab_is_called_with_a_list_never_a_shell()
    test_job_schema_and_registration()
    print("[TEST] PASS get_status free space and Tactical cron read")
