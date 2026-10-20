#!/usr/bin/env python3
# ruff: noqa: E402
"""1.17.67 regression (Q83 part 2): one audit row when a system update finishes, worded 'Update installed successfully 1.17.16 -> 1.17.17'.

The real system_update_audit.py and module_job_logs.py on stubs and temp roots. Covered: a succeeded job with installed_version writes exactly
one row with the exact message; a second sweep writes none; a job found only in history works; a job without installed_version reads 'to 1.17.17';
a failed job with a successful rollback, a failed rollback and no rollback gives the three wordings and carries no error text; a bad version
string becomes 'unknown'; a job older than 24 hours, a running job and a symlinked file write nothing; a failing audit lookup writes nothing; at
most 20 rows per tick. Source pins: the root helper sets job['installed_version'] right after old_version is read, and the tick calls the step.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


TMP = Path(tempfile.mkdtemp(prefix="tectac-su-audit-"))
JOBS, HISTORY = TMP / "jobs", TMP / "history"
JOBS.mkdir()
HISTORY.mkdir()
ROWS = []  # what the (stub) audit table holds
STATE = {"lookup_fails": False, "write_fails": False}


class FakeQuery:
    def __init__(self, rows, correlation, job_id, action, object_id):
        self.rows, self.args = rows, (correlation, job_id, action, object_id)

    def exists(self):
        if STATE["lookup_fails"]:
            raise RuntimeError("audit table unreadable")
        correlation, job_id, action, object_id = self.args
        return any(r["action"] == action and r["object_id"] == object_id and (r["correlation_id"] == correlation or r["metadata"].get("job_id") == job_id) for r in self.rows)


class FakeModel:
    class objects:  # noqa: N801 - mimics the manager
        @staticmethod
        def filter(q, **kw):
            return FakeQuery(ROWS, q[0], q[1], kw["action"], kw["debug_info__object_id"])


def record(**kw):
    if STATE["write_fails"]:
        raise RuntimeError("audit store down")
    ROWS.append(dict(kw))
    return {"recorded": True}


class Q:
    def __init__(self, **kw):
        self.kw = kw

    def __or__(self, other):
        return (self.kw["debug_info__correlation_id"], other.kw["debug_info__metadata__job_id"])


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
audit = mod("tec_tac.audit", record=record, service_audit_actor=lambda **kw: SimpleNamespace(kind="service", **kw), _auditlog_model=lambda: FakeModel)
pkg.audit = audit
mod("django")
mod("django.db")
mod("django.db.models", Q=Q)
sys.modules["django"].db = sys.modules["django.db"]
sys.modules["django.db"].models = sys.modules["django.db.models"]
# system_update is only read for its two folder names
mod("tec_tac.system_update", JOBS_ROOT=JOBS, HISTORY_ROOT=HISTORY)
pkg.system_update = sys.modules["tec_tac.system_update"]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


mj = load("tec_tac.module_job_logs", APP / "module_job_logs.py")
pkg.module_job_logs = mj
sua = load("tec_tac.system_update_audit", APP / "system_update_audit.py")
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
COUNTER = [0]


def job(*, where="jobs", ago_minutes=5, **fields):
    COUNTER[0] += 1
    job_id = f"00000000-0000-4000-8000-{COUNTER[0]:012d}"
    data = {"id": job_id, "status": "succeeded", "action": "install", "component": "framework", "version": "1.17.17", "installed_version": "1.17.16",
            "operation": "upgrade", "requested_by": "alice", "finished_at": (NOW - timedelta(minutes=ago_minutes)).isoformat(), "rollback": None,
            "error": "Traceback in /opt/tec-tac/secret.key: password=hunter2hunter2", "backup_path": "/var/lib/tec-tac/x"}
    data.update(fields)
    data = {k: v for k, v in data.items() if v is not ...}
    (HISTORY if where == "history" else JOBS).joinpath(f"{job_id}.json").write_text(json.dumps(data), encoding="utf-8")
    return job_id


def reset():
    del ROWS[:]
    STATE.update(lookup_fails=False, write_fails=False)
    for folder in (JOBS, HISTORY):
        for item in folder.iterdir():
            item.unlink()


def sweep(**kw):
    return sua.audit_finished_system_updates(now=NOW, **kw)


# ---- succeeded: exactly one row, the exact message; a second pass writes none
reset()
jid = job()
must(sweep() == 1 and len(ROWS) == 1, ROWS)
row = ROWS[0]
must(row["message"] == "Update installed successfully 1.17.16 -> 1.17.17", row["message"])
must(row["action"] == "install" and row["object_type"] == "system_update" and row["object_id"] == "framework" and row["module_id"] == "core" and row["strict"] is False, row)
must(row["actor"].kind == "service" and row["actor"].module_id == "core" and row["actor"].service == "system-update" and row["actor"].identity == "system", row["actor"].__dict__)
must(row["correlation_id"] == f"system-update:installed:{jid}", row["correlation_id"])
must(row["metadata"] == {"job_id": jid, "component": "framework", "from_version": "1.17.16", "to_version": "1.17.17", "operation": "upgrade", "result": "installed",
                         "requested_by": "alice", "rollback_status": None}, row["metadata"])
must("hunter2" not in repr(ROWS) and "secret.key" not in repr(ROWS) and "/var/lib" not in repr(ROWS), "no error text, no path")
must(sweep() == 0 and len(ROWS) == 1, "a second sweep writes nothing")
print("       a succeeded job writes one row 'Update installed successfully 1.17.16 -> 1.17.17' (action install, object system_update, service actor); a second sweep writes none")

# ---- history only, ui component, downgrade operation
reset()
jid = job(where="history", component="ui", installed_version="0.12.80", version="0.12.79", operation="downgrade")
must(sweep() == 1 and ROWS[0]["message"] == "Update installed successfully 0.12.80 -> 0.12.79" and ROWS[0]["object_id"] == "ui" and ROWS[0]["metadata"]["operation"] == "downgrade", ROWS)
reset()
a = job()
b = job(where="history")
(HISTORY / f"{a}.json").write_text((JOBS / f"{a}.json").read_text(encoding="utf-8"), encoding="utf-8")  # the same job in both folders: one row
must(sweep() == 2 and len(ROWS) == 2, ROWS)
print("       a job found only in history works; the same job in both folders gives one row; a downgrade reads the same and says so in the metadata")

# ---- an older helper: no installed_version
reset()
job(installed_version=...)
must(sweep() == 1 and ROWS[0]["message"] == "Update installed successfully to 1.17.17" and ROWS[0]["metadata"]["from_version"] == "unknown", ROWS)
print("       a job without installed_version reads 'Update installed successfully to 1.17.17'")

# ---- failed: three wordings, no error text
for label, fields, expected in (
    ("rollback succeeded", {"rollback": {"performed": True, "status": "succeeded", "version": "1.17.16"}}, "Update failed 1.17.16 -> 1.17.17. 1.17.16 was restored."),
    ("nothing changed", {"rollback": {"performed": False, "status": "not-required", "reason": "installer-refused"}}, "Update failed 1.17.16 -> 1.17.17. 1.17.16 was restored."),
    ("rollback failed", {"rollback": {"performed": True, "status": "failed", "version": "1.17.16", "error": "/opt/x/secret failed"}}, "Update failed 1.17.16 -> 1.17.17. The rollback did not finish, check the server."),
    ("no rollback", {"rollback": None}, "Update failed 1.17.16 -> 1.17.17."),
    ("no from version", {"rollback": None, "installed_version": ...}, "Update failed to 1.17.17."),
    ("no from version, rollback failed", {"rollback": {"performed": True, "status": "failed"}, "installed_version": ...}, "Update failed to 1.17.17. The rollback did not finish, check the server."),
):
    reset()
    jid = job(status="failed", **fields)
    must(sweep() == 1 and len(ROWS) == 1, (label, ROWS))
    must(ROWS[0]["message"] == expected, (label, ROWS[0]["message"]))
    must(ROWS[0]["action"] == "custom:system-update-failed" and ROWS[0]["correlation_id"] == f"system-update:failed:{jid}" and ROWS[0]["metadata"]["result"] == "failed", ROWS[0])
    must("hunter2" not in repr(ROWS) and "secret" not in repr(ROWS) and "Traceback" not in repr(ROWS) and "/opt" not in repr(ROWS), (label, "no error text, no path"))
print("       a failed job reads restored / the rollback did not finish / no restore claim / 'failed to X', and carries no error text or path")

# ---- a bad version string becomes 'unknown'
reset()
job(version="1.17.17; rm -rf /", installed_version="../../etc/passwd")
must(sweep() == 1 and ROWS[0]["message"] == "Update installed successfully to unknown" and ROWS[0]["metadata"]["to_version"] == "unknown" and "passwd" not in repr(ROWS), ROWS)
reset()
job(version="1.17.17", installed_version="x" * 80)
must(sweep() == 1 and ROWS[0]["message"] == "Update installed successfully to 1.17.17", ROWS)
reset()
job(component="../../x")
must(sweep() == 1 and ROWS[0]["object_id"] == "unknown", ROWS)
print("       a version that is not version-shaped becomes 'unknown'; so does an odd component")

# ---- nothing for these
reset()
job(ago_minutes=24 * 60 + 5)
job(status="running", finished_at=None)
job(status="queued")
(JOBS / "not-a-job.json").write_text("{}", encoding="utf-8")
(JOBS / "00000000-0000-4000-8000-0000000000ff.json").write_text("[1]", encoding="utf-8")
must(sweep() == 0 and not ROWS, ROWS)
print("       a job older than 24 hours, a running or queued job and an unreadable file write nothing")

real_lstat = os.lstat
reset()
jid = job()


def lstat(path, *a, **k):
    info = real_lstat(path, *a, **k)
    if str(path).replace("\\", "/").endswith(f"{jid}.json"):
        values = list(info)
        values[0] = stat.S_IFLNK | 0o644
        return os.stat_result(values)
    return info


os.lstat = lstat
try:
    must(sweep() == 0 and not ROWS, "a symlinked job file writes nothing")
finally:
    os.lstat = real_lstat
must(sweep() == 1, "the same file as a regular file does")
print("       a symlinked job file writes nothing")

# ---- a failing lookup or write
reset()
job()
STATE["lookup_fails"] = True
must(sweep() == 0 and not ROWS, "a broken lookup writes nothing, so it cannot repeat a row every tick")
STATE["lookup_fails"] = False
STATE["write_fails"] = True
must(sweep() == 0 and not ROWS, "a failed write is not counted and never raises")
STATE["write_fails"] = False
must(sweep() == 1 and len(ROWS) == 1, "the next tick retries")
print("       a failing audit lookup writes nothing; a failing write is not counted; the next tick retries; the sweep never raises")

# ---- at most 20 rows per tick, newest first
reset()
ids = [job(ago_minutes=i + 1) for i in range(25)]
must(sweep() == 20 and len(ROWS) == 20, len(ROWS))
must([r["metadata"]["job_id"] for r in ROWS] == ids[:20], "newest first")
must(sweep() == 5 and len(ROWS) == 25, "the rest on the next tick")
must(sweep() == 0, "then none")
print("       at most 20 rows per tick, newest first; the rest follow on the next tick")

# ---- a bad input never raises
must(sua.audit_finished_system_updates(now=NOW, jobs=[None, 5, {"status": "succeeded"}, {"status": "succeeded", "finished_at": "junk"}]) == 0, "odd input")
must(sua.audit_finished_system_updates(now=NOW, jobs=5) == 0, "a jobs value that is not a list never raises")

# ---- source pins
helper = (ROOT / "scripts" / "system-update-helper.py").read_text(encoding="utf-8")
lines = helper.splitlines()
at = next(i for i, line in enumerate(lines) if line.strip().startswith("old_version = (target / \"VERSION\")"))
must(lines[at + 1].strip().startswith('job["installed_version"] = old_version'), "run_job records the version that was installed before, right after it reads it")
must(helper.count('job["installed_version"]') == 1, "set once")
tick = (APP / "management" / "commands" / "tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
must("from tec_tac.system_update_audit import audit_finished_system_updates" in tick and "audit_finished_system_updates()" in tick, "the tick calls the step")
must("system_update_audit" in tick.split('sweep_state = "error"')[0], "inside a guarded step before the output line")
must("replacement_audit_rows={replacement_audit}" in tick and "system_update" not in tick.split("self.stdout.write(")[1], "the tick's own output line is unchanged")
public = (APP / "system_update.py").read_text(encoding="utf-8")
must('"installed_version"' in public.split("def public_job")[1].split("result =")[0], "public_job already whitelists installed_version")
print("PASS system update audit 1.17.67")
