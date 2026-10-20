#!/usr/bin/env python3
"""1.17.60 regression: retention of finished module job records and logs (180 days, one constant).

Django side (``module_job_logs.prune_expired``, on a tempdir): an old finished record goes and a younger one stays; a queued, dispatched
or running job stays at any age; the newest job for a module stays at 400 days while an older job of the same module goes; a batch job is
kept when it is the newest for either module it names; a record with a missing or unparseable time stays; a non-uuid name, a directory
named <uuid>.json (and a symlink, where this OS can make one) is never removed; at most 200 records go per run; the audit row has counts
and no ids and is not written when nothing went; an audit failure does not stop the removal; the hourly gate works and a cache error runs
the sweep anyway; a dry run removes and writes nothing; the tick step is wrapped and a raising prune does not stop it.

Root side (the two helper scripts): static checks (the call is inside try/except in claim_job, lstat and S_ISREG, the uuid pattern,
the missing record, a limit, and the helpers are byte-identical to 1.17.59 apart from one added block and one call) and a functional run
of the real function text on a tempdir: an old orphan log goes; a log with a record, a fresh orphan, a directory and a bad name stay.

What cannot run here: the tick under Django, the root helpers as root, a real logs folder with root:tactical 2750.
"""
from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import textwrap
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))

AUDITS = []
AUDIT = {"fail": False}


def _record(**kwargs):
    if AUDIT["fail"]:
        raise RuntimeError("audit store down")
    AUDITS.append(kwargs)
    return {"recorded": True}


_audit = types.ModuleType("tec_tac.audit")
_audit.record = _record
_audit.service_audit_actor = lambda *, module_id, service, identity=None: types.SimpleNamespace(module_id=module_id, service=service, identity=identity)
sys.modules["tec_tac.audit"] = _audit


class Cache:
    def __init__(self):
        self.data, self.fail = {}, False

    def get(self, key):
        if self.fail:
            raise RuntimeError("cache down")
        return self.data.get(key)

    def add(self, key, value, timeout=None):
        if self.fail:
            raise RuntimeError("cache down")
        self.data.setdefault(key, value)


CACHE = Cache()
for _name in ("django", "django.core"):
    sys.modules.setdefault(_name, types.ModuleType(_name))
_cache_mod = types.ModuleType("django.core.cache")
_cache_mod.cache = CACHE
sys.modules["django.core.cache"] = _cache_mod

from tec_tac import module_job_logs as m  # noqa: E402


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
TMP = Path(tempfile.mkdtemp(prefix="tectac-retention-"))
m.JOBS_ROOT, m.LOGS_ROOT = TMP / "jobs", TMP / "logs"
m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT = TMP / "hf" / "jobs", TMP / "hf" / "logs"
for folder in (m.JOBS_ROOT, m.LOGS_ROOT, m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT):
    folder.mkdir(parents=True)
N = [0]


def put(days_old, *, status="succeeded", module="reportmanager", hotfix=False, finished="auto", log=False, **extra):
    N[0] += 1
    job_id = f"44444444-4444-4444-8444-{N[0]:012d}"
    stamp = (NOW - timedelta(days=days_old)).isoformat()
    record = {"id": job_id, "status": status, "action": "install", "plugin_id": module, "created_at": stamp,
              "finished_at": stamp if finished == "auto" else finished}
    record.update(extra)
    jobs, logs = (m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT) if hotfix else (m.JOBS_ROOT, m.LOGS_ROOT)
    (jobs / f"{job_id}.json").write_text(json.dumps(record), encoding="utf-8")
    if log:
        (logs / f"{job_id}.log").write_bytes(b"log\n")
    return job_id


def present(job_id, hotfix=False):
    return ((m.HOTFIX_JOBS_ROOT if hotfix else m.JOBS_ROOT) / f"{job_id}.json").exists()


def reset():
    for folder in (m.JOBS_ROOT, m.LOGS_ROOT, m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT):
        for item in folder.iterdir():
            if item.is_dir() and not item.is_symlink():
                item.rmdir()
            else:
                item.unlink()
    AUDITS.clear()
    AUDIT["fail"] = False
    CACHE.data.clear()
    CACHE.fail = False


def sweep(**kw):
    CACHE.data.clear()
    return m.prune_expired(now=NOW, **kw)


# ------------------------------------------------------------------ the one number
source = (ROOT / "framwork" / "tec_tac" / "module_job_logs.py").read_text(encoding="utf-8")
must(m.MODULE_JOB_RETENTION_DAYS == 180, "retention is 180 days")
must(len(re.findall(r"\b180\b", source)) == 1 and "MODULE_JOB_RETENTION_DAYS = 180" in source, "180 appears once, as the named constant")
for helper in ("module-v2-job-helper.py", "module-hotfix-job-helper.py"):
    text = (ROOT / "scripts" / helper).read_text(encoding="utf-8")
    must("180" not in text.split("def sweep_orphan_logs")[1].split("def claim_job")[0] and "RETENTION" not in text, f"{helper} holds no retention number")
print("PASS the retention period is one named constant, 180")

# ------------------------------------------------------------------ age, status, newest per module
reset()
old = put(200, module="alpha")
young = put(179, module="alpha")
newest_alpha = put(10, module="alpha")  # keeps alpha's newest protected
queued, dispatched, running = (put(400, status=s, module="beta", finished=None) for s in ("queued", "dispatched", "running"))
newest_gamma = put(400, module="gamma")
older_gamma = put(500, module="gamma")
batch = put(300, module="batch", action="batch_install", plan={"actions": [{"id": "delta", "version": "1"}, {"id": "epsilon", "version": "1"}]})
newer_delta = put(250, module="delta")  # delta's newest, epsilon's newest is the batch
no_time = put(300, module="zeta", finished=None)
bad_time = put(300, module="eta", finished="not a time")
no_time_at_all = put(300, module="theta", finished=None)
rec = json.loads((m.JOBS_ROOT / f"{no_time_at_all}.json").read_text())
rec["created_at"] = None
(m.JOBS_ROOT / f"{no_time_at_all}.json").write_text(json.dumps(rec))
failed_old = put(220, status="failed", module="alpha")
dispatch_failed = put(230, status="dispatch_failed", module="alpha")
hf_old = put(300, hotfix=True, module="reportmanager", action="apply", module_id="reportmanager", plugin_id=None)
hf_newest = put(290, hotfix=True, module="reportmanager", action="rollback", module_id="reportmanager", plugin_id=None)
result = sweep()
must(not present(old) and not present(failed_old) and not present(dispatch_failed), "old finished records go (succeeded, failed, dispatch_failed)")
must(present(young), "a 179-day record stays")
must(present(newest_alpha) and present(queued) and present(dispatched) and present(running), "newest and active jobs stay")
must(present(newest_gamma) and not present(older_gamma), "the newest job for a module stays at 400 days; an older one of the same module goes")
must(present(batch) and present(newer_delta), "a batch job stays when it is the newest for either module it names")
must(present(no_time) and present(bad_time) and present(no_time_at_all), "missing or unparseable times keep the record")
must(not present(hf_old, True) and present(hf_newest, True), "hotfix records are pruned with the same rules; the newest hotfix for a module stays")
must(result["records_removed"] == 4 and result["hotfix_records_removed"] == 1, f"counts: {result}")
must(result["kept_active"] >= 3 and result["kept_newest_per_module"] >= 2, f"kept counts: {result}")
print("PASS old finished records go; 179-day, active, newest-per-module and unreadable-time records stay")

# ------------------------------------------------------------------ audit
must(len(AUDITS) == 1, "one audit row per sweep that removed something")
row = AUDITS[0]
must(row["action"] == "custom:module-job-retention" and row["object_type"] == "module_job_retention" and row["module_id"] == "core", f"audit row: {row}")
must(set(row["metadata"]) == {"retention_days", "records_removed", "hotfix_records_removed", "kept_newest_per_module", "kept_active", "logs_awaiting_root_sweep"}, "audit metadata is counts")
must(all(isinstance(v, int) for v in row["metadata"].values()), "audit metadata holds counts only")
must(not re.search(r"44444444|alpha|gamma", json.dumps(row, default=str)), "the audit row carries no job id or module id")
AUDITS.clear()
again = sweep()
must(again["records_removed"] == 0 and again["hotfix_records_removed"] == 0 and not AUDITS, "a sweep that removes nothing writes no row")
print("PASS one audit row with counts and no ids; none when nothing was removed")

# ------------------------------------------------------------------ the names and file types that are never removed
reset()
put(300, module="keepme")  # the newest for its module: protected
stray = [m.JOBS_ROOT / "not-a-uuid.json", m.JOBS_ROOT / "44444444-4444-4444-8444-00000000000A.json", m.JOBS_ROOT / "README.txt"]
for path in stray:
    path.write_text(json.dumps({"status": "succeeded", "created_at": "2020-01-01T00:00:00+00:00", "plugin_id": "x"}))
dir_named = m.JOBS_ROOT / "55555555-5555-4555-8555-555555555555.json"
dir_named.mkdir()
victim = put(400, module="keepme")
linked_ok = False
target = TMP / "outside.json"
target.write_text(json.dumps({"status": "succeeded", "created_at": "2020-01-01T00:00:00+00:00", "plugin_id": "linked"}))
link = m.JOBS_ROOT / "66666666-6666-4666-8666-666666666666.json"
try:
    os.symlink(target, link)
    linked_ok = True
except (OSError, NotImplementedError):
    pass
sweep()
must(not present(victim), "the eligible record goes")
must(all(path.exists() for path in stray) and dir_named.is_dir(), "a non-uuid name, an upper-case uuid name and a directory named <uuid>.json are never removed")
if linked_ok:
    must(os.path.lexists(link) and target.exists(), "a symlink named <uuid>.json is never removed")
print(f"PASS odd names and file types are never removed (symlink {'tested' if linked_ok else 'not tested: this PC cannot make one'})")

# ------------------------------------------------------------------ the 200 per run bound
reset()
ids = [put(300 + i, module="bulk") for i in range(251)]  # the youngest (300 days) is the newest for the module and stays
sweep_one = sweep()
gone = [job for job in ids if not present(job)]
must(len(gone) == 200 and sweep_one["records_removed"] == 200, f"250 eligible, 200 removed in one run, got {len(gone)}")
must(all(job in gone for job in ids[-200:]) , "the oldest go first")
sweep_two = sweep()
must(sweep_two["records_removed"] == 50 and sum(present(job) for job in ids) == 1, "the second run removes the rest, the newest stays")
print("PASS at most 200 records per run, oldest first; the rest on the next run")

# ------------------------------------------------------------------ audit failure, gate, dry run
reset()
put(10, module="solo")
victim = put(300, module="solo")
AUDIT["fail"] = True
result = sweep()
must(not present(victim) and result["records_removed"] == 1, "an audit failure does not stop the removal")
AUDIT["fail"] = False

reset()
put(10, module="solo")
victim = put(300, module="solo")
first = m.prune_expired(now=NOW)  # real gate
must(first["records_removed"] == 1 and CACHE.data, "the first run goes and sets the gate")
victim2 = put(310, module="solo")
second = m.prune_expired(now=NOW)
must(second.get("skipped") and present(victim2), "within the hour the sweep does not run again")
CACHE.fail = True
third = m.prune_expired(now=NOW)
must(third["records_removed"] == 1 and not present(victim2), "a cache error runs the sweep anyway")
CACHE.fail = False

reset()
put(10, module="solo")
victim = put(300, module="solo")
CACHE.data["tec-tac:module-job-retention:gate"] = 1
dry = m.prune_expired(now=NOW, dry_run=True)
must(present(victim) and not AUDITS and dry["dry_run"] is True and dry["records_removed"] == 1, "a dry run counts, removes nothing, writes no row and ignores the gate")
print("PASS audit failure keeps the removal; the hourly gate; a cache error runs anyway; dry run")

# ------------------------------------------------------------------ the tick step
tick_path = ROOT / "framwork" / "tec_tac" / "management" / "commands" / "tec_tac_scheduler_tick.py"
tick = tick_path.read_text(encoding="utf-8")
start = tick.index("        try:\n            # 1.17.60")
end = tick.index("        sweep_state = ")
block = textwrap.dedent(tick[start:end])
tree = ast.parse(block)
must(len(tree.body) == 1 and isinstance(tree.body[0], ast.Try) and any(h.type is not None and getattr(h.type, "id", "") == "Exception" for h in tree.body[0].handlers),
     "the retention step is one try/except Exception")
must("prune_expired()" in block and "self.stderr" not in block, "the step calls prune_expired and writes nothing to the tick's output")
must("retention" not in tick[end:].lower() and "prune" not in tick[end:].lower(), "the tick's output line is unchanged")
calls = []
fake = types.ModuleType("tec_tac.module_job_logs")


def boom():
    calls.append(1)
    raise RuntimeError("the sweep failed")


fake.prune_expired = boom
package = types.ModuleType("tec_tac")
package.module_job_logs = fake
saved = {k: sys.modules.get(k) for k in ("tec_tac", "tec_tac.module_job_logs")}
sys.modules["tec_tac"], sys.modules["tec_tac.module_job_logs"] = package, fake
try:
    logging.disable(logging.CRITICAL)
    exec(compile(block, "tick-step", "exec"), {"logging": logging})
finally:
    logging.disable(logging.NOTSET)
    for key, value in saved.items():
        if value is None:
            sys.modules.pop(key, None)
        else:
            sys.modules[key] = value
must(calls == [1], "the step ran the raising prune and swallowed it")
print("PASS the tick step is wrapped: a raising prune does not stop the tick, the output line is unchanged")

# ------------------------------------------------------------------ the root helpers
PREVIOUS = {  # sha256 of each helper as released in 1.17.59 (commit 519531c)
    "module-v2-job-helper.py": "a8a0087d7b0d8e415cb507506cd3b03d0b2cad43929f43c3a199dc676bd3dffa",
    "module-hotfix-job-helper.py": "e74c0f8f577e04231d7393537a6cd75a7bee64f36cbcd11c2536efcd44bc54ed",
}
for name, previous in PREVIOUS.items():
    text = (ROOT / "scripts" / name).read_bytes().decode("utf-8")
    block_start = text.index("ORPHAN_LOG_RE = ")
    block_end = text.index("def claim_job(job_id):\n")
    call = "    try:\n        sweep_orphan_logs(LOGS_ROOT, JOBS_ROOT)\n    except Exception:\n        pass\n"
    must(text.count(call) == 1, f"{name}: exactly one guarded call")
    restored = (text[:block_start] + text[block_end:]).replace(call, "")
    must(hashlib.sha256(restored.encode("utf-8")).hexdigest() == previous,
         f"{name} must be byte-identical to 1.17.59 apart from the added function and its one call")
    tree = ast.parse(text)
    claim = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "claim_job")
    guarded = [n for n in claim.body if isinstance(n, ast.Try) and any(isinstance(c, ast.Expr) and isinstance(c.value, ast.Call)
                                                                       and getattr(c.value.func, "id", "") == "sweep_orphan_logs" for c in n.body)]
    must(len(guarded) == 1 and guarded[0].handlers[0].type.id == "Exception" and isinstance(guarded[0].handlers[0].body[0], ast.Pass),
         f"{name}: the call sits in claim_job inside try/except Exception: pass")
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "sweep_orphan_logs")
    body = ast.get_source_segment(text, func)
    must("os.lstat" in body and "S_ISREG" in body and "ORPHAN_LOG_RE.fullmatch" in body and "os.path.lexists" in body and "limit" in body and "86400" in body,
         f"{name}: lstat, S_ISREG, the uuid pattern, the missing-record test, a limit and the one-day age")
    must("json." not in body and "load_job" not in body and "read_text" not in body and "open(" not in body, f"{name}: the sweep reads no job state")
    must(len(re.findall(r"\bsweep_orphan_logs\(", text)) == 2, f"{name}: defined once and called once")
print("PASS helpers: one added function and one guarded call, everything else byte-identical to 1.17.59")

# functional run of the real function text
for name in PREVIOUS:
    text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
    ns = {"os": os, "re": re, "stat": __import__("stat"), "time": time}
    exec(text[text.index("ORPHAN_LOG_RE = "):text.index("def claim_job(job_id):\n")], ns)
    sweep_orphan_logs = ns["sweep_orphan_logs"]
    logs, jobs = TMP / f"h-{name}-logs", TMP / f"h-{name}-jobs"
    logs.mkdir()
    jobs.mkdir()
    ten_days = time.time() - 10 * 86400

    def log(uid, age=ten_days, logs=logs):
        path = logs / f"{uid}.log"
        path.write_bytes(b"x\n")
        os.utime(path, (age, age))
        return path

    orphan = log("77777777-7777-4777-8777-000000000001")
    with_record = log("77777777-7777-4777-8777-000000000002")
    (jobs / "77777777-7777-4777-8777-000000000002.json").write_text("{}")
    fresh = log("77777777-7777-4777-8777-000000000003", age=time.time() - 3600)
    bad_name = logs / "notes.log"
    bad_name.write_bytes(b"x")
    os.utime(bad_name, (ten_days, ten_days))
    upper = log("77777777-7777-4777-8777-00000000000A")
    directory = logs / "77777777-7777-4777-8777-000000000004.log"
    directory.mkdir()
    os.utime(directory, (ten_days, ten_days))
    removed = sweep_orphan_logs(logs, jobs)
    must(removed == 1 and not orphan.exists(), "an old orphan log is removed")
    must(with_record.exists() and fresh.exists() and bad_name.exists() and directory.is_dir() and upper.exists(),
         "a log with a record, a fresh orphan, a bad name, an upper-case name and a directory stay")
    for i in range(30):
        log(f"88888888-8888-4888-8888-{i:012d}")
    must(sweep_orphan_logs(logs, jobs, limit=10) == 10, "the limit bounds one call")
    must(sweep_orphan_logs(TMP / "no-such-folder", jobs) == 0, "a missing folder raises nothing")
print("PASS the real sweep function: removes an old orphan only; keeps a log with a record, a fresh one, a symlink-or-directory and odd names")

print("PASS module-job-retention-1.17.60")
