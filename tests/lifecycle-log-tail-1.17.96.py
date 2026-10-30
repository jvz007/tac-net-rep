#!/usr/bin/env python3
"""1.17.96: the lifecycle log_tail is 200 lines, read from the end of the file only.

Module jobs (module_manager.public_job, was 40), hotfix jobs (module_hotfix.public_hotfix_job, was 40) and system update jobs
(system_update.public_job, was 80) all use module_job_logs.tail_lines: the last 512 KiB of the file at most, at most 200 lines, each cut at
2000 characters, a partial first line dropped, [] for a missing or unreadable log. The old module job list (every row carries a tail) keeps 40
lines per row so a 1000-row payload does not grow five-fold; the history route without log text and the system update list rows
(include_log_tail=False) carry no log_tail. The contract and the docs say 200.

system_update.py needs pwd and the root-only helpers, so it loads here with the same small stubs as tests/job-log-routes-1.17.67.py.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


from tec_tac import module_hotfix
from tec_tac import module_job_logs as mj
from tec_tac import module_manager as mm

# system_update with stubs for what it imports (pwd on Windows, the trust modules)
if "pwd" not in sys.modules:
    try:
        import pwd  # noqa: F401
    except ImportError:
        sys.modules["pwd"] = types.ModuleType("pwd")
for name, attrs in {
    "tec_tac.trusted_publishers": {"PublisherTrustError": type("PublisherTrustError", (Exception,), {}),
                                   "verify_release_manifest_signature": lambda *a, **k: None, "verify_release_tree": lambda *a, **k: None},
    "tec_tac.trust_policy": {"TrustPolicyError": type("TrustPolicyError", (Exception,), {}), "acceptance": lambda *a, **k: {},
                             "get_policy": dict, "require_accepted": lambda *a, **k: None},
}.items():
    if name not in sys.modules:
        stub = types.ModuleType(name)
        stub.__dict__.update(attrs)
        sys.modules[name] = stub
spec = importlib.util.spec_from_file_location("tec_tac.system_update", APP / "system_update.py")
su = importlib.util.module_from_spec(spec)
sys.modules["tec_tac.system_update"] = su
spec.loader.exec_module(su)

TMP = Path(tempfile.mkdtemp(prefix="lifecycle-tail-"))
for folder in ("m", "h", "s"):
    (TMP / folder).mkdir()
mm.LOGS_ROOT, module_hotfix.HOTFIX_LOGS_ROOT, su.LOGS_ROOT = TMP / "m", TMP / "h", TMP / "s"
JID = "00000000-0000-4000-8000-000000000001"


def write(folder, text=None, raw=None):
    path = TMP / folder / f"{JID}.log"
    if raw is not None:
        path.write_bytes(raw)
    else:
        path.write_text(text, encoding="utf-8", newline="\n")
    return path


def tails(folder_text=None, raw=None):
    """The log_tail from the three public job functions, for the same log text."""
    for folder in ("m", "h", "s"):
        path = TMP / folder / f"{JID}.log"
        path.unlink(missing_ok=True)
        if folder_text is not None or raw is not None:
            write(folder, folder_text, raw)
    return (
        mm.public_job({"id": JID, "status": "failed"}).get("log_tail"),
        module_hotfix.public_hotfix_job({"id": JID, "status": "failed"}).get("log_tail"),
        su.public_job({"id": JID, "status": "failed"}).get("log_tail"),
    )


# (1) 500 lines: exactly the last 200 from all three; 150 lines: 150
text = "".join(f"line {i}\n" for i in range(500))
for got in tails(text):
    must(got == [f"line {i}" for i in range(300, 500)] and len(got) == 200, got[:3])
for got in tails("".join(f"line {i}\n" for i in range(150))):
    must(got == [f"line {i}" for i in range(150)], len(got))
print("       500 lines give the last 200 (module, hotfix and system update); 150 lines give 150")

# (2) a 5 MB log is read without loading the whole file: at most 512 KiB are read
big = TMP / "big.log"
with big.open("wb") as handle:
    for i in range(5 * 1024 * 1024 // 20):
        handle.write(f"row {i:015d}\n".encode())  # 20 bytes a line
size = big.stat().st_size
must(size >= 5 * 1024 * 1024 - 20, size)
real_read, total_read = os.read, [0]


def counting_read(fd, n):
    data = real_read(fd, n)
    total_read[0] += len(data)
    return data


os.read = counting_read
real_read_text = Path.read_text
Path.read_text = lambda *a, **k: (_ for _ in ()).throw(AssertionError("the whole log must not be read with read_text"))
try:
    lines = mj.tail_lines(big)
finally:
    os.read = real_read
    Path.read_text = real_read_text
must(total_read[0] <= 512 * 1024, f"read {total_read[0]} bytes")
must(len(lines) == 200 and lines[-1] == f"row {size // 20 - 1:015d}", (len(lines), lines[-1]))
must(all(len(line) == 19 and line.startswith("row ") for line in lines), "no partial line")
print(f"       a {size // 1024} KiB log: {total_read[0] // 1024} KiB read, last 200 lines")

# (3) a long line is cut at 2000 characters; a partial first line from the byte offset is dropped
for got in tails("short\n" + "x" * 10000 + "\nend\n"):
    must(got == ["short", "x" * 2000, "end"], [len(line) for line in got])
partial = ("A" * 600 + "\n") * 1000  # 600 KiB of lines, so the 512 KiB read starts inside one
must(len(partial) > 512 * 1024)
raw = ("head-line-that-is-cut " + "B" * 100 + "\n").encode() * 20000
lines = mj.tail_lines(write("m", raw=raw))
must(lines and all(line.startswith("head-line-that-is-cut B") for line in lines), "the first partial line is dropped, every other line is whole")
must(len(lines) == 200, len(lines))
small = mj.tail_lines(write("m", "first\nsecond\n"))
must(small == ["first", "second"], "a file under 512 KiB keeps its first line")
print("       long lines cut at 2000 characters; the partial first line of a large file is dropped; a small file keeps its first line")

# (4) a missing or unreadable log gives []
for got in tails(None):
    must(got == [], got)
must(mj.tail_lines(TMP / "m" / "no-such-file.log") == [], "missing")
must(mj.tail_lines(TMP / "m") == [], "a directory is not a log")
real_open = os.open


def denied(*a, **k):
    raise PermissionError("denied")


os.open = denied
try:
    must(mj.tail_lines(TMP / "m" / f"{JID}.log") == [], "unreadable")
finally:
    os.open = real_open
print("       missing, directory and unreadable logs give []")

# (5) bad bytes do not raise, and text is not scrubbed (as before)
for got in tails(raw=b"ok\xff\xfe line\npassword=KEEP\n"):
    must(got[-1] == "password=KEEP" and got[0].startswith("ok"), got)
print("       invalid UTF-8 is replaced; the text is not scrubbed here (as before)")

# (6) the list path keeps 40 per row; the history without log text has none; include_log_tail=False has none
mm.JOBS_ROOT = TMP / "jobs"
mm.JOBS_ROOT.mkdir()
for index in range(3):
    jid = f"00000000-0000-4000-8000-0000000001{index:02d}"
    (mm.JOBS_ROOT / f"{jid}.json").write_text(json.dumps({"id": jid, "status": "failed", "action": "install", "plugin_id": "demo", "created_at": f"2026-10-30T00:00:0{index}"}), encoding="utf-8")
    (TMP / "m" / f"{jid}.log").write_text("".join(f"l{i}\n" for i in range(300)), encoding="utf-8")
rows = mm._load_job_history_rows()
must(len(rows) == 3 and all(row["log_tail"] == [f"l{i}" for i in range(260, 300)] for row in rows), "40 lines per list row")
must(len(mm.list_jobs()) == 3 and all(len(row["log_tail"]) == 40 for row in mm.list_jobs()), "list_jobs rows keep 40")
must(mm.HISTORY_ROW_LOG_TAIL_LINES == 40, "the list constant")
one = mm.public_job({"id": "00000000-0000-4000-8000-000000000100", "status": "failed"})
must(len(one["log_tail"]) == 200, "a single job returns 200")
must("log_tail" not in su.public_job({"id": JID, "status": "failed"}, include_log_tail=False), "system update list rows have no log_tail")
history_row = mj.build_row({"id": JID, "status": "failed", "action": "install", "plugin_id": "demo"}, JID, "module", TMP / "m")
must("log_tail" not in history_row, "the history route has no log text")
print("       list rows keep 40 lines, a single job returns 200, rows without log text have no log_tail")

# (7) contract and docs say 200
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
must("the last 200 log lines" in contracts and "the last 80 log lines" not in contracts, "contract text")
docs = (ROOT / "docs" / "module-job-logs.md").read_text(encoding="utf-8")
must("200 lines" in docs and "40 per row" in docs, "module-job-logs.md")
must("200" in (ROOT / "docs" / "system-update-logs.md").read_text(encoding="utf-8"), "system-update-logs.md")
print("[TEST] PASS lifecycle log tail 1.17.96")
