#!/usr/bin/env python3
"""1.18.15 regression: the 'write /run' canary row proves that /run is a private per-run tmpfs (dev02 canary of 1.18.14, item 1).

The writes probe leaves a marker named by the helper in /run. The row is OK only when the marker is NOT in the skeleton's run/ folder and the
next run's own listing of /run does not show it; the marker in either place stays ATTACK SUCCEEDED; a check that cannot be made is NOT RUN.
No unit property is changed (no TemporaryFileSystem=/run, no size cap): systemd 255's credential mount under a read-only /run cannot be shown
here, and a wrong property would break credential delivery for every run.

Not runnable here: the unit's own /run, the skeleton on a server and systemd (dev02: tests/sandbox-canary-1.18.15.sh).
"""
from __future__ import annotations

import contextlib
import errno
import importlib.util
import io
import os
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sh = load("sandbox_helper_1815a", ROOT / "scripts" / "sandbox-helper.py")
runner = load("canary_runner_1815a", ROOT / "scripts" / "sandbox-canary-runner.py")
TAB, NL = chr(9), chr(10)
MARKER = sh.RUN_MARKER_PREFIX + "0123456789abcdef"

# ---- the probe: a marker named by the plan is written and left; no name means the old behaviour (a test file, removed)
must(runner.run_marker_name({"run_marker": MARKER}) == MARKER, "a valid name")
for bad in (None, "", "x", "../etc/passwd", runner.RUN_MARKER_PREFIX + "zz", runner.RUN_MARKER_PREFIX + "0123456789abcde",
            runner.RUN_MARKER_PREFIX + "0123456789abcdefg", 5):
    must(runner.run_marker_name({"run_marker": bad}) is None, bad)
must(runner.run_marker_name([]) is None, "a plan that is not a dict")


def run_writes(plan):
    rows, opened, unlinked = [], [], []

    def fake_open(path, mode="r", *a, **k):
        opened.append(str(path))
        if not str(path).replace(chr(92), "/").startswith("/run/"):
            raise OSError(errno.EROFS, "read-only")
        return io.StringIO()

    saved = (runner.row, runner.os)
    runner.row = lambda attack, tag, actual: rows.append((attack, tag, actual))
    runner.os = types.SimpleNamespace(path=os.path, unlink=unlinked.append)
    runner.open = fake_open
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            runner.g_writes(plan)
    finally:
        runner.row, runner.os = saved
        del runner.open
    return rows, opened, unlinked, out.getvalue()


rows, opened, unlinked, printed = run_writes({"run_marker": MARKER})
must(len(rows) == 9, rows)
must(("write /run", "SUCCEEDED", "written") in rows and sum(1 for r in rows if r[1] == "OK") == 8, rows)
must(printed == f"CANARYRUNMARKER{TAB}{MARKER}{NL}", printed)
must(unlinked == [] and any(p.replace(chr(92), "/").endswith("/run/" + MARKER) for p in opened), (unlinked, opened))
rows, opened, unlinked, printed = run_writes({})
must(("write /run", "SUCCEEDED", "written") in rows and printed == "" and len(unlinked) == 1 and unlinked[0].endswith(".tectac-write-test"),
     (rows, unlinked, printed))

# ---- the reading side
must(sh.parse_run_marker(f"CANARYRUNMARKER{TAB}{MARKER}{NL}".encode()) == MARKER, "marker line")
must(sh.parse_run_marker(f"CANARYRUNMARKER{TAB}/etc/passwd{NL}".encode()) is None and sh.parse_run_marker(b"") is None, "only the exact shape")
must(sh.parse_run_listing(b"") is None, "no end line: did not list")
must(sh.parse_run_listing(f"CANARYRUNLISTED{TAB}0{NL}".encode()) == [], "listed, empty")
must(sh.parse_run_listing(f"CANARYRUNLIST{TAB}systemd{NL}CANARYRUNLISTED{TAB}1{NL}".encode()) == ["systemd"], "one name")
must("runview" in sh.CANARY_GROUPS and "runview" in runner.GROUPS, "the next-run listing group exists")

# ---- the verdicts (fake collect, fake skeleton listing)
LISTING_OK = f"CANARYRUNLIST{TAB}credentials{NL}CANARYRUNLIST{TAB}systemd{NL}CANARYRUNLISTED{TAB}2{NL}".encode()
LISTING_BAD = f"CANARYRUNLIST{TAB}credentials{NL}CANARYRUNLIST{TAB}{MARKER}{NL}CANARYRUNLISTED{TAB}2{NL}".encode()
WRITTEN = {"stdout": f"CANARYRUNMARKER{TAB}{MARKER}{NL}".encode(), "refused": None, "end": {"reason": "exited"}}
SUCCEEDED_ROW = {"wall": "Writes", "attack": "write /run", "expected": "read-only or private", "actual": "written", "verdict": "ATTACK SUCCEEDED"}


def table_of(run_row):
    return [{"wall": "Writes", "attack": "write /usr", "expected": "e", "actual": "EROFS", "verdict": "OK"}, run_row,
            {"wall": "Writes", "attack": "write /sys", "expected": "e", "actual": "EROFS", "verdict": "OK"}]


def check(written, listing, skeleton, marker=MARKER, refused=None):
    calls = []

    def collect(group, plan, **kw):
        calls.append(group)
        return {"stdout": listing, "refused": refused, "end": {}}

    def list_dir(path):
        if skeleton is None:
            raise OSError(errno.ENOENT, "missing")
        must(str(path).replace(chr(92), "/").endswith("/root/run"), path)
        return list(skeleton)

    table = table_of(dict(SUCCEEDED_ROW))
    sh.table_private_run(table, written, marker, collect, {"ready": True}, list_dir)
    return table, calls


table, calls = check(WRITTEN, LISTING_OK, [])  # (a)
must(table[1]["verdict"] == "OK" and "private per-run /run" in table[1]["actual"] and table[1]["actual"] == sh.RUN_PRIVATE_TEXT, table[1])
must(calls == ["runview"], calls)
table, _ = check(WRITTEN, LISTING_OK, [MARKER])  # (b)
must(table[1]["verdict"] == "ATTACK SUCCEEDED" and "skeleton" in table[1]["actual"], table[1])
table, _ = check(WRITTEN, LISTING_BAD, [])  # (c)
must(table[1]["verdict"] == "ATTACK SUCCEEDED" and "next run lists the marker" in table[1]["actual"], table[1])
table, calls = check({"stdout": b"", "refused": None}, LISTING_OK, [])  # (d)
must(table[1]["verdict"] == "NOT RUN" and "no marker" in table[1]["actual"] and calls == [], (table[1], calls))
other = sh.RUN_MARKER_PREFIX + "ffffffffffffffff"
table, _ = check({"stdout": f"CANARYRUNMARKER{TAB}{other}{NL}".encode()}, LISTING_OK, [])
must(table[1]["verdict"] == "NOT RUN", "a marker the helper did not choose is not evidence")
table, _ = check(WRITTEN, LISTING_OK, None)
must(table[1]["verdict"] == "NOT RUN" and "skeleton" in table[1]["actual"], table[1])
table, _ = check(WRITTEN, b"", [])
must(table[1]["verdict"] == "NOT RUN" and "next run" in table[1]["actual"], table[1])
table, _ = check(WRITTEN, LISTING_OK, [], refused="busy")
must(table[1]["verdict"] == "NOT RUN", table[1])

# a write that was refused stays OK and costs no extra run; a missing row changes nothing
refused_row = dict(SUCCEEDED_ROW, actual="EROFS", verdict="OK")
table = table_of(dict(refused_row))
calls = []
sh.table_private_run(table, WRITTEN, MARKER, lambda *a, **k: calls.append(a) or {}, {}, lambda p: [])
must(table[1] == refused_row and calls == [], table)
table = [table_of(dict(SUCCEEDED_ROW))[0]]
sh.table_private_run(table, WRITTEN, MARKER, lambda *a, **k: calls.append(a) or {}, {}, lambda p: [])
must(len(table) == 1 and calls == [], "no write /run row")

# ---- (e) the other eight write rows are untouched; the group still needs 9 'write /' rows
table, _ = check(WRITTEN, LISTING_OK, [])
must(table[0] == table_of(dict(SUCCEEDED_ROW))[0] and table[2] == table_of(dict(SUCCEEDED_ROW))[2], "neighbours")
must(sh.CANARY_REQUIRED["writes"] == ([], [("write /", 9)]), sh.CANARY_REQUIRED["writes"])
must(sh.CANARY_VIEW_ALLOWED["/run"] == ("credentials", "systemd"), "the view row is unchanged")
missing = sh.group_table("Writes", "writes", "e", [{"attack": "write /usr", "tag": "OK", "actual": "EROFS"}])
must(any(r["verdict"] == "NOT RUN" and "results" in r["actual"] for r in missing), missing)

# ---- no unit property was added for /run, and the helper wires the proof into the Writes group
source = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must("TemporaryFileSystem=/run" not in source and "BindReadOnlyPaths=/run" not in source and "InaccessiblePaths=/run" not in source, "no /run property")
must('"run_marker": marker' in source and "table_private_run(table, written, marker, collect, status)" in source, "wired into run_canary")
must(sh.SANDBOX_ENABLED is False, "the kill switch stays off")
for name in ("scripts/sandbox-helper.py", "scripts/sandbox-canary-runner.py"):
    must(b"\r" not in (ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox run private 1.18.15")
