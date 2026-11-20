#!/usr/bin/env python3
"""1.18.16 regression: the /run privacy probe reports the marker as seen or not seen directly (held Low of the 1.18.15 review).

The next run (``runview``) gets the marker name in its plan and prints one line, CANARYRUNSEEN 1 or 0. The old listing was cut at 200 names,
so a marker sorting after 200 other names could be missed and the row read OK. Now nothing is cut.

Not runnable here: the unit's own /run (dev02: tests/sandbox-canary-1.18.16.sh).
"""
from __future__ import annotations

import contextlib
import errno
import importlib.util
import io
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import load_helper  # noqa: E402  (1.18.26: the helper and sandbox-selftest.py as one object)
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sh = load_helper(ROOT, "sandbox_helper_1816r")
runner = load("canary_runner_1816r", ROOT / "scripts" / "sandbox-canary-runner.py")
TAB, NL = chr(9), chr(10)
MARKER = sh.RUN_MARKER_PREFIX + "0123456789abcdef"


def probe(plan, names=None, error=None):
    real = runner.os.listdir

    def listing(path):
        must(path == "/run", path)
        if error:
            raise error
        return list(names)

    runner.os.listdir = listing
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            runner.g_runview(plan)
    finally:
        runner.os.listdir = real
    return out.getvalue()


must(probe({"run_marker": MARKER}, [MARKER, "systemd"]) == f"CANARYRUNSEEN{TAB}1{NL}", "marker present")
must(probe({"run_marker": MARKER}, ["credentials", "systemd"]) == f"CANARYRUNSEEN{TAB}0{NL}", "marker absent")
for bad in (None, "", "x", "../etc/passwd", sh.RUN_MARKER_PREFIX + "zz", 5):
    must(probe({"run_marker": bad}, [MARKER]) == "", bad)  # an invalid or missing name prints nothing
must(probe({}, [MARKER]) == "" and probe([], [MARKER]) == "", "no plan marker")
must(probe({"run_marker": MARKER}, error=OSError(errno.EACCES, "denied")) == "", "an unreadable /run prints nothing")
# the review's case: 500 names sort before the marker, none are cut
many = [f".aaa-{n:04d}" for n in range(500)]
must(probe({"run_marker": MARKER}, many + [MARKER]) == f"CANARYRUNSEEN{TAB}1{NL}", "500 names before the marker: still seen")
must(probe({"run_marker": MARKER}, many) == f"CANARYRUNSEEN{TAB}0{NL}", "500 other names: not seen")
must("CANARYRUNLIST" not in (ROOT / "scripts" / "sandbox-canary-runner.py").read_text(encoding="utf-8"), "the listing lines are gone from the probe")

# ---- helper side
must(sh.parse_run_seen(f"CANARYRUNSEEN{TAB}1{NL}".encode()) is True and sh.parse_run_seen(f"CANARYRUNSEEN{TAB}0{NL}".encode()) is False, "values")
must(sh.parse_run_seen(f"CANARYRUNSEEN{TAB}0{NL}CANARYRUNSEEN{TAB}1{NL}".encode()) is True, "the last exact line counts")
for junk in (b"", b"CANARYRUNSEEN", f"CANARYRUNSEEN{TAB}2{NL}".encode(), f"CANARYRUNSEEN{TAB}1{TAB}x{NL}".encode(), f" CANARYRUNSEEN{TAB}1{NL}".encode(),
             f"CANARYRUNSEEN 1{NL}".encode(), f"read /x{TAB}OK{TAB}CANARYRUNSEEN{TAB}1{NL}".encode(), f"CANARYRUNSEEN{TAB}{NL}".encode()):
    must(sh.parse_run_seen(junk) is None, junk)
must(sh.parse_run_seen(b"CANARYRUNLISTED\t0\n") is None and not hasattr(sh, "parse_run_listing"), "the old listing parser is gone")

SUCCEEDED = {"wall": "Writes", "attack": "write /run", "expected": "x", "actual": "written", "verdict": "ATTACK SUCCEEDED"}
must(sh.run_private_row(dict(SUCCEEDED), MARKER, [], False)["verdict"] == "OK", "absent: OK")
must(sh.run_private_row(dict(SUCCEEDED), MARKER, [], False)["actual"] == sh.RUN_PRIVATE_TEXT, "row text unchanged")
row = sh.run_private_row(dict(SUCCEEDED), MARKER, [], True)
must(row["verdict"] == "ATTACK SUCCEEDED" and "next run sees the marker" in row["actual"], row)
row = sh.run_private_row(dict(SUCCEEDED), MARKER, [MARKER], False)
must(row["verdict"] == "ATTACK SUCCEEDED" and "skeleton" in row["actual"], row)
row = sh.run_private_row(dict(SUCCEEDED), MARKER, [], None)
must(row["verdict"] == "NOT RUN" and "could not report" in row["actual"], row)

# ---- wiring: the plan carries the marker
seen = []


def collect(group, plan, **kw):
    seen.append((group, plan))
    return {"stdout": f"CANARYRUNSEEN{TAB}0{NL}".encode(), "refused": None, "end": {}}


table = [dict(SUCCEEDED)]
written = {"stdout": f"CANARYRUNMARKER{TAB}{MARKER}{NL}".encode()}
sh.table_private_run(table, written, MARKER, collect, {"ready": True}, lambda p: [])
must(seen == [("runview", {"run_marker": MARKER})] and table[0]["verdict"] == "OK", (seen, table))
for name in ("scripts/sandbox-helper.py", "scripts/sandbox-canary-runner.py", "tests/sandbox-run-seen-1.18.16.py"):
    must(b"\r" not in (ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox run seen 1.18.16")
