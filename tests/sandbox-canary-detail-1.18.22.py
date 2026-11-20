#!/usr/bin/env python3
"""1.18.22 regression: the canary prints the full text of a row the table cut (dev02 canary of 1.18.21, step 4u).

format_table cuts the actual column at ACTUAL_COLUMN_MAX (140), so the memory row's '; proof: ...' never reached the canary script. The helper
now prints ``DETAIL <row id> <full actual>`` for every cut row, after the ROW lines and before the totals. The table, the ROW lines and the verdicts
are unchanged. Also: the end frame's exit and signal are described as the unit's main process (the launcher), in comments and the docstring only.

Not runnable here: the real canary (dev02: tests/sandbox-canary-1.18.22.sh).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location("sandbox_harness_1822d", HERE / "sandbox-harness-1.17.118.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
sh, must = H.sh, H.must
MB = 128
ZERO = {"max": 0, "high": 0, "oom": 0, "oom_kill": 0}


def memory_row():
    out = b"CANARYMEM" + chr(9).encode() + b"112\n"
    end = {"reason": "oom", "exit": None, "signal": 9, "unit_result": "oom-kill", "exit_source": "unit", "oom_kills": 0, "peak_mb": 127.9,
           "evidence": "unit_result", "memory_events": dict(ZERO, max=1)}
    return sh.memory_row({"stdout": out, "stderr": b"", "end": end, "refused": None}, MB)


def row(attack, actual="x", verdict="OK"):
    return {"wall": "W", "attack": attack, "expected": "e", "actual": actual, "verdict": verdict}


# (1) the dev02 memory row: the table cuts the proof, the DETAIL line keeps it
mem = memory_row()
must(mem["verdict"] == "OK" and "; proof: systemd unit result oom-kill" in mem["actual"], mem)
must(len(mem["actual"]) > sh.ACTUAL_COLUMN_MAX, len(mem["actual"]))
table = [row("noop"), mem]
printed = sh.format_table(table)
must("; proof:" not in printed, "the table cut hides the proof (the bug)")
details = sh.detail_lines(table)
must(len(details) == 1 and details[0] == "DETAIL memory-beyond-memorymax " + mem["actual"], details)
must(details[0].endswith("; proof: systemd unit result oom-kill"), details[0])

# (2) a row that is not cut gets no DETAIL line (exactly at the width is not cut)
must(sh.detail_lines([row("a", "y" * sh.ACTUAL_COLUMN_MAX)]) == [], "at the width")
must(len(sh.detail_lines([row("a", "y" * (sh.ACTUAL_COLUMN_MAX + 1))])) == 1, "one over the width")

# (3) ids match row_lines / assign_row_ids, including the repeat rule
long = "z" * 200
rep = [row("same label", long), row("same label", "short"), row("same label", long), row("with id", long)]
rep[3]["id"] = "own-id"
ids = sh.assign_row_ids(rep)
must(ids == ["same-label", "same-label-2", "same-label-3", "own-id"], ids)
must([line.split(" ")[1] for line in sh.detail_lines(rep)] == ["same-label", "same-label-3", "own-id"], sh.detail_lines(rep))
must([line.split(" ")[1] for line in sh.row_lines(rep)] == ids, "same ids as the ROW lines")

# (4) one line, printable ASCII, at most 600 characters of text
nasty = row("nasty", "a" * 150 + "\nOK\r\tESC\x1b caf\u00e9 \u2603 " + "b" * 900, "NOT RUN")
line = sh.detail_lines([nasty])[0]
text = line[len("DETAIL nasty "):]
must(len(text) <= 600 and len(text) == 600, len(text))
must("\n" not in line and "\r" not in line and all(32 <= ord(ch) < 127 for ch in line), "one printable ASCII line")
must(len(sh.detail_lines([row("short nasty", "q\nr" + "c" * 150)])[0].split("\n")) == 1, "newline replaced")

# (5) the printed output keeps ROW lines first, DETAIL next and the totals last
buffer = io.StringIO()
real_run, real_summary = sh.run_canary, sh.canary_summary
sh.ensure_layout = lambda: None
sh.run_canary = lambda: table
writes = []
sh._write_root_file = lambda *args, **kw: writes.append(args)
sh.append_audit = lambda *args, **kw: None
try:
    with contextlib.redirect_stdout(buffer):
        sh.run_canary_command()
finally:
    sh.run_canary = real_run
lines = buffer.getvalue().splitlines()
first_row = next(i for i, l in enumerate(lines) if l.startswith("ROW "))
first_detail = next(i for i, l in enumerate(lines) if l.startswith("DETAIL "))
last_row = max(i for i, l in enumerate(lines) if l.startswith("ROW "))
totals = next(i for i, l in enumerate(lines) if " OK, " in l and "ATTACK SUCCEEDED" in l)
must(first_row < last_row < first_detail < totals, (first_row, last_row, first_detail, totals))
must(lines[-1] in ("CANARY PASSED", "CANARY FAILED"), lines[-1])

# the launcher wording: no 'program's own exit code', the launcher is named
source = "\n".join((ROOT / "scripts" / name).read_text(encoding="utf-8") for name in ("sandbox-helper.py", "sandbox-selftest.py"))
must("program's own exit code" not in source and "program's real end" not in source, "old wording is gone")
must("sandbox-launcher.py" in source and "main process (the launcher" in source, "the launcher is named")

# no behaviour moved: the 1.18.17 tests pass unchanged
for name in ("sandbox-memory-1.18.17.py", "sandbox-unit-result-1.18.17.py", "sandbox-canary-ids-1.18.15.py", "sandbox-canary-table-1.17.122.py"):
    done = subprocess.run([sys.executable, str(HERE / name)], capture_output=True, text=True, check=False)
    must(done.returncode == 0, name + "\n" + done.stdout[-600:] + done.stderr[-600:])
must(b"\r" not in (ROOT / "scripts" / "sandbox-helper.py").read_bytes(), "helper is LF")
must(b"\r" not in Path(__file__).read_bytes(), "test is LF")
print("[TEST] PASS sandbox canary detail 1.18.22")
