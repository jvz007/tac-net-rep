#!/usr/bin/env python3
"""1.17.124 regression: the abstract-socket list is capped below the runner's 64 KiB stdin read (held Low from the 1.17.123 review).

collect_run sends json.dumps(plan) (ensure_ascii) and the runner reads sys.stdin.read(65536). A latin-1 byte becomes a 6-character escape, so
200 names of up to 107 bytes can pass the read; json.loads then failed, the plan became {} and the abstract row was NOT RUN for no visible
reason. Now fit_abstract_names keeps names while the exact json length of the list stays within 49152 characters and counts what it left out;
the runner shows the count, and a plan that does not parse prints a 'plan unreadable' row instead of silently continuing with {}. The 64 KiB
read limit is unchanged. A left-out name is covered by the 'unix socket creation refused' rows, so the count never fails the canary.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_124a", "sandbox-harness-1.17.118.py")
sh, must = H.sh, H.must
spec = importlib.util.spec_from_file_location("canary_runner_124a", H.ROOT / "scripts" / "sandbox-canary-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
LIMIT = 65536

# ---- the problem: 200 names of 107 bytes of 0xFF
names = [("\xff" * 106) + chr(65 + i % 26) for i in range(200)]
raw_plan = json.dumps({"abstract": names, "abstract_seconds": 40, "abstract_probe": "tectac-canary-0123456789abcdef"})
must(len(raw_plan) > 1.9 * LIMIT, len(raw_plan))  # far above the read without a cap

# ---- the fix
kept, left = sh.fit_abstract_names(names)
must(0 < len(kept) < 200 and left == 200 - len(kept) and left > 0, (len(kept), left))
must(len(json.dumps(kept)) <= 49152 and len(json.dumps(kept + [names[len(kept)]])) > 49152, "stops exactly at the budget")
must(kept == names[:len(kept)], "the kept names are the first ones, in order")
must(json.loads(json.dumps(kept)) == kept and all(a.encode("latin-1") == b.encode("latin-1") for a, b in zip(json.loads(json.dumps(kept)), kept, strict=True)), "byte exact through json")
plan = {"abstract": kept, "abstract_left_out": left, "abstract_seconds": 40, "abstract_probe": "tectac-canary-0123456789abcdef"}
must(len(json.dumps(plan)) < LIMIT, len(json.dumps(plan)))
# a short ASCII list keeps everything
short = ["a", "b" * 50, "c" * 107]
must(sh.fit_abstract_names(short) == (short, 0), "")
must(sh.fit_abstract_names([]) == ([], 0), "")
# the budget argument is honoured, and exactly 200 plain names pass whole
must(sh.fit_abstract_names(short, budget=10) == (["a"], 2), sh.fit_abstract_names(short, budget=10))
plain = [f"name{i}" for i in range(200)]
must(sh.fit_abstract_names(plain) == (plain, 0), "200 ordinary names fit")
# one name that alone is over the budget is left out and the rest are not tried after it (order is kept, never skipped over)
huge = ["x" * 60000, "ok"]
must(sh.fit_abstract_names(huge) == ([], 2), sh.fit_abstract_names(huge))

# ---- run_canary hands the capped list and the count to the unit
PLANS = {}


class Outside:
    def run_cmd(self, argv, *, timeout=15):
        if argv[0] == "ss":
            return 0, "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", ""
        if argv[0] == "ip" and argv[1] == "-o":
            return 0, "2: eth0    inet 192.168.1.5/24 scope global eth0\n", ""
        return 0, "default via 192.168.1.1 dev eth0\n" if argv[1] == "-4" else "", ""


def collect(group, plan, **kwargs):
    PLANS[group] = (plan, kwargs)
    if group == "abstract":
        must(len(json.dumps(plan)) < LIMIT, "the plan the unit reads is under 64 KiB")
    return {"stdout": b"", "stderr": b"", "end": {"reason": "exited", "exit": 0}, "refused": None, "run_id": "r", "frames": []}


sh._cancel_rows = lambda c, s: []
sh._holders_search = lambda token, unit: []
sh._credential_file_ready = lambda unit: True
sh._foreign_credential_probe = lambda unit: "DENIED"
sh._latency_rows = lambda c, s: []
sh._concurrency_rows = lambda c, s: []
sh._credential_rows = lambda c, s, *a, **k: []
sh._limit_rows = lambda c, s: []
sh.CANARY_MARKER_DIRS = ()
sh.CANARY_REAL_FILES = ()
sh.read_abstract_names = lambda: list(names)
sh.run_canary(status={"ready": True, "resolver": "9.9.9.9", "resolvers": ["9.9.9.9"]}, collect=collect, outside=Outside())
plan, _kwargs = PLANS["abstract"]
must(plan["abstract"] == kept and plan["abstract_left_out"] == left, (len(plan["abstract"]), plan["abstract_left_out"]))
sh.read_abstract_names = lambda: None
sh.run_canary(status={"ready": True, "resolver": "9.9.9.9", "resolvers": ["9.9.9.9"]}, collect=collect, outside=Outside())
must("abstract" not in PLANS["abstract"][0] and "abstract_left_out" not in PLANS["abstract"][0], "no list: nothing is claimed")

# ---- the runner shows the count, and a left-out count does not fail the canary
rows = []
runner.row = lambda attack, tag, actual: rows.append((attack, tag, actual))
runner._abstract_connect = lambda name: ("refused", "EAFNOSUPPORT")
runner.g_abstract(plan)
info = [r for r in rows if r[0] == "abstract sockets left out (information)"]
main = [r for r in rows if r[0].startswith("abstract sockets (")]
must(info == [("abstract sockets left out (information)", "OK", f"{left} left out (covered by the unix socket creation rows)")], info)
must(len(main) == 1 and main[0][1] == "OK" and f"({len(kept)} listed, {left} left out)" in main[0][2], main)
table = sh.group_table("Abstract sockets", "abstract", "x", [{"attack": a, "tag": t, "actual": d} for a, t, d in rows])
must(not [r for r in table if r["verdict"] != "OK"] and sh.canary_summary(table)[0] is True, "a non-zero left-out count does not fail the canary")
# the information row alone does not satisfy the required main row
only_info = [{"attack": a, "tag": t, "actual": d} for a, t, d in info]
must(any(r["verdict"] == "NOT RUN" for r in sh.group_table("Abstract sockets", "abstract", "x", only_info)), "the main row is still required")

# ---- a truncated stdin: the runner says 'plan unreadable' instead of continuing with {}
truncated = raw_plan[:LIMIT]
must(len(raw_plan) > LIMIT and not truncated.endswith("}"), "the 1.17.123 situation: a plan cut by the read")
fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fresh)
out = io.StringIO()
saved_stdin = sys.stdin
sys.stdin = io.StringIO(raw_plan)  # the runner reads at most 65536 characters, as before
try:
    with contextlib.redirect_stdout(out):
        code = fresh.main(["abstract"])
finally:
    sys.stdin = saved_stdin
parsed = sh.parse_runner_rows(out.getvalue().encode())
must(code == 0 and len(parsed) == 1 and parsed[0]["attack"] == "plan unreadable" and parsed[0]["tag"] == "NOTRUN", out.getvalue())
must(sh.group_table("Abstract sockets", "abstract", "x", parsed)[0]["verdict"] == "NOT RUN", "and the table says NOT RUN")
must(sh.canary_summary(sh.group_table("Abstract sockets", "abstract", "x", parsed))[0] is False, "which fails the canary")
# not a dict: also unreadable; empty stdin and a good plan are as before
for text, expect in (("[1, 2]", True), ("", False), ("{}", False), ('{"abstract": []}', False)):
    out = io.StringIO()
    sys.stdin = io.StringIO(text)
    fresh2 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh2)
    try:
        with contextlib.redirect_stdout(out):
            fresh2.main(["abstract"])
    finally:
        sys.stdin = saved_stdin
    must(("plan unreadable" in out.getvalue()) is expect, (text, out.getvalue()))
runner_source = (H.ROOT / "scripts" / "sandbox-canary-runner.py").read_text(encoding="utf-8")
must("read(65536)" in runner_source, "the 64 KiB read limit is kept, not raised")

print("[TEST] PASS sandbox abstract cap 1.17.124")
