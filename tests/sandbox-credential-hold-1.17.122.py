#!/usr/bin/env python3
"""1.17.122 regression: the credential canary run stays alive long enough for the root-side checks and the foreign reader (Low finding of 1.17.121).

The run used to hold only 3 seconds. The helper waits 1.5 s, then searches for the token on the host, checks the file, runs the foreign-reader
unit and checks the file again; on a slow server that did not fit in 3 s and the row turned NOT RUN. The hold is now the named constant
CANARY_CRED_HOLD_SECONDS (10), under canary_row's 20 s run_seconds, so the run still ends on its own and the limit never fires first.

The test runs on a virtual clock (time.sleep and time.monotonic are replaced for the length of each case), so it takes well under a second:
slow stubs (holders search 3 s, probe 4 s, each file check 0.5 s) keep the row OK with the 10 s hold, and the same stubs with the old 3 s hold
turn it into NOT RUN, so the test can fail.

Not runnable here: real systemd. tests/sandbox-canary-1.17.122.sh proves the row on dev02.
"""
from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_122h", "sandbox-harness-1.17.118.py")
sh, must = H.sh, H.must
WALL = "another dynamic user reads the credential file"
SLEEP_BEFORE = 1.5  # the helper's own pause before the first check (read from the source below)
HOLDERS, PROBE, READY = 3.0, 4.0, 0.5

source = (Path(__file__).resolve().parents[1] / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must("time.sleep(1.5)" in source[source.index("def _credential_rows"):source.index("def _unit_gone")], "the pause the test assumes is still 1.5 s")
must('"hold_seconds": 3}' not in source[source.index("def _credential_rows"):source.index("def _unit_gone")], "no literal 3 s hold in the credential rows")
must(sh.CANARY_CRED_HOLD_SECONDS >= 10, sh.CANARY_CRED_HOLD_SECONDS)

# the hold sits under canary_row's run_seconds (the run ends on its own; the limit never fires first)
canary_row_source = source[source.index("def canary_row"):source.index("def canary_row") + 600]
must('"run_seconds": 20' in canary_row_source, canary_row_source)
must(sh.CANARY_CRED_HOLD_SECONDS < 20, "hold is below canary_row's run_seconds")


def run_case():
    clock = {"now": 0.0}
    seen = {}
    real_sleep, real_monotonic = sh.time.sleep, sh.time.monotonic
    real_holders = sh._holders_search

    def collect(group, plan, **kwargs):
        seen["hold"] = plan["hold_seconds"]
        seen["start"] = clock["now"]
        import base64
        return {"stdout": b"CANARYROW\tcredential arrives\tOK\tarrived\n", "stderr": b"", "refused": None, "run_id": kwargs.get("run_id", ""),
                "end": {"reason": "exited", "exit": 0, "credential_b64": base64.b64encode(("refreshed-" + plan["credential_token"]).encode()).decode()}}

    def holders(token, unit):
        clock["now"] += HOLDERS
        return []

    def probe(unit):
        clock["now"] += PROBE
        return "DENIED"

    def ready(unit):
        alive = clock["now"] - seen.get("start", 0.0) < seen.get("hold", 0)
        clock["now"] += READY
        return alive

    sh.time.sleep = lambda seconds: clock.__setitem__("now", clock["now"] + seconds)
    sh.time.monotonic = lambda: clock["now"]
    sh._holders_search = holders
    try:
        rows = sh._credential_rows(collect, {"ready": True, "resolver": "127.0.0.53", "resolvers": ["127.0.0.53"]}, probe, ready)
    finally:
        sh.time.sleep, sh.time.monotonic = real_sleep, real_monotonic
        sh._holders_search = real_holders
    found = [r for r in rows if r["attack"] == WALL]
    must(len(found) == 1, rows)
    return seen, found[0], clock["now"]


# ---- the real constant: the slow stubs still give OK
seen, row, finished = run_case()
must(seen["hold"] == sh.CANARY_CRED_HOLD_SECONDS and seen["hold"] >= 10, seen)
must(row["verdict"] == "OK" and row["actual"] == "denied", row)
must(SLEEP_BEFORE + HOLDERS + READY + PROBE < seen["hold"], "1.5 s + the slow stubs up to the probe end sit inside the hold")
must(SLEEP_BEFORE + HOLDERS + READY + PROBE + READY < seen["hold"] + 0.001, ("the second check also lands inside the hold", finished))
must(seen["hold"] < 20, "the hold is below canary_row's run_seconds")

# ---- the control: the old 3 s hold turns the same stubs into NOT RUN, so this test can fail
old = sh.CANARY_CRED_HOLD_SECONDS
sh.CANARY_CRED_HOLD_SECONDS = 3
try:
    seen, row, _ = run_case()
finally:
    sh.CANARY_CRED_HOLD_SECONDS = old
must(seen["hold"] == 3, seen)
must(row["verdict"] == "NOT RUN", ("the old hold cannot cover the slow stubs", row))
must(sh.CANARY_CRED_HOLD_SECONDS == old, "the constant is restored")

# no thread of the case is left running
must(not [t for t in threading.enumerate() if t is not threading.main_thread() and t.is_alive() and t.daemon is False], "no stray thread")

print("[TEST] PASS sandbox credential hold 1.17.122")
