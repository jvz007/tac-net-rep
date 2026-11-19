#!/usr/bin/env python3
"""1.18.17 regression: a failed run unit is forgotten (reset-failed) after each run and by the sweep.

* A finished run, a cancelled run and a run whose helper path raises each reset their unit once; a unit systemd says is not loaded is not reset.
* The sweep lists failed ``tectac-*`` units and resets the old ones; a unit whose run record or handoff is young, or that is active, is left.
* A name outside ``^tectac-[a-z0-9-]+\\.service$`` (spaces, '..', uppercase, a slash, another prefix) never reaches systemctl.
* A failing list-units or reset-failed never stops the rest of the sweep; ``units_reset`` is in the printed JSON and the audit row.

Not runnable here: real systemd failed units (dev02: tests/sandbox-canary-1.18.17.sh closes with an empty failed list).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sandbox_harness_1817s", HERE / "sandbox-harness-1.17.118.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
sh, must, BASE = H.sh, H.must, H.BASE
(BASE / "result").mkdir(exist_ok=True)


def run_id():
    return os.urandom(16).hex()


def run(body="print('hi')", mode="", before=None, rid=None):
    rid = rid or run_id()
    H.make_runner("ai.chat", body=body, limits={"run_seconds": 20})
    sh.CHILD_ENV.pop("FAKE_RESULT", None)
    if mode:
        sh.CHILD_ENV["FAKE_RESULT"] = mode
    if before:
        before(rid)
    _code, frames = H.start(H.header(run_id=rid))
    sh.CHILD_ENV.pop("FAKE_RESULT", None)
    return rid, frames


def unit(rid):
    return f"tectac-sbx-{rid}"


def audit_sweeps():
    rows = [json.loads(line) for line in sh.AUDIT_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if r.get("event") == "sweep"]


# ---- a finished run that failed is reset once; one that exited 0 (garbage-collected) is not
rid, frames = run("import sys\nsys.exit(3)")
must(H.resets().count(unit(rid)) == 1, H.resets())
must(not (BASE / "result" / f"{unit(rid)}.json").exists(), "the fake record is gone after the reset")
before = len(H.resets())
rid, frames = run("print('ok')")
must(unit(rid) not in H.resets() and len(H.resets()) == before, "a unit systemd no longer knows is not reset (saves a call)")
rid, frames = run("print('ok')", "oom-kill")
must(H.resets().count(unit(rid)) == 1, "an oom-killed run is reset")

# ---- a cancelled run resets
rid, frames = run("import time\ntime.sleep(30)", before=lambda r: (sh.RUNS_ROOT.mkdir(parents=True, exist_ok=True), (sh.RUNS_ROOT / f"{r}.cancel").write_text("1")))
must(H.end_of(frames)["reason"] == "cancelled" and H.resets().count(unit(rid)) == 1, H.resets())

# ---- a helper path that raises still resets (the fault path)
real_supervise = sh._supervise


def boom(*a, **k):
    raise RuntimeError("fault")


sh._supervise = boom
rid = run_id()
H.make_runner("ai.chat")
try:
    H.start(H.header(run_id=rid))
except RuntimeError as exc:  # the helper's --start may let the fault out; either way the unit must be reset
    must(str(exc) == "fault", exc)
finally:
    sh._supervise = real_supervise
must(H.resets().count(unit(rid)) == 1, "a crashed run leaves no failed unit")

# ---- the sweep
GOOD_OLD, GOOD_YOUNG, GOOD_ACTIVE, GOOD_OLD_HANDOFF = run_id(), run_id(), run_id(), run_id()
SELFTEST = "tectac-selftest-abc123.service"
failed = [f"{unit(GOOD_OLD)}.service loaded failed failed Tec-Tac sandbox run",
          f"{unit(GOOD_YOUNG)}.service loaded failed failed Tec-Tac sandbox run",
          f"{unit(GOOD_ACTIVE)}.service loaded failed failed Tec-Tac sandbox run",
          f"{unit(GOOD_OLD_HANDOFF)}.service loaded failed failed Tec-Tac sandbox run",
          f"{SELFTEST} loaded failed failed selftest",
          "tectac-sbx-UPPER.service loaded failed failed x",
          "tectac-../etc.service loaded failed failed x",
          "tectac-a b.service loaded failed failed x",
          "tectac-x/y.service loaded failed failed x",
          "tectac-x.timer loaded failed failed x",
          "other-unit.service loaded failed failed x",
          "tectac-.service-extra loaded failed failed x",
          "tectac-x;rm.service loaded failed failed x",
          "* tectac-star.service loaded failed failed x",
          ""]
(BASE / "failed.txt").write_text("\n".join(failed) + "\n", encoding="utf-8")
sh.RUNS_ROOT.mkdir(parents=True, exist_ok=True)
sh.HANDOFF_ROOT.mkdir(parents=True, exist_ok=True)
old = time.time() - 3600
(sh.RUNS_ROOT / f"{GOOD_OLD}.json").write_text("{}", encoding="utf-8")
os.utime(sh.RUNS_ROOT / f"{GOOD_OLD}.json", (old, old))
(sh.RUNS_ROOT / f"{GOOD_YOUNG}.json").write_text("{}", encoding="utf-8")  # young: its helper may still read the Result
(sh.HANDOFF_ROOT / f"{GOOD_OLD_HANDOFF}.json").write_text("{}", encoding="utf-8")  # young handoff
(BASE / "pids").mkdir(exist_ok=True)
(BASE / "pids" / unit(GOOD_ACTIVE)).write_text("1")  # the fake's is-active answers 0 while a pid file exists
(BASE / "resets.log").write_text("", encoding="utf-8")
import contextlib
import io

out = io.StringIO()
with contextlib.redirect_stdout(out):
    sh.sweep()
printed = json.loads(out.getvalue().strip().splitlines()[-1])
must(sorted(printed["units_reset"]) == sorted([f"{unit(GOOD_OLD)}.service", SELFTEST]), printed)
must(sorted(H.resets()) == sorted(f"{n}".removesuffix(".service") for n in printed["units_reset"]), H.resets())
for bad in ("UPPER", "..", " ", "/", ".timer", "other-unit", ";", "star", "service-extra"):
    must(not any(bad in name for name in H.resets()), (bad, H.resets()))
must(audit_sweeps()[-1]["detail"]["units_reset"] == printed["units_reset"], "the audit row names them too")
(BASE / "pids" / unit(GOOD_ACTIVE)).unlink()

# ---- a failing list-units still lets the sweep finish
stray = sh.RUNS_ROOT / f"{run_id()}.json"
stray.write_text("{}", encoding="utf-8")
os.utime(stray, (old, old))
sh.CHILD_ENV["FAKE_LIST_FAIL"] = "1"
out = io.StringIO()
with contextlib.redirect_stdout(out):
    sh.sweep()
printed = json.loads(out.getvalue().strip().splitlines()[-1])
sh.CHILD_ENV.pop("FAKE_LIST_FAIL")
must(printed["units_reset"] == [] and not stray.exists() and f"runs/{stray.name}" in printed["removed"], printed)
# a failing reset-failed does not abort it either
sh.CHILD_ENV["FAKE_RESET_FAIL"] = "1"
out = io.StringIO()
with contextlib.redirect_stdout(out):
    sh.sweep()
sh.CHILD_ENV.pop("FAKE_RESET_FAIL")
must(json.loads(out.getvalue().strip().splitlines()[-1])["checked"] >= 0, "the sweep finished")
# a raising list is tolerated too
real = sh.reset_failed_units
sh.reset_failed_units = lambda *a, **k: (_ for _ in ()).throw(OSError("x"))
out = io.StringIO()
with contextlib.redirect_stdout(out):
    sh.sweep()
sh.reset_failed_units = real
must(json.loads(out.getvalue().strip().splitlines()[-1])["units_reset"] == [], "an error in the reset pass is tolerated")

for name in ("tests/sandbox-sweep-failed-1.18.17.py",):
    must(b"\r" not in (H.ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox sweep failed units 1.18.17")
