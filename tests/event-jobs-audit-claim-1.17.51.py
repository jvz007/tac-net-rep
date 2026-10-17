#!/usr/bin/env python3
"""1.17.51 core.event_jobs: _audit counts only a confirmed write, and the limit wording is stated plainly.

Closes the held 1.17.49 MEDIUM (``_audit`` returned True when ``audit.record`` answered ``recorded: False``, so the hourly refusal report
kept its claim and the count was lost) and the held LOW (the 'at most one minute' wording of unsent counts).

Runs the real tec_tac/event_jobs.py with the stub set of tests/event-jobs-refusal-bound-1.17.49.py: the setup part of that file is
executed here (everything above its 'the tick' section), then the cases below. Django, Redis and Celery are not installed on this PC.

Covered: audit.record answering {'recorded': False, 'error': 'audit_write_failed'} makes _audit return False, the 'reported' claim key is
gone after the tick, no row is counted as reported, and the next tick with a good stub writes exactly one custom:event-job-refused row with
the full count; a dict with recorded True is success; a raise is a failure; a non-dict answer, a missing key and a truthy non-True value
are failures; the outcome-row callers ignore the return value; no text says 'at most one minute' of unsent counts, and the new limit is
stated in the contract row, the capability text, docs/event-jobs.md and the release notes.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "event-jobs-refusal-bound-1.17.49.py").read_text(encoding="utf-8")
SETUP = SOURCE[: SOURCE.index("# ------------------------------------------------------------------------------------------------ the tick")]
SETUP_NS: dict = {"__name__": "event_jobs_refusal_bound_setup", "__file__": str(HERE / "event-jobs-refusal-bound-1.17.49.py")}
exec(compile(SETUP, str(HERE / "event-jobs-refusal-bound-1.17.49.py"), "exec"), SETUP_NS)  # noqa: S102 (a test reusing its own stub set)
# the names the cases below use, bound explicitly so no name comes from the exec
ROOT = SETUP_NS["ROOT"]
APP = SETUP_NS["APP"]
AUDIT = SETUP_NS["AUDIT"]
CACHE = SETUP_NS["CACHE"]
HOUR = SETUP_NS["HOUR"]
WALL = SETUP_NS["WALL"]
beta = SETUP_NS["beta"]
deliver = SETUP_NS["deliver"]
ej = SETUP_NS["ej"]
key = SETUP_NS["key"]
must = SETUP_NS["must"]
register = SETUP_NS["register"]
reset = SETUP_NS["reset"]
rows = SETUP_NS["rows"]
tick_only = SETUP_NS["tick_only"]
window = SETUP_NS["window"]

audit_module = sys.modules["tec_tac.audit"]
good_record = audit_module.record
MODE = {"answer": "good"}


def switchable(**kw):
    mode = MODE["answer"]
    if mode == "false":
        return {"recorded": False, "error": "audit_write_failed", "error_type": "RuntimeError", "module_id": "core"}
    if mode == "raise":
        raise RuntimeError("audit down")
    if mode == "none":
        return None
    if mode == "truthy":
        return {"recorded": 1}
    if mode == "missing":
        return {}
    return good_record(**kw)


audit_module.record = switchable


def counted_hour_51(n=3):
    reset()
    handle = register()
    for _ in range(n):
        beta["fire"](handle, key())
    window()
    ej._flush_refusals()
    deliver()


# --- _audit itself -------------------------------------------------------------------------------------
def call():
    return ej._audit("custom:x", module_id="alerts", job_id="alerts.deliver", message="m")


MODE["answer"] = "good"
must(call() is True, "recorded True is success")
for mode in ("false", "raise", "none", "truthy", "missing"):
    MODE["answer"] = mode
    must(call() is False, f"{mode} is a failure")
MODE["answer"] = "good"
print("       _audit is True only for a dict whose recorded is exactly True")

# --- the claim is released when the write answers recorded False ------------------------------------------
counted_hour_51(3)
rk = ej._refusal_key("alerts", "alerts.deliver", int(WALL[0] // HOUR), "reported")
MODE["answer"] = "false"
out = tick_only(WALL[0] + HOUR + 5)
must(out["refused_reported"] == 0, out)
must(rk not in CACHE.data, "the 'reported' claim key is gone after the tick")
must(not rows(), "no row counted as reported")
MODE["answer"] = "good"
out = tick_only(WALL[0] + HOUR + 65)
must(out["refused_reported"] == 1 and len(rows()) == 1 and rows()[0]["metadata"]["count"] == 3, (out, AUDIT))
must(tick_only(WALL[0] + HOUR + 125)["refused_reported"] == 0 and len(rows()) == 1, "exactly one row with the full count")
print("       recorded False: claim released, nothing counted, the next tick writes one row with the full count")

# a raise still behaves the same, and a confirmed write keeps its claim
counted_hour_51(2)
MODE["answer"] = "raise"
must(tick_only(WALL[0] + HOUR + 5)["refused_reported"] == 0 and rk not in CACHE.data)
MODE["answer"] = "good"
must(tick_only(WALL[0] + HOUR + 65)["refused_reported"] == 1 and rows()[0]["metadata"]["count"] == 2)
must(rk in CACHE.data, "a confirmed write keeps the claim, so the hour is reported once")

# the outcome-row callers ignore the return value, so a failed write is only logged
MODE["answer"] = "false"
src = (APP / "event_jobs.py").read_text(encoding="utf-8")
body = src[src.index("def _audit_row("): src.index("\n\n\n", src.index("def _audit_row("))]
must("return" not in body, "_audit_row ignores the answer of _audit")
MODE["answer"] = "good"
audit_module.record = good_record
print("       outcome rows only log a failed write")

# --- the wording ------------------------------------------------------------------------------------------
CONTRACTS = (APP / "contracts.py").read_text(encoding="utf-8")
DOC = (ROOT / "docs" / "event-jobs.md").read_text(encoding="utf-8")
NOTES = (ROOT / "RELEASE_NOTES_1.17.51-1.md").read_text(encoding="utf-8")
meta = ej.event_jobs_contract_metadata()
for label, text in (("source", src), ("contracts.py", CONTRACTS), ("docs/event-jobs.md", DOC), ("release notes", NOTES), ("capability text", meta["caller"])):
    flat = " ".join(text.split())
    must("hold up to one minute" not in flat, f"{label}: the old 'hold up to one minute' wording is gone")
    must(not re.search(r"at most one minute of (unsent )?counts", flat), f"{label}: no 'at most one minute' claim about unsent counts")
for label, text in (("contracts.py", CONTRACTS), ("docs/event-jobs.md", DOC), ("release notes", NOTES), ("capability text", meta["caller"])):
    flat = " ".join(text.split())
    must("wait in the web process's memory" in flat, f"{label} states the memory limit")
    must("lost if it restarts first" in flat or "lost if that process restarts first" in flat, f"{label} states the restart limit")
    must("has already been reported is not reported" in flat or "already been reported is not reported" in flat, f"{label} states the late-count limit")
must(ej.CAPABILITY_VERSION == "1.1.0", "core.event_jobs stays 1.1.0")
print("       the limit is stated plainly in the capability text, the contract row, the doc and the notes")
print("[TEST] PASS event jobs audit claim 1.17.51")
