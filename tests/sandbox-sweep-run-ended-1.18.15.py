#!/usr/bin/env python3
"""1.18.15 regression: the sweep writes run.ended for a run it removes (dev02 canary of 1.18.14, item 4).

Run a56fed3d was the canary's own 'SIGKILL the helper' run: a killed helper never reaches its finally block, so no run.ended exists, and the
canary's own sweep removes the run file. The sweep now writes ``run.ended`` with reason ``swept`` for each ``runs/<32 hex>.json`` it removes.
The launch record gains ``person`` (the person key hash already used in the audit) and ``canary`` so that row is complete. The row holds only
runner, run_id, person, canary and reason: no credential, input, output or path. A live unit's record is untouched; secrets and handoff
entries never produce a row; a record from before 1.18.15 (no person, no canary) still sweeps.

Not runnable here: the real helper kill (dev02: step 5o of tests/sandbox-canary-1.18.15.sh).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_1815s", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
BASE, must, sh, header, make_runner = H.BASE, H.must, H.sh, H.header, H.make_runner


def audit_rows():
    if not sh.AUDIT_FILE.is_file():
        return []
    return [json.loads(line) for line in sh.AUDIT_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]


def ended_rows():
    return [r for r in audit_rows() if r["event"] == "run.ended"]


sh.RUNS_ROOT.mkdir(parents=True, exist_ok=True)
sh.SECRETS_ROOT.mkdir(parents=True, exist_ok=True)
sh.HANDOFF_ROOT.mkdir(parents=True, exist_ok=True)
DEAD, LIVE, OLD, RAW = "aa" * 16, "bb" * 16, "cc" * 16, "dd" * 16
PERSON = sh.person_key("canary-kill")
record = {"run_id": DEAD, "runner": "core.canary", "unit": "tectac-sbx-" + DEAD, "at": "2026-11-19T10:00:00Z", "person": PERSON, "canary": True}
(sh.RUNS_ROOT / f"{DEAD}.json").write_text(json.dumps(record), encoding="utf-8")
(sh.RUNS_ROOT / f"{OLD}.json").write_text(json.dumps({"run_id": OLD, "runner": "ai.chat", "unit": "tectac-sbx-" + OLD, "at": "x"}), encoding="utf-8")
(sh.RUNS_ROOT / f"{RAW}.json").write_text("not json at all", encoding="utf-8")
(sh.RUNS_ROOT / f"{DEAD}.cancel").write_text("1", encoding="utf-8")  # a cancel flag is not a run record
(sh.SECRETS_ROOT / DEAD).mkdir()
(sh.SECRETS_ROOT / DEAD / "cred0").write_text("secret-value-123", encoding="utf-8")
(sh.HANDOFF_ROOT / f"{DEAD}.json").write_text("{}", encoding="utf-8")
# a live unit: the fake systemctl says active while a pid file exists
(BASE / "pids").mkdir(exist_ok=True)
(BASE / "pids" / ("tectac-sbx-" + LIVE)).write_text("1", encoding="utf-8")
(sh.RUNS_ROOT / f"{LIVE}.json").write_text(json.dumps(dict(record, run_id=LIVE, unit="tectac-sbx-" + LIVE)), encoding="utf-8")

sh.sweep(min_age=0)
rows = ended_rows()
by_id = {r["detail"]["run_id"]: r["detail"] for r in rows}
must(set(by_id) == {DEAD, OLD, RAW}, sorted(by_id))
must(len(rows) == 3, "exactly one row per removed run record: the cancel flag, the secrets folder and the handoff file give none")
must(by_id[DEAD] == {"runner": "core.canary", "run_id": DEAD, "person": PERSON, "canary": True, "reason": "swept"}, by_id[DEAD])
must(by_id[OLD] == {"runner": "ai.chat", "run_id": OLD, "person": None, "canary": False, "reason": "swept"}, by_id[OLD])  # an old record: still sweeps
must(by_id[RAW] == {"runner": None, "run_id": RAW, "person": None, "canary": False, "reason": "swept"}, by_id[RAW])
text = sh.AUDIT_FILE.read_text(encoding="utf-8")
must("secret-value-123" not in text and str(sh.RUNS_ROOT) not in text and "not json at all" not in text, "nothing but ids in the audit")
for detail in by_id.values():
    must(set(detail) <= {"runner", "run_id", "person", "canary", "reason"}, detail)  # inside the run.ended allow-list
must((sh.RUNS_ROOT / f"{LIVE}.json").exists() and LIVE not in by_id, "a live unit's record is untouched and has no row")
must(not (sh.RUNS_ROOT / f"{DEAD}.json").exists() and not (sh.SECRETS_ROOT / DEAD).exists() and not (sh.HANDOFF_ROOT / f"{DEAD}.json").exists(), "files removed as before")
sweep_row = [r for r in audit_rows() if r["event"] == "sweep"][-1]
must(f"runs/{DEAD}.json" in sweep_row["detail"]["removed"], "the sweep row still lists what it removed")

# a record whose person is not a 32-hex key or whose runner is not an id keeps nothing of it
before = len(ended_rows())
NASTY = "ee" * 16
(sh.RUNS_ROOT / f"{NASTY}.json").write_text(json.dumps({"runner": "../../etc/passwd", "person": "x" * 40, "canary": "yes"}), encoding="utf-8")
sh.sweep(min_age=0)
new = ended_rows()[before:]
must(len(new) == 1 and new[0]["detail"] == {"runner": None, "run_id": NASTY, "person": None, "canary": False, "reason": "swept"}, new)
(BASE / "pids" / ("tectac-sbx-" + LIVE)).unlink()
sh.sweep(min_age=0)
must(any(r["detail"]["run_id"] == LIVE for r in ended_rows()), "once the unit is gone the record is swept like any other")

# ---- launch writes person and canary into the record
make_runner("ai.hold", body="time.sleep(2)\nprint('x')")
RID = "ab" * 16
out_holder = {}


def go():
    out_holder["r"] = H.start(header("ai.hold", run_id=RID, person="user:7"))


thread = threading.Thread(target=go, daemon=True)
thread.start()
path = sh.RUNS_ROOT / f"{RID}.json"
deadline = time.monotonic() + 8
launched = None
while time.monotonic() < deadline and thread.is_alive():
    if path.exists():
        try:
            launched = json.loads(path.read_text(encoding="utf-8"))
            break
        except ValueError:
            pass
    time.sleep(0.01)
thread.join(30)
must(launched is not None, "the run record was seen while the run was live")
must(launched["person"] == sh.person_key("user:7") and launched["canary"] is False and launched["runner"] == "ai.hold" and launched["run_id"] == RID, launched)
must(set(launched) == {"run_id", "runner", "unit", "at", "person", "canary"}, sorted(launched))
must(not path.exists(), "the finally block removed the record: a normal run has its own run.ended and no swept row")
must(sum(1 for r in ended_rows() if r["detail"]["run_id"] == RID) == 1, "one run.ended for a normal run")

# ---- the canary script's 5o report accepts a swept row as the ended row of a started run
SCRIPT = (H.ROOT / "tests" / "sandbox-canary-1.18.15.sh").read_text(encoding="utf-8")
must("swept" in SCRIPT, "the canary script knows the swept reason")
NL = chr(10)
start_marker = "AUDIT_REPORT=$(python3 - " + chr(34) + "$STATE/audit.jsonl" + chr(34)
body = SCRIPT[SCRIPT.index(start_marker):]
body = body[body.index("<<'PY'" + NL) + len("<<'PY'" + NL):]
report = body[:body.index(NL + "PY" + NL)]
import subprocess
import tempfile


def run_report(rows, skip=0):
    audit = Path(tempfile.mkdtemp(prefix="tectac-5o-")) / "audit.jsonl"
    audit.write_text(NL.join(json.dumps(r) for r in rows) + NL, encoding="utf-8")
    script = audit.with_name("report.py")
    script.write_text(report, encoding="utf-8")
    done = subprocess.run([sys.executable, str(script), str(audit), str(skip)], capture_output=True, text=True, check=False)
    return done.stdout.strip().splitlines()


def audit_rows_for(count, swept_ids=(), canary=True):
    out = []
    for n in range(count):
        rid = f"{n:032x}"
        person = sh.person_key("canary")
        out.append({"at": "t", "event": "run.started", "detail": {"runner": "core.canary", "run_id": rid, "person": person, "canary": canary}})
        if rid in swept_ids:
            out.append({"at": "t", "event": "run.ended", "detail": {"runner": "core.canary", "run_id": rid, "person": person, "canary": canary, "reason": "swept"}})
        elif n not in (3,):
            out.append({"at": "t", "event": "run.ended", "detail": {"runner": "core.canary", "run_id": rid, "person": person, "canary": canary, "reason": "exited", "exit": 0, "ms": 5}})
    return out


no_swept = run_report(audit_rows_for(12))
must(no_swept[0] == "started=12 ended=11 swept=0 problems=1" and "no run.ended" in no_swept[1], no_swept)  # without the sweep row, run 3 has no ended row
fixed = run_report(audit_rows_for(12, swept_ids={f"{3:032x}"}))
must(fixed == ["started=12 ended=12 swept=1 problems=0"], fixed)  # the swept row is the ended row of that started run
# a swept row for a run of an old record (no person) is still a problem: it names the gap
old = audit_rows_for(12, swept_ids={f"{3:032x}"})
for row in old:
    if row["event"] == "run.ended" and row["detail"]["reason"] == "swept":
        row["detail"]["person"] = None
must(run_report(old)[0].endswith("problems=1"), "a swept row without a person key is reported")
# rows before the skip line (earlier runs) are not counted
must(run_report(audit_rows_for(12, swept_ids={f"{3:032x}"}), skip=2)[0].startswith("started=11 "), "skip")
for name in ("scripts/sandbox-helper.py",):
    must(b"\r" not in (H.ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox sweep run.ended 1.18.15")
