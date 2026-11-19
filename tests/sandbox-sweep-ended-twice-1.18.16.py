#!/usr/bin/env python3
"""1.18.16 regression: the sweep never writes a second run.ended for a run that already has one (held Low of the 1.18.15 review).

A record whose run already has a run.ended row gets no swept row and is still removed; a record with no row gets exactly one; a row of another
run id does not suppress; only the last 1 MiB of audit.jsonl is read; a corrupt line is ignored; an unreadable audit still writes the one row.

Not runnable here: the microsecond race between the check and launch()'s own unlink-then-append (stated in the release notes).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_1816s", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
BASE, must, sh = H.BASE, H.must, H.sh


def audit_rows():
    if not sh.AUDIT_FILE.is_file():
        return []
    out = []
    for line in sh.AUDIT_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def ended_for(run_id):
    return [r for r in audit_rows() if r.get("event") == "run.ended" and r.get("detail", {}).get("run_id") == run_id]


def record(run_id):
    path = sh.RUNS_ROOT / f"{run_id}.json"
    path.write_text(json.dumps({"run_id": run_id, "runner": "ai.chat", "unit": "tectac-sbx-" + run_id, "at": "x"}), encoding="utf-8")
    return path


def ended_row(run_id):
    return {"at": "t", "event": "run.ended", "detail": {"runner": "ai.chat", "run_id": run_id, "reason": "exited", "exit": 0}}


sh.RUNS_ROOT.mkdir(parents=True, exist_ok=True)
sh.AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
A, B, C, D, E = ("a1" * 16, "b2" * 16, "c3" * 16, "d4" * 16, "e5" * 16)

# a run that wrote its own run.ended: no swept row, record still removed
sh.AUDIT_FILE.write_text(json.dumps(ended_row(A)) + "\n", encoding="utf-8")
path = record(A)
sh.sweep(min_age=0)
must(len(ended_for(A)) == 1 and ended_for(A)[0]["detail"]["reason"] == "exited", ended_for(A))
must(not path.exists(), "the record is removed as before")

# no row yet: exactly one swept row
path = record(B)
sh.sweep(min_age=0)
rows = ended_for(B)
must(len(rows) == 1 and rows[0]["detail"]["reason"] == "swept" and not path.exists(), rows)
sh.sweep(min_age=0)
must(len(ended_for(B)) == 1, "a second sweep adds nothing: no record is left")

# a row for another run id does not suppress this one
sh.AUDIT_FILE.write_text(json.dumps(ended_row(A)) + "\n", encoding="utf-8")
path = record(C)
sh.sweep(min_age=0)
must(len(ended_for(C)) == 1 and ended_for(C)[0]["detail"]["reason"] == "swept", ended_for(C))

# run_already_ended: exact event and run id only; a started row is not an ended row; a corrupt line is ignored
sh.AUDIT_FILE.write_text("not json run.ended\n" + json.dumps({"event": "run.started", "detail": {"run_id": D}}) + "\n"
                         + json.dumps({"event": "run.started", "detail": {"note": "run.ended", "run_id": D}}) + "\n" + '{"event": "run.ended", "detail": 5}\n',
                         encoding="utf-8")
must(sh.run_already_ended(D) is False, "no run.ended for D")
with open(sh.AUDIT_FILE, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(ended_row(D)) + "\n")
must(sh.run_already_ended(D) is True and sh.run_already_ended(E) is False, "found, and only for its own id")

# only the tail is read: a row older than 1 MiB is not seen; a row inside the tail is
filler = (json.dumps({"event": "x", "detail": {"pad": "y" * 900}}) + "\n").encode()
with open(sh.AUDIT_FILE, "wb") as handle:
    handle.write((json.dumps(ended_row(E)) + "\n").encode())
    handle.writelines(filler for _ in range((sh.AUDIT_TAIL_BYTES // len(filler)) + 20))
must(sh.run_already_ended(E) is False, "a row beyond the last 1 MiB is not read")
with open(sh.AUDIT_FILE, "ab") as handle:
    handle.write((json.dumps(ended_row(E)) + "\n").encode())
must(sh.run_already_ended(E) is True, "a row inside the tail is")

# unreadable audit: nothing is claimed, the one row is still written
sh.AUDIT_FILE.unlink()
must(sh.run_already_ended(A) is False, "a missing audit file claims nothing")
path = record(A)
sh.sweep(min_age=0)
must(len(ended_for(A)) == 1 and ended_for(A)[0]["detail"]["reason"] == "swept", ended_for(A))

# the record vanishing between the check and the write: no row
real = sh.run_already_ended
F = "f6" * 16
path = record(F)
sh.run_already_ended = lambda run_id: path.unlink() or False  # the run's own cleanup removed the record during the check
try:
    must(sh.note_swept_run(path) is True, "still reports the entry as handled")
finally:
    sh.run_already_ended = real
must(ended_for(F) == [], "the record was gone: the run's own row stands, no swept row")


# ---- the 1.18.16 canary script's step 5o reports a second run.ended for one run id
import subprocess
import tempfile

SCRIPT = (H.ROOT / "tests" / "sandbox-canary-1.18.16.sh").read_text(encoding="utf-8")
NLC = chr(10)
head = "AUDIT_REPORT=$(python3 - " + chr(34) + "$STATE/audit.jsonl" + chr(34)
body = SCRIPT[SCRIPT.index(head):]
body = body[body.index("<<'PY'" + NLC) + len("<<'PY'" + NLC):]
report = body[:body.index(NLC + "PY" + NLC)]
person = sh.person_key("canary")


def report_for(rows):
    folder = Path(tempfile.mkdtemp(prefix="tectac-5o-"))
    (folder / "audit.jsonl").write_text(NLC.join(json.dumps(r) for r in rows) + NLC, encoding="utf-8")
    (folder / "report.py").write_text(report, encoding="utf-8")
    done = subprocess.run([sys.executable, str(folder / "report.py"), str(folder / "audit.jsonl"), "0"], capture_output=True, text=True, check=False)
    return done.stdout.strip().splitlines()


def rows_for(twice=()):
    out = []
    for n in range(12):
        rid = f"{n:032x}"
        out.append({"event": "run.started", "detail": {"runner": "core.canary", "run_id": rid, "person": person, "canary": True}})
        ended = {"event": "run.ended", "detail": {"runner": "core.canary", "run_id": rid, "person": person, "canary": True, "reason": "exited", "exit": 0}}
        out.append(ended)
        if rid in twice:
            out.append({"event": "run.ended", "detail": dict(ended["detail"], reason="swept")})
    return out


must(report_for(rows_for())[0] == "started=12 ended=12 swept=0 problems=0", report_for(rows_for()))
twice = report_for(rows_for({f"{3:032x}"}))
must(twice[0].endswith("problems=1") and "second run.ended" in twice[1], twice)

for name in ("scripts/sandbox-helper.py", "tests/sandbox-sweep-ended-twice-1.18.16.py", "tests/sandbox-canary-1.18.16.sh"):
    must(b"\r" not in (H.ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox sweep ended twice 1.18.16")
