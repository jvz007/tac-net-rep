#!/usr/bin/env python3
"""1.18.8 regression: root ``run.started`` and ``run.ended`` audit rows written by the helper itself (core.sandbox Patch A, part 4).

With the 1.17.118 fake systemd:

* a normal run leaves a ``run.started`` and then a ``run.ended`` row in the helper's audit file with the listed fields only;
* a refused start (not ready, unknown runner, bad parameter, wrong skeleton) leaves none;
* the started row is on disk before the first spawn; an audit file that cannot be written refuses the start (``start_failed``) and nothing is spawned;
* a cancelled run, a timed-out run and a run the caller walked away from still write ``run.ended``;
* no row holds the input text, a parameter, the credential token, the person text or a path; ``person`` is ``person_key(person)``;
* the canary's runs carry ``canary: true``; Django's own ``sandbox.run.*`` rows are not touched by this change.

Not runnable here: real systemd (dev02: step 5 of tests/sandbox-canary-1.18.8.sh checks the rows of the canary runs).
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import threading
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_188a", HERE / "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
H.write_ready_status()
STARTED = {"runner", "run_id", "person", "canary"}
ENDED = STARTED | {"reason", "exit", "ms", "bytes_out", "bytes_err", "peak_mb", "oom_kills", "evidence", "egress_allowed", "egress_refused", "egress_bytes"}  # 1.18.24: the egress counts


def audit_rows(event=None):
    path = sh.AUDIT_FILE
    if not path.is_file():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if event is None or r["event"] == event]


def run_rows(run_id):
    return [r for r in audit_rows() if r["event"] in ("run.started", "run.ended") and r["detail"].get("run_id") == run_id]


# ---- a normal run
TOKEN, INPUT, PERSON = "tok-" + os.urandom(6).hex(), b"SECRET-INPUT-" + os.urandom(4).hex().encode(), "alice@example.com"
H.make_runner("ai.audit", body="print('hello out')\nsys.stderr.write('warn')", credential_files=["auth"], parameters={"mode": {"type": "string"}}, argv=["--m", {"param": "mode"}])
rid = os.urandom(16).hex()
code, frames = H.start(H.header("ai.audit", run_id=rid, person=PERSON, parameters={"mode": "param-secret"}, credentials={"auth": TOKEN}, input_bytes=len(INPUT)), INPUT)
end = H.end_of(frames)
rows = run_rows(rid)
must([r["event"] for r in rows] == ["run.started", "run.ended"], rows)
started, ended = rows[0]["detail"], rows[1]["detail"]
must(set(started) == STARTED and set(ended) == ENDED, (sorted(started), sorted(ended)))
must(started == {"runner": "ai.audit", "run_id": rid, "person": sh.person_key(PERSON), "canary": False}, started)
must(ended["person"] == sh.person_key(PERSON) and ended["reason"] == "exited" and ended["exit"] == 0 and ended["canary"] is False, ended)
must(ended["bytes_out"] == end["bytes_out"] and ended["bytes_out"] >= len("hello out"), (ended, end))
must(ended["bytes_err"] == 4 and ended["ms"] == end["ms"] and ended["peak_mb"] == end["peak_mb"] and ended["oom_kills"] == end["oom_kills"] and ended["evidence"] == end["evidence"], (ended, end))
text = sh.AUDIT_FILE.read_text(encoding="utf-8")
for secret in (TOKEN, INPUT.decode(), PERSON, "param-secret", "hello out", "warn", "credential_b64", str(BASE), "/usr/local", "SECRET_KEY"):
    must(secret not in text, f"the audit log holds {secret!r}")
must(PERSON.split("@")[0] not in text and TOKEN not in json.dumps(rows), "no person text, no token")
must(rows[0]["at"].endswith("Z") and rows[1]["at"].endswith("Z"), "timestamps")
must(all(isinstance(v, (str, int, float, bool, type(None))) for r in rows for v in r["detail"].values()), "plain values only")
must(os.stat(sh.AUDIT_FILE).st_mode & 0o777 in (0o640, 0o666, 0o644) and sh.AUDIT_FILE.is_file(), "the file is the helper's own audit file")
must(not H.leftovers(), H.leftovers())

# ---- refused starts leave no row
before = len(audit_rows())
for label, hdr in (("unknown runner", H.header("ai.nothere")), ("bad parameter", H.header("ai.audit", parameters={"mode": 5}, run_id=os.urandom(16).hex())),
                   ("bad credential name", H.header("ai.audit", credentials={"other": "x"}))):
    code, frames = H.start(hdr, hold=False)
    must(frames and frames[0]["t"] == "refused", (label, frames))
H.write_ready_status(ready=False, reason="x")
code, frames = H.start(H.header("ai.audit"), hold=False)
must(frames[0]["t"] == "refused", frames)
H.write_ready_status()
sh.require_skeleton = lambda: (_ for _ in ()).throw(sh.Refusal("sandbox_unavailable", "wrong root"))
code, frames = H.start(H.header("ai.audit"), hold=False)
must(frames[0]["t"] == "refused" and frames[0]["message"] == "wrong root", frames)
sh.require_skeleton = lambda: None
must(not [r for r in audit_rows()[before:] if r["event"].startswith("run.")], "a refused start leaves no run row")

# ---- the started row is on disk before the first spawn
order = []
real_spawn = sh._spawn


def spy(argv):
    run_id = next(a for a in argv if a.startswith("--unit="))[len("--unit=tectac-sbx-"):]
    order.append(("spawn", [r["event"] for r in run_rows(run_id)]))
    return real_spawn(argv)


sh._spawn = spy
rid2 = os.urandom(16).hex()
H.start(H.header("ai.audit", run_id=rid2, parameters={"mode": "x"}))
sh._spawn = real_spawn
must(order == [("spawn", ["run.started"])], order)

# ---- an audit file that cannot be written refuses the start; nothing is spawned
real_audit_file = sh.AUDIT_FILE
blocker = BASE / "not-a-folder"
blocker.write_text("x", encoding="utf-8")
sh.AUDIT_FILE = blocker / "audit.jsonl"
spawned = []
sh._spawn = lambda argv: spawned.append(argv) or real_spawn(argv)
rid3 = os.urandom(16).hex()
logs_before = {p.name for p in (BASE / "log").iterdir()}
code, frames = H.start(H.header("ai.audit", run_id=rid3, parameters={"mode": "x"}), hold=False)
sh._spawn = real_spawn
sh.AUDIT_FILE = real_audit_file
must(code == 3 and frames == [{"t": "refused", "code": "start_failed", "message": "the run could not be recorded in the audit log"}], (code, frames))
must(not spawned and {p.name for p in (BASE / "log").iterdir()} == logs_before, "systemd-run was never started")
must(not run_rows(rid3) and not H.leftovers(), "no row, no leftover (secrets, handoff and run record were cleaned)")

# ---- cancel, timeout and a vanished caller still write run.ended
H.make_runner("ai.slow", body="time.sleep(30)", limits={"run_seconds": 3})
rid4 = os.urandom(16).hex()
code, frames = H.start(H.header("ai.slow", run_id=rid4))
must(H.end_of(frames)["reason"] == "timeout", frames)
rows = run_rows(rid4)
must([r["event"] for r in rows] == ["run.started", "run.ended"] and rows[1]["detail"]["reason"] == "timeout", rows)
row = sh.load_runner_row("ai.slow")
row["limits"]["run_seconds"] = 30
rid5 = os.urandom(16).hex()
eof = threading.Event()
threading.Timer(1.5, eof.set).start()
frames5 = []
try:
    sh.launch(row, run_id=rid5, person="user:9", parameters={}, credentials={}, input_data=b"", emit=frames5.append, stdin_eof=eof, status=H.write_ready_status())
    raise AssertionError("a vanished caller did not raise DeadMan")
except sh.DeadMan:
    pass
rows = run_rows(rid5)
must([r["event"] for r in rows] == ["run.started", "run.ended"], rows)
ended = rows[1]["detail"]
must(ended["reason"] == "cancelled" and ended["exit"] is None and isinstance(ended["ms"], int) and ended["person"] == sh.person_key("user:9"), ended)
must(set(ended) == ENDED, sorted(ended))
must(not H.leftovers(), H.leftovers())
# a run cancelled through --stop
rid6 = os.urandom(16).hex()
box = {}


def go():
    box["result"] = H.start(H.header("ai.slow", run_id=rid6))


row["limits"]["run_seconds"] = 30
thread = threading.Thread(target=go, daemon=True)
H.make_runner("ai.slow", body="time.sleep(30)", limits={"run_seconds": 30})
thread.start()
for _ in range(100):
    if (sh.RUNS_ROOT / f"{rid6}.json").exists():
        break
    threading.Event().wait(0.1)
import io

out = io.StringIO()
must(sh.stop_command(io.BytesIO(rid6.encode() + b"\n"), out) == 0, out.getvalue())
thread.join(30)
rows = run_rows(rid6)
must([r["event"] for r in rows] == ["run.started", "run.ended"] and rows[1]["detail"]["reason"] == "cancelled", rows)

# ---- the canary's own runs carry canary true
sh.CANARY_DIR.mkdir(parents=True, exist_ok=True)
shutil.copy(HERE.parent / "scripts" / "sandbox-canary-runner.py", sh.CANARY_DIR / "sandbox-canary-runner.py")
rid7 = os.urandom(16).hex()
result = sh.collect_run("noop", {}, run_id=rid7, status=H.write_ready_status())
must(result["refused"] is None and result["end"]["reason"] == "exited", result)
rows = run_rows(rid7)
must([r["event"] for r in rows] == ["run.started", "run.ended"] and rows[0]["detail"]["canary"] is True and rows[1]["detail"]["canary"] is True and rows[0]["detail"]["runner"] == "core.canary", rows)
must(rows[0]["detail"]["person"] == sh.person_key("canary"), "the canary's person is a key too")

# ---- the Django side keeps its own rows, unchanged
django_side = (HERE.parent / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
must(all(f'"sandbox.run.{word}"' in django_side for word in ("started", "ended", "refused", "cancelled")), "the Django rows keep their names (sandbox.run.*)")

print("[TEST] PASS sandbox run audit 1.18.8")
