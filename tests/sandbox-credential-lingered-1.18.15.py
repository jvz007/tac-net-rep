#!/usr/bin/env python3
"""1.18.15 regression: a credential remover that gives up is recorded (dev02 canary of 1.18.14, held Low).

launch() used to throw away what ``remove_credentials_when_active`` returned. A False answer with the stop event NOT set means the unit never
showed its copies within the 15 s window. The wrapper then writes the root audit row ``run.credentials_lingered`` with run_id, runner and
seconds only. The finally block still removes the folder on every path, so trust is not widened. A run that ended early (stop set) or a
successful removal writes nothing.

Not runnable here: systemd's own credential copies (dev02: the canary's step 5 reports any lingered row).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_1815c", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
BASE, must, sh, header, make_runner, leftovers = H.BASE, H.must, H.sh, H.header, H.make_runner, H.leftovers

UNIT, RID, RUNNER = "tectac-sbx-" + "12" * 16, "12" * 16, "ai.cred"
SLOT = "cred0"
rows = []


def audit(event, detail):
    rows.append((event, detail))


def make_source():
    folder = sh.SECRETS_ROOT / RID
    folder.mkdir(parents=True, exist_ok=True)
    (folder / SLOT).write_text("secret-abc", encoding="utf-8")
    return folder


def clock_factory():
    ticks = {"n": 0}

    def clock():
        ticks["n"] += 1
        return ticks["n"] * 0.5
    return clock


def call(stop=None, root=BASE / "nowhere"):
    folder = make_source()
    return sh.remove_credentials_noted(UNIT, folder, [SLOT], run_id=RID, runner=RUNNER, stop=stop, audit=audit, credentials_root=root,
                                       clock=clock_factory(), sleep=lambda s: None), folder


# the copies never appear: one row, three keys, the folder is left for launch()'s finally block
got, folder = call()
must(got is False and folder.exists(), (got, folder))
must(rows == [("run.credentials_lingered", {"run_id": RID, "runner": RUNNER, "seconds": 15})], rows)
must(set(rows[0][1]) == {"run_id", "runner", "seconds"}, "ids and a number only")
text = json.dumps(rows)
must("secret-abc" not in text and SLOT not in text and str(sh.SECRETS_ROOT) not in text and "nowhere" not in text, "no path, credential or slot name")
sh.remove_secrets(RID)

# the run ended early: stop is set before the window is over, so nothing is written
rows.clear()
stop = threading.Event()
stop.set()
got, folder = call(stop=stop)
must(got is False and rows == [], (got, rows))
sh.remove_secrets(RID)

# a stop that is set after the timeout has started but not by the end of it still counts as a genuine timeout only when not set at the end
rows.clear()
stop = threading.Event()
got, folder = call(stop=stop)
must(len(rows) == 1, rows)
sh.remove_secrets(RID)

# a successful removal writes nothing
rows.clear()
good = BASE / "copies"
(good / f"{UNIT}.service").mkdir(parents=True)
folder = make_source()
(good / f"{UNIT}.service" / SLOT).write_text("secret-abc", encoding="utf-8")
got = sh.remove_credentials_noted(UNIT, folder, [SLOT], run_id=RID, runner=RUNNER, audit=audit, credentials_root=good)
must(got is True and not folder.exists() and rows == [], (got, rows))

# the default sink is the root audit log, written without raising
folder = make_source()
sh.remove_credentials_noted(UNIT, folder, [SLOT], run_id=RID, runner=RUNNER, credentials_root=BASE / "nowhere", clock=clock_factory(), sleep=lambda s: None)
logged = [json.loads(line) for line in sh.AUDIT_FILE.read_text(encoding="utf-8").splitlines() if '"run.credentials_lingered"' in line]
must(len(logged) == 1 and logged[0]["detail"] == {"run_id": RID, "runner": RUNNER, "seconds": 15}, logged)
sh.remove_secrets(RID)

# launch() uses the wrapper, with its own stop event, and still removes the folder on every path
source = "\n".join((H.ROOT / "scripts" / name).read_text(encoding="utf-8") for name in ("sandbox-helper.py", "sandbox-selftest.py"))
launch_source = source[source.index("def launch("):source.index("def run_ended_detail(")]
must("target=remove_credentials_noted" in launch_source and "remove_credentials_when_active" not in launch_source, "launch starts the wrapper")
real_root = sh.CREDENTIALS_RUNTIME
sh.CREDENTIALS_RUNTIME = BASE / "never-there"
try:
    make_runner("ai.cred", body="import time\ntime.sleep(1)\nprint('done')", credential_files=["auth"])
    code, frames = H.start(header("ai.cred", credentials={"auth": "tok-xyz"}))
    must(H.end_of(frames)["reason"] == "exited" and not leftovers(), (frames, leftovers()))
finally:
    sh.CREDENTIALS_RUNTIME = real_root
must(sh.CREDENTIAL_REMOVER_SECONDS == 15.0, "the window is 15 s")
must(b"\r" not in (H.ROOT / "scripts" / "sandbox-helper.py").read_bytes(), "helper is LF")
print("[TEST] PASS sandbox credential lingered 1.18.15")
