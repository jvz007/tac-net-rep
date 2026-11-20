#!/usr/bin/env python3
"""1.18.26 regression (AD-65 Patch C, item 1): the launcher kills the run's leftover processes before it reads the returned credential.

Windows-safe: os.kill, /proc, Popen and the clock are stubs; nothing is killed and nothing listens. Covered:

* kill_leftovers: a clean table ends at once with True; a survivor that dies after the second kill ends True; a survivor at the deadline
  ends False; an unreadable table is never "clean"; kill(-1, SIGKILL) is the only signal ever sent;
* other_processes: counts only the unit's own uid, never itself, never a zombie, and a missing stat file counts as gone;
* main(): the kill happens before read_credential (order of calls), a survivor at the deadline sends NO credential frame, a clean run still
  sends the frame, and a run without --return-credential reads nothing.
"""
from __future__ import annotations

import importlib.util
import os
import signal
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_launcher_pc", ROOT / "scripts" / "sandbox-launcher.py")
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
must(b"\r" not in (ROOT / "scripts" / "sandbox-launcher.py").read_bytes(), "the launcher keeps LF")

SIGKILL = getattr(signal, "SIGKILL", 9)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def run_kill(tables):
    """tables: successive answers of others(); the last one repeats."""
    clock, calls, sent = Clock(), [], []
    answers = list(tables)

    def others():
        calls.append("others")
        return answers.pop(0) if len(answers) > 1 else answers[0]

    result = L.kill_leftovers(kill=lambda pid, sig: sent.append((pid, sig)), reap=lambda: calls.append("reap"), others=others,
                              clock=clock, sleep=clock.sleep, seconds=2.0)
    return result, sent, calls, clock.t


ok, sent, calls, elapsed = run_kill([[]])
must(ok is True and sent == [(-1, SIGKILL)] and calls == ["reap", "others"] and elapsed == 0, ("clean table", ok, sent, calls))
ok, sent, calls, elapsed = run_kill([[41], [41], []])
must(ok is True and len(sent) == 3 and all(item == (-1, SIGKILL) for item in sent), ("survivor gone on the third look", ok, sent))
ok, sent, calls, elapsed = run_kill([[41]])
must(ok is False and 1.9 < elapsed < 2.2 and len(sent) > 5, ("a survivor at the deadline", ok, elapsed, len(sent)))
ok, sent, calls, elapsed = run_kill([None])
must(ok is False, "an unreadable table is never clean")

# other_processes with a fake /proc
base = Path(tempfile.mkdtemp(prefix="tectac-launcher-pc-"))
for name, uid_state in {"10": ("me", "S"), "11": ("me", "Z"), "12": ("other", "S"), "13": ("me", "S"), "14": ("me", None)}.items():
    (base / name).mkdir()
    if uid_state[1]:
        (base / name / "stat").write_text(f"{name} (a b) {uid_state[1]} 1 1\n", encoding="ascii")
(base / "self").mkdir()
uids = {"10": 7, "11": 7, "12": 8, "13": 7, "14": 7}


class St:
    def __init__(self, uid):
        self.st_uid = uid


def fake_stat(path):
    name = os.path.basename(path)
    if name not in uids:
        raise OSError("gone")
    return St(uids[name])


found = L.other_processes(str(base), stat=fake_stat, uid=7, own_pid=13)
must(found == [10], ("only a live process of the own uid that is not this one", found))
must(L.other_processes(str(base / "missing"), uid=7, own_pid=1) is None, "unreadable /proc")

# main(): order of calls and the credential frame
order, frames = [], []


def run_main(extra, clean):
    order.clear()
    frames.clear()
    work = tempfile.mkdtemp(prefix="tectac-launcher-pc-work-")
    saved = {name: getattr(L, name) for name in ("kill_leftovers", "read_credential", "_write_all", "_not_dumpable", "_watch_stdout")}
    saved_popen = L.subprocess.Popen
    saved_env = dict(os.environ)

    class Child:
        pid = 1

        def poll(self):
            return 0

        def wait(self):
            order.append("wait")
            return 0

    L.kill_leftovers = lambda: (order.append("kill"), clean)[1]
    L.read_credential = lambda folder: (order.append("read"), b"cred")[1]
    L._write_all = lambda fd, data: frames.append(bytes(data))
    L._not_dumpable = lambda: None
    L._watch_stdout = lambda child, interval=0.5: None
    L.subprocess.Popen = lambda *a, **k: Child()
    os.environ.update({"SANDBOX_WORK": work, "SANDBOX_OUT": os.path.join(work, "out"), "HOME": os.path.join(work, "home"),
                       "TMPDIR": os.path.join(work, "tmp")})
    try:
        return L.main([*extra, "--", "runner"])
    finally:
        for name, value in saved.items():
            setattr(L, name, value)
        L.subprocess.Popen = saved_popen
        os.environ.clear()
        os.environ.update(saved_env)


code = run_main(["--return-credential"], True)
must(code == 0 and order == ["wait", "kill", "read"], ("kill before read", order))
must(any(b" CRED " in frame for frame in frames), "a clean run still sends the credential frame")
code = run_main(["--return-credential"], False)
must(order == ["wait", "kill"] and not any(b" CRED " in frame for frame in frames), ("a survivor: no read, no frame", order))
code = run_main([], True)
must(order == ["wait"], ("without --return-credential nothing is killed or read", order))
print("sandbox-launcher-patchc-1.18.26: ok")
