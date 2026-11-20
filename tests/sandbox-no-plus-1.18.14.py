#!/usr/bin/env python3
"""1.18.14 regression: core.sandbox has no unit property that runs a command (dev02, 19 November 2026).

On systemd 255 a ``+`` property command runs with full privileges but inside the unit's RootDirectory, so it saw neither the secrets folder
nor /usr/local/sbin/tec-tac-sandbox. The helper now removes the credential folder itself and builds the end frame's evidence from its own
cgroup poll.

Covered: no ``Exec*`` property is built, and check_unit_properties refuses one; launch() removes secrets/<run id> while the fake unit still
runs and the runner still reads its copy; a unit that never shows its copies leaves the folder until the finally block, which removes it;
a copy of a different size is not ready; the end frame's oom_kills, peak and result come from the poll; ``--finish`` and ``finish_run`` are
gone and not in the sudoers rule; the selftest probes ``credential`` and ``real_unit_shape`` pass only when the helper removed the source;
the two new canary rows; the touched files keep their own line endings.

Not runnable here: real systemd. The dev02 canary (tests/sandbox-canary-1.18.14.sh) decides.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_118", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
BASE, ROOT, sh, must = H.BASE, H.ROOT, H.sh, H.must
(end_of, header, leftovers, make_runner, start, unit_log) = (H.end_of, H.header, H.leftovers, H.make_runner, H.start, H.unit_log)
_FAKE = importlib.util.spec_from_file_location("sandbox_fake_runner", Path(__file__).with_name("sandbox-fake-runner-1.17.120.py"))
F = importlib.util.module_from_spec(_FAKE)
_FAKE.loader.exec_module(F)

ROW = make_runner("ai.plain")
RUN_ID = "ab" * 16
seen = {}

# ---- (1) no Exec* property, with and without credentials; the closed set refuses one
for names in ([], ["auth"], ["auth", "key"]):
    props = sh.build_properties(ROW, RUN_ID, credential_names=names, exists=lambda p: True)
    must(not [p for p in props if p.startswith("Exec")], props)
    must(len([p for p in props if p.startswith("LoadCredential=")]) == len(names), props)
good = sh.build_properties(ROW, RUN_ID, credential_names=["auth"], exists=lambda p: True)
for bad in ("ExecStartPost=+/bin/sh", f"ExecStopPost=+{sh.HELPER_COMMAND} --finish {RUN_ID}", "ExecStartPre=/bin/true", "ExecStart=/bin/true",
            f"ExecStartPost=+/bin/rm -rf {sh.SECRETS_ROOT / RUN_ID}", "ExecAnything"):
    try:
        sh.check_unit_properties([*good, bad], ROW, RUN_ID)
        raise AssertionError(bad)
    except sh.Refusal as exc:
        must(exc.code == "sandbox_unavailable", exc.code)

# ---- (2) launch() with a credential: the folder is gone while the unit still runs, and the runner reads its copy
TOKEN = "tok-" + os.urandom(8).hex()
body = ("import json\n"
        "path = os.path.join(os.environ['CREDENTIALS_DIRECTORY'], 'auth')\n"
        "time.sleep(2)\n"
        "print(open(path).read())\n")
make_runner("ai.cred", body=body, credential_files=["auth"])
out = io.BytesIO()
result = {}


def go():
    result["code"] = sh.start_command(H.HoldOpen(json.dumps(header("ai.cred", run_id="cd" * 16, credentials={"auth": TOKEN})).encode() + b"\n"), out_stream=out)


thread = threading.Thread(target=go, daemon=True)
thread.start()
folder = sh.SECRETS_ROOT / ("cd" * 16)
deadline = time.monotonic() + 1.5
while time.monotonic() < deadline and not folder.exists():
    time.sleep(0.01)
gone_at = None
pid_file = BASE / "pids" / ("tectac-sbx-" + "cd" * 16)
deadline = time.monotonic() + 8
while time.monotonic() < deadline and thread.is_alive():
    if not folder.exists() and pid_file.exists():  # the fake unit's process is alive and the source folder is already gone
        gone_at = "gone while the unit runs"
        break
    time.sleep(0.01)
must(gone_at, "the folder was not removed while the fake unit was still running")
thread.join(30)
frames = [json.loads(line) for line in out.getvalue().decode().splitlines() if line.strip()]
end = end_of(frames)
text = b"".join(__import__("base64").b64decode(f["b"]) for f in frames if f["t"] == "out").decode()
must(end["reason"] == "exited" and TOKEN in text, (end, text))  # the runner read its own copy after the source was gone
must(not leftovers(), leftovers())

# ---- (3) a unit that never shows its copies: the folder survives until the finally block, which removes it; nothing is left
unit = "tectac-sbx-" + "ef" * 16
(sh.SECRETS_ROOT / ("ef" * 16)).mkdir(parents=True)
(sh.SECRETS_ROOT / ("ef" * 16) / "cred0").write_text("abc", encoding="utf-8")
ticks = {"n": 0}


def fake_clock():
    ticks["n"] += 1
    return ticks["n"] * 0.5


must(sh.remove_credentials_when_active(unit, sh.SECRETS_ROOT / ("ef" * 16), ["cred0"], credentials_root=BASE / "nowhere", clock=fake_clock, sleep=lambda s: None, timeout=15) is False,
     "no copies, no removal")
must((sh.SECRETS_ROOT / ("ef" * 16) / "cred0").exists(), "the folder stays when the unit never shows its copy")
stop = threading.Event()
stop.set()
must(sh.remove_credentials_when_active(unit, sh.SECRETS_ROOT / ("ef" * 16), ["cred0"], credentials_root=BASE / "nowhere", stop=stop) is False, "stopped")
sh.remove_secrets("ef" * 16)  # what launch()'s finally does
must(not leftovers(), leftovers())

# through launch(): a fake unit that never copies (the copy folder is made unreadable by pointing the root elsewhere)
real_root = sh.CREDENTIALS_RUNTIME
sh.CREDENTIALS_RUNTIME = BASE / "never-there"
try:
    make_runner("ai.nocopy", body="time.sleep(1)\nprint('done')", credential_files=["auth"])
    code, frames = start(header("ai.nocopy", credentials={"auth": TOKEN}))
    must(end_of(frames)["reason"] == "exited" and not leftovers(), (frames, leftovers()))
finally:
    sh.CREDENTIALS_RUNTIME = real_root

# ---- (4) a copy of a different size is not treated as ready
sizes = BASE / "sizes"
(sizes / "u.service").mkdir(parents=True)
(sizes / "u.service" / "cred0").write_text("short", encoding="utf-8")
src = BASE / "sizes-src"
src.mkdir()
(src / "cred0").write_text("a much longer source", encoding="utf-8")
ticks["n"] = 0
must(sh.remove_credentials_when_active("u", src, ["cred0"], credentials_root=sizes, clock=fake_clock, sleep=lambda s: None, timeout=5) is False and (src / "cred0").exists(),
     "a copy of another size is not complete")
(sizes / "u.service" / "cred0").write_text("a much longer source", encoding="utf-8")
must(sh.remove_credentials_when_active("u", src, ["cred0"], credentials_root=sizes) is True and not src.exists(), "a complete copy removes the folder")
must(sh.remove_credentials_when_active("u", src, [], credentials_root=sizes, clock=fake_clock, sleep=lambda s: None, timeout=1) is False, "no slots, no removal")


# ---- (5) the end frame's evidence: poll values, result rules, keys unchanged
class Watch:
    def __init__(self, kills, peak):
        self.oom_kill, self._peak = kills, peak

    def peak_bytes(self):
        return self._peak


must(sh.in_memory_handoff(Watch(2, 7), 137, 1, 20, False)["result"] == "oom-kill", "kill and failing exit")
must(sh.in_memory_handoff(Watch(2, 7), 0, 1, 20, False)["result"] == "", "kill but exit 0")
must(sh.in_memory_handoff(Watch(0, 7), 1, 1, 20, False)["result"] == "", "no kill")
must(sh.in_memory_handoff(Watch(None, None), 1, 1, 20, False)["result"] == "", "unknown is never guessed")
must(sh.in_memory_handoff(Watch(0, 7), 143, 25, 20, False)["result"] == "timeout", "past run_seconds plus slack")
must(sh.in_memory_handoff(Watch(0, 7), 143, 25, 20, True)["result"] == "", "a helper stop reason is not a timeout")
must(sh.in_memory_handoff(Watch(0, 7), 0, 20, 20, False)["result"] == "", "inside the slack")
handoff = sh.in_memory_handoff(Watch(1, 5 * 1048576), 9, 1, 20, False)
must(sh.merge_memory_evidence(Watch(1, 5 * 1048576), handoff, handoff["result"]) == (5 * 1048576, 1, "poll"), "poll evidence")
make_runner("ai.keys", body="print('x')")
code, frames = start(header("ai.keys"))
end = end_of(frames)
must(sorted(end) == sorted(["t", "exit", "reason", "ms", "peak_mb", "oom_kills", "evidence", "credential_b64", "bytes_out", "bytes_err", "signal", "unit_result", "exit_source"]), sorted(end))
must(end["reason"] == "exited" and end["evidence"] is None, end)


class KillWatch(sh.CgroupWatch):
    def sample(self, now_value=None, *, force=False):
        self.oom_kill, self.peak = 1, 100 * 1048576


real_watch = sh.CgroupWatch
sh.CgroupWatch = KillWatch
try:
    make_runner("ai.killed", body="sys.exit(7)")
    end = end_of(start(header("ai.killed"))[1])
    must(end["reason"] == "oom" and end["oom_kills"] == 1 and end["peak_mb"] == 100.0 and end["evidence"] == "poll", end)
finally:
    sh.CgroupWatch = real_watch

# ---- (6) --finish is gone and was never in the sudoers rule
must(not hasattr(sh, "finish_run") and not hasattr(sh, "read_handoff"), "finish_run and read_handoff are gone")
sh.os.geteuid = lambda: 0
try:
    sh.main(["--finish", "a" * 32])
    raise AssertionError("--finish was accepted")
except SystemExit as exc:
    must("usage" in str(exc.code), exc.code)
source = "\n".join((ROOT / "scripts" / name).read_text(encoding="utf-8") for name in ("sandbox-helper.py", "sandbox-selftest.py"))
must('"--finish"' not in source and 'props.append(f"Exec' not in source and 'f"ExecStartPost' not in source and 'f"ExecStopPost' not in source,
     "no property command is built any more")
install = (ROOT / "install.sh").read_text(encoding="utf-8")
rule = install[install.index('cat > "${SANDBOX_SUDOERS}"'):]
rule = rule[:rule.index("\nEOF")]
must("--finish" not in rule, "--finish is not in the sudoers rule")

# ---- (7) the selftest probes: ok when the helper removed the source and the token arrived, not ok when the source stays
sh.CREDENTIALS_RUNTIME = F.CREDS_ROOT
fake = F.Fake()
status = F.run_selftest(sh, H.RUN, BASE, fake)
must(status["checks"]["credential"]["ok"] is True and status["checks"]["real_unit_shape"]["ok"] is True, status["checks"])
for call in fake.calls:
    if call[0] in ("credential", "real_unit_shape"):
        must(not [p for p in call[1] if p.startswith("Exec")], call)
fake = F.Fake()
fake.credential["remove"] = False  # the unit never shows its copy, so the helper never removes the source
status = F.run_selftest(sh, H.RUN, BASE, fake)
must(status["checks"]["credential"]["ok"] is False and "not removed by the helper" in status["checks"]["credential"]["detail"], status["checks"]["credential"])

# the real_unit_shape probe on its own, with a runner that honours unit= and one that leaves the source
class Shape:
    def __init__(self, copy):
        self.copy = copy

    def run_unit(self, name, properties, command, *, timeout=30, unit=None):
        source = Path(next(p for p in properties if p.startswith("LoadCredential=probe:")).split(":", 1)[1])
        return 0, F.hand_in(unit, source, self.copy), ""


ok, detail = sh._probe_real_shape(Shape(True), H.RUN)
must(ok is True, detail)
ok, detail = sh._probe_real_shape(Shape(False), H.RUN)
must(ok is False and "not removed by the helper" in detail, detail)

# ---- (8) the two new canary rows
rows = sh.credential_cleanup_rows(True, {"ExecStartPost": "", "ExecStopPost": "", "ExecStartPre": ""}, True)
must([r["verdict"] for r in rows] == ["ATTACK SUCCEEDED", "OK"], rows)
rows = sh.credential_cleanup_rows(False, {"ExecStartPost": "", "ExecStopPost": "", "ExecStartPre": ""}, True)
must([r["verdict"] for r in rows] == ["OK", "OK"], rows)
rows = sh.credential_cleanup_rows(False, {"ExecStartPost": "{ path=/bin/rm ; }", "ExecStopPost": "", "ExecStartPre": ""}, True)
must([r["verdict"] for r in rows] == ["OK", "ATTACK SUCCEEDED"] and "ExecStartPost" in rows[1]["actual"], rows)
rows = sh.credential_cleanup_rows(False, {"ExecStartPost": "unreadable", "ExecStopPost": "", "ExecStartPre": ""}, True)
must(rows[1]["verdict"] == "NOT RUN", rows)
must([r["verdict"] for r in sh.credential_cleanup_rows(True, {}, False)] == ["NOT RUN", "NOT RUN"], "an unproven unit is NOT RUN")
names = [r["attack"] for r in sh.credential_cleanup_rows(False, {}, True)]
must(names == ["credential source folder is gone while the run is still active", "no host command property on the live unit"], names)

# ---- (9) line endings: every touched file keeps its own (LF here unless it was CRLF before; no file may be mixed)
for name in ("scripts/sandbox-helper.py", "docs/sandbox-capability.md", "VERSION", "tec_tac_package.json", "install.sh", "tests/sandbox-canary-1.18.14.sh",
             "tests/sandbox-harness-1.17.118.py", "tests/sandbox-launch-1.18.28.py", "tests/sandbox-memory-1.17.124.py", "tests/sandbox-cgroup-evidence-1.18.8.py",
             "tests/sandbox-unit-builder-1.18.27.py", "tests/sandbox-template-1.18.8.py", "tests/sandbox-skeleton-run-1.18.27.py",
             "tests/sandbox-fake-runner-1.17.120.py", "tests/sandbox-selftest-1.18.27.py", "tests/sandbox-credential-mode-1.17.120.py", f"RELEASE_NOTES_{(ROOT / 'VERSION').read_text().strip()}.md"):
    data = (ROOT / name).read_bytes()
    must(data.count(b"\r") in (0, data.count(b"\n")) and (b"\r\n" not in data or data.count(b"\r\n") == data.count(b"\n")), f"{name}: mixed line endings")
for name in ("scripts/sandbox-helper.py", "docs/sandbox-capability.md", "VERSION", "tec_tac_package.json", "install.sh", "tests/sandbox-canary-1.18.14.sh"):
    must(b"\r" not in (ROOT / name).read_bytes(), f"{name} was LF and must stay LF")
for name in ("tests/sandbox-fake-runner-1.17.120.py", "tests/sandbox-selftest-1.18.27.py", "tests/sandbox-credential-mode-1.17.120.py"):
    data = (ROOT / name).read_bytes()
    must(data.count(b"\r\n") == data.count(b"\n"), f"{name} was CRLF and must stay CRLF")
bash = subprocess.run(["bash", "-n", "tests/sandbox-canary-1.18.14.sh"], capture_output=True, text=True, check=False, cwd=ROOT)
must(bash.returncode == 0, bash.stderr)

print("[TEST] PASS sandbox no plus 1.18.14")
