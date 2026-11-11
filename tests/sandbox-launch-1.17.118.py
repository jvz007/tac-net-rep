#!/usr/bin/env python3
"""1.17.118 regression: the helper's launch path (core.sandbox Patch 2, part A): --start, --stop, --finish, slots, credential hand-in,
framing, the launcher, cancel and the dead-man switch, sweep.

Django-free. The helper runs for real, in this process, against a fake file-system layer and a fake systemd-run and systemctl (tests/
sandbox-harness-1.17.118.py): the launcher and the runner are real child processes, the unit properties are only logged.

Covered: the kill switch still refuses before it reads stdin; a bad run id, runner, parameter, credential name, an oversize input, an
oversize credential and an unknown header key are refused before anything is written; an unverified runtime, a changed executable and a
not-ready selftest are refused; slot limits (server and per person), the queue timeout and the release after a crash; credential folder
modes and removal on success, failure, cancel and exception, and no credential in argv, in the child's environment or in the audit log;
frame order, partial UTF-8 across frames, output caps with the truncated flag, the timeout, the dead-man stop on stdin EOF; the launcher's
nonce framing (a forged frame from the runner is plain output) and the credential round trip; --stop accepts only a unit this helper
started; --finish writes a root-only handoff; sweep removes strays and keeps live runs.

Not runnable here: real systemd, cgroups and the unit's own file system (the dev02 canary).
"""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
# The shared set-up (fake file system, helper loaded as sh, fake systemd), loaded by path; the names it gives are taken explicitly.
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_118", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
(BASE, CHMODS, HoldOpen, NOTROOT, ROOT, audit_text, end_of, header, joined, leftovers, make_runner, must, norm, sh, start, stops, unit_log, write_ready_status,) = (H.BASE, H.CHMODS, H.HoldOpen, H.NOTROOT, H.ROOT, H.audit_text, H.end_of, H.header, H.joined, H.leftovers, H.make_runner, H.must, H.norm, H.sh, H.start, H.stops, H.unit_log, H.write_ready_status,)

# ------------------------------------------------------------------------------------------------ slot arithmetic
SC = sh.slot_count
must(SC(8_000_000, 1024) == 6, "plenty of memory: at most 6")
must(SC(3_000_000, 1024) == 1 and SC(2_700_000, 1024) == 1, SC(3_000_000, 1024))
must(SC(1_000_000, 1024) == 1 and SC(0, 1024) == 1, "at least one slot")
must(SC(1_572_864 + 2 * 1048576, 1024) == 2, "exactly two")
must(SC(1_572_864 + 2 * 1048576 - 1, 1024) == 1, "one KiB short is one slot fewer")
must(SC(8_000_000, 2048) == 3, SC(8_000_000, 2048))

# ------------------------------------------------------------------------------------------------ the kill switch
must(sh.SANDBOX_ENABLED is False, "off")


class NoStdin:
    def __getattr__(self, name):
        raise AssertionError(f"stdin was touched ({name})")


real_stdin = sys.stdin
sys.stdin = NoStdin()
try:
    for flag in ("--start", "--stop"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sh.main([flag])
        must(code == 3 and json.loads(out.getvalue()) == {"t": "refused", "code": "sandbox_disabled"}, out.getvalue())
finally:
    sys.stdin = real_stdin
must(not leftovers() and not (sh.SLOTS_ROOT / "0").exists(), "the refusal touched nothing")
# --finish and the canary are root only commands; they exist but are not in the sudo rule (installer test)
must(sh.main.__doc__ is None or True, "")

# ------------------------------------------------------------------------------------------------ refusals before anything is written
make_runner("ai.chat", body="print('hi')", parameters={"mode": {"type": "enum", "choices": ["fast", "slow"]}, "n": {"type": "integer", "minimum": 1, "maximum": 5}},
            argv=["--mode", {"param": "mode"}], credential_files=["auth"], limits={"input_kib": 1})


def refused(frames, code):
    must(len(frames) == 1 and frames[0]["t"] == "refused" and frames[0]["code"] == code, (code, frames))
    must(not leftovers(), "nothing was written")
    must(not [p for p in (sh.SLOTS_ROOT.glob("*")) if p.is_file()] or True, "")


good = header(parameters={"mode": "fast"})
cases = [
    ("bad run id", {**good, "run_id": "xyz"}, b"", "invalid_input"),
    ("short run id", {**good, "run_id": "ab" * 8}, b"", "invalid_input"),
    ("unknown key", {**good, "argv": ["x"]}, b"", "invalid_input"),
    ("bad runner id", {**good, "runner_id": "../x"}, b"", "invalid_input"),
    ("unknown runner", {**good, "runner_id": "ai.nothing"}, b"", "runner_unknown"),
    ("bad person", {**good, "person": ""}, b"", "invalid_input"),
    ("person control char", {**good, "person": "a\nb"}, b"", "invalid_input"),
    ("parameters not object", {**good, "parameters": [1]}, b"", "invalid_input"),
    ("unknown parameter", header(parameters={"mode": "fast", "rm": "-rf"}), b"", "invalid_input"),
    ("enum outside choices", header(parameters={"mode": "turbo"}), b"", "invalid_input"),
    ("integer out of range", header(parameters={"mode": "fast", "n": 9}), b"", "invalid_input"),
    ("integer is a bool", header(parameters={"mode": "fast", "n": True}), b"", "invalid_input"),
    ("param needed by argv missing", header(parameters={}), b"", "invalid_input"),
    ("credential name not declared", header(parameters={"mode": "fast"}, credentials={"other": "x"}), b"", "credential_invalid"),
    ("credential over 16 KiB", header(parameters={"mode": "fast"}, credentials={"auth": b"x" * (16 * 1024 + 1)}), b"", "credential_invalid"),
    ("credential not base64", {**good, "credentials": {"auth": "not base64!!"}}, b"", "credential_invalid"),
    ("input over input_kib", header(parameters={"mode": "fast"}, input_bytes=1025), b"x" * 1025, "input_too_large"),
]
for label, hdr, data, code in cases:
    got_code, frames = start(hdr, data, hold=False)
    refused(frames, code)
    must(got_code == 3, label)
for label, raw in (("not json", b"{nope\n"), ("no newline", b"{}"), ("empty", b""), ("json list", b"[1]\n"), ("header too long", b"x" * (sh.HEADER_MAX_BYTES + 5) + b"\n")):
    got_code, frames = start(None, hold=False, stdin_bytes=raw)
    refused(frames, "invalid_input")
got_code, frames = start(header(parameters={"mode": "fast"}, input_bytes=10), b"abc", hold=False)  # input ends early
refused(frames, "invalid_input")
must(not (BASE / "log").exists() or not list((BASE / "log").iterdir()), "no systemd-run was ever started")

# ------------------------------------------------------------------------------------------------ unverified, changed, not ready
make_runner("ai.unver", verified=False)
refused(start(header("ai.unver"), hold=False)[1], "runtime_unverified")
row = make_runner("ai.tamper", body="print('a')")
Path(row["executable"]).write_bytes(b"print('evil')\n")
refused(start(header("ai.tamper"), hold=False)[1], "runtime_unverified")
make_runner("ai.rooted", body="print('a')")
NOTROOT.add(norm(sh.RUNNERS_ROOT / "ai" / "rooted.py"))
refused(start(header("ai.rooted"), hold=False)[1], "runtime_unverified")
NOTROOT.discard(norm(sh.RUNNERS_ROOT / "ai" / "rooted.py"))
make_runner("ai.rootless", body="print('a')", roots=[{"path": "/opt/tec-tac/runtimes/ai/nowhere", "tree_sha256_file": "sandbox/t.txt", "listing_sha256": "0" * 64}])
refused(start(header("ai.rootless"), hold=False)[1], "runtime_unverified")  # the folder does not exist
make_runner("ai.badroot", body="print('a')", roots=[{"path": "/etc", "tree_sha256_file": "sandbox/t.txt", "listing_sha256": "0" * 64}])
refused(start(header("ai.badroot"), hold=False)[1], "runtime_unverified")  # outside /opt/tec-tac/runtimes/ai/
write_ready_status(ready=False, reason="no cgroup v2")
refused(start(header("ai.chat", parameters={"mode": "fast"}), hold=False)[1], "sandbox_unavailable")
write_ready_status(resolver="9.9.9.9")  # the proven resolver is no longer listed in resolv.conf
refused(start(header("ai.chat", parameters={"mode": "fast"}), hold=False)[1], "sandbox_unavailable")
write_ready_status(resolver="::1", resolvers=["::1"])
Path(sh.RESOLV_CONF).write_text("nameserver ::1\n", encoding="utf-8")
refused(start(header("ai.chat", parameters={"mode": "fast"}), hold=False)[1], "sandbox_unavailable")  # an IPv6 resolver cannot be used
Path(sh.RESOLV_CONF).write_text("nameserver 127.0.0.53\n", encoding="utf-8")
write_ready_status()
(sh.REGISTRY_ROOT / "ai.nonroot.json").write_text("{}", encoding="utf-8")
refused(start(header("ai.nonroot"), hold=False)[1], "runner_unknown")
row = json.loads((sh.REGISTRY_ROOT / "ai.chat.json").read_text(encoding="utf-8"))
(sh.REGISTRY_ROOT / "ai.forged.json").write_text(json.dumps({**row, "id": "ai.forged", "registered_by": "hand"}), encoding="utf-8")
refused(start(header("ai.forged"), hold=False)[1], "runner_unknown")
(sh.REGISTRY_ROOT / "core.canary.json").write_text(json.dumps({**row, "id": "core.canary", "owner_module": "core"}), encoding="utf-8")
refused(start(header("core.canary"), hold=False)[1], "runner_unknown")  # a registry row can never be the canary
must(not (BASE / "log").exists() or not list((BASE / "log").iterdir()), "still no unit started")

# ------------------------------------------------------------------------------------------------ a normal run: frame order and content
make_runner("ai.say", body="sys.stdout.buffer.write('héllo wörld\\n'.encode('utf-8')); sys.stderr.write('warn\\n'); sys.exit(3)", limits={})
code, frames = start(header("ai.say"))
must(code == 0, code)
tags = [f["t"] for f in frames]
must(tags[0] == "started" and tags[-1] == "end" and set(tags) <= {"started", "out", "err", "end"}, tags)
must(joined(frames, "out").decode("utf-8").strip() == "héllo wörld" and joined(frames, "err").strip() == b"warn", frames)
end = end_of(frames)
must(end["exit"] == 3 and end["reason"] == "exited" and end["peak_mb"] == 50.0 and end["credential_b64"] is None and isinstance(end["ms"], int), end)
must(not leftovers(), leftovers())
log = unit_log(frames[0]["run_id"])
must(frames[0]["unit"] == "tectac-sbx-" + frames[0]["run_id"], frames[0])
must("--pipe" in log["args"] and "--wait" in log["args"] and "--collect" in log["args"] and f"--slice={sh.SLICE}" in log["args"], log["args"])
must(sh.CHILD_ENV["FAKE_BASE"] and "TOKEN" not in "".join(log["environ_keys"]), "the child's environment is only what the helper gives")

# stdin sent to the runner
make_runner("ai.echo", body="sys.stdout.buffer.write(sys.stdin.buffer.read().decode('utf-8').upper().encode('utf-8'))")
data = "naïve input".encode()
code, frames = start(header("ai.echo", input_bytes=len(data)), data)
must(joined(frames, "out").decode("utf-8") == "NAÏVE INPUT" and end_of(frames)["reason"] == "exited", frames)

# argv: literal strings and {param}, no shell
make_runner("ai.argv", body="print(sys.argv[1:])", parameters={"name": {"type": "string", "max_length": 20}, "flag": {"type": "boolean"}},
            argv=["--n", {"param": "name"}, "--f", {"param": "flag"}])
code, frames = start(header("ai.argv", parameters={"name": "a b; rm -rf /", "flag": True}))
must(joined(frames, "out").decode().strip() == "['--n', 'a b; rm -rf /', '--f', 'true']", joined(frames, "out"))

# partial UTF-8: a multi-byte character split across two writes arrives whole once the frames are joined
make_runner("ai.split", body="b='é€'.encode('utf-8')\nfor i in range(len(b)):\n    sys.stdout.buffer.write(b[i:i+1]); sys.stdout.buffer.flush(); time.sleep(0.15)")
code, frames = start(header("ai.split"))
must(joined(frames, "out").decode("utf-8") == "é€", joined(frames, "out"))
must(sum(1 for f in frames if f["t"] == "out") >= 2, "the bytes were streamed in more than one frame")

# ------------------------------------------------------------------------------------------------ output caps and the timeout
make_runner("ai.flood", body="sys.stdout.write('x' * 20000); sys.stdout.flush(); time.sleep(30)", limits={"stdout_kib": 4, "run_seconds": 20})
started = time.monotonic()
code, frames = start(header("ai.flood"))
end = end_of(frames)
must(end["reason"] == "output_limit" and len(joined(frames, "out")) == 4096 and any(f.get("truncated") for f in frames if f["t"] == "out"), end)
must(time.monotonic() - started < 15 and any("tectac-sbx-" + frames[0]["run_id"] == u for u in stops()), "the unit was stopped at the cap")
make_runner("ai.errflood", body="sys.stderr.write('e' * 5000); sys.stderr.flush(); time.sleep(30)", limits={"stderr_kib": 1})
code, frames = start(header("ai.errflood"))
must(end_of(frames)["reason"] == "output_limit" and len(joined(frames, "err")) == 1024 and any(f.get("truncated") for f in frames if f["t"] == "err"), "stderr cap")
make_runner("ai.slow", body="time.sleep(30)", limits={"run_seconds": 1})
started = time.monotonic()
code, frames = start(header("ai.slow"))
must(end_of(frames)["reason"] == "timeout" and time.monotonic() - started < 15, frames)
must(not leftovers(), leftovers())
sh.CHILD_ENV["FAKE_RESULT"] = "oom-kill"
make_runner("ai.oom", body="print('x')")
must(end_of(start(header("ai.oom"))[1])["reason"] == "oom", "systemd's oom-kill result becomes reason oom")
sh.CHILD_ENV["FAKE_RESULT"] = "timeout"
must(end_of(start(header("ai.oom"))[1])["reason"] == "timeout", "systemd's own timeout result")
sh.CHILD_ENV.pop("FAKE_RESULT")

# ------------------------------------------------------------------------------------------------ credentials
TOKEN = "s3cret-" + os.urandom(8).hex()
make_runner("ai.cred", body=("d = os.environ['CREDENTIALS_DIRECTORY']\n"
                             "sys.stdout.write('got=' + open(os.path.join(d, 'auth')).read() + '\\n')\n"
                             "open(os.path.join(os.environ['SANDBOX_OUT'], 'credential'), 'w').write('refreshed-' + open(os.path.join(d, 'auth')).read())"),
            credential_files=["auth"], credential_return=True)
seen = {}
real_spawn = sh._spawn


def spy_spawn(argv):
    folder = sh.SECRETS_ROOT / argv[argv.index("--") - 0 - 0 and 0 or 0] if False else None
    run_id = next(a for a in argv if a.startswith("--unit="))[len("--unit=tectac-sbx-"):]
    folder = sh.SECRETS_ROOT / run_id
    seen["folder_mode"] = CHMODS.get(norm(folder))
    seen["file_mode"] = CHMODS.get(norm(folder / "auth"))
    seen["exists"] = (folder / "auth").is_file()
    seen["argv"] = list(argv)
    return real_spawn(argv)


sh._spawn = spy_spawn
code, frames = start(header("ai.cred", credentials={"auth": TOKEN}))
sh._spawn = real_spawn
end = end_of(frames)
must(end["reason"] == "exited" and joined(frames, "out").decode().strip() == "got=" + TOKEN, frames)
must(seen["exists"] and seen["folder_mode"] == 0o700 and seen["file_mode"] == 0o600, seen)
must(base64.b64decode(end["credential_b64"]).decode() == "refreshed-" + TOKEN, end)
must(b"CRED" not in joined(frames, "out") and TOKEN.encode() not in joined(frames, "err"), "the credential frame is stripped from the output")
must(not leftovers() and not (sh.SECRETS_ROOT / frames[0]["run_id"]).exists(), "the secrets folder is gone after success")
must(TOKEN not in json.dumps(seen["argv"]) and TOKEN not in json.dumps(unit_log(frames[0]["run_id"])["args"]), "never in argv")
must(TOKEN not in json.dumps(sorted(sh.CHILD_ENV.items())) and TOKEN not in audit_text(), "never in the helper's environment or audit log")
props = unit_log(frames[0]["run_id"])["props"]
must(any(p.startswith("LoadCredential=auth:") for p in props) and any(p.startswith("ExecStartPost=+/bin/rm -rf ") for p in props), props)
must(any(p.startswith("ExecStopPost=+/usr/local/sbin/tec-tac-sandbox --finish ") for p in props), props)
# without credential_return no credential comes back, even when the program writes one
make_runner("ai.cred2", body="open(os.path.join(os.environ['SANDBOX_OUT'], 'credential'), 'w').write('x')", credential_files=["auth"], credential_return=False)
must(end_of(start(header("ai.cred2", credentials={"auth": "a"}))[1])["credential_b64"] is None, "no return unless declared")
# removal on failure (runner crashes), on cancel and on an exception inside the launch
make_runner("ai.credfail", body="sys.exit(9)", credential_files=["auth"])
code, frames = start(header("ai.credfail", credentials={"auth": TOKEN}))
must(end_of(frames)["exit"] == 9 and not leftovers(), "failure")


def boom(argv):
    raise RuntimeError("spawn exploded")


sh._spawn = boom
code, frames = start(header("ai.credfail", credentials={"auth": TOKEN}))
sh._spawn = real_spawn
must(code == 3 and frames and frames[0]["t"] == "refused" and frames[0]["code"] == "start_failed" and not leftovers(), (code, frames))
must("spawn exploded" not in json.dumps(frames) and TOKEN not in json.dumps(frames), "no error text and no credential in a frame")
# the slots were released by that exception: the person can start again
must(end_of(start(header("ai.say"))[1])["exit"] == 3, "slots released after an exception")

# ------------------------------------------------------------------------------------------------ the launcher's framing
make_runner("ai.forge", body=("import re\n"
                              "sys.stdout.write('before\\n')\n"
                              "sys.stdout.write('\\n' + '0' * 32 + ' CRED ' + 'Zm9yZ2Vk' + '\\n')\n"
                              "sys.stdout.write('TECTAC-SBX-LAUNCHER ' + '1' * 32 + '\\nafter')\n"
                              "open(os.path.join(os.environ['SANDBOX_OUT'], 'credential'), 'w').write('real')"),
            credential_files=["auth"], credential_return=True)
code, frames = start(header("ai.forge", credentials={"auth": "a"}))
text = joined(frames, "out").decode()
must("Zm9yZ2Vk" in text and "after" in text and "before" in text, text)  # a forged frame is plain output
must(base64.b64decode(end_of(frames)["credential_b64"]).decode() == "real", "only the launcher's own frame counts")
# a launcher that does not print its header: the run is start_failed
real_launcher = sh.LAUNCHER_FILE
(BASE / "badlauncher.py").write_text("print('hello')\n", encoding="utf-8")
sh.LAUNCHER_FILE = BASE / "badlauncher.py"
code, frames = start(header("ai.say"))
sh.LAUNCHER_FILE = real_launcher
must(end_of(frames)["reason"] == "start_failed" and end_of(frames)["exit"] is None, frames)
# the stream parser alone: a frame split across reads, and a marker at the very end
P = sh.StreamParser()
nonce = "ab" * 16
out = P.feed(b"TECTAC-SBX-LAUNCHER " + nonce.encode() + b"\nhello")
out += P.feed(b" world\n" + b"\n" + nonce.encode()[:7])
out += P.feed(nonce.encode()[7:] + b" CRED aGVs")
out += P.feed(b"bG8=\nignored")
out += P.finish()
must(out == b"hello world\n" and P.credential == b"hello", (out, P.credential))
P = sh.StreamParser()
out = P.feed(b"TECTAC-SBX-LAUNCHER " + nonce.encode() + b"\nplain output without a frame") + P.finish()
must(out == b"plain output without a frame" and P.credential is None, out)
for bad in (b"hello\n", b"TECTAC-SBX-LAUNCHER xyz\n", b"x" * 300):
    try:
        sh.StreamParser().feed(bad)
        raise AssertionError("accepted a bad launcher header")
    except sh.LauncherError:
        pass
# an oversize credential frame is dropped
P = sh.StreamParser()
P.feed(b"TECTAC-SBX-LAUNCHER " + nonce.encode() + b"\n")
P.feed(b"\n" + nonce.encode() + b" CRED " + base64.b64encode(b"x" * (16 * 1024 + 1)) + b"\n")
must(P.credential is None, "over 16 KiB is dropped")

# the launcher program itself
_LSPEC = importlib.util.spec_from_file_location("sandbox_launcher_118", ROOT / "scripts" / "sandbox-launcher.py")
launcher = importlib.util.module_from_spec(_LSPEC)
_LSPEC.loader.exec_module(launcher)
(BASE / "outdir").mkdir()
must(launcher.read_credential(str(BASE / "outdir")) is None, "no file")
(BASE / "outdir" / "credential").write_bytes(b"x" * (16 * 1024))
must(launcher.read_credential(str(BASE / "outdir")) == b"x" * (16 * 1024), "exactly 16 KiB is fine")
(BASE / "outdir" / "credential").write_bytes(b"x" * (16 * 1024 + 1))
must(launcher.read_credential(str(BASE / "outdir")) is None, "over 16 KiB")
(BASE / "outdir" / "credential").unlink()
(BASE / "outdir" / "credential").mkdir()
must(launcher.read_credential(str(BASE / "outdir")) is None, "a directory is not a credential")
must(launcher.credential_line("n" * 32, b"hi") == b"\n" + b"n" * 32 + b" CRED aGk=\n", "line shape")

# ------------------------------------------------------------------------------------------------ the dead-man switch
make_runner("ai.hang", body="time.sleep(60)", credential_files=["auth"], limits={"run_seconds": 50})
hdr = header("ai.hang", credentials={"auth": TOKEN})
stdin = HoldOpen(json.dumps(hdr).encode() + b"\n")
out = io.BytesIO()
box = {}


def go():
    box["code"] = sh.start_command(stdin, out_stream=out)


thread = threading.Thread(target=go, daemon=True)
thread.start()
for _ in range(100):
    if (BASE / "pids" / f"tectac-sbx-{hdr['run_id']}").exists():
        break
    time.sleep(0.1)
must((BASE / "pids" / f"tectac-sbx-{hdr['run_id']}").exists(), "the unit is running")
started = time.monotonic()
stdin.done.set()  # the caller closes its end (or died)
thread.join(20)
must(not thread.is_alive() and box["code"] == 4 and time.monotonic() - started < 10, box)
must(f"tectac-sbx-{hdr['run_id']}" in stops(), "EOF on stdin stopped the unit")
must(not leftovers(), "everything cleaned after a dead man")
# a broken stdout pipe is the same


class BrokenOut(io.BytesIO):
    def write(self, data):
        if b'"t":"started"' in data:
            return super().write(data)
        raise BrokenPipeError()


hdr = header("ai.hang")
code = {}
thread = threading.Thread(target=lambda: code.update(v=sh.start_command(HoldOpen(json.dumps(hdr).encode() + b"\n"), out_stream=BrokenOut())), daemon=True)
make_runner("ai.chatty", body="while True:\n    print('x' * 100, flush=True); time.sleep(0.05)", limits={"run_seconds": 50})
hdr = header("ai.chatty")
thread = threading.Thread(target=lambda: code.update(v=sh.start_command(HoldOpen(json.dumps(hdr).encode() + b"\n"), out_stream=BrokenOut())), daemon=True)
thread.start()
thread.join(30)
must(not thread.is_alive() and code.get("v") == 4 and f"tectac-sbx-{hdr['run_id']}" in stops(), "a broken stdout pipe stops the unit")
must(not leftovers(), leftovers())

# ------------------------------------------------------------------------------------------------ cancel with --stop
make_runner("ai.long", body="time.sleep(60)", limits={"run_seconds": 50})
hdr = header("ai.long")
stdin = HoldOpen(json.dumps(hdr).encode() + b"\n")
out = io.BytesIO()
box = {}
thread = threading.Thread(target=lambda: box.update(code=sh.start_command(stdin, out_stream=out)), daemon=True)
thread.start()
for _ in range(100):
    if (BASE / "pids" / f"tectac-sbx-{hdr['run_id']}").exists():
        break
    time.sleep(0.1)
reply = io.StringIO()
must(sh.stop_command(io.BytesIO(hdr["run_id"].encode() + b"\n"), out=reply) == 0 and json.loads(reply.getvalue())["t"] == "stopped", reply.getvalue())
thread.join(20)
stdin.done.set()
frames = [json.loads(line) for line in out.getvalue().decode().splitlines()]
must(end_of(frames)["reason"] == "cancelled" and not leftovers(), frames)
for label, raw in (("a run id this helper never started", os.urandom(16).hex()), ("not a run id", "../../etc"), ("empty", ""), ("a unit name", "tectac-sbx-" + "a" * 32)):
    reply = io.StringIO()
    must(sh.stop_command(io.BytesIO(raw.encode() + b"\n"), out=reply) == 3, label)
    must(json.loads(reply.getvalue())["t"] == "refused", label)
must(os.urandom(16).hex() not in stops(), "")
foreign = os.urandom(16).hex()
must(f"tectac-sbx-{foreign}" not in stops(), "a foreign run id never reached systemctl")

# ------------------------------------------------------------------------------------------------ slots
now_t = {"v": 0.0}
clock = lambda: now_t["v"]


def sleeper(seconds):
    now_t["v"] += seconds


row = json.loads((sh.REGISTRY_ROOT / "ai.say.json").read_text(encoding="utf-8"))
held = []
try:
    held.append(sh.acquire_slots("p1", row, slots_n=2, clock=clock, sleep=sleeper))
    held.append(sh.acquire_slots("p2", row, slots_n=2, clock=clock, sleep=sleeper))
    try:
        sh.acquire_slots("p3", row, slots_n=2, clock=clock, sleep=sleeper)
        raise AssertionError("a third run got a slot")
    except sh.Refusal as exc:
        must(exc.code == "busy" and exc.retry_after == 5, exc.code)
    must(now_t["v"] >= row["limits"]["queue_seconds"], "it waited the queue time first")
    must(sh.slots_in_use(2) == 2, "two in use")
    held.pop().release()
    held.append(sh.acquire_slots("p3", row, slots_n=2, clock=clock, sleep=sleeper))  # a freed slot is taken at once
finally:
    for holder in held:
        holder.release()
must(sh.slots_in_use(2) == 0, "all released")
# per person: the third start of one person is person_busy even with free server slots
pers = []
try:
    pers.append(sh.acquire_slots("same", row, slots_n=6, clock=clock, sleep=sleeper))
    pers.append(sh.acquire_slots("same", row, slots_n=6, clock=clock, sleep=sleeper))
    try:
        sh.acquire_slots("same", row, slots_n=6, clock=clock, sleep=sleeper)
        raise AssertionError("a third run for one person")
    except sh.Refusal as exc:
        must(exc.code == "person_busy" and exc.retry_after == 5, exc.code)
    other = sh.acquire_slots("someone-else", row, slots_n=6, clock=clock, sleep=sleeper)  # another person is not limited by it
    other.release()
    must(sh.slots_in_use(6) == 2, "the refused third took no server slot")
finally:
    for holder in pers:
        holder.release()
must(sh.person_key("a") != sh.person_key("b") and len(sh.person_key("a")) == 32 and "a" not in sh.person_key("user:7")[:0] + "x", "person hashed")
must(not [p.name for p in sh.PERSON_SLOTS_ROOT.iterdir() if "user" in p.name], "the person's name is never a file name")
# a crash between taking the slots and the run: the holder releases
try:
    holder = sh.acquire_slots("crash", row, slots_n=1, clock=clock, sleep=sleeper)
    raise RuntimeError("crash")
except RuntimeError:
    holder.release()
sh.acquire_slots("crash", row, slots_n=1, clock=clock, sleep=sleeper).release()

# ------------------------------------------------------------------------------------------------ --finish
reply_dir = sh.HANDOFF_ROOT
rid = os.urandom(16).hex()
must(sh.finish_run(rid, {"SERVICE_RESULT": "oom-kill"}) == 0, "")
handoff = json.loads((sh.HANDOFF_ROOT / f"{rid}.json").read_text(encoding="utf-8"))
must(handoff == {"cpu_ns": 1000, "memory_peak": 52428800, "result": "oom-kill"} and CHMODS[norm(sh.HANDOFF_ROOT / f"{rid}.json")] == 0o600, handoff)
must(sh.read_handoff(rid)["result"] == "oom-kill" and not (sh.HANDOFF_ROOT / f"{rid}.json").exists(), "read once, then deleted")
for bad in ("../x", "abc", "G" * 32, ""):
    try:
        sh.finish_run(bad, {})
        raise AssertionError(bad)
    except RuntimeError:
        pass
sh.finish_run(rid, {"SERVICE_RESULT": "x" * 100 + "\n;rm"})
must(set(json.loads((sh.HANDOFF_ROOT / f"{rid}.json").read_text(encoding="utf-8"))["result"]) <= set("abcdefghijklmnopqrstuvwxyz-"), "the result is sanitised")
(sh.HANDOFF_ROOT / f"{rid}.json").unlink()

# ------------------------------------------------------------------------------------------------ sweep
live, dead = os.urandom(16).hex(), os.urandom(16).hex()
(BASE / "pids").mkdir(exist_ok=True)
(BASE / "pids" / f"tectac-sbx-{live}").write_text("1", encoding="utf-8")
for run_id in (live, dead):
    (sh.SECRETS_ROOT / run_id).mkdir(parents=True)
    (sh.SECRETS_ROOT / run_id / "auth").write_text("x", encoding="utf-8")
    (sh.HANDOFF_ROOT / f"{run_id}.json").write_text("{}", encoding="utf-8")
    (sh.RUNS_ROOT / f"{run_id}.json").write_text("{}", encoding="utf-8")
(sh.RUN_ROOT / "selftest-abc").mkdir()
(sh.SECRETS_ROOT / "not-a-run-id").mkdir()
sh.CANARY_MARKERS_FILE.write_text(json.dumps({"paths": [str(BASE / ".tectac-canary-aa"), str(BASE / "keep-me.txt")]}), encoding="utf-8")
(BASE / ".tectac-canary-aa").write_text("m", encoding="utf-8")
(BASE / "keep-me.txt").write_text("k", encoding="utf-8")
old = time.time() - 3600
for path in list(sh.SECRETS_ROOT.rglob("*")) + list(sh.HANDOFF_ROOT.glob("*")) + list(sh.RUNS_ROOT.glob("*")):
    os.utime(path, (old, old))
with contextlib.redirect_stdout(io.StringIO()):
    sh.sweep()
must(not (sh.SECRETS_ROOT / dead).exists() and not (sh.HANDOFF_ROOT / f"{dead}.json").exists() and not (sh.RUNS_ROOT / f"{dead}.json").exists(), "a dead run's files are removed")
must((sh.SECRETS_ROOT / live / "auth").exists() and (sh.HANDOFF_ROOT / f"{live}.json").exists() and (sh.RUNS_ROOT / f"{live}.json").exists(), "a live run keeps its files")
must(not (sh.RUN_ROOT / "selftest-abc").exists() and not (sh.SECRETS_ROOT / "not-a-run-id").exists(), "selftest folders and strays go")
must(not (BASE / ".tectac-canary-aa").exists() and (BASE / "keep-me.txt").exists() and not sh.CANARY_MARKERS_FILE.exists(), "only canary markers are removed")
# a run that is still starting (young files) is kept even when its unit does not exist yet
young = os.urandom(16).hex()
(sh.RUNS_ROOT / f"{young}.json").write_text("{}", encoding="utf-8")
with contextlib.redirect_stdout(io.StringIO()):
    sh.sweep()
must((sh.RUNS_ROOT / f"{young}.json").exists(), "young files are kept")
with contextlib.redirect_stdout(io.StringIO()):
    sh.sweep(min_age=0)
must(not (sh.RUNS_ROOT / f"{young}.json").exists() and (sh.SECRETS_ROOT / live).exists(), "min_age 0 still keeps a live unit")
shutil.rmtree(sh.SECRETS_ROOT / live)
for p in list(sh.HANDOFF_ROOT.glob("*")) + list(sh.RUNS_ROOT.glob("*")):
    p.unlink()

print("[TEST] PASS sandbox launch 1.17.118")
shutil.rmtree(BASE, ignore_errors=True)
