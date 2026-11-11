#!/usr/bin/env python3
"""1.17.123 regression: the credential frame never reaches stdout on any path, and the canary looks for the real thing (core.sandbox canary, fix 4).

Diagnosis from the dev02 table: every row the credential group prints says 'arrived in CREDENTIALS_DIRECTORY', and the 1.17.122 check was the
substring 'CRED' in stdout, so 'found in output' was very probably a false positive of the check. The real frame is
``\\n<32 hex nonce> CRED <base64>\\n`` after the launcher header ``TECTAC-SBX-LAUNCHER <nonce>``.

* the canary check searches stdout, stderr and the end frame for the nonce-shaped frame start, the launcher header text, the token and the
  refreshed token (plain and base64); the words CREDENTIALS_DIRECTORY and CRED alone are not a finding; a forged-shape line or a planted
  token is, so the check can fail;
* StreamParser: a frame split at every byte offset, a held partial marker at EOF (dropped, no nonce byte reaches stdout), no newline before
  the stream ends, an oversized or garbled frame, a runner with no credential_return, a missing or garbled header;
* _supervise: cancel, timeout and output cap in the middle of a frame, and a normal end;
* the end frame keeps credential_b64 while out and err events never hold the token, the refreshed token or the nonce; the Django side reads
  credential_b64 in one place only (the end event) and never logs it.

Not runnable here: the real launcher under systemd (dev02 runs tests/sandbox-canary-1.17.123.sh).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("sandbox_harness_123d", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
sh, must, make_runner, start, header, joined, end_of = H.sh, H.must, H.make_runner, H.start, H.header, H.joined, H.end_of

NONCE = os.urandom(16).hex()
TOKEN = "s3cret-" + os.urandom(8).hex()
REFRESHED = "refreshed-" + TOKEN
HEADER = f"TECTAC-SBX-LAUNCHER {NONCE}\n".encode()
FRAME = b"\n" + NONCE.encode() + b" CRED " + base64.b64encode(REFRESHED.encode()) + b"\n"
SECRETS = [NONCE.encode(), b" CRED ", base64.b64encode(REFRESHED.encode()), REFRESHED.encode(), b"TECTAC-SBX-LAUNCHER"]


def run_parser(chunks, frames=True):
    parser = sh.StreamParser(frames)
    out = b""
    for chunk in chunks:
        out += parser.feed(chunk)
    out += parser.finish()
    return out, parser


def no_secret(data, label):
    for needle in SECRETS:
        must(needle not in data, (label, needle, data[:200]))
    must(not re.search(rb"[0-9a-f]{32} CRED ", data), (label, "a frame-shaped line"))


STREAM = HEADER + b"hello\nworld\n" + FRAME
# ---- a real frame, split at every byte offset, byte by byte, and as two reads at every offset
out, parser = run_parser([bytes([b]) for b in STREAM])
must(out == b"hello\nworld\n" and parser.credential == REFRESHED.encode(), (out, parser.credential))
for cut in range(len(STREAM) + 1):
    out, parser = run_parser([STREAM[:cut], STREAM[cut:]])
    must(out == b"hello\nworld\n" and parser.credential == REFRESHED.encode(), (cut, out))
    no_secret(out, f"split at {cut}")
# the header comes in pieces too
out, parser = run_parser([HEADER[:7], HEADER[7:30], HEADER[30:] + b"x", FRAME[:20], FRAME[20:]])
must(out == b"x" and parser.credential == REFRESHED.encode(), out)
# text after the frame is dropped, and text before it that merely looks like part of a marker is kept
out, parser = run_parser([HEADER + b"a CRED b\n" + FRAME + b"trailing text\n"])
must(out == b"a CRED b\n" and parser.credential == REFRESHED.encode(), out)
out, parser = run_parser([HEADER + b"keep\n"])
must(out == b"keep\n", "a lone newline at the end of ordinary output is kept")

# ---- EOF with a held partial marker: dropped, so no nonce byte reaches stdout (1.17.122 would emit it)
marker = b"\n" + NONCE.encode() + b" CRED "
for size in (2, 3, 10, 20, 33, 38):
    out, parser = run_parser([HEADER + b"text" + marker[:size]])
    must(out == b"text" and parser.credential is None, (size, out))
    no_secret(out, f"held {size}")
    out, parser = run_parser([HEADER + b"text", marker[:size]])
    must(out == b"text", (size, out))
out, parser = run_parser([HEADER + b"text\n" + b"not a marker"])
must(out == b"text\nnot a marker", "an ordinary tail is kept")

# ---- a frame with no newline before the stream ends, an oversized frame, a garbled frame
out, parser = run_parser([HEADER + b"hi" + marker + base64.b64encode(b"never finished")])
must(out == b"hi" and parser.credential is None, out)
no_secret(out, "no newline")
out, parser = run_parser([HEADER + b"hi" + marker + b"A" * (sh.CREDENTIAL_FILE_MAX_BYTES * 2 + 10), b"more"])
must(out == b"hi" and parser.credential is None and parser.closed, "oversized")
out, parser = run_parser([HEADER + b"hi" + marker + b"!!!not base64!!!\nafter\n"])
must(out == b"hi" and parser.credential is None, out)
out, parser = run_parser([HEADER + b"hi" + marker + base64.b64encode(b"x" * (sh.CREDENTIAL_FILE_MAX_BYTES + 1)) + b"\n"])
must(out == b"hi" and parser.credential is None, "a decoded frame over the limit is dropped")

# ---- a runner with credential_return false: no frame is expected, nothing is held back, the flag is never set
out, parser = run_parser([HEADER, b"plain output\n", FRAME[:10]], frames=False)
must(out == b"plain output\n" + FRAME[:10] and parser.credential is None, out)
out, parser = run_parser([HEADER + b"x" + FRAME], frames=False)
must(parser.credential is None, "without credential_return no frame is ever read as one")

# ---- header missing or garbled
out, parser = run_parser([b"TECTAC-SBX-LAUNCHER " + NONCE.encode()[:12]])
must(out == b"" and parser.header_done is False, "a header that never ends is never output")
out, parser = run_parser([b"some text the runner printed with no newline"])
must(out == b"" and parser.header_done is False, out)
for bad in (b"no header here\n", b"TECTAC-SBX-LAUNCHER xyz\n", b"TECTAC-SBX-LAUNCHER " + NONCE.upper().encode() + b"\n"):
    try:
        run_parser([bad + FRAME])
    except sh.LauncherError:
        continue
    raise AssertionError(("a bad header was accepted", bad))
try:
    run_parser([b"x" * 300])
except sh.LauncherError:
    pass
else:
    raise AssertionError("no header within 200 bytes was accepted")

# ---- _supervise: a fake process on real pipes, scripted from this thread
ROW = {"limits": {"run_seconds": 30, "stdout_kib": 64, "stderr_kib": 16}, "credential_return": True}


class Sink:
    def __init__(self):
        self.frames = []

    def __call__(self, frame):
        self.frames.append(frame)

    def stream(self, tag):
        return b"".join(base64.b64decode(f["b"]) for f in self.frames if f["t"] == tag)

    def everything(self):
        return json.dumps([f for f in self.frames if f["t"] != "end"]).encode() + b"".join(base64.b64decode(f["b"]) for f in self.frames if f["t"] in ("out", "err"))


class Proc:
    def __init__(self):
        self.out_r, self.out_w = os.pipe()
        self.err_r, self.err_w = os.pipe()

        class Wrap:
            def __init__(self, fd):
                self.fd = fd

            def fileno(self):
                return self.fd

        class Stdin:
            def write(self, data):
                return len(data)

            def flush(self):
                pass

            def close(self):
                pass

        self.stdout, self.stderr, self.stdin = Wrap(self.out_r), Wrap(self.err_r), Stdin()
        self.returncode = 0

    def poll(self):
        return None

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass

    def write_out(self, data):
        os.write(self.out_w, data)

    def close(self):
        os.close(self.out_w)
        os.close(self.err_w)


def supervise(script, row=ROW, eof=None, started_back=0, clock=time.monotonic):
    """Run _supervise in a thread against a Proc; ``script(proc)`` writes what the launcher would. Returns (sink, end frame or None, error)."""
    proc, sink, box = Proc(), Sink(), {}
    started = clock() - started_back

    def go():
        try:
            box["end"] = sh._supervise(proc, row, "ab" * 16, b"", sink, eof, started, clock)
        except sh.DeadMan as exc:
            box["dead"] = exc

    thread = threading.Thread(target=go, daemon=True)
    thread.start()
    script(proc)
    thread.join(20)
    must(not thread.is_alive(), "_supervise returned")
    for fd in (proc.out_r, proc.err_r):
        try:
            os.close(fd)
        except OSError:
            pass
    return sink, box.get("end"), box.get("dead")


def normal(proc):
    proc.write_out(HEADER + b"hi\n")
    time.sleep(0.15)
    proc.write_out(FRAME)
    proc.close()


sink, end, dead = supervise(normal)
must(end["reason"] == "exited" and sink.stream("out") == b"hi\n", (end, sink.stream("out")))
must(base64.b64decode(end["credential_b64"]) == REFRESHED.encode(), "the end frame keeps credential_b64")
no_secret(sink.everything(), "normal end")
must(REFRESHED.encode() not in json.dumps([f for f in sink.frames if f["t"] != "end"]).encode(), "no event but the end frame holds it")
# the same through a start of a real (fake-systemd) runner: the program's own text, its stderr, and the real launcher frame
make_runner("ai.cred", body=("d = os.environ['CREDENTIALS_DIRECTORY']\n"
                             "sys.stdout.write('got=' + open(os.path.join(d, 'auth')).read() + '\\n')\n"
                             "sys.stderr.write('CREDENTIALS_DIRECTORY and CRED are only words\\n')\n"
                             "open(os.path.join(os.environ['SANDBOX_OUT'], 'credential'), 'w').write('refreshed-' + open(os.path.join(d, 'auth')).read())"),
            credential_files=["auth"], credential_return=True)
code, frames = start(header("ai.cred", credentials={"auth": TOKEN}))
end = end_of(frames)
must(end["reason"] == "exited" and base64.b64decode(end["credential_b64"]).decode() == REFRESHED, end)
for tag in ("out", "err"):
    data = joined(frames, tag)
    must(REFRESHED.encode() not in data and base64.b64encode(REFRESHED.encode()) not in data and not re.search(rb"[0-9a-f]{32} CRED ", data) and b"TECTAC-SBX-LAUNCHER" not in data, (tag, data))
must(joined(frames, "out").decode().strip() == "got=" + TOKEN and b"CREDENTIALS_DIRECTORY and CRED" in joined(frames, "err"), "the program's own text comes through")
must(sum(1 for f in frames if f["t"] != "end" and "credential" in json.dumps(f)) == 0, "no non-end frame names a credential")
launcher_nonce = None  # the nonce is private to the launcher and the helper; it appears in no emitted frame
must(not re.search(r"[0-9a-f]{32} CRED", json.dumps(frames)), "no frame-shaped text in any emitted frame")


# ---- cancel in the middle of a frame
def cancel_script(proc):
    proc.write_out(HEADER + b"hi\n" + FRAME[:30])
    time.sleep(0.3)
    eof.set()
    time.sleep(0.4)
    proc.write_out(FRAME[30:])
    proc.close()


eof = threading.Event()
sink, end, dead = supervise(cancel_script, eof=eof)
must(dead is not None and end is None, "cancelled: DeadMan")
no_secret(sink.everything(), "cancel mid-frame")


# ---- timeout in the middle of a frame (the run's own deadline has passed)
def timeout_script(proc):
    proc.write_out(HEADER + b"hi\n" + FRAME[:30])
    time.sleep(0.4)
    proc.write_out(FRAME[30:])
    proc.close()


sink, end, dead = supervise(timeout_script, started_back=1000)
must(end is not None and end["reason"] == "timeout", end)
no_secret(sink.everything(), "timeout mid-frame")


# ---- the output cap reached before the frame, and during it
def flood_script(proc):
    proc.write_out(HEADER + b"x" * 4000 + FRAME)
    proc.close()


small = {"limits": {"run_seconds": 30, "stdout_kib": 1, "stderr_kib": 16}, "credential_return": True}
sink, end, dead = supervise(flood_script, row=small)
must(end["reason"] == "output_limit" and len(sink.stream("out")) <= 1024, end)
no_secret(sink.everything(), "cap before the frame")
exact = {"limits": {"run_seconds": 30, "stdout_kib": 1, "stderr_kib": 16}, "credential_return": True}
for filler in (1000, 1019, 1023, 1024, 1025):  # the cap lands before, at and after the frame's first bytes
    def cap_script(proc, filler=filler):
        proc.write_out(HEADER + b"y" * filler)
        time.sleep(0.1)
        proc.write_out(FRAME[:25])
        time.sleep(0.1)
        proc.write_out(FRAME[25:])
        proc.close()
    sink, end, dead = supervise(cap_script, row=exact)
    must(len(sink.stream("out")) <= 1024, (filler, len(sink.stream("out"))))
    no_secret(sink.everything(), f"cap during the frame, filler {filler}")


# ---- an oversized or garbled frame, a missing header and a premature end, through _supervise
def garbled(proc):
    proc.write_out(HEADER + b"hi" + FRAME[:39] + b"@@@@\nmore text\n")
    proc.close()


sink, end, dead = supervise(garbled)
must(end["reason"] == "exited" and end["credential_b64"] is None and sink.stream("out") == b"hi", (end, sink.stream("out")))


def no_header(proc):
    proc.write_out(b"TECTAC-SBX-LAUNCHER " + NONCE.encode()[:10])
    proc.close()


sink, end, dead = supervise(no_header)
must(end["reason"] == "start_failed" and sink.stream("out") == b"", (end, sink.stream("out")))
no_secret(sink.everything(), "premature end in the header")


def eof_partial(proc):
    proc.write_out(HEADER + b"done" + FRAME[:20])
    proc.close()


sink, end, dead = supervise(eof_partial)
must(sink.stream("out") == b"done", sink.stream("out"))
no_secret(sink.everything(), "stream ends with a held partial marker")
plain_row = {"limits": ROW["limits"], "credential_return": False}
sink, end, dead = supervise(normal, row=plain_row)
must(end["credential_b64"] is None, "a runner without credential_return never gets the flag")

# ---- the canary check: the real thing, not a word
CAN = {"stdout": b"CANARYROW\tcredential arrives\tOK\tarrived in CREDENTIALS_DIRECTORY\nCANARYROW\tx\tOK\tthe word CRED alone\n", "stderr": b"CRED CREDENTIALS_DIRECTORY\n",
       "end": {"reason": "exited", "exit": 0, "credential_b64": base64.b64encode(REFRESHED.encode()).decode(), "bytes_out": 5}, "refused": None}
F = sh.credential_leak_findings
must(F(TOKEN, CAN) == [], F(TOKEN, CAN))  # the 1.17.122 check ('CRED' in stdout) called this a leak
must("CRED" in CAN["stdout"].decode() and "CRED" in CAN["stderr"].decode(), "the words are really there")
forged = {**CAN, "stdout": CAN["stdout"] + b"\n" + os.urandom(16).hex().encode() + b" CRED " + b"QUJD\n"}
must(F(TOKEN, forged) == ["stdout: the nonce frame"], F(TOKEN, forged))
planted = {**CAN, "stdout": CAN["stdout"] + base64.b64encode(REFRESHED.encode()) + b"\n"}
must(F(TOKEN, planted) == ["stdout: the refreshed token (base64)"], F(TOKEN, planted))
for label, key, data, want in (("plain token on stdout", "stdout", TOKEN.encode(), "stdout: the token"), ("refreshed on stderr", "stderr", REFRESHED.encode(), "stderr: the refreshed token"),
                               ("header on stdout", "stdout", HEADER, "stdout: the launcher header"), ("token base64 on stderr", "stderr", base64.b64encode(TOKEN.encode()), "stderr: the token (base64)")):
    found = F(TOKEN, {**CAN, key: CAN[key] + data})
    must(want in found, (label, found))
leaky_end = {**CAN, "end": {**CAN["end"], "note": TOKEN}}
must(F(TOKEN, leaky_end) == ["end frame: the token"], "a field of the end frame other than credential_b64 holding the token")
must(F(TOKEN, {**CAN, "end": {k: v for k, v in CAN["end"].items() if k != "credential_b64"}}) == [], "credential_b64 itself is the one place the value belongs")
must(F(TOKEN, {**CAN, "refused": "x" + TOKEN}) == ["refusal: the token"], "a refusal text")
# the row reports exactly which checks found what, through _credential_rows with a fake collect
real = {"token": None}


def make_collect(extra_stdout=b"", extra_stderr=b""):
    def collect(group, plan, **kwargs):
        token = plan["credential_token"]
        refreshed = "refreshed-" + token
        return {"stdout": b"CANARYROW\tcredential arrives\tOK\tarrived in CREDENTIALS_DIRECTORY\nCANARYROW\tcredential mode\tOK\t0o400\nCANARYROW\tcredential not in environment\tOK\tabsent\n" + extra_stdout.replace(b"@T@", token.encode()),
                "stderr": extra_stderr, "end": {"reason": "exited", "exit": 0, "credential_b64": base64.b64encode(refreshed.encode()).decode()}, "refused": None}
    return collect


sh._holders_search = lambda token, unit: []
sh.SECRETS_ROOT = H.BASE / "secrets-none"
sh.time.sleep = lambda seconds: None
for label, extra_out, extra_err, verdict, part in (("clean", b"", b"", "OK", "stripped"), ("planted token", b"@T@\n", b"", "ATTACK SUCCEEDED", "found: stdout: the token"),
                                                   ("forged frame", b"\n" + b"a" * 32 + b" CRED QUJD\n", b"", "ATTACK SUCCEEDED", "stdout: the nonce frame"),
                                                   ("header on stderr", b"", HEADER, "ATTACK SUCCEEDED", "stderr: the launcher header")):
    rows = sh._credential_rows(make_collect(extra_out, extra_err), {"ready": True}, lambda unit: "DENIED", lambda unit: True)
    frame_row = [r for r in rows if r["attack"] == "credential frame stripped from output"]
    must(len(frame_row) == 1 and frame_row[0]["verdict"] == verdict and part in frame_row[0]["actual"], (label, frame_row))
    must("CREDENTIALS_DIRECTORY" in next(r for r in rows if r["attack"] == "credential arrives")["actual"] and next(r for r in rows if r["attack"] == "credential_return round trip")["verdict"] == "OK", rows)

# ---- the Django side: credential_b64 is read in one place and never logged, audited or put in out/err events
django = (H.ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
uses = [n for n, line in enumerate(django.splitlines(), 1) if "credential_b64" in line]
must(len(uses) == 2 and all("frame" in django.splitlines()[n - 1] for n in uses), ("credential_b64 appears outside _end_event", uses))
lines = django.splitlines()
start_end = next(n for n, line in enumerate(lines) if "def _end_event" in line)
must(all(start_end <= n - 1 <= start_end + 8 for n in uses), "only the end-event builder touches credential_b64")
must(not re.search(r"(logger|logging|log\.|print|audit)\w*\(.*credential", django), "no log, print or audit line names a credential value")
helper = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must(len([line for line in helper.splitlines() if "credential_b64" in line and "emit" in line]) == 0 and helper.count('"credential_b64": base64') == 1, "the helper puts credential_b64 into the end frame only")

print("[TEST] PASS sandbox credential frame 1.17.123")
