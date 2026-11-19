#!/usr/bin/env python3
"""1.18.24 regression (AD-65 Patch B, item 3): the in-unit forwarder of scripts/sandbox-launcher.py (127.0.0.1:3128 to the egress door).

Django-free, 127.0.0.1 only. The door is a fake TCP echo server on an ephemeral loopback port (a development PC has no AF_UNIX); the forwarder
listens on an ephemeral loopback port too, never on 3128, never on 0.0.0.0, never on a public address. Covered:

* bytes are relayed both ways, byte for byte and unparsed (all 256 byte values, a 1 MiB body, text that is not HTTP);
* at most 16 live connections: the 17th is closed at once; a closed connection frees its place;
* the whole forwarder is one loop thread (no thread per connection);
* an idle connection and a connection past the total limit are closed;
* a door that does not answer or a port that cannot be bound ends the launcher with exit 70 and a plain stderr line, before the runner starts
  and before any header is printed;
* the listener is closed when the runner exits; without --egress no forwarder exists;
* the launcher keeps its other arguments (--credential, --return-credential) beside --egress.

Not runnable here: the real AF_UNIX door inside a unit (dev02: tests/sandbox-canary-1.18.24.sh).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_launcher_fw", ROOT / "scripts" / "sandbox-launcher.py")
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
must(b"\r" not in (ROOT / "scripts" / "sandbox-launcher.py").read_bytes(), "the launcher keeps LF")
must((L.FORWARD_HOST, L.FORWARD_PORT, L.DOOR_PATH, L.FORWARD_MAX, L.EXIT_NO_DOOR) == ("127.0.0.1", 3128, "/run/egress/door.sock", 16, 70), "the constants")


class Door:
    """A fake door: a loopback echo server that records what reached it."""

    def __init__(self, mode="echo"):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.addr = self.srv.getsockname()
        self.mode = mode
        self.received = bytearray()
        self.opened = 0
        self.stop = False
        threading.Thread(target=self.work, daemon=True).start()

    def connect(self, path):
        return socket.create_connection(self.addr, timeout=3)

    def work(self):
        while not self.stop:
            try:
                conn, _peer = self.srv.accept()
            except OSError:
                return
            self.opened += 1
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                self.received.extend(data)
                if self.mode == "echo":
                    conn.sendall(data)
                elif self.mode == "reverse":
                    conn.sendall(data[::-1])
        except OSError:
            return
        finally:
            conn.close()

    def close(self):
        self.stop = True
        self.srv.close()


def started(door, **kw):
    fw = L.Forwarder(port=0, door_connect=door.connect, **kw)
    fw.bind()
    fw.start()
    return fw


def client(fw):
    return socket.create_connection(("127.0.0.1", fw.port), timeout=5)


def read_exactly(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(min(65536, n - len(data)))
        if not chunk:
            break
        data += chunk
    return data


# ------------------------------------------------------------------------------------------------ the relay: both ways, byte for byte
door = Door()
fw = started(door)
must(fw.host == "127.0.0.1" and fw.listener.getsockname()[0] == "127.0.0.1", "it listens on 127.0.0.1 only")
c = client(fw)
every = bytes(range(256)) * 4
c.sendall(every)
must(read_exactly(c, len(every)) == every and bytes(door.received) == every, "all byte values come back unchanged")
body = os.urandom(1024 * 1024)
sender = threading.Thread(target=lambda: c.sendall(body), daemon=True)
sender.start()
must(read_exactly(c, len(body)) == body, "a 1 MiB body is relayed both ways")
sender.join(10)
c.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nnot parsed: \x00\xff\r\n\r\n")
must(read_exactly(c, 40)[:7] == b"CONNECT", "text that looks like a request is just bytes")
c.close()
time.sleep(0.3)
fw.close()
door.close()
door = Door("reverse")
fw = started(door)
c = client(fw)
c.sendall(b"abcdef")
must(read_exactly(c, 6) == b"fedcba", "bytes from the door come back to the client untouched")
c.close()
fw.close()
door.close()

# ------------------------------------------------------------------------------------------------ at most 16 live connections
door = Door()
fw = started(door)
held = []
for _ in range(16):
    c = client(fw)
    c.sendall(b"x")
    must(read_exactly(c, 1) == b"x", "a live connection works")
    held.append(c)
must(fw.live() == 16, fw.live())
extra = client(fw)
extra.settimeout(3)
try:
    closed = extra.recv(16) == b""
except OSError:
    closed = True
must(closed, "the 17th connection is closed at once")
extra.close()
held[0].close()
time.sleep(0.6)
again = client(fw)
again.sendall(b"y")
must(read_exactly(again, 1) == b"y", "a closed connection frees its place")
again.close()
for c in held:
    c.close()
before = threading.active_count()
more = [client(fw) for _ in range(10)]
for c in more:
    c.sendall(b"z")
for c in more:
    must(read_exactly(c, 1) == b"z", "relay")
must(threading.active_count() <= before + 1 and sum(1 for t in threading.enumerate() if t.daemon and t.is_alive()) <= before + 12, "no thread per connection")
must(fw.thread is not None and fw.thread.is_alive(), "one loop thread")
for c in more:
    c.close()
fw.close()
door.close()

# ------------------------------------------------------------------------------------------------ idle and total limits (driven by hand with a fake clock)
clock = {"now": 100.0}
door = Door()
fw = L.Forwarder(port=0, door_connect=door.connect, idle_seconds=60, total_seconds=600, clock=lambda: clock["now"])
fw.bind()
c = client(fw)
for _ in range(10):
    fw.step(0.05)
must(fw.live() == 1, "the connection is accepted")
clock["now"] += 59
fw.step(0.05)
must(fw.live() == 1, "59 s of silence is not idle yet")
c.sendall(b"ping")
for _ in range(20):
    fw.step(0.05)
must(read_exactly(c, 4) == b"ping", "traffic keeps it alive")
clock["now"] += 61
fw.step(0.05)
must(fw.live() == 0, "60 s without a byte closes it")
c.close()
c = client(fw)
for _ in range(10):
    fw.step(0.05)
for _ in range(11):  # traffic every 59 s: never idle, but the total limit of 600 s ends it
    clock["now"] += 59
    c.sendall(b"k")
    for _ in range(10):
        fw.step(0.02)
fw.step(0.05)
must(fw.live() == 0, "a connection past its total limit is closed")
c.close()
fw.close()
door.close()

# ------------------------------------------------------------------------------------------------ main(): exit 70, the close on exit, the arguments
def fd1_captured(call):
    """Run ``call`` with file descriptor 1 pointing at a temp file; returns (result, what was written to fd 1)."""
    with tempfile.TemporaryFile() as tmp:
        saved = os.dup(1)
        sys.stdout.flush()
        os.dup2(tmp.fileno(), 1)
        try:
            result = call()
        finally:
            sys.stdout.flush()
            os.dup2(saved, 1)
            os.close(saved)
        tmp.seek(0)
        return result, tmp.read()


command = ["--", sys.executable, "-c", "pass"]
err = io.StringIO()
with contextlib.redirect_stderr(err):
    code, out = fd1_captured(lambda: L.main(["--egress", *command]))  # no AF_UNIX door here (or no /run/egress): the door cannot be reached
must(code == 70 and "egress door is not available" in err.getvalue(), (code, err.getvalue()))
must(out == b"", "no header is printed and the runner never started")

# a door that works but a port that cannot be bound
door = Door()
taken = socket.socket()
taken.bind(("127.0.0.1", 0))
taken.listen(1)
real = L.Forwarder
L.Forwarder = lambda: real(host="127.0.0.1", port=taken.getsockname()[1], door_connect=door.connect)
err = io.StringIO()
try:
    with contextlib.redirect_stderr(err):
        code, out = fd1_captured(lambda: L.main(["--egress", *command]))
finally:
    L.Forwarder = real
must(code == 70 and "egress door is not available" in err.getvalue() and out == b"", ("a port that cannot be bound is exit 70", code, err.getvalue()))
taken.close()

# a working door: the listener exists while the runner runs and is closed when it exits
made = []


def make():
    forwarder = real(host="127.0.0.1", port=0, door_connect=door.connect)
    made.append(forwarder)
    return forwarder


L.Forwarder = make
seen = {}
sleeper = ["--", sys.executable, "-c", "import time; time.sleep(1.5)"]
runner = threading.Thread(target=lambda: seen.update(result=fd1_captured(lambda: L.main(["--egress", "--credential=auth", "--return-credential", *sleeper]))), daemon=True)
runner.start()
for _ in range(100):
    if made and made[0].listener is not None:
        break
    time.sleep(0.02)
must(made and made[0].listener is not None, "the listener is bound before the runner starts")
port = made[0].listener.getsockname()[1]
c = socket.create_connection(("127.0.0.1", port), timeout=3)
c.sendall(b"hello")
must(read_exactly(c, 5) == b"hello", "the forwarder works while the runner runs")
c.close()
runner.join(15)
L.Forwarder = real
code, out = seen["result"]
must(code == 0 and out.startswith(b"TECTAC-SBX-LAUNCHER "), (code, out[:40]))
must(made[0].listener is None, "the listener is closed when the runner exits")
try:
    socket.create_connection(("127.0.0.1", port), timeout=1).close()
except OSError:
    pass
else:
    raise AssertionError("the port still answers after the runner exited")
door.close()

# without --egress there is no forwarder at all
created = []
L.Forwarder = lambda: created.append(1)
try:
    code, out = fd1_captured(lambda: L.main(command))
finally:
    L.Forwarder = real
must(code == 0 and created == [], "no --egress: no forwarder")
# a missing separator is still the usage error
with contextlib.redirect_stderr(io.StringIO()):
    must(L.main(["--egress"]) == 64, "usage")
print("[TEST] PASS sandbox launcher forwarder 1.18.24")
