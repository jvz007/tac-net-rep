#!/usr/bin/python3
"""In-unit launcher for core.sandbox (Core 1.17.118, Patch 2; 1.18.8: credential slots; 1.18.24: the egress forwarder).

The root helper starts every run as ``systemd-run ... python3 -I <this file> [--egress] [--credential=<name> ...] [--return-credential] -- <runner> <args>``.
This small Core-owned program runs inside the unit, as the unit's own unprivileged user, and does six things:

* 1.18.24 (AD-65 Patch B): with ``--egress`` (only a run whose runner declares allowed_hosts) it binds 127.0.0.1:3128 inside the unit's own network
  space BEFORE the runner starts and relays every connection, byte for byte and without parsing, to the AF_UNIX door at /run/egress/door.sock (the
  per-run folder the helper binds in read only). The proxy behind the door applies every rule; this relay decides nothing. One single-thread
  selectors loop (a thread per connection would eat the run's TasksMax), at most 16 live connections, idle and total limits. When the port cannot
  be bound or the door is missing the launcher ends with exit 70 and one plain stderr line: no run without the door it was promised;

* 1.18.8: the unit's LoadCredential files carry the fixed slot names ``cred0`` and ``cred1`` (no module text in a unit property). Each
  ``--credential=<name>`` argument (strict name, in slot order) becomes a symlink ``/work/credentials/<name>`` to
  ``$CREDENTIALS_DIRECTORY/cred<i>`` (the folder is 0700 and holds no secret), and the runner gets ``CREDENTIALS_DIRECTORY=/work/credentials``,
  so it still reads ``$CREDENTIALS_DIRECTORY/<declared name>`` and the file keeps its mode and ACL;

* prints one header line ``TECTAC-SBX-LAUNCHER <nonce>`` before the runner starts. The nonce is random, lives only in this process and is
  never given to the runner (this process also turns off its own dumpable flag, so the runner cannot read its memory);
* makes the runner's folders in the private /work tmpfs (home, tmp, out) and starts the runner as a child that shares this process's
  stdout and stderr, so the runner's output passes straight through to the helper's two pipes;
* watches stdout: when the reader is gone (the helper or its caller died), it kills the runner's process group and exits (a second dead-man
  switch beside the helper's own);
* with ``--return-credential``: after the runner has exited, sends the refreshed ``$SANDBOX_OUT/credential`` (a regular file, no symlink, at
  most 16 KiB) as one final line ``\n<nonce> CRED <base64>\n``. The helper takes only that line and strips it from the output. A runner
  cannot forge it: it does not know the nonce. 1.18.26: before the file is read, every other process of the unit's own user is killed
  and the launcher waits (about 2 seconds at most) until none is left; if one survives, no credential line is sent.

Why this exists: the plan had the root ExecStopPost read SANDBOX_OUT, but a ``+`` ExecStopPost runs outside the unit's mount namespace and
cannot see the unit's /work tmpfs.
"""
from __future__ import annotations

import base64
import errno
import os
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

CREDENTIAL_MAX_BYTES = 16 * 1024
CREDENTIAL_SLOTS_MAX = 2
CREDENTIAL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")  # the same rule as the helper's CREDENTIAL_NAME_RE
HEADER = "TECTAC-SBX-LAUNCHER"
FORWARD_HOST = "127.0.0.1"
FORWARD_PORT = 3128
DOOR_PATH = "/run/egress/door.sock"
FORWARD_MAX = 16  # live relayed connections; the 17th is closed at once
FORWARD_IDLE_SECONDS = 60
FORWARD_TOTAL_SECONDS = 600  # the longest a single relayed connection lives (the Core run ceiling)
FORWARD_CHUNK = 16384
FORWARD_BUFFER_MAX = 256 * 1024  # bytes held for one direction before reading from the other side pauses
EXIT_NO_DOOR = 70


class Forwarder:
    """127.0.0.1:3128 to the egress door, byte for byte. ``door_connect(path)`` returns a connected socket and is replaced by a test (a server has
    AF_UNIX; the tests on another system use a loopback socket). The loop runs in one thread and never starts another."""

    def __init__(self, *, host=FORWARD_HOST, port=FORWARD_PORT, door_path=DOOR_PATH, door_connect=None, max_live=FORWARD_MAX,
                 idle_seconds=FORWARD_IDLE_SECONDS, total_seconds=FORWARD_TOTAL_SECONDS, clock=time.monotonic):
        self.host, self.port, self.door_path = host, port, door_path
        self.door_connect = door_connect or self._connect_unix
        self.max_live, self.idle_seconds, self.total_seconds, self.clock = max_live, idle_seconds, total_seconds, clock
        self.listener = None
        self.selector = selectors.DefaultSelector()
        self.pairs = {}  # socket -> pair dict, for both ends
        self.stop = False
        self.thread = None

    @staticmethod
    def _connect_unix(path):
        if not hasattr(socket, "AF_UNIX"):  # not Linux (a test on another system): there is no door
            raise OSError(errno.EAFNOSUPPORT, "no unix sockets here")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(3)
            sock.connect(path)
        except OSError:
            sock.close()
            raise
        return sock

    def bind(self):
        """Bind the listener and prove the door answers. OSError when either fails (the caller ends the launcher with exit 70)."""
        probe = self.door_connect(self.door_path)
        probe.close()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(self.max_live + 4)
            listener.setblocking(False)
        except OSError:
            listener.close()
            raise
        self.listener = listener
        self.port = listener.getsockname()[1]
        self.selector.register(listener, selectors.EVENT_READ, None)

    def start(self):
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def live(self):
        return len({id(pair) for pair in self.pairs.values()})

    def _accept(self):
        try:
            client, _peer = self.listener.accept()
        except OSError:
            return
        if self.live() >= self.max_live:
            client.close()
            return
        try:
            door = self.door_connect(self.door_path)
        except OSError:
            client.close()
            return
        client.setblocking(False)
        door.setblocking(False)
        now = self.clock()
        pair = {"born": now, "seen": now, "out": {client: bytearray(), door: bytearray()}, "peer": {client: door, door: client},
                "reg": {client, door}}
        for sock in (client, door):
            self.pairs[sock] = pair
            self.selector.register(sock, selectors.EVENT_READ, pair)

    def _drop(self, pair):
        for sock in list(pair["peer"]):
            if sock in self.pairs:
                if sock in pair["reg"]:
                    try:
                        self.selector.unregister(sock)
                    except (KeyError, ValueError):
                        pass
                    pair["reg"].discard(sock)
                self.pairs.pop(sock, None)
            try:
                sock.close()
            except OSError:
                pass

    def _flush(self, pair, sock):
        """Send what is waiting for ``sock``. False when the connection is gone."""
        buffer = pair["out"][sock]
        while buffer:
            try:
                sent = sock.send(buffer)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                return False
            if sent <= 0:
                return False
            del buffer[:sent]
        self._interest(pair, sock)
        self._interest(pair, pair["peer"][sock])
        return True

    def _interest(self, pair, sock):
        """What ``sock`` is watched for: reads unless the other side's buffer is full, writes while its own buffer holds bytes."""
        if sock not in self.pairs:
            return
        mask = selectors.EVENT_READ
        if pair["out"][sock]:
            mask |= selectors.EVENT_WRITE
        if len(pair["out"][pair["peer"][sock]]) >= FORWARD_BUFFER_MAX:
            mask &= ~selectors.EVENT_READ  # the other side is not draining: stop reading until it does
        registered = sock in pair["reg"]
        try:
            if mask and registered:
                self.selector.modify(sock, mask, pair)
            elif mask:
                self.selector.register(sock, mask, pair)
                pair["reg"].add(sock)
            elif registered:
                self.selector.unregister(sock)
                pair["reg"].discard(sock)
        except (KeyError, ValueError, OSError):
            pass

    def _event(self, sock, mask, pair):
        if mask & selectors.EVENT_WRITE and not self._flush(pair, sock):
            self._drop(pair)
            return
        if mask & selectors.EVENT_READ:
            try:
                data = sock.recv(FORWARD_CHUNK)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                self._drop(pair)
                return
            if not data:
                self._drop(pair)  # either side closing ends the tunnel
                return
            pair["seen"] = self.clock()
            peer = pair["peer"][sock]
            pair["out"][peer].extend(data)
            if not self._flush(pair, peer):
                self._drop(pair)

    def _expire(self):
        now = self.clock()
        for pair in {id(p): p for p in self.pairs.values()}.values():
            if now - pair["seen"] >= self.idle_seconds or now - pair["born"] >= self.total_seconds:
                self._drop(pair)

    def step(self, timeout=0.5):
        """One turn of the loop (a test calls this). Returns the number of events handled."""
        handled = 0
        for key, mask in self.selector.select(timeout):
            handled += 1
            if key.data is None:
                self._accept()
            elif key.fileobj in self.pairs:
                self._event(key.fileobj, mask, key.data)
        self._expire()
        return handled

    def loop(self):
        while not self.stop:
            try:
                self.step(0.5)
            except (OSError, ValueError):
                continue

    def close(self):
        self.stop = True
        for pair in {id(p): p for p in self.pairs.values()}.values():
            self._drop(pair)
        if self.listener is not None:
            try:
                self.selector.unregister(self.listener)
            except (KeyError, ValueError):
                pass
            self.listener.close()
            self.listener = None


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _not_dumpable():
    """Best effort: a non-dumpable process cannot be read through /proc/<pid>/mem by its own child."""
    try:
        import ctypes

        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 4
    except (ImportError, OSError, AttributeError, TypeError):  # not Linux, or no libc: the nonce is still unknown to the runner
        return


def read_credential(out_dir):
    """The refreshed credential bytes, or None. Regular file only (lstat, O_NOFOLLOW), at most 16 KiB."""
    path = os.path.join(out_dir, "credential")
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > CREDENTIAL_MAX_BYTES:
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            data = os.read(fd, CREDENTIAL_MAX_BYTES + 1)
        finally:
            os.close(fd)
    except OSError:
        return None
    return data if len(data) <= CREDENTIAL_MAX_BYTES else None


def link_credentials(names, source, work):
    """Make ``<work>/credentials/<name>`` for each name whose slot file exists in ``source`` (the real CREDENTIALS_DIRECTORY). A name that fails
    the strict rule, a slot past the second and a missing slot file are skipped (never an error); slot i belongs to the i-th name. The links
    hold no secret. Returns the new folder, or None when nothing was linked. Where symlinks do not exist (the tests on a non-POSIX system)
    the slot file is copied instead; a server always has symlinks."""
    if not names or not source:
        return None
    folder = os.path.join(work, "credentials")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    try:
        os.chmod(folder, 0o700)
    except OSError:
        pass
    linked = 0
    for index, name in enumerate(names[:CREDENTIAL_SLOTS_MAX]):
        if not CREDENTIAL_NAME_RE.fullmatch(name):
            continue
        slot = os.path.join(source, f"cred{index}")
        if not os.path.lexists(slot):
            continue
        target = os.path.join(folder, name)
        try:
            if os.path.lexists(target):
                os.unlink(target)  # a reused work folder behaves like a fresh one
            if os.name == "posix":
                os.symlink(slot, target)
            else:
                shutil.copyfile(slot, target)
            linked += 1
        except OSError:
            continue
    return folder if linked else None


def credential_line(nonce, data):
    return ("\n" + nonce + " CRED " + base64.b64encode(data).decode("ascii") + "\n").encode("ascii")


LEFTOVER_SECONDS = 2.0  # 1.18.26: how long the launcher waits for the run's own leftover processes to be gone
LEFTOVER_STEP = 0.02


def _process_state(proc_root, pid):
    """The one-letter state of a process from ``<proc_root>/<pid>/stat`` (the field after the closing bracket of the name), or None."""
    try:
        with open(os.path.join(proc_root, pid, "stat"), "rb") as handle:
            data = handle.read(4096).decode("ascii", "replace")
    except OSError:
        return None
    tail = data.rpartition(")")[2].split()
    return tail[0] if tail else None


def other_processes(proc_root="/proc", *, listdir=os.listdir, stat=os.stat, uid=None, own_pid=None):
    """1.18.26: the live processes of this unit's own user other than this one. A unit's DynamicUser is unique to the unit, so every process
    of that uid belongs to this run. A zombie or a process that has just gone is not counted (it can run nothing)."""
    if uid is None:
        if not hasattr(os, "getuid"):
            return None  # no user ids here (tests on another system): not proven clean
        uid = os.getuid()
    own_pid = os.getpid() if own_pid is None else own_pid
    found = []
    try:
        names = listdir(proc_root)
    except OSError:
        return None  # the table cannot be read: the caller must treat that as "not proven clean"
    for name in names:
        if not name.isdigit() or int(name) == own_pid:
            continue
        try:
            if stat(os.path.join(proc_root, name)).st_uid != uid:
                continue
        except OSError:
            continue
        if _process_state(proc_root, name) in (None, "Z", "X"):
            continue
        found.append(int(name))
    return found


def _reap_children():
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except (OSError, AttributeError):
            return
        if pid == 0:
            return


def kill_leftovers(*, kill=os.kill, reap=_reap_children, others=other_processes, clock=time.monotonic, sleep=time.sleep,
                   seconds=LEFTOVER_SECONDS):
    """1.18.26 (AD-65 Patch C): the runner has exited, but it may have left a process behind that keeps writing ``$SANDBOX_OUT/credential``.
    Kill every other process of the unit's own user (``kill(-1, SIGKILL)`` never signals the caller, and init is excluded; the DynamicUser is
    unique to the unit, so only this run's processes are hit), reap what became a child of this one, and look again until none is left or the
    short deadline passes. Returns True only when the table was read and held no other live process: otherwise the caller sends no credential."""
    sig = getattr(signal, "SIGKILL", 9)  # 9 only where signal has no SIGKILL (tests on another system)
    deadline = clock() + seconds
    while True:
        try:
            kill(-1, sig)
        except OSError:
            pass  # ESRCH: nothing left to signal
        reap()
        left = others()
        if left is not None and not left:
            return True
        if clock() >= deadline:
            return False
        sleep(LEFTOVER_STEP)


def _watch_stdout(child, interval=0.5):
    try:
        import select

        poller = select.poll()
        poller.register(1, 0)  # POLLERR and POLLHUP are always reported
    except (ImportError, OSError, AttributeError, TypeError):
        return  # no poll here (tests on another system): the helper's own dead-man switch still applies
    while child.poll() is None:
        for _fd, event in poller.poll(int(interval * 1000)):
            if event & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except OSError:
                    child.kill()
                os._exit(1)
        time.sleep(0.05)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    return_credential = False
    egress = False
    names = []
    while args and (args[0] in ("--return-credential", "--egress") or args[0].startswith("--credential=")):
        if args[0] == "--return-credential":
            return_credential = True
        elif args[0] == "--egress":
            egress = True
        else:
            names.append(args[0][len("--credential="):])
        args = args[1:]
    if not args or args[0] != "--" or len(args) < 2:
        sys.stderr.write("usage: sandbox-launcher [--egress] [--credential=<name> ...] [--return-credential] -- <program> [args]\n")
        return 64
    command = args[1:]
    forwarder = None
    if egress:  # 1.18.24: the door is promised, so a run without it never starts
        forwarder = Forwarder()
        try:
            forwarder.bind()
        except OSError as exc:
            sys.stderr.write(f"sandbox-launcher: the egress door is not available ({exc.strerror or 'error'})\n")
            return EXIT_NO_DOOR
        forwarder.start()
    nonce = secrets.token_hex(16)
    _not_dumpable()
    _write_all(1, (HEADER + " " + nonce + "\n").encode("ascii"))
    work = os.environ.get("SANDBOX_WORK", "/work")
    out_dir = os.environ.get("SANDBOX_OUT", os.path.join(work, "out"))
    for folder in (os.environ.get("HOME", os.path.join(work, "home")), os.environ.get("TMPDIR", os.path.join(work, "tmp")), out_dir):
        os.makedirs(folder, mode=0o700, exist_ok=True)
    try:
        os.chdir(work)
    except OSError:
        pass
    options = {"start_new_session": True} if os.name == "posix" else {}
    child_env = dict(os.environ)
    credentials = link_credentials(names, os.environ.get("CREDENTIALS_DIRECTORY"), work)
    if credentials:
        child_env["CREDENTIALS_DIRECTORY"] = credentials
    elif names:
        child_env.pop("CREDENTIALS_DIRECTORY", None)  # slots were declared but none could be linked: the runner finds no file, never the raw slot folder
    try:
        child = subprocess.Popen(command, close_fds=True, env=child_env, **options)
    except OSError as exc:
        sys.stderr.write(f"sandbox-launcher: cannot start the runner ({exc.strerror or 'error'})\n")
        if forwarder is not None:
            forwarder.close()
        return 127
    threading.Thread(target=_watch_stdout, args=(child,), daemon=True).start()
    code = child.wait()
    if forwarder is not None:
        forwarder.close()  # the listener closes when the runner exits
    if code < 0:
        code = 128 - code
    if return_credential:
        # 1.18.26: a leftover of the runner could rewrite the credential file after it is read. Nothing else of this run may be alive first;
        # when that is not proven inside the deadline, no credential frame is sent (the helper then reports no credentials_out).
        data = read_credential(out_dir) if kill_leftovers() else None
        if data is not None:
            try:
                _write_all(1, credential_line(nonce, data))
            except OSError:
                pass
    return code


if __name__ == "__main__":
    sys.exit(main())
