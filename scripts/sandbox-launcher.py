#!/usr/bin/python3
"""In-unit launcher for core.sandbox (Core 1.17.118, Patch 2).

The root helper starts every run as ``systemd-run ... python3 -I <this file> [--return-credential] -- <runner> <args>``. This small
Core-owned program runs inside the unit, as the unit's own unprivileged user, and does four things:

* prints one header line ``TECTAC-SBX-LAUNCHER <nonce>`` before the runner starts. The nonce is random, lives only in this process and is
  never given to the runner (this process also turns off its own dumpable flag, so the runner cannot read its memory);
* makes the runner's folders in the private /work tmpfs (home, tmp, out) and starts the runner as a child that shares this process's
  stdout and stderr, so the runner's output passes straight through to the helper's two pipes;
* watches stdout: when the reader is gone (the helper or its caller died), it kills the runner's process group and exits (a second dead-man
  switch beside the helper's own);
* with ``--return-credential``: after the runner has exited, sends the refreshed ``$SANDBOX_OUT/credential`` (a regular file, no symlink, at
  most 16 KiB) as one final line ``\n<nonce> CRED <base64>\n``. The helper takes only that line and strips it from the output. A runner
  cannot forge it: it does not know the nonce.

Why this exists: the plan had the root ExecStopPost read SANDBOX_OUT, but a ``+`` ExecStopPost runs outside the unit's mount namespace and
cannot see the unit's /work tmpfs.
"""
from __future__ import annotations

import base64
import os
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time

CREDENTIAL_MAX_BYTES = 16 * 1024
HEADER = "TECTAC-SBX-LAUNCHER"


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


def credential_line(nonce, data):
    return ("\n" + nonce + " CRED " + base64.b64encode(data).decode("ascii") + "\n").encode("ascii")


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
    if args and args[0] == "--return-credential":
        return_credential = True
        args = args[1:]
    if not args or args[0] != "--" or len(args) < 2:
        sys.stderr.write("usage: sandbox-launcher [--return-credential] -- <program> [args]\n")
        return 64
    command = args[1:]
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
    try:
        child = subprocess.Popen(command, close_fds=True, **options)
    except OSError as exc:
        sys.stderr.write(f"sandbox-launcher: cannot start the runner ({exc.strerror or 'error'})\n")
        return 127
    threading.Thread(target=_watch_stdout, args=(child,), daemon=True).start()
    code = child.wait()
    if code < 0:
        code = 128 - code
    if return_credential:
        data = read_credential(out_dir)
        if data is not None:
            try:
                _write_all(1, credential_line(nonce, data))
            except OSError:
                pass
    return code


if __name__ == "__main__":
    sys.exit(main())
