#!/usr/bin/python3
"""In-unit launcher for core.sandbox (Core 1.17.118, Patch 2; 1.18.8: credential slots).

The root helper starts every run as ``systemd-run ... python3 -I <this file> [--credential=<name> ...] [--return-credential] -- <runner> <args>``.
This small Core-owned program runs inside the unit, as the unit's own unprivileged user, and does five things:

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
  cannot forge it: it does not know the nonce.

Why this exists: the plan had the root ExecStopPost read SANDBOX_OUT, but a ``+`` ExecStopPost runs outside the unit's mount namespace and
cannot see the unit's /work tmpfs.
"""
from __future__ import annotations

import base64
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

CREDENTIAL_MAX_BYTES = 16 * 1024
CREDENTIAL_SLOTS_MAX = 2
CREDENTIAL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")  # the same rule as the helper's CREDENTIAL_NAME_RE
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
    names = []
    while args and (args[0] == "--return-credential" or args[0].startswith("--credential=")):
        if args[0] == "--return-credential":
            return_credential = True
        else:
            names.append(args[0][len("--credential="):])
        args = args[1:]
    if not args or args[0] != "--" or len(args) < 2:
        sys.stderr.write("usage: sandbox-launcher [--credential=<name> ...] [--return-credential] -- <program> [args]\n")
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
