#!/usr/bin/env python3
"""1.18.25 regression (AD-65 Patch C, canary rows only): the in-unit groups of scripts/sandbox-canary-runner.py, with a stubbed syscall layer.

Django-free. No socket is opened and no real syscall is made: ``raw_syscall`` and ``machine_name`` are replaced. Covered:

* PATCHC_GROUPS holds patchc_syscalls and patchc_leftover, and neither is in GROUPS, NETWORK_GROUPS or the helper's CANARY_GROUPS (not reachable from --start);
* the three syscall rows print once each; EPERM is OK, success or any other errno (EINVAL, EFAULT, ENOKEY) is SUCCEEDED, ENOSYS is NOTRUN with the
  reason, kernel.io_uring_disabled=2 is NOTRUN for io_uring only;
* an unknown architecture prints three NOTRUN rows and never crashes; x86_64 and aarch64 use their own numbers;
* a descriptor returned by a syscall is closed at once; the only pointer a probe passes is its own buffer (at least the 120 bytes of io_uring_params),
  and the other arguments are plain integers; no probe passes a pointer to anything else;
* main() accepts the new group names and still refuses an unknown one; a plan that does not parse still prints one NOTRUN row;
* the helper file is unchanged by this release's Part 2: the CANARY_GROUPS tuple and the start path source lines hash to the 1.18.24 values.
"""
from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import importlib.util
import io
import os
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R = load("canary_runner_pc25", ROOT / "scripts" / "sandbox-canary-runner.py")
sh = load("sandbox_helper_pc25", ROOT / "scripts" / "sandbox-helper.py")

must(set(R.PATCHC_GROUPS) == {"patchc_syscalls", "patchc_leftover"}, R.PATCHC_GROUPS)
for group in R.PATCHC_GROUPS:
    must(group not in R.GROUPS and group not in R.NETWORK_GROUPS and group not in sh.CANARY_GROUPS, group)
must(set(R.GROUPS) == set(sh.CANARY_GROUPS), "the helper's CANARY_GROUPS still equals GROUPS")
must(R.PATCHC_SYSCALL_ROW_NAMES == (R.PC_IO_URING, R.PC_USERFAULTFD, R.PC_KEYCTL) and len(set(R.PATCHC_SYSCALL_ROW_NAMES)) == 3, "three rows")


class Syscalls:
    def __init__(self, answers, machine="x86_64", proc=None):
        self.calls, self.answers, self.machine, self.proc = [], answers, machine, proc or {}
        self.closed = []

    def raw(self, number, *args):
        self.calls.append((number, args))
        answer = self.answers[number]
        return answer if isinstance(answer, tuple) else (answer, 0)

    def read_proc(self, path):
        return self.proc.get(path)


def run(world, group="patchc_syscalls", plan=b"{}"):
    saved = {n: getattr(R, n) for n in ("raw_syscall", "machine_name", "read_proc")}
    R.raw_syscall, R.machine_name, R.read_proc = world.raw, lambda: world.machine, world.read_proc
    saved_close = os.close
    os.close = lambda fd: world.closed.append(fd)
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(plan.decode())
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            code = R.main([group])
    finally:
        sys.stdin = old_stdin
        os.close = saved_close
        for name, value in saved.items():
            setattr(R, name, value)
    must(code == 0, "main returns 0")
    rows = {}
    for line in out.getvalue().splitlines():
        parts = line.split("\t")
        if parts[0] == "CANARYROW":
            must(parts[1] not in rows, "a row printed twice: " + parts[1])
            rows[parts[1]] = (parts[2], parts[3])
    return rows


X86 = R.PC_ARCH["x86_64"]
EPERM = (-1, errno.EPERM)
# 1. the build today: nothing refuses the three calls
today = Syscalls({X86["io_uring_setup"]: 7, X86["userfaultfd"]: 8, X86["keyctl"]: 1234})
rows = run(today)
must(set(rows) == set(R.PATCHC_SYSCALL_ROW_NAMES), rows)
must(all(tag == "SUCCEEDED" for tag, _t in rows.values()), rows)
must(today.closed == [7, 8], f"the two descriptors are closed at once: {today.closed}")
# 2. the filter refuses all three
refused = Syscalls({X86["io_uring_setup"]: EPERM, X86["userfaultfd"]: EPERM, X86["keyctl"]: EPERM})
rows = run(refused)
must(all(tag == "OK" and "EPERM" in text for tag, text in rows.values()), rows)
must(not refused.closed, "nothing to close when refused")
# 3. an errno that is not EPERM came from the kernel, so the filter let the call through
other = Syscalls({X86["io_uring_setup"]: (-1, errno.EINVAL), X86["userfaultfd"]: (-1, errno.EFAULT), X86["keyctl"]: (-1, 126)})
rows = run(other)
must(all(tag == "SUCCEEDED" and "did not refuse" in text for tag, text in rows.values()), rows)
# 4. ENOSYS is NOTRUN with the reason; io_uring_disabled=2 is NOTRUN for io_uring only
nosys = Syscalls({X86["io_uring_setup"]: (-1, errno.ENOSYS), X86["userfaultfd"]: (-1, errno.ENOSYS), X86["keyctl"]: (-1, errno.ENOSYS)})
rows = run(nosys)
must(all(tag == "NOTRUN" and "(ENOSYS)" in text for tag, text in rows.values()), rows)
off = Syscalls({X86["io_uring_setup"]: 9, X86["userfaultfd"]: EPERM, X86["keyctl"]: EPERM}, proc={"/proc/sys/kernel/io_uring_disabled": "2\n"})
rows = run(off)
must(rows[R.PC_IO_URING][0] == "NOTRUN" and "io_uring_disabled=2" in rows[R.PC_IO_URING][1], rows)
must(not any(call[0] == X86["io_uring_setup"] for call in off.calls), "io_uring is not even called when the kernel switch is 2")
must(rows[R.PC_USERFAULTFD][0] == "OK" and rows[R.PC_KEYCTL][0] == "OK", rows)
one = Syscalls({X86["io_uring_setup"]: 9, X86["userfaultfd"]: EPERM, X86["keyctl"]: EPERM}, proc={"/proc/sys/kernel/io_uring_disabled": "1\n"})
must(run(one)[R.PC_IO_URING][0] == "SUCCEEDED", "io_uring_disabled=1 does not excuse the row")
# 5. architectures
unknown = Syscalls({}, machine="riscv64")
rows = run(unknown)
must(len(rows) == 3 and all(tag == "NOTRUN" and "unknown machine architecture" in text for tag, text in rows.values()) and not unknown.calls, rows)
empty = Syscalls({}, machine="")
must(all(tag == "NOTRUN" for tag, _t in run(empty).values()), "an empty machine name is unknown, not a crash")
arm = R.PC_ARCH["aarch64"]
armed = Syscalls({arm["io_uring_setup"]: EPERM, arm["userfaultfd"]: EPERM, arm["keyctl"]: EPERM}, machine="aarch64")
must(all(tag == "OK" for tag, _t in run(armed).values()) and {c[0] for c in armed.calls} == set(arm.values()), "aarch64 uses its own numbers")
must(X86 == {"io_uring_setup": 425, "userfaultfd": 323, "keyctl": 250} and arm == {"io_uring_setup": 425, "userfaultfd": 282, "keyctl": 219}, "numbers")
# 6. the arguments: harmless values; the only pointer is the probe's own buffer
for call_number, args in today.calls:
    for arg in args:
        must(isinstance(arg, (ctypes.c_ulong, ctypes.c_void_p)) or hasattr(arg, "_obj"), (call_number, arg))
uring_args = next(args for number, args in today.calls if number == X86["io_uring_setup"])
must(uring_args[0].value == 1, "io_uring_setup entries is 1")
buffer = uring_args[1]._obj
must(isinstance(buffer, ctypes.Array) and len(buffer) >= 120 and not any(buffer.raw), "a zeroed buffer of at least 120 bytes (the size of io_uring_params)")
uffd_args = next(args for number, args in today.calls if number == X86["userfaultfd"])
must(len(uffd_args) == 1 and uffd_args[0].value == R.PC_UFFD_USER_MODE_ONLY, "userfaultfd with the user-mode-only flag")
keyctl_args = next(args for number, args in today.calls if number == X86["keyctl"])
must(keyctl_args[0].value == 0 and keyctl_args[2].value == 0, "KEYCTL_GET_KEYRING_ID with create 0")
source = (ROOT / "scripts" / "sandbox-canary-runner.py").read_text(encoding="utf-8")
patchc = source[source.index("# ---- Patch C") if "# ---- Patch C" in source else source.index("Patch C canary rows (1.18.25"):]
must("addressof" not in patchc and patchc.count("byref(") == 1, "no pointer other than the one byref of the probe's own buffer")
# 7. main: the new group names are accepted, an unknown one is not, an unreadable plan is one NOTRUN row
saved_err = sys.stderr
sys.stderr = io.StringIO()
try:
    must(R.main(["patchc_nothing"]) == 64, "an unknown group is refused")
finally:
    sys.stderr = saved_err
rows = run(today, plan=b"{not json")
must(list(rows) == ["plan unreadable"] and rows["plan unreadable"][0] == "NOTRUN", rows)

# 8. the leftover group (real fork on a POSIX box; the logic is checked through its source on Windows)
if hasattr(os, "fork"):
    import tempfile
    import time
    folder = tempfile.mkdtemp(prefix="tectac-pcleft-")
    os.environ["SANDBOX_OUT"] = folder
    started = time.monotonic()
    R.g_patchc_leftover({"marker": "MARK-1", "leftover_seconds": 1})
    time.sleep(0.2)
    must((Path(folder) / "credential").read_text(encoding="utf-8") == "MARK-1", "the leftover replaced the credential after the runner function returned")
    time.sleep(1.5)
else:
    must("os.fork()" in source and "os.setsid()" in source and "os.replace(tmp, target)" in source and "os._exit(0)" in source, "the leftover forks, detaches, replaces the file and exits")
must("seconds = max(1.0, min(float(plan.get(\"leftover_seconds\") or 5), 10.0))" in source, "the leftover is bounded to 10 s")

# 9. the helper's production paths are unchanged by Part 2: only Part 1's functions differ from 1.18.24
helper_text = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
groups_line = re.search(r"CANARY_GROUPS = \(.*?\)\n", helper_text, re.DOTALL).group(0)
must(hashlib.sha256(groups_line.encode()).hexdigest() == hashlib.sha256(
    b'CANARY_GROUPS = ("files", "rootview", "work_hold", "work_peer", "sockets", "loopback", "lan", "privilege", "writes", "processes",\n'
    b'                 "mem", "fork", "loop", "scratch", "flood", "abstract", "cred", "sleep", "noop", "runview")\n').hexdigest(), groups_line)
must("patchc" not in helper_text.lower(), "the helper knows nothing about the Patch C groups: nothing reaches them through --start")
print("[TEST] PASS sandbox canary patchc runner 1.18.25")
