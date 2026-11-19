#!/usr/bin/env python3
"""1.17.124 regression: runs no longer get AF_UNIX (core.sandbox canary, fix 1, Medium R1: abstract unix sockets were reachable).

* the unit gets exactly 'RestrictAddressFamilies=AF_INET': no AF_UNIX, no AF_INET6;
* with socket(AF_UNIX) refused (EAFNOSUPPORT), the in-unit probes must not crash: g_sockets still prints its 13 rows, g_abstract reports a
  refusal at creation as OK 'all refused', a connect that works is ATTACK SUCCEEDED, and a socket that can be created at all is ATTACK SUCCEEDED
  on the 'unix socket creation refused' rows (the filter is not in force);
* the positive controls (socketpair, pipe, a child process with stdio pipes) work on a real interpreter, and a forced failure is NOT RUN;
* CANARY_REQUIRED turns a missing new row into NOT RUN.

Not runnable here: real seccomp on dev02 (the Windows or Linux interpreter running this test has no such filter).
"""
from __future__ import annotations

import errno
import importlib.util
import socket as real_socket
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_124u", "sandbox-harness-1.17.118.py")
sh, must, make_runner, start, header, unit_log = H.sh, H.must, H.make_runner, H.start, H.header, H.unit_log
spec = importlib.util.spec_from_file_location("canary_runner_124u", H.ROOT / "scripts" / "sandbox-canary-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
EAF = errno.errorcode.get(errno.EAFNOSUPPORT, "error")
EPERM = errno.errorcode.get(errno.EPERM, "error")

# ---- the unit: exactly AF_INET, through a real start
H.write_ready_status()
make_runner("ai.chat", body="print('hello')")
code, frames = start(header("ai.chat"))
props = unit_log(frames[0]["run_id"])["props"]
families = [p for p in props if p.startswith("RestrictAddressFamilies")]
must(families == ["RestrictAddressFamilies=AF_INET"], families)  # 1.17.123 said AF_INET AF_UNIX
must("AF_UNIX" not in " ".join(props) and "AF_INET6" not in " ".join(props), props)
source = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must("AF_INET AF_UNIX" not in source, "the helper no longer says AF_INET AF_UNIX anywhere")


# ---- a fake socket module: AF_UNIX can be refused, or created with a chosen connect result
class FakeSocket:
    def __init__(self, module):
        self.module = module

    def settimeout(self, value):
        pass

    def connect(self, address):
        if self.module.connect_errno is not None:
            raise OSError(self.module.connect_errno, "connect failed")

    def bind(self, address):
        if self.module.bind_errno is not None:
            raise OSError(self.module.bind_errno, "bind failed")

    def close(self):
        self.module.closed += 1


class FakeSocketModule:
    AF_UNIX, AF_INET, AF_INET6 = 1, 2, 10
    SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET = 1, 2, 5

    def __init__(self, create_errno=None, connect_errno=errno.ENOENT, bind_errno=None):
        self.create_errno, self.connect_errno, self.bind_errno, self.closed, self.made = create_errno, connect_errno, bind_errno, 0, 0

    def socket(self, family=2, kind=1):
        if self.create_errno is not None and family == self.AF_UNIX:
            raise OSError(self.create_errno, "refused")
        self.made += 1
        return FakeSocket(self)

    socketpair = staticmethod(real_socket.socketpair)  # the controls use the real one: socketpair is not filtered


rows = []
runner.row = lambda attack, tag, actual: rows.append((attack, tag, actual))
real_runner_socket = runner.socket
REAL_ABSTRACT = runner._abstract_connect


def with_socket(fake, call, *args):
    rows.clear()
    runner.socket = fake
    try:
        return call(*args)
    finally:
        runner.socket = real_runner_socket


def by_name(prefix):
    return [r for r in rows if r[0].startswith(prefix)]


# ---- 1. AF_UNIX refused at creation (what the unit now does): no traceback, 13 path rows, the filter rows OK, the controls OK
with_socket(FakeSocketModule(create_errno=errno.EAFNOSUPPORT), runner.g_sockets, {})  # 1.17.123 raised OSError here
paths = by_name("unix /")
must(len(paths) == 13 and all(r[1] == "OK" and EAF in r[2] and "creation refused" in r[2] for r in paths), paths)
for kind in ("stream", "dgram", "seqpacket"):
    got = [r for r in rows if r[0] == f"unix socket creation refused ({kind})"]
    must(got == [(f"unix socket creation refused ({kind})", "OK", EAF)], got)
must([r for r in rows if r[0] == "unix pathname socket refused"] == [("unix pathname socket refused", "OK", EAF)], rows)
for name in ("socketpair round trip", "pipe round trip", "child process with stdio pipes"):
    got = [r for r in rows if r[0] == name]
    must(len(got) == 1 and got[0][1] == "OK" and got[0][2] == "worked", got)
must(not [r for r in rows if r[1] not in ("OK",)], [r for r in rows if r[1] != "OK"])
# EPERM counts the same
with_socket(FakeSocketModule(create_errno=errno.EPERM), runner.g_sockets, {})
must(all(r[1] == "OK" for r in rows) and [r for r in rows if r[0].endswith("(stream)")][0][2] == EPERM, rows)
# any other errno is not evidence: NOT RUN
with_socket(FakeSocketModule(create_errno=errno.ENOMEM), runner.unix_creation_rows)
must(all(r[1] == "NOTRUN" for r in rows) and len(rows) == 4, rows)

# ---- 2. the filter is not in force: a created socket is ATTACK SUCCEEDED on the creation rows and the pathname row
fake = FakeSocketModule(create_errno=None, connect_errno=errno.ENOENT)
with_socket(fake, runner.g_sockets, {})
must(all(r[1] == "OK" and r[2] == "ENOENT" for r in by_name("unix /")), "no listener there: a refused connect is still OK")
must(all(r[1] == "SUCCEEDED" for r in by_name("unix socket creation refused")) and len(by_name("unix socket creation refused")) == 3, rows)
must(by_name("unix pathname socket refused")[0][1] == "SUCCEEDED", rows)
must(fake.closed == fake.made, "every socket made was closed")
with_socket(FakeSocketModule(create_errno=None, connect_errno=None), runner.g_sockets, {})
must(all(r[1] == "SUCCEEDED" and r[2] == "connected" for r in by_name("unix /")) and len(by_name("unix /")) == 13, "a connect that works is the finding")
# classify: SUCCEEDED is ATTACK SUCCEEDED in the table
must(sh.classify_tag("SUCCEEDED") == "ATTACK SUCCEEDED" and sh.classify_tag("NOTRUN") == "NOT RUN", "")

# ---- 3. abstract sockets: three states, never a raise on a creation failure
runner.socket = FakeSocketModule(create_errno=errno.EAFNOSUPPORT)
must(runner._abstract_connect("x") == ("refused", EAF), runner._abstract_connect("x"))
runner.socket = FakeSocketModule(connect_errno=errno.ECONNREFUSED)
must(runner._abstract_connect("x") == ("unreachable", ""), "")
runner.socket = FakeSocketModule(connect_errno=None)
must(runner._abstract_connect("x") == ("connected", ""), "")
runner.socket = real_runner_socket
NAMES = ["/org/kernel/linux/storage/multipathd", "ISCSIADM_ABSTRACT_NAMESPACE"]
with_socket(FakeSocketModule(create_errno=errno.EAFNOSUPPORT), runner.g_abstract,
            {"abstract": NAMES, "abstract_probe": "tectac-canary-x", "abstract_left_out": 0, "abstract_seconds": 30})
must(("abstract sockets (2 listed)", "OK", f"all refused: {EAF} (2 listed, 0 left out)") in rows, rows)
must(by_name("abstract probe listener")[0][1] == "OK" and "refused" in by_name("abstract probe listener")[0][2], rows)
must(by_name("abstract sockets left out")[0] == ("abstract sockets left out (information)", "OK", "0 left out (covered by the unix socket creation rows)"), rows)
with_socket(FakeSocketModule(connect_errno=None), runner.g_abstract, {"abstract": NAMES, "abstract_seconds": 30})
hit = by_name("abstract sockets (")[0]
must(hit[1] == "SUCCEEDED" and "@/org/kernel/linux/storage/multipathd" in hit[2], hit)
with_socket(FakeSocketModule(connect_errno=errno.ECONNREFUSED), runner.g_abstract, {"abstract": NAMES, "abstract_seconds": 30})
must(by_name("abstract sockets (")[0][1:] == ("OK", "none reachable (2 listed, 0 left out)"), rows)
# a mixed result is never reported as 'all refused'
calls = iter([("refused", EAF), ("unreachable", "")])
runner._abstract_connect = lambda name: next(calls)
with_socket(real_runner_socket, runner.g_abstract, {"abstract": NAMES, "abstract_seconds": 30})
must(by_name("abstract sockets (")[0][2].startswith("none reachable"), rows)
runner._abstract_connect = REAL_ABSTRACT
# a non-zero left-out count shows in both rows
runner._abstract_connect = lambda name: ("refused", EAF)
with_socket(real_runner_socket, runner.g_abstract, {"abstract": NAMES, "abstract_left_out": 5, "abstract_seconds": 30})
must("5 left out" in by_name("abstract sockets left out")[0][2] and "(2 listed, 5 left out)" in by_name("abstract sockets (")[0][2], rows)

# ---- 4. positive controls: real interpreter, real socketpair, real pipe, real child process
rows.clear()
runner.control_rows()
must([(r[0], r[1]) for r in rows] == [("socketpair round trip", "OK"), ("pipe round trip", "OK"), ("child process with stdio pipes", "OK")], rows)
# a forced failure is NOT RUN with 'control failed', never an attack and never OK
original = runner._pipe_check


def broken():
    raise OSError(errno.EMFILE, "no")


runner._pipe_check = broken
rows.clear()
runner.control_rows()
failed = [r for r in rows if r[0] == "pipe round trip"][0]
must(failed[1] == "NOTRUN" and failed[2].startswith("control failed") and sh.classify_tag(failed[1]) == "NOT RUN", failed)
must([r[1] for r in rows if r[0] != "pipe round trip"] == ["OK", "OK"], "the other controls still ran")
runner._pipe_check = original
runner._socketpair_check = lambda: ""  # wrong answer instead of an error
rows.clear()
runner.control_rows()
must([r for r in rows if r[0] == "socketpair round trip"][0][1:] == ("NOTRUN", "control failed"), rows)
table = sh.group_table("Sockets", "sockets", "x", [{"attack": a, "tag": "NOTRUN" if t == "NOTRUN" else t, "actual": d} for a, t, d in rows])
must(sh.canary_summary(table)[0] is False, "a failed control fails the canary")

# ---- 5. CANARY_REQUIRED: every new row is required, so a missing one is NOT RUN
good = ([{"attack": f"unix /s{k}", "tag": "OK", "actual": "EAFNOSUPPORT"} for k in range(13)]
        + [{"attack": f"unix socket creation refused ({k})", "tag": "OK", "actual": "EAFNOSUPPORT"} for k in ("stream", "dgram", "seqpacket")]
        + [{"attack": n, "tag": "OK", "actual": "x"} for n in ("unix pathname socket refused", "socketpair round trip", "pipe round trip",
                                                                 "child process with stdio pipes")])
must(all(r["verdict"] == "OK" for r in sh.group_table("Sockets", "sockets", "x", good)), "a full table is OK")
for drop in range(len(good)):
    table = sh.group_table("Sockets", "sockets", "x", good[:drop] + good[drop + 1:])
    must(any(r["verdict"] == "NOT RUN" for r in table), (good[drop]["attack"], table))
# the 13 path rows cannot be faked by the new 'unix ...' rows (the prefix is 'unix /')
only_new = [r for r in good if not r["attack"].startswith("unix /")]
must(any(r["verdict"] == "NOT RUN" and "0 of 13" in r["actual"] for r in sh.group_table("Sockets", "sockets", "x", only_new)), "")

# ---- 6. the 1.17.123 source would fail this test: g_sockets made the socket outside the try
text = (H.ROOT / "scripts" / "sandbox-canary-runner.py").read_text(encoding="utf-8")
body = text[text.index("def g_sockets"):text.index("UNIX_KINDS")]
must(body.index("try:") < body.index("socket.socket(socket.AF_UNIX"), "the socket is made inside the try")

print("[TEST] PASS sandbox unix 1.17.124")
