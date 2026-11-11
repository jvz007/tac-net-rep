#!/usr/bin/env python3
"""1.17.123 regression: abstract unix sockets are probed from a root-made list; no security row may be SKIPPED (core.sandbox canary, fix 5).

The 'abstract sockets' row was SKIPPED on dev02 because ProcSubset=pid hides /proc/net inside the unit. Now root lists the host's abstract
listeners before the canary (/proc/net/unix as root: stream-listening entries whose path starts with '@', capped at 200, byte-exact in the
JSON plan, shown cleaned) and the in-unit probe tries every one: refused or unreachable is OK, connected is ATTACK SUCCEEDED with the cleaned
name and never any content. If root cannot read the list the row is NOT RUN. The row reports how many were listed. Information only: root's
own throw-away abstract listener shows whether the namespace is shared at all.

canary_summary: a SKIPPED row in any security group fails the canary (only 'public tcp 443', for a server with no public route, may be
SKIPPED); canary.json lists the skipped rows.

Decision recorded (AF_UNIX stays in RestrictAddressFamilies for runners): the runners are Node-based CLIs and libuv creates socketpair(AF_UNIX)
pipes for child processes; seccomp cannot tell a pathname or abstract connect from a socketpair; the abstract namespace belongs to the network
namespace, which IPAddressDeny does not change. So the unit does not keep abstract sockets out, the canary detects them. Nothing is widened.

Not runnable here: the real unit (dev02). The real AF_UNIX abstract listener case runs only on Linux and says so on other systems.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_123e", "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
spec = importlib.util.spec_from_file_location("canary_runner_123e", H.ROOT / "scripts" / "sandbox-canary-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

UNIX = (
    "Num       RefCount Protocol Flags    Type St Inode Path\n"
    "ffff9a0e00000001: 00000002 00000000 00010000 0001 01 20100 /run/systemd/private\n"
    "ffff9a0e00000002: 00000002 00000000 00010000 0001 01 20101 @/org/kernel/linux/storage/multipathd\n"
    "ffff9a0e00000003: 00000002 00000000 00010000 0001 01 20102 @ISCSIADM_ABSTRACT_NAMESPACE\n"
    "ffff9a0e00000004: 00000003 00000000 00000000 0001 03 20103 @/tmp/dbus-AbCdEf012\n"        # connected, not listening
    "ffff9a0e00000005: 00000002 00000000 00000000 0002 01 20104 @dgram-only-no-listener\n"
    "ffff9a0e00000006: 00000002 00000000 00010000 0005 01 20105 @seqpacket listener with spaces\n"
    "ffff9a0e00000007: 00000002 00000000 00010000 0001 01 20106\n"                              # no path
    "ffff9a0e00000008: 00000002 00000000 00010000 0001 01 20107 /var/run/docker.sock\n"
    "ffff9a0e00000009: 00000002 00000000 00010000 0001 01 20108 @ISCSIADM_ABSTRACT_NAMESPACE\n"  # repeated
    "ffff9a0e0000000a: 00000002 00000000 00010000 0001 01 20109 @\n"
)
P = sh.parse_abstract_sockets
names = P(UNIX)
must(names == ["/org/kernel/linux/storage/multipathd", "ISCSIADM_ABSTRACT_NAMESPACE", "seqpacket listener with spaces", ""], names)
must(P(UNIX.encode()) == names and P(b"") == [] and P("") == [], "bytes and text give the same list; empty gives []")
must("/run/systemd/private" not in names and "/var/run/docker.sock" not in names, "pathname sockets are ignored")
must("/tmp/dbus-AbCdEf012" not in names and "dgram-only-no-listener" not in names, "only listening entries count")
# odd bytes: every byte survives (latin-1), nothing raises; the JSON plan carries them exactly
odd = b"Num RefCount Protocol Flags Type St Inode Path\nffff: 00000002 00000000 00010000 0001 01 1 @\xff\xfe\x01abc\n"
got = P(odd)
must(got == ["\xff\xfe\x01abc"] and got[0].encode("latin-1") == b"\xff\xfe\x01abc", got)
must(json.loads(json.dumps({"abstract": got}))["abstract"][0].encode("latin-1") == b"\xff\xfe\x01abc", "a JSON round trip keeps the bytes")
must(P("garbage\nnot a line at all\nffff: zz zz zz zz zz zz @x\n") == [], "garbage never raises")
many = "Num RefCount Protocol Flags Type St Inode Path\n" + "".join(f"ffff: 00000002 00000000 00010000 0001 01 {i} @name{i}\n" for i in range(500))
must(len(P(many)) == 200 and P(many)[0] == "name0" and P(many)[-1] == "name199", "capped at 200")
must(sh.read_abstract_names(BASE / "no-such-file") is None, "unreadable gives None, not []")
real = BASE / "net-unix"
real.write_bytes(UNIX.encode())
must(sh.read_abstract_names(real) == names, "read from a file")

# ---- the in-unit probe: every listed name is tried; a connection is the finding; names are shown cleaned; nothing is SKIPPED
rows = []
runner.row = lambda attack, tag, actual: rows.append((attack, tag, actual))
tried = []
reachable = {"ISCSIADM_ABSTRACT_NAMESPACE"}
runner._abstract_connect = lambda name: (tried.append(name) or name in reachable)
runner.g_abstract({"abstract": names, "abstract_seconds": 30})
must(tried == names, "every listed name was tried")
must(rows == [("abstract sockets (4 listed)", "SUCCEEDED", "Medium finding R1, connected to: @ISCSIADM_ABSTRACT_NAMESPACE")], rows)
rows.clear()
reachable.clear()
runner.g_abstract({"abstract": names, "abstract_seconds": 30})
must(rows == [("abstract sockets (4 listed)", "OK", "none reachable")], rows)
rows.clear()
runner.g_abstract({"abstract": [], "abstract_seconds": 30})
must(rows == [("abstract sockets (0 listed)", "OK", "none reachable")], "an empty list is a result, not a skip")
rows.clear()
runner.g_abstract({"abstract_seconds": 30})
must(rows == [], "no list in the plan prints nothing: the table says NOT RUN")
source = (H.ROOT / "scripts" / "sandbox-canary-runner.py").read_text(encoding="utf-8")
body = source[source.index("def g_abstract"):source.index("def g_cred")]
must('"SKIP"' not in body and "open(" not in body, "no SKIP path in the abstract group, and the unit no longer opens /proc/net/unix")
# a name with control characters is shown cleaned by the real row(): one line, three tab separators, nothing else
fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fresh)
fresh._abstract_connect = lambda name: True
captured = io.StringIO()
with contextlib.redirect_stdout(captured):
    fresh.g_abstract({"abstract": ["evil" + chr(10) + "name" + chr(9) + chr(0)], "abstract_seconds": 30})
printed = captured.getvalue()
must(printed.count(chr(10)) == 1 and printed.count(chr(9)) == 3 and chr(0) not in printed and "@evil?name??" in printed, repr(printed))
# the information row: root's own listener
rows.clear()
reachable.clear()
reachable.add("tectac-canary-probe")
runner.g_abstract({"abstract": [], "abstract_probe": "tectac-canary-probe", "abstract_seconds": 30})
must(rows[0] == ("abstract probe listener (information)", "OK", "reachable: the abstract namespace is shared with the host"), rows)
rows.clear()
reachable.clear()
runner.g_abstract({"abstract": [], "abstract_probe": "tectac-canary-probe", "abstract_seconds": 30})
must(rows[0][2] == "not reachable from this unit", rows)
# names not tried in time are NOT RUN, never OK
rows.clear()
runner.time.monotonic = lambda: 10 ** 9
runner.g_abstract({"abstract": names, "abstract_seconds": -1})
must(rows and rows[0][1] == "NOTRUN" and sh.classify_tag("NOTRUN") == "NOT RUN", rows)

# ---- the table: a connected name is ATTACK SUCCEEDED naming it; no list is NOT RUN, never SKIPPED
PLANS = {}
OUT = {"abstract": None}


class Outside:
    def run_cmd(self, argv, *, timeout=15):
        if argv[0] == "ss":
            return 0, "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", ""
        if argv[0] == "ip" and argv[1] == "-o":
            return 0, "2: eth0    inet 129.232.197.50/24 scope global eth0\n", ""
        return 0, "default via 129.232.197.1 dev eth0\n" if argv[1] == "-4" else "", ""


def collect(group, plan, **kwargs):
    PLANS[group] = (plan, kwargs)
    stdout = b""
    if group == "abstract":
        lines = []
        saved = runner.row
        runner.row = lambda attack, tag, actual: lines.append(f"CANARYROW\t{attack}\t{tag}\t{actual}")
        runner._abstract_connect = lambda name: name in OUT["abstract"]
        runner.time.monotonic = time.monotonic
        try:
            runner.g_abstract(plan)
        finally:
            runner.row = saved
        stdout = "\n".join(lines).encode()
    return {"stdout": stdout, "stderr": b"", "end": {"reason": "exited", "exit": 0}, "refused": None, "run_id": os.urandom(16).hex(), "frames": []}


sh._cancel_rows = lambda c, s: []
sh._holders_search = lambda token, unit: []
sh._credential_file_ready = lambda unit: True
sh._foreign_credential_probe = lambda unit: "DENIED"
sh._latency_rows = lambda c, s: []
sh._concurrency_rows = lambda c, s: []
sh._credential_rows = lambda c, s, *a, **k: []
sh._limit_rows = lambda c, s: []
sh.CANARY_MARKER_DIRS = ()
sh.CANARY_REAL_FILES = ()
STATUS = {"ready": True, "resolver": "9.9.9.9", "resolvers": ["9.9.9.9"]}


def abstract_rows(table):
    return [r for r in table if r["wall"] == "Abstract sockets"]


sh.read_abstract_names = lambda: list(names)
OUT["abstract"] = {"ISCSIADM_ABSTRACT_NAMESPACE"}
table = sh.run_canary(status=STATUS, collect=collect, outside=Outside())
plan, kwargs = PLANS["abstract"]
must(plan["abstract"] == names and plan["abstract_seconds"] >= 30 and kwargs.get("run_seconds") == sh.CANARY_ABSTRACT_SECONDS and sh.CANARY_ABSTRACT_SECONDS > 20, (plan, kwargs))
hit = [r for r in abstract_rows(table) if r["attack"].startswith("abstract sockets")]
must(len(hit) == 1 and hit[0]["verdict"] == "ATTACK SUCCEEDED" and "@ISCSIADM_ABSTRACT_NAMESPACE" in hit[0]["actual"] and "(4 listed)" in hit[0]["attack"], hit)
must(sh.canary_summary(table)[0] is False, "a reachable host listener fails the canary")
OUT["abstract"] = set()
table = sh.run_canary(status=STATUS, collect=collect, outside=Outside())
hit = [r for r in abstract_rows(table) if r["attack"].startswith("abstract sockets")]
must(hit[0]["verdict"] == "OK" and "(4 listed)" in hit[0]["attack"], hit)
# root cannot read the list: the row is NOT RUN (the plan carries no list), never SKIPPED
sh.read_abstract_names = lambda: None
table = sh.run_canary(status=STATUS, collect=collect, outside=Outside())
plan, _kwargs = PLANS["abstract"]
must("abstract" not in plan, plan)
hit = [r for r in abstract_rows(table) if r["attack"].startswith("abstract sockets")]
must(len(hit) == 1 and hit[0]["verdict"] == "NOT RUN" and not [r for r in table if r["verdict"] == "SKIPPED"], hit)
must(sh.canary_summary(table)[0] is False, "NOT RUN fails")
must(sh.CANARY_REQUIRED["abstract"] == ([], [("abstract sockets", 1)]), "the table requires the row")

# ---- canary_summary and canary.json: a skipped security row fails; only 'public tcp 443' may be skipped
def row(attack, verdict, wall="X"):
    return {"wall": wall, "attack": attack, "expected": "x", "actual": "x", "verdict": verdict}


S = sh.canary_summary
must(S([row("a", "OK"), row("public tcp 443", "SKIPPED", "Public")])[0] is True, "a server with no public route may skip public tcp 443")
for attack in ("abstract sockets (0 listed)", "loopback ports", "other resolver dropped", "read /etc/shadow", "unix /run/x", "public tcp 4430", ""):
    must(S([row("a", "OK"), row(attack, "SKIPPED")])[0] is False, attack)
must(S([row("a", "OK"), row("public tcp 443", "SKIPPED"), row("loopback x", "SKIPPED")])[0] is False, "one skipped security row among allowed ones")
ok, counts = S([row("a", "OK"), row("public tcp 443", "SKIPPED")])
must(counts["SKIPPED"] == 1 and counts["OK"] == 1, "SKIPPED is counted but never OK")
table = [row("a", "OK"), row("public tcp 443", "SKIPPED", "Public"), row("abstract sockets (0 listed)", "SKIPPED", "Abstract sockets")]
passed, counts = S(table)
record = sh.canary_record(table, passed, counts)
must(record["ok"] is False and record["skipped"] == ["public tcp 443", "abstract sockets (0 listed)"], record)
must(record["failing"] == [{"wall": "Abstract sockets", "attack": "abstract sockets (0 listed)", "verdict": "SKIPPED"}], "the failing skipped row is listed; the allowed one is not")
must("content" not in json.dumps(record), "no content in canary.json")
ok_table = [row("a", "OK"), row("public tcp 443", "SKIPPED", "Public")]
record = sh.canary_record(ok_table, *S(ok_table))
must(record["ok"] is True and record["failing"] == [] and record["skipped"] == ["public tcp 443"], record)

# ---- root's own throw-away abstract listener (information row), and a real AF_UNIX abstract socket where the platform has one
if not sys.platform.startswith("linux") or not hasattr(socket, "AF_UNIX"):
    print("[NOTE] this system has no AF_UNIX abstract namespace (Windows): the real-listener case was skipped; the fake-connect cases above ran")
else:
    listener, name = sh.open_abstract_listener()
    must(listener is not None and name.startswith("tectac-canary-"), name)
    unix = sh.read_abstract_names()
    must(unix is not None and name in unix, "root's own listener is in the host's list")
    rows.clear()
    importlib_runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(importlib_runner)
    seen = []
    importlib_runner.row = lambda attack, tag, actual: seen.append((attack, tag, actual))
    importlib_runner.g_abstract({"abstract": [name], "abstract_probe": name, "abstract_seconds": 10})
    must(seen[0][2].startswith("reachable"), seen)
    must(seen[1][1] == "SUCCEEDED" and ("@" + name) in seen[1][2], "the real connection to a real abstract listener is found")
    accepted = []
    threading.Thread(target=lambda: accepted.append(listener.accept()), daemon=True).start()
    listener.close()

print("[TEST] PASS sandbox abstract 1.17.123")
