#!/usr/bin/env python3
"""1.18.26 regression (AD-65 Patch B, item 6): the in-unit network group of scripts/sandbox-canary-runner.py, flipped to the Patch B exit list.

Django-free, 127.0.0.1 only: the socket layer (connect, DNS, /proc readers, if_nameindex, the proxy door) is replaced, so the verdict rules run here
without a unit. Nothing here opens a 0.0.0.0 listener or contacts a public address. Covered:

* the group is still separate from GROUPS; the helper's CANARY_GROUPS equals runner.GROUPS after the dns and public groups are retired; the four
  'unix socket creation refused' rows are gone and the door row ('unix door path without a door') is there;
* the wall (Patch B): nothing succeeds, the forwarder's own port is not a host service, every one of the 31 rows is OK; the nine proxy rows are live (1.18.26 adds the own-public-address row; 1.18.25 added the own-domain row):
  the positive control answers 200 (OK), each of the six refusals is refused, and a 200 on a refusal row is ATTACK SUCCEEDED;
* the build before the wall (today's 1.18.23 world, kept as a self-test of the rows): the rows that Patch B changes show SUCCEEDED, so a row that
  reads OK after Patch B proves something;
* every attack row has its OWN host control: with only one control false only that row is SKIP, the others still show their verdict; a positive
  proxy control that cannot work (the host has no public route) is SKIPPED, never OK; a door that cannot be reached is NOT RUN;
* the listener bind address is a parameter (127.0.0.1 here); the proxy forwarder port 3128 is never probed as a host port;
* the host-service probes are separate pool jobs with a deadline: 40 slow ports finish inside it and a partial result is printed, never an empty row,
  and NET_HOST_PORTS_MAX x NET_LOCAL_SECONDS stays well under the run's time limit.

Not runnable here: the real unit (systemd, cgroups, root). That is the dev02 run of tests/sandbox-canary-1.18.26.sh.
"""
from __future__ import annotations

import contextlib
import errno
import importlib.util
import io
import json
import socket
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import load_helper  # noqa: E402  (1.18.26: the helper and sandbox-selftest.py as one object)
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("canary_runner_net25", ROOT / "scripts" / "sandbox-canary-runner.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
sh = load_helper(ROOT, "sandbox_helper_net25")

# ------------------------------------------------------------------------------------------------ the tables
must(set(R.NETWORK_GROUPS) == {"patchb_network"} and "patchb_network" not in R.GROUPS, R.NETWORK_GROUPS)
must(set(R.PATCHC_GROUPS) == {"patchc_syscalls", "patchc_leftover"} and not set(R.PATCHC_GROUPS) & set(R.GROUPS) and not set(R.PATCHC_GROUPS) & set(sh.CANARY_GROUPS), "the Patch C groups stay out of GROUPS and CANARY_GROUPS")
must(len(R.NETWORK_ROW_NAMES) == len(set(R.NETWORK_ROW_NAMES)) == 31, len(R.NETWORK_ROW_NAMES))
must(set(R.GROUPS) == set(sh.CANARY_GROUPS), set(R.GROUPS) ^ set(sh.CANARY_GROUPS))
must("dns" not in R.GROUPS and "public" not in R.GROUPS and "dns" not in sh.CANARY_GROUPS and "public" not in sh.CANARY_GROUPS, "the dns and public groups are retired")
must("loopback" in R.GROUPS and "lan" in R.GROUPS and "sockets" in R.GROUPS, "loopback and lan stay as regression guards")
must(sh.CANARY_SKIP_ALLOWED == () and "dns" not in sh.CANARY_REQUIRED and "public" not in sh.CANARY_REQUIRED, "no skip is allowed in the normal table")
required = sh.CANARY_REQUIRED["sockets"][0]
must(R.R_DOOR_NONE in required and "unix door path without a door" == R.R_DOOR_NONE, required)
must(not any("creation refused" in name or "pathname socket refused" in name for name in required), required)
text = (ROOT / "scripts" / "sandbox-canary-runner.py").read_text(encoding="utf-8")
must("unix_creation_rows" not in text and "unix socket creation refused" not in text and "def g_dns" not in text and "def g_public" not in text, "retired rows are gone")
must(R.NET_HOST_PORTS_MAX * R.NET_LOCAL_SECONDS <= 22.5, "40 ports at 0.5 s each stay well under the 45 s run limit even one by one")
must(R.NET_LOCAL_DEADLINE < 45 and not hasattr(R, "NET_NO_PROXY"), "the deadline is inside the run; the 'no proxy yet' text is gone")
err = io.StringIO()
with contextlib.redirect_stderr(err):
    must(R.main(["no_such_group"]) == 64 and R.main(["dns"]) == 64 and R.main(["public"]) == 64, "retired and unknown groups are refused")
must(b"\r" not in (ROOT / "scripts" / "sandbox-canary-runner.py").read_bytes(), "the runner keeps LF")

# ------------------------------------------------------------------------------------------------ stubs
for name, number in (("AF_PACKET", 17), ("AF_NETLINK", 16)):
    if not hasattr(socket, name):  # this PC is Windows: the constants only have to exist for the rule to run
        setattr(socket, name, number)

TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
TCP_HOST = TCP_HEADER + "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n" \
                        "   1: 0100007F:1F90 0100007F:D2A4 01 00000000:00000000 00:00000000 00000000     0        0 2\n"
TCP_ONLY_FORWARDER = TCP_HEADER + "   0: 0100007F:0C38 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n"
UDP_HOST = TCP_HEADER + "   0: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 3\n"
ROUTE_DEFAULT = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
ROUTE_LOCAL = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\nlo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n"
RESOLV = "nameserver 9.9.9.9\nnameserver 1.0.0.1\n"
PLAN = {"host_tcp443_1111": True, "host_tcp80_1111": True, "host_tcp443_9999": True, "host_tcp443_allowed": True, "host_dns": True, "host_udp53_listed": True,
        "host_udp53_9999": True, "host_ping": True, "host_ipv6": True, "loopback_ports": [22, 80, 3128, 8000], "own": ["192.168.1.5"], "gateways": ["192.168.1.1"],
        "listed_name_server": "9.9.9.9", "allowed_host": "example.com", "allowed_host_address": "93.184.216.34", "listen_seconds": 0.3, "listen_bind": "127.0.0.1", "own_domain": "api.example.test", "own_public_name": "93-184-216-34.sslip.io"}
PUBLIC = {"1.1.1.1", "9.9.9.9", "93.184.216.34", "2606:4700:4700::1111"}
PUBLIC_ROWS = (R.R_PUB_443, R.R_PUB_80, R.R_PUB_OTHER, R.R_PUB_DIRECT, R.R_DNS_LISTED, R.R_DNS_GAI, R.R_DNS_LISTED_ASK, R.R_DNS_PUBLIC_ASK,
               R.R_PROC_TCP, R.R_PROC_UDP, R.R_IFACES, R.R_ROUTE, R.R_PING)
PROXY_ROWS = (R.R_PROXY_OK, R.R_PROXY_HOST, R.R_PROXY_IP, R.R_PROXY_PRIVATE, R.R_PROXY_OWN, R.R_PROXY_80, R.R_PROXY_22, R.R_PROXY_OWN_NAME, R.R_PROXY_OWN_PUBLIC)


class World:
    """A replaceable socket layer. ``open_net`` is the build before Patch B (the public network works); ``walled`` is Patch B."""

    def __init__(self, open_net, proxy=None, tables=None, refuse_errno=errno.EAFNOSUPPORT, delay=0.0):
        self.open_net, self.proxy, self.calls, self.proxy_calls = open_net, proxy, [], []
        self.tables = tables or {}
        self.refuse_errno = refuse_errno
        self.created = {}
        self.delay = delay

    def tcp_connect(self, host, port, timeout=1.5, family=socket.AF_INET):
        self.calls.append((host, port, family))
        if self.delay:
            time.sleep(self.delay)
        if family == socket.AF_INET6:
            raise OSError(errno.EAFNOSUPPORT, "no ipv6")
        if self.open_net and host in PUBLIC:
            return "connected"
        if self.open_net and host == "127.0.0.1" and port == 8000 and self.created.get("loopback"):
            return "connected"
        return "timeout" if self.open_net else "ENETUNREACH"

    def make_socket(self, family, kind, proto=0):
        if family == socket.AF_INET and kind == socket.SOCK_STREAM:
            return socket.socket(family, kind, proto)  # the listener row binds a real local socket
        if family in self.created:
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raise OSError(self.refuse_errno, "refused")

    def read_proc(self, path):
        return self.tables.get(path)

    def proxy_status(self, proxy, host, port):
        self.proxy_calls.append((host, port))
        return self.proxy(host, port) if self.proxy else None


def table_of(world, plan=None, resolv=RESOLV, dns=True, names=("lo", "eth0"), echo="reply"):
    """Run the group through main() with the world's stubs; return {row name: (tag, text)} and the printed lines."""
    saved = {n: getattr(R, n) for n in ("tcp_connect", "make_socket", "read_proc", "dns_query", "if_names", "resolve_v4", "icmp_echo", "proxy_status", "proxy_address")}
    world.tables.setdefault("/etc/resolv.conf", resolv)
    R.tcp_connect, R.make_socket, R.read_proc = world.tcp_connect, world.make_socket, world.read_proc
    R.dns_query = lambda address, name="example.com": dns
    R.if_names = lambda: list(names)
    R.resolve_v4 = lambda name: ["93.184.216.34"] if dns else []
    R.icmp_echo = lambda address: echo
    R.proxy_status, R.proxy_address = world.proxy_status, lambda: ("127.0.0.1", 3128)
    old_stdin, out = sys.stdin, io.StringIO()
    sys.stdin = io.StringIO(json.dumps(plan or PLAN))
    try:
        with contextlib.redirect_stdout(out):
            must(R.main(["patchb_network"]) == 0, "main returns 0")
    finally:
        sys.stdin = old_stdin
        for name, value in saved.items():
            setattr(R, name, value)
    rows, lines = {}, out.getvalue().splitlines()
    for line in lines:
        parts = line.split("\t")
        if parts[0] == "CANARYROW":
            must(parts[1] not in rows, "a row printed twice: " + parts[1])
            rows[parts[1]] = (parts[2], parts[3])
    must(set(rows) == set(R.NETWORK_ROW_NAMES), set(R.NETWORK_ROW_NAMES) ^ set(rows))
    return rows, lines


NEWTAB = {"/proc/self/net/tcp": TCP_HOST, "/proc/self/net/tcp6": None, "/proc/self/net/udp": UDP_HOST, "/proc/self/net/udp6": None,
          "/proc/self/net/route": ROUTE_DEFAULT}
WALLED_TABLES = {"/proc/self/net/tcp": TCP_ONLY_FORWARDER, "/proc/self/net/udp": TCP_HEADER, "/proc/self/net/route": ROUTE_LOCAL}


def proxy_ok(host, port):
    return 200 if (host, port) == ("example.com", 443) else 403


# ------------------------------------------------------------------------------------------------ the wall (Patch B): every one of the 31 rows is OK
walled = World(open_net=False, tables=dict(WALLED_TABLES), proxy=proxy_ok)
rows, lines = table_of(walled, dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
must(all(tag == "OK" for tag, _t in rows.values()), {n: v for n, v in rows.items() if v[0] != "OK"})
must(len(rows) == 31, len(rows))
must(rows[R.R_PROC_TCP][0] == "OK" and "no socket lines" in rows[R.R_PROC_TCP][1], "only the forwarder's own socket: not a host socket")
must(rows[R.R_PROXY_OK] == ("OK", "answered 200"), rows[R.R_PROXY_OK])
for name in (R.R_PROXY_HOST, R.R_PROXY_IP, R.R_PROXY_PRIVATE, R.R_PROXY_OWN, R.R_PROXY_80, R.R_PROXY_22, R.R_PROXY_OWN_NAME, R.R_PROXY_OWN_PUBLIC):
    must(rows[name][0] == "OK" and "refused (403)" in rows[name][1], (name, rows[name]))
must(set(walled.proxy_calls) >= {("example.com", 443), ("example.net", 443), ("1.1.1.1", 443), ("10.255.255.254", 443), ("192.168.1.5", 443), ("example.com", 80),
                                 ("example.com", 22), ("api.example.test", 443), ("93-184-216-34.sslip.io", 443)}, walled.proxy_calls)
must(all(call[1] != 3128 for call in walled.calls), "port 3128 is the in-unit forwarder: never probed as a host service")
must(any(line.startswith("CANARYLISTEN\t") for line in lines), "the listener prints its port for the driver")
listen_port = next(int(line.split("\t")[1]) for line in lines if line.startswith("CANARYLISTEN\t"))
must(listen_port > 0, "the listener bound 127.0.0.1 here (a parameter), never 0.0.0.0")

# 200 on a refusal row is ATTACK SUCCEEDED, on every one of the six
every = World(open_net=False, tables=dict(WALLED_TABLES), proxy=lambda host, port: 200)
rows, _ = table_of(every, dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
for name in (R.R_PROXY_HOST, R.R_PROXY_IP, R.R_PROXY_PRIVATE, R.R_PROXY_OWN, R.R_PROXY_80, R.R_PROXY_22, R.R_PROXY_OWN_NAME, R.R_PROXY_OWN_PUBLIC):
    must(rows[name][0] == "SUCCEEDED" and "opened a tunnel (200)" in rows[name][1], (name, rows[name]))
must(rows[R.R_PROXY_OK][0] == "OK", "the positive control still answers 200")
# a positive control that does not answer 200 is NOT RUN (the proxy is broken), never OK
broken = World(open_net=False, tables=dict(WALLED_TABLES), proxy=lambda host, port: 502 if (host, port) == ("example.com", 443) else 403)
rows, _ = table_of(broken, dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
must(rows[R.R_PROXY_OK][0] == "NOTRUN" and "502" in rows[R.R_PROXY_OK][1], rows[R.R_PROXY_OK])
# a closed answer (0) on a refusal row is OK
closing = World(open_net=False, tables=dict(WALLED_TABLES), proxy=lambda host, port: 200 if (host, port) == ("example.com", 443) else 0)
rows, _ = table_of(closing, dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
must(rows[R.R_PROXY_IP][0] == "OK" and "closed" in rows[R.R_PROXY_IP][1], rows[R.R_PROXY_IP])
# no door at all: every proxy row is NOT RUN with the plain reason
nodoor = World(open_net=False, tables=dict(WALLED_TABLES), proxy=None)
rows, _ = table_of(nodoor, dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
for name in PROXY_ROWS:
    must(rows[name] == ("NOTRUN", R.NET_NO_DOOR), (name, rows[name]))
# a host with no public route: the positive control is SKIPPED, never OK; the refusal rows still run
rows, _ = table_of(World(open_net=False, tables=dict(WALLED_TABLES), proxy=proxy_ok), dict(PLAN, host_tcp443_allowed=False, allowed_host_address=""),
                   dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
must(rows[R.R_PROXY_OK][0] == "SKIP" and "no public route" in rows[R.R_PROXY_OK][1], rows[R.R_PROXY_OK])
must(all(rows[n][0] == "OK" for n in (R.R_PROXY_HOST, R.R_PROXY_IP, R.R_PROXY_PRIVATE, R.R_PROXY_80, R.R_PROXY_22)), rows)
# the own-domain row: a plan with no own domain is NOT RUN with the helper's plain reason, never OK and never a crash
rows, _ = table_of(World(open_net=False, tables=dict(WALLED_TABLES), proxy=proxy_ok), dict(PLAN, own_domain="", own_domain_reason="this server's own names could not be read from Tactical's settings file"),
                   dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
must(rows[R.R_PROXY_OWN_NAME][0] == "NOTRUN" and "could not be read" in rows[R.R_PROXY_OWN_NAME][1], rows[R.R_PROXY_OWN_NAME])
rows, _ = table_of(World(open_net=False, tables=dict(WALLED_TABLES), proxy=proxy_ok), dict(PLAN, own_domain=""), dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
must(rows[R.R_PROXY_OWN_NAME][0] == "NOTRUN" and "no own domain" in rows[R.R_PROXY_OWN_NAME][1], rows[R.R_PROXY_OWN_NAME])
# the own-public-address row: no name in the plan is NOT RUN with the driver's plain reason (or a default one), never OK and never a crash
rows, _ = table_of(World(open_net=False, tables=dict(WALLED_TABLES), proxy=proxy_ok), dict(PLAN, own_public_name="", own_public_reason="this server's own names answer no public IPv4 address, so there is no public address to test"),
                   dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
must(rows[R.R_PROXY_OWN_PUBLIC][0] == "NOTRUN" and "no public IPv4 address" in rows[R.R_PROXY_OWN_PUBLIC][1], rows[R.R_PROXY_OWN_PUBLIC])
rows, _ = table_of(World(open_net=False, tables=dict(WALLED_TABLES), proxy=proxy_ok), dict(PLAN, own_public_name=""), dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
must(rows[R.R_PROXY_OWN_PUBLIC][0] == "NOTRUN" and "no name that answers" in rows[R.R_PROXY_OWN_PUBLIC][1], rows[R.R_PROXY_OWN_PUBLIC])
# no own address in the plan: that one refusal row is SKIP
rows, _ = table_of(World(open_net=False, tables=dict(WALLED_TABLES), proxy=proxy_ok), dict(PLAN, own=[]), dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
must(rows[R.R_PROXY_OWN][0] == "SKIP" and rows[R.R_OWN][0] == "SKIP", rows[R.R_PROXY_OWN])

# ------------------------------------------------------------------------------------------------ the build before the wall: the rows prove something
today = World(open_net=True, tables=dict(NEWTAB))
rows, lines = table_of(today)
for name in PUBLIC_ROWS:
    must(rows[name][0] == "SUCCEEDED", (name, rows[name]))
must("1 LISTEN and 1 other" in rows[R.R_PROC_TCP][1], rows[R.R_PROC_TCP])
for name in (R.R_PACKET, R.R_RAW, R.R_NETLINK, R.R_INET6, R.R_V6_443, R.R_LOOPBACK, R.R_OWN, R.R_GATEWAY):
    must(rows[name][0] == "OK", (name, rows[name]))
for name in PROXY_ROWS:
    must(rows[name][0] == "NOTRUN", (name, rows[name]))
# every attack row has its OWN control: one false control skips only that row
for key, row_names in (("host_tcp443_1111", (R.R_PUB_443,)), ("host_tcp80_1111", (R.R_PUB_80,)), ("host_tcp443_9999", (R.R_PUB_OTHER,)),
                       ("host_tcp443_allowed", (R.R_PUB_DIRECT,)), ("host_udp53_listed", (R.R_DNS_LISTED_ASK,)), ("host_udp53_9999", (R.R_DNS_PUBLIC_ASK,)),
                       ("host_dns", (R.R_DNS_LISTED, R.R_DNS_GAI)), ("host_ping", (R.R_PING,)), ("host_ipv6", (R.R_V6_443,))):
    rows, _ = table_of(World(open_net=True, tables=dict(NEWTAB)), dict(PLAN, **{key: False}))
    skipped = {n for n, (tag, _t) in rows.items() if tag == "SKIP"}
    expected = set(row_names) | ({R.R_PROXY_OK} if key == "host_tcp443_allowed" else set())
    must(skipped == expected, (key, skipped, expected))
    for name in set(PUBLIC_ROWS) - skipped - {R.R_PING}:
        must(rows[name][0] == "SUCCEEDED", ("another row lost its verdict", key, name, rows[name]))
# a resolved allowed host the host cannot reach: unresolved is a SKIP too
rows, _ = table_of(World(open_net=True, tables=dict(NEWTAB)), dict(PLAN, allowed_host_address=""))
must(rows[R.R_PUB_DIRECT][0] == "SKIP", rows[R.R_PUB_DIRECT])
# no own address, gateway or listening port in the plan is SKIP
rows, _ = table_of(World(open_net=True, tables=dict(NEWTAB)), dict(PLAN, own=[], gateways=[], loopback_ports=[3128]))
must(all(rows[n][0] == "SKIP" for n in (R.R_OWN, R.R_GATEWAY, R.R_LOOPBACK)), rows)
# a host service that answers is SUCCEEDED with its port
leaky = World(open_net=True, tables=dict(NEWTAB))
leaky.created["loopback"] = True
rows, _ = table_of(leaky)
must(rows[R.R_LOOPBACK][0] == "SUCCEEDED" and "127.0.0.1:8000" in rows[R.R_LOOPBACK][1], rows[R.R_LOOPBACK])

# ------------------------------------------------------------------------------------------------ the host-service probes: parallel jobs with a deadline
slow = World(open_net=False, tables=dict(WALLED_TABLES), proxy=proxy_ok, delay=0.3)
many = dict(PLAN, loopback_ports=list(range(9000, 9040)), own=["192.168.1.5", "192.168.1.6"], gateways=["192.168.1.1"])
started = time.monotonic()
rows, _ = table_of(slow, many, dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
took = time.monotonic() - started
must(took < 25, ("40 slow ports finish well inside the run", took))
must(rows[R.R_LOOPBACK][0] == "OK" and "none of 40 ports connected" in rows[R.R_LOOPBACK][1], rows[R.R_LOOPBACK])
saved_deadline = R.NET_LOCAL_DEADLINE
R.NET_LOCAL_DEADLINE = 0.6  # a deadline the 40 slow ports cannot meet: a partial result, never an empty row
try:
    rows, _ = table_of(World(open_net=False, tables=dict(WALLED_TABLES), proxy=proxy_ok, delay=0.3), many, dns=False, names=("lo",), echo="ENETUNREACH", resolv="")
finally:
    R.NET_LOCAL_DEADLINE = saved_deadline
tag, detail = rows[R.R_LOOPBACK]
must(tag == "OK" and "partial:" in detail and " of 40 tried" in detail, rows[R.R_LOOPBACK])

# the loopback group skips the forwarder's port
seen = []
saved = R.tcp_connect
R.tcp_connect = lambda host, port, timeout=1.5, family=socket.AF_INET: seen.append((host, port)) or "ECONNREFUSED"
with contextlib.redirect_stdout(io.StringIO()):
    R.g_loopback({"ports": [22, 3128, 8000], "stub": "127.0.0.53", "stub_ports": [22, 3128], "loopback_seconds": 10})
R.tcp_connect = saved
must(("127.0.0.1", 3128) not in seen and ("127.0.0.1", 22) in seen and ("127.0.0.1", 8000) in seen, seen)

# ------------------------------------------------------------------------------------------------ the door row of the sockets group
made = []


class FakeSock:
    def __init__(self, connects):
        self.connects = connects

    def settimeout(self, value):
        pass

    def connect(self, path):
        made.append(path)
        if self.connects:
            return
        raise OSError(errno.ENOENT, "no such file")

    def close(self):
        pass


saved = R.make_socket
for connects, tag in ((False, "OK"), (True, "SUCCEEDED")):
    R.make_socket = lambda family, kind, proto=0, connects=connects: FakeSock(connects)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        R.door_row()
    must(f"\t{tag}\t" in out.getvalue() and out.getvalue().startswith("CANARYROW\tunix door path without a door"), out.getvalue())
R.make_socket = saved
must(made == ["/run/egress/door.sock", "/run/egress/door.sock"], made)

# ------------------------------------------------------------------------------------------------ the listener, against a real local socket
out = io.StringIO()
result = {}
with contextlib.redirect_stdout(out):
    thread = threading.Thread(target=lambda: result.update(row=R._listen_row(5, "127.0.0.1")), daemon=True)
    thread.start()
    port = None
    for _ in range(100):
        for line in out.getvalue().splitlines():
            if line.startswith("CANARYLISTEN\t"):
                port = int(line.split("\t")[1])
        if port:
            break
        time.sleep(0.05)
    must(port, "the listener printed its port")
    probe = socket.create_connection(("127.0.0.1", port), timeout=3)
    probe.close()
    thread.join(10)
must(result["row"][0] == "SUCCEEDED" and "arrived" in result["row"][1], result)
with contextlib.redirect_stdout(io.StringIO()):
    quiet = R._listen_row(0.3, "127.0.0.1")
must(quiet[0] == "OK" and "no connection" in quiet[1], quiet)
must(R.NET_LISTEN_BIND == "0.0.0.0", "the default bind is 0.0.0.0 and only ever runs inside the unit")

# ------------------------------------------------------------------------------------------------ the proxy reader, against a real local server
def serve(answer):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)

    def work():
        conn, _peer = srv.accept()
        conn.recv(1024)
        if answer:
            conn.sendall(answer)
        conn.close()
        srv.close()

    threading.Thread(target=work, daemon=True).start()
    return ("127.0.0.1", srv.getsockname()[1])


must(R.proxy_status(serve(b"HTTP/1.1 200 Connection established\r\n\r\n"), "example.com", 443) == 200, "200")
must(R.proxy_status(serve(b"HTTP/1.1 403 Forbidden\r\n\r\n"), "example.com", 22) == 403, "403")
must(R.proxy_status(serve(b""), "example.com", 22) == 0, "closed")
free = socket.socket()
free.bind(("127.0.0.1", 0))
dead = ("127.0.0.1", free.getsockname()[1])
free.close()
must(R.proxy_status(dead, "example.com", 443) is None, "no proxy at all")
must(R.proxy_address() == R.NET_PROXY_DEFAULT, "the default is the forwarder's 127.0.0.1:3128")
print("[TEST] PASS sandbox canary network rows (runner) 1.18.26")
