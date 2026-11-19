#!/usr/bin/env python3
"""1.18.23 regression: the Patch B network probe group of scripts/sandbox-canary-runner.py (canary rows first, AD-65).

Django-free. The socket layer (connect, DNS, /proc readers, if_nameindex, the proxy door) is replaced, so the verdict rules run here without a unit:
SUCCEEDED only when the stub lets the thing work, OK when it is refused, SKIP when a host control is false, NOTRUN for an unexpected errno and for
every proxy row with no proxy, 200 on a refusal row is SUCCEEDED, port 3128 is never probed as a host service. The listener row and the proxy
reader run against real local sockets. The helper is unchanged: its sha256 is the 1.18.22 value, the kill switch is still False and the group is
not in CANARY_GROUPS.

Not runnable here: the real unit (systemd, cgroups, root). That is the dev02 run of tests/sandbox-canary-1.18.23.sh.
"""
from __future__ import annotations

import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import socket
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
HELPER_SHA256_1_18_22 = "f6125e66a57b5c2eaff0861bf3dc7723b0d2ac3ba8dc7419ed389e118574574a"


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("canary_runner_net", ROOT / "scripts" / "sandbox-canary-runner.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

# ------------------------------------------------------------------------------------------------ separate from GROUPS, dispatched by main
must(set(R.NETWORK_GROUPS) == {"patchb_network"}, R.NETWORK_GROUPS)
must("patchb_network" not in R.GROUPS, "the group stays out of GROUPS (the helper's CANARY_GROUPS)")
must(len(R.NETWORK_ROW_NAMES) == len(set(R.NETWORK_ROW_NAMES)) == 29, len(R.NETWORK_ROW_NAMES))
err = io.StringIO()
with contextlib.redirect_stderr(err):
    must(R.main(["no_such_group"]) == 64, "an unknown group is still refused")
helper_text = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must(hashlib.sha256((ROOT / "scripts" / "sandbox-helper.py").read_bytes()).hexdigest() == HELPER_SHA256_1_18_22, "the helper must be byte-identical to 1.18.22")
must("SANDBOX_ENABLED = False" in helper_text, "the kill switch stays off")
must("patchb_network" not in helper_text, "no new CANARY_GROUPS entry")
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
DEV_TEXT = "Inter-|   Receive\n face |bytes\n    lo: 1 2\n  eth0: 3 4\n"
RESOLV = "nameserver 9.9.9.9\nnameserver 1.0.0.1\n"
PLAN = {"host_public": True, "host_dns": True, "host_ping": True, "host_ipv6": True, "loopback_ports": [22, 80, 3128, 8000],
        "own": ["192.168.1.5"], "gateways": ["192.168.1.1"], "allowed_host": "example.com", "allowed_host_address": "93.184.216.34", "listen_seconds": 0.3}
PUBLIC = {"1.1.1.1", "9.9.9.9", "93.184.216.34", "2606:4700:4700::1111"}


class World:
    """A replaceable socket layer. ``open_net`` is today's build (the public network works, the local addresses are dropped); ``walled`` is Patch B."""

    def __init__(self, open_net, proxy=None, tables=None, refuse_errno=errno.EAFNOSUPPORT):
        self.open_net, self.proxy, self.calls, self.proxy_calls = open_net, proxy, [], []
        self.tables = tables or {}
        self.refuse_errno = refuse_errno
        self.created = {}

    def tcp_connect(self, host, port, timeout=1.5, family=socket.AF_INET):
        self.calls.append((host, port, family))
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
    saved = {n: getattr(R, n) for n in ("tcp_connect", "make_socket", "read_proc", "dns_query", "if_names", "resolve_v4", "icmp_echo",
                                        "proxy_status", "proxy_address")}
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

# ------------------------------------------------------------------------------------------------ today's build: the wall rows that Patch B changes show SUCCEEDED
today = World(open_net=True, tables=dict(NEWTAB))
rows, lines = table_of(today)
for name in (R.R_PUB_443, R.R_PUB_80, R.R_PUB_OTHER, R.R_PUB_DIRECT, R.R_DNS_LISTED, R.R_DNS_GAI, R.R_DNS_LISTED_ASK, R.R_DNS_PUBLIC_ASK,
             R.R_PROC_TCP, R.R_PROC_UDP, R.R_IFACES, R.R_ROUTE, R.R_PING):
    must(rows[name][0] == "SUCCEEDED", (name, rows[name]))
must("1 LISTEN and 1 other" in rows[R.R_PROC_TCP][1], rows[R.R_PROC_TCP])
for name in (R.R_PACKET, R.R_RAW, R.R_NETLINK, R.R_INET6, R.R_V6_443, R.R_LOOPBACK, R.R_OWN, R.R_GATEWAY, R.R_LISTEN):
    must(rows[name][0] == "OK", (name, rows[name]))
for name in (R.R_PROXY_OK, R.R_PROXY_HOST, R.R_PROXY_IP, R.R_PROXY_PRIVATE, R.R_PROXY_OWN, R.R_PROXY_80, R.R_PROXY_22):
    must(rows[name] == ("NOTRUN", R.NET_NO_PROXY), (name, rows[name]))
must(all(call[1] != 3128 for call in today.calls), "port 3128 is the in-unit forwarder: never probed as a host service")
must(not any(c[0] == "127.0.0.1" and c[1] == 3128 for c in today.calls), "")
must(any(line.startswith("CANARYLISTEN\t") for line in lines), "the listener prints its port for the driver")

# a host control that is false turns the row into SKIP, never OK
plan = dict(PLAN, host_public=False, host_dns=False, host_ping=False, host_ipv6=False, allowed_host_address="")
rows, _ = table_of(World(open_net=True, tables=dict(NEWTAB)), plan)
for name in (R.R_PUB_443, R.R_PUB_80, R.R_PUB_OTHER, R.R_PUB_DIRECT, R.R_DNS_LISTED, R.R_DNS_GAI, R.R_DNS_LISTED_ASK, R.R_DNS_PUBLIC_ASK, R.R_PING,
             R.R_V6_443):
    must(rows[name][0] == "SKIP", (name, rows[name]))
# a resolved allowed host the host cannot reach is a SKIP too, an unresolved one is
rows, _ = table_of(World(open_net=True, tables=dict(NEWTAB)), dict(PLAN, allowed_host_address=""))
must(rows[R.R_PUB_DIRECT][0] == "SKIP", rows[R.R_PUB_DIRECT])
# no own address, gateway or listening port in the plan is SKIP
rows, _ = table_of(World(open_net=True, tables=dict(NEWTAB)), dict(PLAN, own=[], gateways=[], loopback_ports=[3128]))
must(all(rows[n][0] == "SKIP" for n in (R.R_OWN, R.R_GATEWAY, R.R_LOOPBACK)), rows)

# ------------------------------------------------------------------------------------------------ the wall (Patch B): nothing succeeds, the proxy door works
walled = World(open_net=False, tables={"/proc/self/net/tcp": TCP_ONLY_FORWARDER, "/proc/self/net/udp": TCP_HEADER, "/proc/self/net/route": ROUTE_LOCAL},
               proxy=lambda host, port: 200 if (host, port) in (("example.com", 443), ("1.1.1.1", 443)) else 403)
rows, _ = table_of(walled, dns=False, names=("lo",), echo="EPERM", resolv="")
must([n for n, (tag, _t) in rows.items() if tag == "SUCCEEDED"] == [R.R_PROXY_IP], rows)  # the stub proxy lets 1.1.1.1 through: that one is a finding
must(rows[R.R_PROC_TCP][0] == "OK" and "no socket lines" in rows[R.R_PROC_TCP][1], "only the forwarder's own socket: not a host socket")
must(rows[R.R_ROUTE][0] == "OK" and rows[R.R_IFACES][0] == "OK" and rows[R.R_PING][0] == "OK", rows)
must(rows[R.R_PROXY_OK] == ("OK", "answered 200"), rows[R.R_PROXY_OK])
for name in (R.R_PROXY_HOST, R.R_PROXY_PRIVATE, R.R_PROXY_OWN, R.R_PROXY_80, R.R_PROXY_22):
    must(rows[name][0] == "OK" and "refused (403)" in rows[name][1], (name, rows[name]))
must(("10.255.255.254", 443) in walled.proxy_calls and ("192.168.1.5", 443) in walled.proxy_calls and ("example.com", 80) in walled.proxy_calls
     and ("example.com", 22) in walled.proxy_calls and ("example.net", 443) in walled.proxy_calls, walled.proxy_calls)
# 200 on every refusal row: all six are SUCCEEDED; a non-200 positive control is NOTRUN
every = World(open_net=False, tables=dict(NEWTAB), proxy=lambda host, port: 200)
rows, _ = table_of(every)
for name in (R.R_PROXY_HOST, R.R_PROXY_IP, R.R_PROXY_PRIVATE, R.R_PROXY_OWN, R.R_PROXY_80, R.R_PROXY_22):
    must(rows[name][0] == "SUCCEEDED", (name, rows[name]))
bad_control = World(open_net=False, tables=dict(NEWTAB), proxy=lambda host, port: 502 if (host, port) == ("example.com", 443) else 403)
rows, _ = table_of(bad_control)
must(rows[R.R_PROXY_OK][0] == "NOTRUN" and "502" in rows[R.R_PROXY_OK][1], rows[R.R_PROXY_OK])
# a closed answer (0) on a refusal row is OK
closing = World(open_net=False, tables=dict(NEWTAB), proxy=lambda host, port: 200 if port == 443 and host == "example.com" else 0)
rows, _ = table_of(closing)
must(rows[R.R_PROXY_IP][0] == "OK" and "closed" in rows[R.R_PROXY_IP][1], rows[R.R_PROXY_IP])

# ------------------------------------------------------------------------------------------------ an unexpected errno is NOTRUN, never OK
odd = World(open_net=True, tables=dict(NEWTAB), refuse_errno=errno.ENOMEM)
rows, _ = table_of(odd)
for name in (R.R_PACKET, R.R_RAW, R.R_NETLINK, R.R_INET6):
    must(rows[name][0] == "NOTRUN" and "ENOMEM" in rows[name][1], (name, rows[name]))
for errname in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT):
    rows, _ = table_of(World(open_net=True, tables=dict(NEWTAB), refuse_errno=errname))
    must(all(rows[n][0] == "OK" for n in (R.R_PACKET, R.R_RAW, R.R_NETLINK, R.R_INET6)), (errname, rows))
# a socket that can be made is SUCCEEDED
made = World(open_net=True, tables=dict(NEWTAB))
made.created = {socket.AF_PACKET: 1, socket.AF_NETLINK: 1, socket.AF_INET6: 1}
rows, _ = table_of(made)
must(all(rows[n][0] == "SUCCEEDED" for n in (R.R_PACKET, R.R_NETLINK, R.R_INET6)), rows)
# an unreadable /proc is OK; a probe that raises is NOTRUN with the name of the error, the group still prints every row
rows, _ = table_of(World(open_net=True, tables={}))
must(rows[R.R_PROC_TCP] == ("OK", "not readable") and rows[R.R_ROUTE] == ("OK", "not readable"), rows)
boom = World(open_net=True, tables=dict(NEWTAB))
boom.tcp_connect = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("x"))
rows, _ = table_of(boom)
must(rows[R.R_PUB_443] == ("NOTRUN", "probe failed: RuntimeError"), rows[R.R_PUB_443])
# a plan that does not parse is one NOTRUN line, not a missing group
old_stdin, out = sys.stdin, io.StringIO()
sys.stdin = io.StringIO("[1, 2")
try:
    with contextlib.redirect_stdout(out):
        R.main(["patchb_network"])
finally:
    sys.stdin = old_stdin
must("plan unreadable" in out.getvalue() and "NOTRUN" in out.getvalue(), out.getvalue())

# ------------------------------------------------------------------------------------------------ the listener, against a real local socket
out = io.StringIO()
result = {}
with contextlib.redirect_stdout(out):
    thread = threading.Thread(target=lambda: result.update(row=R._listen_row(5)), daemon=True)
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
    quiet = R._listen_row(0.3)
must(quiet[0] == "OK" and "no connection" in quiet[1], quiet)

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
must(R.proxy_status(serve(b"garbage\r\n\r\n"), "example.com", 22) == 0, "not http")
free = socket.socket()
free.bind(("127.0.0.1", 0))
dead = ("127.0.0.1", free.getsockname()[1])
free.close()
must(R.proxy_status(dead, "example.com", 443) is None, "no proxy at all")
must(R.proxy_address() == R.NET_PROXY_DEFAULT, "the default is Patch B's 127.0.0.1:3128")
print("[TEST] PASS sandbox canary network rows (runner) 1.18.23")
