#!/usr/bin/env python3
"""1.17.123 regression: every local interface address and every default gateway is denied at each start (core.sandbox canary, fix 2).

dev02 (Core 1.17.122) showed a run could connect to the server's own public address and to its gateway: IPAddressDeny judges the destination
address, and the own public address is neither loopback nor private. Now, at every start, root reads ``ip -o addr show``, ``ip -4 route show
default`` and ``ip -6 route show default`` and appends each address and next hop as /32 or /128 to the unit's IPAddressDeny (numeric only,
without repeats, at most 64 outside the ranges already denied). The same function feeds the selftest probes.

* the parsers read real ip text (the dev02 shape: loopback, public 129.232.197.x/24 with gateway 129.232.197.1, IPv6, a docker bridge, a
  multipath default route, a tunnel with no next hop);
* the built unit holds every address outside the ranges and the gateway as /32 or /128 beside the unchanged numeric ranges, no symbolic name;
* unreadable `ip` output (a failing command, no address, a default route with an unreadable next hop, too many addresses) refuses the start;
* the selftest probes a send to the own address and the gateway from a filtered unit, with a control run that must succeed; a filter that lets
  it through, a control that cannot send and unreadable addresses each give ready=false;
* the canary's LAN group adds 'own address <ip> tcp 22/80/443', 'own address <ip> udp', 'gateway <ip> tcp 80/443' and 'gateway <ip> udp'; a
  missing one is NOT RUN; a connection or a refusal (the reset only comes from a host that was reached) is an attack that succeeded.

Known limit, recorded as information: an address that appears after a run has started (a DHCP change) is not covered until the next start.
Not runnable here: real systemd and the real `ip` (dev02 runs tests/sandbox-canary-1.17.123.sh).
"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_123b", "sandbox-harness-1.17.118.py")
F = load("sandbox_fake_123b", "sandbox-fake-runner-1.17.120.py")
sh, must, make_runner, BASE = H.sh, H.must, H.make_runner, H.BASE

# real ip text (dev02 shape): lo, a public address on eth0 with IPv6, a docker bridge with a link-local v6 address
ADDR = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
    "1: lo    inet6 ::1/128 scope host \\       valid_lft forever preferred_lft forever\n"
    "2: eth0    inet 129.232.197.50/24 brd 129.232.197.255 scope global eth0\\       valid_lft forever preferred_lft forever\n"
    "2: eth0    inet 129.232.197.51/24 scope global secondary eth0:1\\       valid_lft forever preferred_lft forever\n"
    "2: eth0    inet6 2c0f:f5c0:1:1::50/64 scope global \\       valid_lft forever preferred_lft forever\n"
    "2: eth0    inet6 fe80::5054:ff:fe12:3456/64 scope link \\       valid_lft forever preferred_lft forever\n"
    "3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever\n"
    "4: tun0    inet 10.8.0.2 peer 10.8.0.1/32 scope global tun0\\       valid_lft forever preferred_lft forever\n"
)
ROUTE4 = "default via 129.232.197.1 dev eth0 proto static\n"
ROUTE6 = "default via fe80::1 dev eth0 proto ra metric 1024 expires 1700sec\n"

P = sh.parse_local_addresses
must(P(ADDR) == ["127.0.0.1", "::1", "129.232.197.50", "129.232.197.51", "2c0f:f5c0:1:1::50", "fe80::5054:ff:fe12:3456", "172.17.0.1", "10.8.0.2"], P(ADDR))
must(P("") == [] and P(None) == [] and P("garbage line\n2: eth0 inet notanaddress/24\n") == [], "nothing readable gives []")
must(P("2: eth0    inet 1.2.3.4/24 brd 1.2.3.255 scope global eth0\n2: eth0    inet 1.2.3.4/24 scope global eth0:1\n") == ["1.2.3.4"], "no repeats")
G = sh.parse_gateways
must(G(ROUTE4) == ["129.232.197.1"] and G(ROUTE6) == ["fe80::1"] and G("") == [], "gateways")
must(G("default proto static\n\tnexthop via 10.0.0.1 dev eth0 weight 1\n\tnexthop via 129.232.197.1 dev eth1 weight 1\n") == ["10.0.0.1", "129.232.197.1"], "multipath")
must(G("default dev tun0 scope link\n") == [], "an on-link default route has no next hop to list")
must(G("default via inet6 fe80::1 dev eth0\n") == ["fe80::1"], "an IPv4 route through an IPv6 next hop")
for bad in ("default via\n", "default via not-an-address dev eth0\n"):
    try:
        G(bad)
    except ValueError:
        continue
    raise AssertionError(("an unreadable next hop was accepted", bad))

local = sh.local_deny(ADDR, ROUTE4, ROUTE6)
must(local["gateways"] == ["129.232.197.1", "fe80::1"], local)
# outside the numeric ranges: the two public v4 addresses, the public v6 address, the gateway. Inside (so not listed twice): lo, link-local,
# the docker bridge 172.17.0.1 (172.16.0.0/12), the tunnel 10.8.0.2 (10.0.0.0/8), fe80::1.
must(local["extra"] == ["129.232.197.50/32", "129.232.197.51/32", "2c0f:f5c0:1:1::50/128", "129.232.197.1/32"], local["extra"])
for address in ("172.17.0.1", "10.8.0.2", "127.0.0.1", "fe80::1"):
    must(sh.denied_by_ranges(address), address)
must(not sh.denied_by_ranges("129.232.197.50") and not sh.denied_by_ranges("2c0f:f5c0:1:1::50"), "public addresses are not inside the ranges")
for item in local["extra"]:
    net = ipaddress.ip_network(item, strict=True)
    must(net.prefixlen == (32 if net.version == 4 else 128), item)

# ---- the built unit
RUN_ID = "ab" * 16
row = make_runner("ai.chat", credential_files=["auth"])
RESOLV = str(BASE / "core-resolv.conf")
Path(RESOLV).write_text("nameserver 9.9.9.9\n", encoding="utf-8")
EXISTS = lambda path: str(path).startswith(str(BASE)) or str(path) == str(sh.LAUNCHER_FILE)
props = sh.build_properties(row, RUN_ID, credential_names=[], exists=EXISTS, deny_extra=local["extra"], resolv_file=RESOLV)
deny = [p for p in props if p.startswith("IPAddressDeny=")]
must(len(deny) == 1, deny)
tokens = deny[0].split("=", 1)[1].split()
must(tokens[:len(sh.ADDRESS_DENY.split())] == sh.ADDRESS_DENY.split(), "the numeric ranges are still first and unchanged")
must(tokens[len(sh.ADDRESS_DENY.split()):] == local["extra"], tokens)
must(len(tokens) == len(set(tokens)), "no repeats")
for token in tokens:
    must(str(ipaddress.ip_network(token, strict=True)) == token, ("numeric and canonical", token))
must(not any(word in deny[0] for word in ("localhost", "link-local", "multicast", "any", "Allow")), deny)
# every address outside the ranges, and the gateway, is in the unit's deny list
for address in ("129.232.197.50", "129.232.197.51", "2c0f:f5c0:1:1::50", "129.232.197.1"):
    must(any(ipaddress.ip_address(address) in ipaddress.ip_network(t) for t in tokens if (":" in t) == (":" in address)), address)

# ---- unreadable output refuses (fail closed)


def cmd(addr=ADDR, route4=ROUTE4, route6=ROUTE6, fail=None):
    def run_cmd(argv, *, timeout=15):
        key = "addr" if argv[1] == "-o" else ("route4" if argv[1] == "-4" else "route6")
        if fail == key:
            return 1, "", "error"
        return 0, {"addr": addr, "route4": route4, "route6": route6}[key], ""
    return run_cmd


must(sh.read_local_deny(cmd())["extra"][-1] == "129.232.197.1/32", "reads all three commands")
for label, run_cmd in (("ip addr fails", cmd(fail="addr")), ("route4 fails", cmd(fail="route4")), ("route6 fails", cmd(fail="route6")),
                       ("no address", cmd(addr="")), ("garbled next hop", cmd(route4="default via ??? dev eth0\n"))):
    try:
        sh.read_local_deny(run_cmd)
    except ValueError:
        continue
    raise AssertionError((label, "was accepted"))
many = "".join(f"2: eth0    inet 129.232.{i // 200}.{i % 200 + 1}/24 scope global eth0\\       valid\n" for i in range(70))
try:
    sh.local_deny(many, "", "")
except ValueError as exc:
    must("more local addresses" in str(exc), exc)
else:
    raise AssertionError("70 public addresses were accepted")
must(len(sh.local_deny(ADDR + many[:0], ROUTE4, "")["extra"]) <= sh.LOCAL_DENY_MAX, "bounded")
# the live reader is the helper's own `ip` call; with a refusing reader a start is refused (tests/sandbox-launch-1.17.118.py covers launch)
real = sh.local_deny_now
sh.local_deny_now = lambda: sh.read_local_deny(cmd(fail="addr"))
make_runner("ai.chat2", body="print('x')")
H.write_ready_status()
code, frames = H.start(H.header("ai.chat2"), hold=False)
must(frames[0]["t"] == "refused" and frames[0]["code"] == "sandbox_unavailable" and "address filter" in frames[0]["message"], frames)
sh.local_deny_now = real

# ---- the selftest probes the own address and the gateway from a filtered unit, with a control run


def selftest(fake):
    return F.run_selftest(sh, H.RUN, BASE, fake)


fake = F.Fake()
ok = selftest(fake)
must(ok["ready"] is True and ok["address_filter_ok"] is True and ok["checks"]["address_filter_local"]["ok"] is True, ok["checks"])
must("129.232.197.50" in ok["checks"]["local_addresses"]["detail"] and "129.232.197.1" in ok["checks"]["local_addresses"]["detail"], ok["checks"]["local_addresses"])
calls = {c[0]: c for c in fake.calls}
must(calls["address_filter_local_control"][1] == sh.PROBE_PROPERTIES["address_filter_control"], "the control has no filter")
must(calls["address_filter_local"][1][1] == "IPAddressDeny=" + sh.ADDRESS_DENY + " 129.232.197.50/32 129.232.197.1/32", calls["address_filter_local"][1])
must(list(calls["address_filter_local"][2][4:]) == ["129.232.197.50", "129.232.197.1"], calls["address_filter_local"][2])
# a filter that lets the own-address send through is not ready (the 1.17.122 code had no such probe, so it passed this server)
leak = selftest(F.Fake(address_filter_local=lambda properties, command: (0, "".join(f"{a} sent\n" for a in command[4:]), "")))
must(leak["ready"] is False and leak["address_filter_ok"] is False and "own address or gateway" in leak["reason"], leak)
half = selftest(F.Fake(address_filter_local=lambda properties, command: (0, f"{command[4]} eperm\n{command[5]} sent\n", "")))
must(half["ready"] is False, "one send through is enough to fail")
unjudged = selftest(F.Fake(address_filter_local=lambda properties, command: (0, "".join(f"{a} other\n" for a in command[4:]), "")))
must(unjudged["ready"] is False, "an unjudgeable answer is never a pass")
# a control that cannot send: the probe cannot be read as a pass
nocontrol = selftest(F.Fake(address_filter_local_control=lambda properties, command: (0, "".join(f"{a} other\n" for a in command[4:]), "")))
must(nocontrol["ready"] is False and "could not be checked" in nocontrol["reason"], nocontrol)
# unreadable addresses: not ready, and the DNS probe is not run
bad = F.Fake()
bad.ip["addr"] = ""
status = selftest(bad)
must(status["ready"] is False and "could not be read" in status["reason"] and status["checks"]["local_addresses"]["ok"] is False, status)
must(not [c for c in bad.calls if c[0] == "dns"], "no DNS probe without the deny list")
# a private-only server has nothing outside the ranges: nothing to add, and nothing to probe
quiet = F.Fake()
quiet.ip["addr"] = "2: eth0    inet 192.168.1.5/24 scope global eth0\n"
quiet.ip["route4"] = "default via 192.168.1.1 dev eth0\n"
status = selftest(quiet)
must(status["ready"] is True and "no own IPv4 address or gateway outside" in status["checks"]["address_filter_local"]["detail"], status["checks"]["address_filter_local"])
must(not [c for c in quiet.calls if c[0].startswith("address_filter_local")], "no local probe when there is nothing to add")

# ---- the canary: the LAN group runs the real runner functions against a fake network; the table needs every row
spec = importlib.util.spec_from_file_location("canary_runner_123b", H.ROOT / "scripts" / "sandbox-canary-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
NET = {"tcp": lambda host, port: "timeout", "udp": lambda host: "eperm"}


def lan_stdout(plan, drop=None):
    rows = []
    runner.row = lambda attack, tag, actual: rows.append(f"CANARYROW\t{attack}\t{tag}\t{actual}")
    runner.tcp_connect = lambda host, port, timeout=1.5, family=None: NET["tcp"](host, port)
    runner.udp_send = lambda host, port=9: NET["udp"](host)
    runner.g_lan(plan)
    return "\n".join(r for r in rows if drop is None or drop not in r).encode()


PLANS = {}


def collect(group, plan, **kwargs):
    PLANS[group] = plan
    stdout = lan_stdout(plan, collect.drop) if group == "lan" else b""
    return {"stdout": stdout, "stderr": b"", "end": {"reason": "exited", "exit": 0}, "refused": None, "run_id": os.urandom(16).hex(), "frames": []}


collect.drop = None


class Outside:
    def run_cmd(self, argv, *, timeout=15):
        if argv[0] == "ss":
            return 0, "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", ""
        return cmd()(argv)


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
table = sh.run_canary(status=STATUS, collect=collect, outside=Outside())
must(PLANS["lan"]["own"] == ["129.232.197.50", "129.232.197.51", "172.17.0.1", "10.8.0.2"] and PLANS["lan"]["gateways"] == ["129.232.197.1"], PLANS["lan"])
must(len(PLANS["lan"]["lan"]) == 5, "the five private probe targets; the gateway has its own rows now")
lan = {r["attack"]: r for r in table if r["wall"] == "LAN"}
want = []
for address in PLANS["lan"]["own"]:  # every non-loopback IPv4 address (at most four), private ones too: the row must refuse them as well
    want += [f"own address {address} tcp {p}" for p in (22, 80, 443)] + [f"own address {address} udp"]
want += [f"gateway 129.232.197.1 tcp {p}" for p in (80, 443)] + ["gateway 129.232.197.1 udp"]
for name in want:
    must(name in lan and lan[name]["verdict"] == "OK", (name, lan.get(name)))
must(not [r for r in lan.values() if r["verdict"] == "NOT RUN"], "every row ran")
# a missing row is NOT RUN, naming it
collect.drop = "gateway 129.232.197.1 udp"
table = sh.run_canary(status=STATUS, collect=collect, outside=Outside())
missing = [r for r in table if r["attack"] == "gateway 129.232.197.1 udp"]
must(len(missing) == 1 and missing[0]["verdict"] == "NOT RUN" and sh.canary_summary(table)[0] is False, missing)
collect.drop = None
# a connection, or a refusal (a reset only comes from a host that was reached), is an attack that succeeded; EPERM and a timeout are not
for tcp_answer, verdict in (("connected", "ATTACK SUCCEEDED"), ("ECONNREFUSED", "ATTACK SUCCEEDED"), ("timeout", "OK"), ("EPERM", "OK")):
    NET["tcp"] = lambda host, port, a=tcp_answer: a
    table = sh.run_canary(status=STATUS, collect=collect, outside=Outside())
    must({r["verdict"] for r in table if r["attack"].startswith(("own address", "gateway")) and " tcp " in r["attack"]} == {verdict}, (tcp_answer, verdict))
NET["tcp"] = lambda host, port: "timeout"
NET["udp"] = lambda host: "sent"
table = sh.run_canary(status=STATUS, collect=collect, outside=Outside())
must({r["verdict"] for r in table if r["attack"].startswith(("own address", "gateway")) and r["attack"].endswith(" udp")} == {"ATTACK SUCCEEDED"}, "a udp send to the own address succeeded")
# unreadable addresses: a NOT RUN row in the table, and the own-address rows are required
table = sh.run_canary(status=STATUS, collect=collect, outside=type("O", (), {"run_cmd": lambda self, argv, timeout=15: (1, "", "") if argv[0] == "ip" else Outside().run_cmd(argv)})())
must(any(r["attack"] == "own addresses and gateway" and r["verdict"] == "NOT RUN" for r in table), table)
must(any("own address" in r["attack"] and r["verdict"] == "NOT RUN" for r in table), "the required own-address rows are missing, so NOT RUN")

print("[TEST] PASS sandbox local deny 1.17.123")
