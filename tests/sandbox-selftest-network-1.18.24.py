#!/usr/bin/env python3
"""1.18.24 regression (AD-65 Patch B, item 5): the selftest of the new network wall.

The selftest no longer probes an address filter, this server's own addresses or DNS from inside a unit. It probes two things:

* ``network_private``: a unit with the real network properties (PrivateNetwork=yes, AF_INET AF_UNIX, the real file view) sees only ``lo``, cannot
  connect to 1.1.1.1:443 or to a loopback port of this server, and has no resolv.conf; a control run without the wall must reach the server's
  loopback listener first (a probe that cannot connect anyway is never read as a pass);
* ``egress_proxy``: the proxy units start for a throw-away run id with one stand-in host; a CONNECT to it answers 200, a CONNECT to an unlisted host,
  to an IP literal and to port 80 answers 403; the units are stopped and cleaned even when the start fails; a host whose name server is a private
  or loopback address other than the systemd-resolved stub 127.0.0.53 fails closed with a plain reason (never an automatic allow).

ready needs both. status.json keeps address_filter_ok and dns_ok (read by sandbox.py status()) with the new meaning and adds network_private_ok and
egress_ok; resolver, resolvers and dns_method stay as empty values so every reader still works.

Not runnable here: real systemd and the real proxy (dev02: tests/sandbox-canary-1.18.24.sh). The helper's hooks are answered by a fake.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_124a", "sandbox-harness-1.17.118.py")
F = load("sandbox_fake_124a", "sandbox-fake-runner-1.17.120.py")
sh, must, BASE = H.sh, H.must, H.BASE


def selftest(fake, resolv=F.PUBLIC):
    return F.run_selftest(sh, H.RUN, BASE, fake, resolv)


# ---- everything passes: ready, both new checks ok, the old status keys keep their names and types
fake = F.Fake()
status = selftest(fake)
must(status["ready"] is True and status["reason"] == "ready", status)
for name in ("network_private", "egress_proxy"):
    must(status["checks"][name]["ok"] is True, (name, status["checks"][name]))
must(status["address_filter_ok"] is True and status["dns_ok"] is True and status["network_private_ok"] is True and status["egress_ok"] is True, status)
must(status["resolver"] == "" and status["resolvers"] == [] and status["dns_method"] == "", status)
must(isinstance(status["selftest_at"], str) and isinstance(status["slots_total"], int) and status["systemd_version"] == 255, status)
must(isinstance(status["selftest_ms"], int) and status["selftest_ms"] >= 0, "the selftest time is recorded in status.json (the install-speed request depends on it)")
for removed in ("address_filter_control", "address_filter_loopback", "address_filter_private", "address_filter_local", "dns", "upstream_resolvers"):
    must(removed not in status["checks"], ("a retired probe is still in the table", removed))
names = [call[0] for call in fake.calls]
must("network_control" in names and "network_private" in names, names)
must(len(fake.egress["started"]) == 1 and fake.egress["stopped"] == fake.egress["started"], "the throw-away door was started and stopped once")
must(len(fake.egress["started"][0]) == 32, "the instance name is a 32-hex run id")
network_props = [call[1] for call in fake.calls if call[0] == "network_private"][0]
must("PrivateNetwork=yes" in network_props and "RestrictAddressFamilies=AF_INET AF_UNIX" in network_props and any(p.startswith("RootDirectory=") for p in network_props), network_props)
control_props = [call[1] for call in fake.calls if call[0] == "network_control"][0]
must("PrivateNetwork=yes" not in control_props, "the control run has no wall")
text = "\n".join((H.ROOT / "scripts" / name).read_text(encoding="utf-8") for name in ("sandbox-helper.py", "sandbox-selftest.py"))
must("IPAddressDeny" not in text.split("def _probe_network")[0].split("PROBE_PROPERTIES")[1].split("DENIED_NETWORKS")[0], "no unit probe carries IPAddressDeny")

# ---- a visible interface, a reachable address, a reachable loopback port or a resolv.conf: not ready, with a plain reason
cases = (
    ("an interface beyond lo", "ifaces lo,eth0\nconnect 1.1.1.1 443 ENETUNREACH\nconnect 127.0.0.1 {port} ECONNREFUSED\nresolv absent\n", "still saw a network"),
    ("1.1.1.1 reachable", "ifaces lo\nconnect 1.1.1.1 443 connected\nconnect 127.0.0.1 {port} ECONNREFUSED\nresolv absent\n", "reached an address"),
    ("a loopback port reachable", "ifaces lo\nconnect 1.1.1.1 443 ENETUNREACH\nconnect 127.0.0.1 {port} connected\nresolv absent\n", "reached an address"),
    ("a resolv.conf", "ifaces lo\nconnect 1.1.1.1 443 ENETUNREACH\nconnect 127.0.0.1 {port} ECONNREFUSED\nresolv present\n", "resolv.conf"),
    ("no answer at all", "", "PrivateNetwork"),
)
for label, out, part in cases:
    fake = F.Fake(network_private=lambda properties, command, out=out: (0, out.format(port=command[-1]), ""))
    status = selftest(fake)
    must(status["ready"] is False and part in status["reason"], (label, status["reason"]))
    must(status["address_filter_ok"] is False and status["network_private_ok"] is False and status["checks"]["network_private"]["ok"] is False, (label, status))
    must(status["egress_ok"] is True, "the proxy check is independent of the wall check")
status = selftest(F.Fake(network_private=(1, "")))
must(status["ready"] is False and status["address_filter_ok"] is False, "a unit that fails to start is not a pass")
# the control must reach the loopback listener, or the wall probe proves nothing
status = selftest(F.Fake(network_control=lambda properties, command: (0, f"ifaces lo\nconnect 1.1.1.1 443 ENETUNREACH\nconnect 127.0.0.1 {command[-1]} ECONNREFUSED\nresolv absent\n", "")))
must(status["ready"] is False and "could not be checked" in status["reason"] and status["address_filter_ok"] is False, status["reason"])
# a wall probe that leaks through the loopback port while the control works
status = selftest(F.Fake(network_private="leak"))
must(status["ready"] is False and status["address_filter_ok"] is False, status)

# ---- the egress proxy: each failure is plain and never ready
for label, change, part in (
        ("start fails", {"start_fails": True}, "did not start"),
        ("the listed host is not tunnelled (502)", {"listed": 502}, "could not open a tunnel"),
        ("the listed host answers nothing (0)", {"listed": 0}, "could not open a tunnel"),
        ("an unlisted host is tunnelled", {"unlisted": 200}, "did not refuse"),
        ("an IP literal is tunnelled", {"literal": 200}, "did not refuse"),
        ("port 80 is tunnelled", {"port80": 200}, "did not refuse")):
    fake = F.Fake()
    fake.egress.update(change)
    status = selftest(fake)
    must(status["ready"] is False and part in status["reason"], (label, status["reason"]))
    must(status["dns_ok"] is False and status["egress_ok"] is False and status["checks"]["egress_proxy"]["ok"] is False, (label, status))
    must(status["address_filter_ok"] is True and status["network_private_ok"] is True, "the wall check is independent of the proxy check")
    must(len(fake.egress["stopped"]) == len(fake.egress["started"]), ("the units are stopped even on failure", label))

# ---- the host's own resolver: the stub and public servers are fine, a private or loopback one fails closed with a plain reason
for resolv in ("nameserver 127.0.0.53\noptions edns0\n", "nameserver 9.9.9.9\nnameserver 1.1.1.1\n", "nameserver 127.0.0.53\nnameserver 2606:4700:4700::1111\n"):
    must(selftest(F.Fake(), resolv)["ready"] is True, resolv)
for resolv, shown in (("nameserver 10.0.0.2\n", "10.0.0.2"), ("nameserver 192.168.1.1\nnameserver 9.9.9.9\n", "192.168.1.1"), ("nameserver 127.0.0.1\n", "127.0.0.1"),
                      ("nameserver 127.0.0.53\nnameserver 172.16.0.9\n", "172.16.0.9"), ("nameserver 100.64.0.3\n", "100.64.0.3"), ("nameserver fe80::1\n", "fe80::1")):
    fake = F.Fake()
    status = selftest(fake, resolv)
    must(status["ready"] is False and shown in status["reason"] and "systemd-resolved stub" in status["reason"], (resolv, status["reason"]))
    must(status["egress_ok"] is False and fake.egress["started"] == [], "no proxy is started for a resolver it cannot reach (fail closed, no automatic allow)")
status = selftest(F.Fake(), "")
must(status["ready"] is False and "no name server is listed" in status["reason"], status["reason"])
must(sh.resolver_problem("nameserver 127.0.0.53\n") == "" and "10.1.1.1" in sh.resolver_problem("nameserver 10.1.1.1\n"), "resolver_problem")

# ---- the own addresses are still read (they go to the proxy), and an unreadable `ip` stops the proxy check
fake = F.Fake()
fake.ip["addr"] = ""
status = selftest(fake)
must(status["ready"] is False and status["checks"]["local_addresses"]["ok"] is False and status["egress_ok"] is False and fake.egress["started"] == [], status["reason"])
must("handed to the egress proxy" in selftest(F.Fake())["checks"]["local_addresses"]["detail"], "the detail names its new use")
print("[TEST] PASS sandbox selftest network 1.18.24")
