#!/usr/bin/env python3
"""1.18.27 regression (from the 1.18.26 test; the three assertions that said answered when at least one query answered are changed): (held Medium and Low of 1.18.25): the proxy also refuses the server's PUBLIC addresses for its own names.

Django-free and network-free: every socket is a stub (nothing is opened, nothing is sent, no 0.0.0.0 listener). Covered:

* the DNS query builder and the answer parser against fixed bytes (header, question, A and AAAA records, a compressed name, a wrong id, a
  short packet, a truncated answer, a question that is not ours, a server failure, a record that runs past the packet, a non-answer packet);
* dns_lookup_name through a fake UDP socket: a good answer, an answer with a wrong id or from another source is ignored and the right one
  still wins, a timeout moves on to the next resolver, no answer at all is ``answered`` False, the per-name limit holds; since 1.18.27 a name is
  answered only when BOTH the A and the AAAA query got a valid answer (tests/sandbox-own-name-dns-1.18.27.py covers the new rule in full);
* upstream_resolvers: the systemd-resolved file wins, 127.0.0.0/8 and ::1 stubs are removed, /etc/resolv.conf is the fallback, [] when only stubs;
* resolve_own_names: a hosts-style 127.0.1.1 alone fails closed; a public address is collected (and the old getaddrinfo answer may add to it but
  never replaces it); private-only answers fail closed with no global local address and pass with one; no resolver, and no answer at all, fail
  closed; the answer is cached 60 s;
* the late-thread race: a lookup that finishes just after the deadline returns only a list or a Refusal, never a RuntimeError, and any unexpected
  exception in a lookup becomes a Refusal;
* the proxy refuses the collected public address (address_blocked) through the existing rule, with no lookup of its own.

Not runnable here: real DNS (dev02 canary row pb-proxy-refuse-own-public-address).
"""
from __future__ import annotations

import importlib.util
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_helper_own_public", ROOT / "scripts" / "sandbox-helper.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

NAME = "api.example.test"
PUBLIC = "93.184.216.34"
V6 = bytes.fromhex("20010db8000000000000000000000005")  # 2001:db8::5


def question(name=NAME, qtype=1):
    return sh.dns_query_packet(name, qtype, 0)[12:]


def answer(ident=7, name=NAME, qtype=1, records=(), flags=0x8180, qname=None, extra=b""):
    body = question(qname or name, qtype)
    packet = struct.pack(">HHHHHH", ident, flags, 1, len(records), 0, 0) + body
    for rtype, rdata in records:
        packet += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
    return packet + extra


# ---- builder and parser with fixed bytes
fixed = sh.dns_query_packet("a.bc", 1, 0x1234)
must(fixed == bytes.fromhex("123401000001000000000000" "01610262630000010001"), fixed.hex())
must(sh.dns_query_packet("a.bc.", 28, 1)[-4:] == b"\x00\x1c\x00\x01", "AAAA question, trailing dot dropped")
for bad in ("a..b", "", "a" * 64 + ".b", "bücher.example"):
    try:
        sh.dns_query_packet(bad, 1, 1)
    except (ValueError, UnicodeError):
        pass
    else:
        raise AssertionError(("a bad name was built", bad))
good = answer(records=[(1, bytes([93, 184, 216, 34]))])
must(sh.dns_parse_answer(good, 7, NAME, 1) == {PUBLIC}, "A record")
must(sh.dns_parse_answer(answer(qtype=28, records=[(28, V6)]), 7, NAME, 28) == {"2001:db8::5"}, "AAAA record")
must(sh.dns_parse_answer(answer(records=[(5, b"\x00")]), 7, NAME, 1) == set(), "a CNAME alone adds no address")
must(sh.dns_parse_answer(answer(flags=0x8183), 7, NAME, 1) == set(), "NXDOMAIN is a real, empty answer")
for label, packet in (("wrong id", answer(ident=8, records=[(1, b"\x01\x02\x03\x04")])), ("short", good[:11]), ("empty", b""),
                      ("not a response", answer(flags=0x0100)), ("truncated", answer(flags=0x8380)), ("server failure", answer(flags=0x8182)),
                      ("other question", answer(qname="other.example.test", records=[(1, b"\x01\x02\x03\x04")])),
                      ("record past the end", good[:-2]), ("text", "not bytes"), ("huge", b"\x00" * 5000)):
    must(sh.dns_parse_answer(packet, 7, NAME, 1) is None, ("must be ignored", label))
must(sh.dns_parse_answer(good, 7, NAME.upper(), 1) == {PUBLIC}, "name case does not matter")


# ---- dns_lookup_name through a fake socket
class FakeSock:
    plan = []  # per socket: a list of ("data", bytes or function of the id, source) or ("timeout",)
    made = []

    def __init__(self, family):
        self.family, self.sent, self.closed = family, [], False
        self.script = FakeSock.plan.pop(0) if FakeSock.plan else [("timeout",)]
        FakeSock.made.append(self)

    def settimeout(self, value):
        self.timeout = value

    def sendto(self, packet, target):
        self.sent.append((packet, target))
        self.ident = struct.unpack(">H", packet[:2])[0]

    def recvfrom(self, size):
        step = self.script.pop(0) if self.script else ("timeout",)
        if step[0] == "timeout":
            raise socket.timeout("timed out")
        data = step[1](self.ident) if callable(step[1]) else step[1]
        return data, (step[2], 53)

    def close(self):
        self.closed = True


def reply(records, qtype=1, wrong_id=False):
    return lambda ident: answer(ident=(ident ^ 1) if wrong_id else ident, qtype=qtype, records=records)


def lookup(plan, servers=("192.0.2.53", "192.0.2.54"), **kw):
    FakeSock.plan, FakeSock.made = [list(item) for item in plan], []
    return sh.dns_lookup_name(NAME, list(servers), sock_factory=FakeSock, **kw)


a_rec, aaaa_rec = [(1, bytes([93, 184, 216, 34]))], [(28, V6)]
result = lookup([[("data", reply(a_rec), "192.0.2.53")], [("data", reply(aaaa_rec, 28), "192.0.2.53")]])
must(result == (True, {PUBLIC, "2001:db8::5"}), result)
must(len(FakeSock.made) == 2 and all(item.closed and item.sent[0][1] == ("192.0.2.53", 53) for item in FakeSock.made), "sockets closed, port 53")
# a wrong id and a packet from another source are ignored; the right answer after them still wins
result = lookup([[("data", reply(a_rec, wrong_id=True), "192.0.2.53"), ("data", reply(a_rec), "198.51.100.9"), ("data", reply(a_rec), "192.0.2.53")],
                 [("timeout",)]], servers=("192.0.2.53",), per_try=0.2)
must(result == (False, {PUBLIC}), result)  # 1.18.27: the A query was answered but the AAAA query was not, so the name is not answered
# the first resolver times out, the second answers
result = lookup([[("timeout",)], [("data", reply(a_rec), "192.0.2.54")], [("timeout",)], [("timeout",)]], per_try=0.2)
must(result[0] is False and result[1] == {PUBLIC}, result)  # 1.18.27: A answered by the second resolver, AAAA never answered
# nobody answers at all
result = lookup([], per_try=0.1, total=0.5)
must(result == (False, set()), result)
# only junk is ever received
result = lookup([[("data", b"\x00\x01", "192.0.2.53")] * 3] * 4, servers=("192.0.2.53",), per_try=0.1, total=0.5)
must(result == (False, set()), result)

# ---- upstream_resolvers
files = {sh.RESOLVED_UPSTREAM: "nameserver 127.0.0.53\nnameserver 192.0.2.53\nnameserver ::1\nnameserver 2001:db8::53\n",
         sh.RESOLV_CONF: "nameserver 198.51.100.1\n"}
must(sh.upstream_resolvers(lambda path: files.get(path, "")) == ["192.0.2.53", "2001:db8::53"], "the resolved file wins and the stubs are removed")
files[sh.RESOLVED_UPSTREAM] = "nameserver 127.0.0.53\nnameserver 127.0.1.1\n"
must(sh.upstream_resolvers(lambda path: files.get(path, "")) == ["198.51.100.1"], "fallback to /etc/resolv.conf")
files[sh.RESOLV_CONF] = "nameserver 127.0.0.53\n"
must(sh.upstream_resolvers(lambda path: files.get(path, "")) == [], "only stubs: none usable")
must(sh.upstream_resolvers(lambda path: "") == [], "unreadable files: none usable")


# ---- resolve_own_names
def refused(call):
    try:
        call()
    except sh.Refusal as exc:
        return exc
    except Exception as exc:
        raise AssertionError(("must be a Refusal, never another exception", type(exc).__name__)) from exc
    return None


def fresh():
    sh._own_cache.update({"at": 0.0, "key": None, "value": None})


def hosts_only(name, port=None, *rest):  # what getaddrinfo reads from /etc/hosts on a Tactical server
    return [(2, 1, 6, "", ("127.0.1.1", 0))]


S = ["192.0.2.53"]
fresh()
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=lambda n, s: (True, set()), servers=S, resolver=hosts_only))
must(exc and exc.code == "sandbox_unavailable" and "public address is unknown" in exc.message, ("a hosts-style 127.0.1.1 alone fails closed", exc and exc.message))
fresh()
got = sh.resolve_own_names([NAME, "rmm." + NAME], lookup=lambda n, s: (True, {PUBLIC} if n == NAME else {"10.0.0.5"}), servers=S, resolver=hosts_only)
must(got == ["10.0.0.5", "127.0.1.1", PUBLIC], ("the public address is collected; hosts adds, never replaces", got))
fresh()
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=lambda n, s: (True, {"10.0.0.5"}), servers=S, resolver=hosts_only,
                                           local_addresses=["10.0.0.5", "fe80::1"]))
must(exc and "no local interface has a public one" in exc.message, "private-only answers and no global interface fail closed")
fresh()
got = sh.resolve_own_names([NAME], lookup=lambda n, s: (True, {"10.0.0.5"}), servers=S, resolver=hosts_only, local_addresses=["10.0.0.5", "8.8.4.4"])
must("10.0.0.5" in got, "private-only answers pass when a local interface holds a global address")
fresh()
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=lambda n, s: (True, {PUBLIC}), servers=[], resolver=hosts_only))
must(exc and "no upstream name server" in exc.message, "(a) no resolver is usable")
fresh()
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=lambda n, s: (False, set()), servers=S, resolver=lambda *a: [(2, 1, 6, "", (PUBLIC, 0))]))
must(exc and "did not get a full DNS answer" in exc.message, "(b) no real DNS answer: the system lookup alone never counts")
fresh()


def boom(name, servers):
    raise RuntimeError("boom")


exc = refused(lambda: sh.resolve_own_names([NAME], lookup=boom, servers=S, resolver=hosts_only))
must(exc and exc.code == "sandbox_unavailable", "an unexpected fault in a lookup is a Refusal")
fresh()
calls = []
now = [100.0]


def counting(n, s):
    calls.append(n)
    return True, {PUBLIC}


sh.resolve_own_names([NAME], lookup=counting, servers=S, resolver=hosts_only, clock=lambda: now[0])
sh.resolve_own_names([NAME], lookup=counting, servers=S, resolver=hosts_only, clock=lambda: now[0] + 30)
must(len(calls) == 1, "cached for 60 s")
now[0] += 61
sh.resolve_own_names([NAME], lookup=counting, servers=S, resolver=hosts_only, clock=lambda: now[0])
must(len(calls) == 2, "looked up again after 60 s")

# ---- the race: a lookup that ends just after the deadline writes harmlessly
fresh()
gate = threading.Event()


def late(n, s):
    if n.startswith("late"):
        gate.wait(5)
    return True, {PUBLIC}


started = time.monotonic()
exc = refused(lambda: sh.resolve_own_names([NAME, "late." + NAME], lookup=late, servers=S, resolver=hosts_only, seconds=0.3))
must(exc and exc.code == "sandbox_unavailable" and "1 of this server's 2 own names" in exc.message and time.monotonic() - started < 3,
     "bounded; 1.18.27: one name that did not answer in time refuses (it used to be a list of the others)")
must(sh._own_cache["value"] is None, "a partial result is not cached")
gate.set()
time.sleep(0.2)  # the late thread has written after the deadline: nothing breaks
fresh()
gate.clear()


def all_late(n, s):
    gate.wait(5)
    return True, {PUBLIC}


exc = refused(lambda: sh.resolve_own_names(["late.a." + NAME, "late.b." + NAME], lookup=all_late, servers=S, resolver=hosts_only, seconds=0.2))
must(exc and exc.code == "sandbox_unavailable", "all lookups late: a Refusal, never a RuntimeError")
gate.set()
time.sleep(0.2)

# ---- the proxy refuses the collected public address and does no lookup of its own when the helper handed addresses in
spec2 = importlib.util.spec_from_file_location("sandbox_egress_own_public", ROOT / "scripts" / "sandbox-egress.py")
eg = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(eg)


def no_lookup(*args):
    raise AssertionError("no lookup when the helper handed in the addresses")


proxy = eg.Egress({"allowed_hosts": ["wild.example.test"], "own": ["10.0.0.5"], "gateways": [], "fqdn": NAME, "own_names": [NAME],
                   "own_name_addresses": [PUBLIC, "10.0.0.5"]}, "audit.jsonl", resolve=no_lookup, probe_bind=lambda address: False)
must(PUBLIC in proxy.fqdn_addresses, "the handed-in public address is in the proxy's own-address set")
print("[TEST] PASS sandbox own public address 1.18.27")
