#!/usr/bin/env python3
"""1.18.27 regression (the two held findings of 1.18.26): the own-name DNS check.

Django-free and network-free: every socket is a stub (nothing is opened, nothing is sent, no 0.0.0.0 listener, no public address is contacted).

Medium (a partial answer): a name counts as answered only when BOTH the A and the AAAA query got a valid answer. An empty set for NXDOMAIN or
NODATA is a valid answer; a timeout, SERVFAIL, a truncated or a mismatched reply is not. If any own name is not fully answered at the deadline the
run's egress is refused (Refusal sandbox_unavailable, a plain reason that names how many names, never an address) and nothing is cached.
  * the reviewer's case 1: A times out, AAAA answers with a global IPv6, a local interface holds a global IPv6 -> refused;
  * case 2: two names, one of them times out -> refused;
  * both names fully answered -> the addresses come back and are cached for 60 s;
  * NXDOMAIN or NODATA on AAAA with a good A -> answered; SERVFAIL on A -> not answered -> refused;
  * a partial result is never cached (the next call looks up again);
  * a hosts-style (/etc/hosts) resolver answer alone never satisfies a name.
Low (reply source): the reply source is compared as an address (a non-canonically written IPv6 upstream matches its canonical reply, a zone suffix
is tolerated) and the source port must be 53; a reply from any other address or port is ignored.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import socket
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_helper_own_name_dns", ROOT / "scripts" / "sandbox-helper.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

NAME, OTHER = "api.example.test", "rmm.example.test"
PUBLIC4 = "93.184.216.34"
PUBLIC6 = "2606:4700:4700::1111"
V6 = ipaddress.IPv6Address(PUBLIC6).packed
S = ["192.0.2.53"]


def reply(name, qtype, ident, records=(), flags=0x8180):
    body = sh.dns_query_packet(name, qtype, 0)[12:]
    packet = struct.pack(">HHHHHH", ident, flags, 1, len(records), 0, 0) + body
    for rtype, rdata in records:
        packet += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
    return packet


A_OK = [(1, bytes([93, 184, 216, 34]))]
AAAA_OK = [(28, V6)]


class Sock:
    """A stub UDP socket. ``responder(name, qtype, ident, server)`` returns a list of (packet, source address, source port) to hand back, or [] for a
    timeout. Sockets are counted so a test can see how many queries a call made."""
    responder = None
    queries = []

    def __init__(self, family):
        self.pending = []

    def settimeout(self, value):
        pass

    def sendto(self, packet, target):
        ident = struct.unpack(">H", packet[:2])[0]
        pos, labels = 12, []
        while packet[pos]:
            labels.append(packet[pos + 1:pos + 1 + packet[pos]].decode("ascii"))
            pos += 1 + packet[pos]
        qtype = struct.unpack(">H", packet[pos + 1:pos + 3])[0]
        name = ".".join(labels)
        Sock.queries.append((name, qtype, target[0]))
        self.pending = list(Sock.responder(name, qtype, ident, target[0]))

    def recvfrom(self, size):
        if not self.pending:
            raise TimeoutError("timed out")
        packet, source, port = self.pending.pop(0)
        return packet, (source, port)

    def close(self):
        pass


def good(name, qtype, ident, server, **kw):
    records = A_OK if qtype == 1 else AAAA_OK
    return [(reply(name, qtype, ident, records), server, 53)]


def lookup_with(responder):
    Sock.responder, Sock.queries = staticmethod(responder), []
    return lambda name, servers: sh.dns_lookup_name(name, servers, sock_factory=Sock, per_try=0.2, total=1.0)


def refused(call):
    try:
        call()
    except sh.Refusal as exc:
        return exc
    except Exception as exc:
        raise AssertionError(("must be a Refusal, never another exception", type(exc).__name__, str(exc))) from exc
    return None


def fresh():
    sh._own_cache.update({"at": 0.0, "key": None, "value": None})


def hosts_only(name, port=None, *rest):  # what getaddrinfo reads from /etc/hosts
    return [(2, 1, 6, "", ("127.0.1.1", 0))]


# ---- dns_lookup_name: both queries must be answered
look = lookup_with(good)
must(look(NAME, S) == (True, {PUBLIC4, PUBLIC6}), "both answered")
must([q[1] for q in Sock.queries] == [1, 28], "an A and an AAAA query")
look = lookup_with(lambda n, t, i, s: [] if t == 1 else good(n, t, i, s))
must(look(NAME, S) == (False, {PUBLIC6}), "A timed out, AAAA answered: not answered (the partial answer is still returned as found)")
look = lookup_with(lambda n, t, i, s: good(n, t, i, s) if t == 1 else [])
must(look(NAME, S) == (False, {PUBLIC4}), "AAAA timed out")
look = lookup_with(lambda n, t, i, s: good(n, t, i, s) if t == 1 else [(reply(n, t, i, flags=0x8183), s, 53)])
must(look(NAME, S) == (True, {PUBLIC4}), "NXDOMAIN on AAAA is a valid, empty answer")
look = lookup_with(lambda n, t, i, s: good(n, t, i, s) if t == 1 else [(reply(n, t, i, records=[], flags=0x8180), s, 53)])
must(look(NAME, S) == (True, {PUBLIC4}), "NODATA on AAAA is a valid, empty answer")
look = lookup_with(lambda n, t, i, s: [(reply(n, t, i, flags=0x8182), s, 53)] if t == 1 else good(n, t, i, s))
must(look(NAME, S) == (False, {PUBLIC6}), "SERVFAIL on A is not an answer")
look = lookup_with(lambda n, t, i, s: [(reply(n, t, i, records=A_OK, flags=0x8380), s, 53)] if t == 1 else good(n, t, i, s))
must(look(NAME, S)[0] is False, "a truncated A reply is not an answer")
look = lookup_with(lambda n, t, i, s: [(reply(n, t, i ^ 1, records=A_OK), s, 53)] if t == 1 else good(n, t, i, s))
must(look(NAME, S)[0] is False, "a reply with another id is not an answer")
look = lookup_with(lambda n, t, i, s: [])
must(look(NAME, S) == (False, set()), "nothing answers")
must(sh.dns_lookup_name(NAME, [], sock_factory=Sock) == (False, set()), "no server at all")

# ---- the Low: reply source and port
# a non-canonically written IPv6 upstream matches its canonical reply
NONCANON = "2001:4860:4860:0:0:0:0:8888"
CANON = str(ipaddress.ip_address(NONCANON))
must(CANON == "2001:4860:4860::8888" and CANON != NONCANON, CANON)
look = lookup_with(lambda n, t, i, s: [(reply(n, t, i, records=A_OK if t == 1 else AAAA_OK), CANON, 53)])
must(look(NAME, [NONCANON]) == (True, {PUBLIC4, PUBLIC6}), "a reply from the canonical form of the written server is accepted")
# a zone suffix on the source is tolerated
look = lookup_with(lambda n, t, i, s: [(reply(n, t, i, records=A_OK if t == 1 else AAAA_OK), "fe80::1%eth0", 53)])
must(look(NAME, ["fe80::1"]) == (True, {PUBLIC4, PUBLIC6}), "a zone suffix on the reply source is tolerated")
# a reply from port 5353 is ignored (the real one that follows still wins)
look = lookup_with(lambda n, t, i, s: [(reply(n, t, i, records=[(1, bytes([6, 6, 6, 6]))] if t == 1 else AAAA_OK), s, 5353),
                                       (reply(n, t, i, records=A_OK if t == 1 else AAAA_OK), s, 53)])
must(look(NAME, S) == (True, {PUBLIC4, PUBLIC6}), "port 5353 is ignored")
# a reply from another address is ignored; with no other reply the name is not answered
look = lookup_with(lambda n, t, i, s: [(reply(n, t, i, records=A_OK if t == 1 else AAAA_OK), "198.51.100.9", 53)])
must(look(NAME, S) == (False, set()), "a reply from another address is ignored")
# a source that is not an address at all is ignored, never an exception
look = lookup_with(lambda n, t, i, s: [(reply(n, t, i, records=A_OK if t == 1 else AAAA_OK), "not-an-address", 53)])
must(look(NAME, S) == (False, set()), "a bad source is ignored")

# ---- resolve_own_names: every own name fully answered, or the egress is refused
LOCAL6 = [PUBLIC6]  # a local interface holds a global IPv6 (the reviewer's case 1)
fresh()
look = lookup_with(lambda n, t, i, s: [] if t == 1 else good(n, t, i, s))
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=look, servers=S, resolver=hosts_only, local_addresses=LOCAL6))
must(exc and exc.code == "sandbox_unavailable" and "1 of this server's 1 own names did not get a full DNS answer" in exc.message, ("case 1", exc and exc.message))
must(PUBLIC6 not in exc.message and PUBLIC4 not in exc.message, "names are counted, addresses are never printed")
must(sh._own_cache["value"] is None, "nothing is cached after a refusal")
# case 2: two names, one times out
fresh()
look = lookup_with(lambda n, t, i, s: [] if n == OTHER else good(n, t, i, s))
exc = refused(lambda: sh.resolve_own_names([NAME, OTHER], lookup=look, servers=S, resolver=hosts_only, local_addresses=LOCAL6))
must(exc and exc.code == "sandbox_unavailable" and "1 of this server's 2 own names" in exc.message, ("case 2", exc and exc.message))
must(sh._own_cache["value"] is None, "nothing is cached after case 2")
# both fully answered: the addresses come back and are cached for 60 s
fresh()
now = [500.0]
look = lookup_with(good)
got = sh.resolve_own_names([NAME, OTHER], lookup=look, servers=S, resolver=hosts_only, clock=lambda: now[0])
must(got == sorted({PUBLIC4, PUBLIC6, "127.0.1.1"}), got)
queries = len(Sock.queries)
must(queries == 4, "two names, an A and an AAAA each")
again = sh.resolve_own_names([NAME, OTHER], lookup=look, servers=S, resolver=hosts_only, clock=lambda: now[0] + 30)
must(again == got and len(Sock.queries) == queries, "cached for 60 s: no new query")
# NODATA on AAAA with a good A: answered; the public IPv4 address is enough
fresh()
look = lookup_with(lambda n, t, i, s: good(n, t, i, s) if t == 1 else [(reply(n, t, i, flags=0x8183), s, 53)])
got = sh.resolve_own_names([NAME], lookup=look, servers=S, resolver=hosts_only)
must(PUBLIC4 in got, got)
# SERVFAIL on A: not answered -> refused
fresh()
look = lookup_with(lambda n, t, i, s: [(reply(n, t, i, flags=0x8182), s, 53)] if t == 1 else good(n, t, i, s))
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=look, servers=S, resolver=hosts_only, local_addresses=LOCAL6))
must(exc and exc.code == "sandbox_unavailable", "SERVFAIL on A refuses")
# a partial result is not cached: the next call looks up again
fresh()
state = {"fail": True}
look_inner = lookup_with(lambda n, t, i, s: [] if state["fail"] and t == 1 else good(n, t, i, s))
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=look_inner, servers=S, resolver=hosts_only, local_addresses=LOCAL6))
must(exc, "first call refused")
before = len(Sock.queries)
state["fail"] = False
got = sh.resolve_own_names([NAME], lookup=look_inner, servers=S, resolver=hosts_only, local_addresses=LOCAL6)
must(len(Sock.queries) > before and PUBLIC4 in got, "the next call looked up again and was answered")
# the hosts-style resolver addition alone never satisfies a name
fresh()
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=lambda n, s: (False, set()), servers=S, local_addresses=LOCAL6,
                                           resolver=lambda *a: [(2, 1, 6, "", (PUBLIC4, 0))]))
must(exc and exc.code == "sandbox_unavailable" and "did not get a full DNS answer" in exc.message, "the system lookup alone never counts")
fresh()
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=lambda n, s: (True, {"10.0.0.5"}), servers=S, resolver=hosts_only, local_addresses=["10.0.0.5"]))
must(exc and "public address is unknown" in exc.message, "check (c) stays: private-only answers and no global interface fail closed")
fresh()
exc = refused(lambda: sh.resolve_own_names([NAME], lookup=lambda n, s: (True, {PUBLIC4}), servers=[], resolver=hosts_only))
must(exc and "no upstream name server" in exc.message, "check (a) stays")
fresh()
# the bounds are unchanged
must(sh.DNS_TRY_SECONDS == 2 and sh.DNS_TOTAL_SECONDS == 5 and sh.OWN_RESOLVE_SECONDS == 5, "2 s per try, 5 s per name, 5 s in all")
print("[TEST] PASS sandbox own name dns 1.18.27")
