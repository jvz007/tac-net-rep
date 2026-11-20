#!/usr/bin/env python3
"""1.18.25 regression (AD-65 Patch B, own names): the egress proxy scripts/sandbox-egress.py, rule by rule. Everything the 1.18.24 test covered, plus the own-name rules at the end.

Django-free. The resolver and the upstream connect are replaced; every listener and every client binds 127.0.0.1 on an ephemeral port. Nothing in
this file opens a 0.0.0.0 listener or contacts a public address. Covered:

* every refusal class answers its status and opens NO upstream connection and does NO lookup (the stubs count their calls): a method that is not
  CONNECT (403), a malformed request line (400), a head over 8 KiB or slower than 10 s (400), a port other than 443 (403), an IP literal in every
  spelling (dotted, decimal, hex, octal, short, bracketed and bare IPv6), a single label and .local/.internal/.localhost/.lan names (403), a host that
  is not an exact lower-case match in allowed_hosts (403);
* a name that resolves to each blocked range (private, loopback, link-local, multicast, CGNAT, 0/8, 240/4, 198.18/15, 192.0.0.0/24, unspecified,
  IPv6 loopback, link-local, unique-local, multicast, IPv4-mapped, NAT64, 6to4) is refused (403) before any connect; one bad address in a mixed answer
  refuses the whole name; this server's own address, its gateway, an address of its own name and an address a bind() probe accepts are refused;
* the positive control: a listed name that resolves to a global address opens a tunnel (200), relays bytes both ways, connects to the validated
  NUMERIC address (never the name again: one lookup per request) and writes an allowed audit row with byte counts;
* 502 for a failed lookup or connect, 504 for a connect timeout;
* the limits: 100 tunnels per run (the 101st is refused), 16 live (the 17th is refused), the byte limit closes a tunnel, 60 s idle closes it;
* the audit file: one JSON line per CONNECT with exactly host, port, result, reason, up, down; no payload, no header value; a host that is not plain
  letters, digits, '.' and '-' (or over 253 characters) is ``<invalid>``.

Not runnable here: systemd socket activation, the dynamic user, real DNS (dev02: tests/sandbox-canary-1.18.25.sh).
"""
from __future__ import annotations

import errno
import importlib.util
import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BASE = Path(tempfile.mkdtemp(prefix="tectac-egress-"))


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_egress", ROOT / "scripts" / "sandbox-egress.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

must(b"\r" not in (ROOT / "scripts" / "sandbox-egress.py").read_bytes(), "the program keeps LF")
PUBLIC = "93.184.216.34"


# ------------------------------------------------------------------------------------------------ a fake world
class World:
    count = 0

    def __init__(self, answers=None, own=(), gateways=(), fqdn="core.example.test", limits=None, bind_local=(), extra=None):
        self.answers = answers if answers is not None else {"example.com": [PUBLIC], "api.example.com": [PUBLIC], "core.example.test": ["198.51.100.7"]}
        self.lookups, self.dials = [], []
        self.upstream = None
        self.bind_local = set(bind_local)
        self.fail_dial = None
        self.config = {"allowed_hosts": ["example.com", "api.example.com"], "own": list(own), "gateways": list(gateways), "fqdn": fqdn}
        if limits:
            self.config["limits"] = limits
        if extra:
            self.config.update(extra)
        World.count += 1
        self.audit = BASE / f"audit-{World.count}.jsonl"
        self.proxy = E.Egress(self.config, str(self.audit), resolve=self.resolve, dial=self.dial, probe_bind=lambda address: address in self.bind_local)
        self.lookups.clear()  # the start-up lookup of the proxy's own name is not a request
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.proxy.serve, args=(self.listener,), daemon=True)
        self.thread.start()

    def resolve(self, host, port=None, family=0, kind=0):
        self.lookups.append(host)
        answer = self.answers.get(host)
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise OSError(errno.ENOENT, "no such name")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 443)) for a in answer]

    def dial(self, address, port, timeout):
        self.dials.append((address, port, timeout))
        if self.fail_dial is not None:
            raise self.fail_dial
        return socket.create_connection(self.upstream, timeout=3)

    def start_upstream(self, echo=True):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(32)
        self.upstream = srv.getsockname()

        def work():
            while True:
                try:
                    conn, _peer = srv.accept()
                except OSError:
                    return
                threading.Thread(target=self.echo, args=(conn,), daemon=True).start()

        threading.Thread(target=work, daemon=True).start()
        self._upstream_listener = srv

    @staticmethod
    def echo(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            return
        finally:
            conn.close()

    def client(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=5)

    def status_of(self, raw):
        """Send raw bytes, return the status code of the answer (0 when the proxy only closed)."""
        c = self.client()
        try:
            c.sendall(raw)
            data = c.recv(512)
        except OSError:
            data = b""
        finally:
            c.close()
        parts = data.split(b"\r\n", 1)[0].split()
        return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

    def connect_status(self, target):
        return self.status_of(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))

    def rows(self):
        time.sleep(0.2)
        if not self.audit.exists():
            return []
        return [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines() if line.strip()]

    def stop(self):
        self.proxy.stopping.set()
        self.thread.join(5)
        self.listener.close()
        upstream = getattr(self, "_upstream_listener", None)
        if upstream is not None:
            upstream.close()


# ------------------------------------------------------------------------------------------------ the pure rules
must(E.looks_like_ip("1.1.1.1") and E.looks_like_ip("2130706433") and E.looks_like_ip("0x7f000001") and E.looks_like_ip("0177.0.0.1")
     and E.looks_like_ip("127.1") and E.looks_like_ip("[::1]") and E.looks_like_ip("::1") and E.looks_like_ip("example.123")
     and E.looks_like_ip("0x7f.0x0.0x0.0x1") and E.looks_like_ip(""), "IP literals in every spelling")
must(not E.looks_like_ip("example.com") and not E.looks_like_ip("1password.com") and not E.looks_like_ip("a1.b2.example.org"), "real names")
for blocked in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.0.1", "172.31.255.255", "100.64.0.1", "100.127.255.254", "0.0.0.0",
                "0.1.2.3", "240.0.0.1", "255.255.255.255", "198.18.0.1", "198.19.255.255", "192.0.0.5", "224.0.0.1", "239.255.255.250", "::", "::1",
                "fe80::1", "fc00::1", "fd12::1", "ff02::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2002:a00:1::", "100::1",
                "2001:db8::1", "not an address"):
    must(E.blocked_address(blocked) == "address_blocked", blocked)
for fine in (PUBLIC, "1.1.1.1", "9.9.9.9", "8.8.8.8", "2606:4700:4700::1111", "::ffff:93.184.216.34"):
    must(E.blocked_address(fine) is None, fine)
must(E.can_bind("127.0.0.1") is True, "a local address accepts a bind")
must(E.can_bind("203.0.113.77") is False, "an address that is not this server's own gives EADDRNOTAVAIL")
must(E.clean_host("example.com") == "example.com" and E.clean_host("a" * 254) == "<invalid>" and E.clean_host("bad host") == "<invalid>"
     and E.clean_host("a/b") == "<invalid>" and E.clean_host(5) == "<invalid>" and E.clean_host("é.com") == "<invalid>", "audit host cleaning")
must(E.parse_head(b"CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n") == ("CONNECT", "example.com:443"), "parse")
for bad in (b"garbage\r\n\r\n", b"CONNECT example.com:443\r\n\r\n", b"CONNECT a b HTTP/1.1\r\n\r\n", b"CONNECT x:443 SPDY/3\r\n\r\n", b"CONNECT x:443 HTTP/1.1\x00\r\n\r\n",
            b"CONNECT " + b"a" * 2000 + b":443 HTTP/1.1\r\n\r\n", b"CONNECT \xff:443 HTTP/1.1\r\n\r\n"):
    try:
        E.parse_head(bad)
    except (ValueError, UnicodeDecodeError):
        continue
    raise AssertionError(("a malformed line was parsed", bad[:40]))

# ------------------------------------------------------------------------------------------------ every refusal class: status, no lookup, no upstream
w = World()
w.start_upstream()
refusals = [
    ("method GET", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", 403),
    ("method POST", b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n", 403),
    ("method CONNECT lower case", b"connect example.com:443 HTTP/1.1\r\n\r\n", 403),
    ("malformed line", b"garbage\r\n\r\n", 400),
    ("two words", b"CONNECT example.com:443\r\n\r\n", 400),
    ("bad version", b"CONNECT example.com:443 SPDY/3\r\n\r\n", 400),
    ("NUL in the line", b"CONNECT example.com:443 HTTP/1.1\x00\r\n\r\n", 400),
    ("non-ASCII", b"CONNECT \xff.com:443 HTTP/1.1\r\n\r\n", 400),
    ("a space in the target", b"CONNECT exa mple.com:443 HTTP/1.1\r\n\r\n", 400),
]
for target, status in (("example.com:80", 403), ("example.com:22", 403), ("example.com:8443", 403), ("example.com:0443", 403), ("example.com:", 403),
                       ("example.com", 403), ("example.com:99999999", 403), ("example.com:-1", 403), ("example.com: 443", 400)):
    refusals.append(("port " + target, f"CONNECT {target} HTTP/1.1\r\n\r\n".encode(), status))
for target in ("1.1.1.1:443", "10.0.0.1:443", "127.0.0.1:443", "2130706433:443", "0x7f000001:443", "0177.0.0.1:443", "127.1:443", "0x7f.0x0.0x0.0x1:443",
               "[::1]:443", "[2606:4700:4700::1111]:443", "::1", "::ffff:10.0.0.1", "example.123:443", "93.184.216.34:443", "example.com.:443"):
    refusals.append(("ip literal " + target, f"CONNECT {target} HTTP/1.1\r\n\r\n".encode(), 403))
for target in ("intranet:443", "localhost:443", "printer.local:443", "db.internal:443", "app.localhost:443", "nas.lan:443", "api.lan:443"):
    refusals.append(("local name " + target, f"CONNECT {target} HTTP/1.1\r\n\r\n".encode(), 403))
for target in ("example.net:443", "EXAMPLE.COM:443", "Example.Com:443", "sub.example.com:443", "example.com.evil.test:443", "evil.test:443", "core.example.test:443",
               "ex_ample.com:443"):
    refusals.append(("not listed " + target, f"CONNECT {target} HTTP/1.1\r\n\r\n".encode(), 403))
for label, raw, status in refusals:
    must(w.status_of(raw) == status, (label, status))
must(w.lookups == [] and w.dials == [], ("a refusal made a lookup or a connection", w.lookups, w.dials))
rows = w.rows()
must(len(rows) == len(refusals), (len(rows), len(refusals)))
must(all(r["result"] == "refused" and r["up"] == 0 and r["down"] == 0 for r in rows), rows[:3])
reasons = {r["reason"] for r in rows}
must({"method", "malformed", "port", "ip_literal", "local_name", "not_listed"} <= reasons, reasons)
w.stop()

# ------------------------------------------------------------------------------------------------ a head over 8 KiB, and a head that never ends
w = World(limits={"head_seconds": 1})
w.start_upstream()
big = b"CONNECT example.com:443 HTTP/1.1\r\n" + b"X-Pad: " + b"a" * 9000
must(w.status_of(big) == 400, "a head over 8 KiB is refused")
c = w.client()
c.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n")  # never finished: slower than the limit
started = time.monotonic()
data = c.recv(512)
c.close()
must(data.startswith(b"HTTP/1.1 400") and time.monotonic() - started < 4, (data, time.monotonic() - started))
must(w.lookups == [] and w.dials == [], "no lookup, no connection")
must({"head_too_large", "head_too_slow"} <= {r["reason"] for r in w.rows()}, w.rows())
w.stop()
must(E.LIMITS["head_bytes"] == 8192 and E.LIMITS["head_seconds"] == 10 and E.LIMITS["tunnels_live"] == 16 and E.LIMITS["tunnels_total"] == 100
     and E.LIMITS["bytes_total"] == 256 * 1024 * 1024 and E.LIMITS["connect_seconds"] == 10 and E.LIMITS["idle_seconds"] == 60, E.LIMITS)

# ------------------------------------------------------------------------------------------------ a name that resolves to a blocked address
BLOCKED_ANSWERS = ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.5.5", "100.64.0.9", "0.0.0.0", "0.1.2.3", "240.0.0.1", "198.18.0.1",
                   "192.0.0.9", "224.0.0.251", "255.255.255.255", "::1", "fe80::1", "fc00::5", "ff02::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::"]
w = World()
w.start_upstream()
for address in BLOCKED_ANSWERS:
    w.answers["example.com"] = [address]
    must(w.connect_status("example.com:443") == 403, ("a name resolving to a blocked address was tunnelled", address))
w.answers["example.com"] = [PUBLIC, "10.0.0.1"]  # one bad address in the answer refuses the whole name
must(w.connect_status("example.com:443") == 403, "a mixed answer is refused")
w.answers["example.com"] = ["10.0.0.1", PUBLIC]
must(w.connect_status("example.com:443") == 403, "a mixed answer is refused, bad one first")
must(w.dials == [], ("no upstream connection for a blocked address", w.dials))
must({r["reason"] for r in w.rows()} == {"address_blocked"}, w.rows()[:3])
w.stop()

# this server's own addresses, gateway, own name and a bind() probe
w = World(own=["203.0.113.50"], gateways=["203.0.113.1"], bind_local={"203.0.113.99"})
w.start_upstream()
for address, why in (("203.0.113.50", "own address"), ("203.0.113.1", "gateway"), ("198.51.100.7", "an address of this server's own name"), ("203.0.113.99", "a bind probe accepts it")):
    w.answers["example.com"] = [address]
    must(w.connect_status("example.com:443") == 403, why)
must(w.dials == [], "none of them was connected to")
w.answers["example.com"] = [PUBLIC]
must(w.connect_status("example.com:443") == 200, "a global address that is not this server's own is allowed")
w.stop()

# ------------------------------------------------------------------------------------------------ the positive control: 200, relay, numeric connect, one lookup
w = World()
w.start_upstream()
c = w.client()
c.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nAuthorization: Bearer SECRET-HEADER-VALUE\r\n\r\n")
head = b""
while b"\r\n\r\n" not in head:
    head += c.recv(512)
must(head.startswith(b"HTTP/1.1 200 "), head)
c.sendall(b"SECRET-PAYLOAD-BYTES")
echoed = b""
while len(echoed) < 20:
    echoed += c.recv(64)
must(echoed == b"SECRET-PAYLOAD-BYTES", echoed)
c.close()
time.sleep(0.4)
must(w.lookups == ["example.com"], ("exactly one lookup per request (no rebinding)", w.lookups))
must(w.dials == [(PUBLIC, 443, 10)], ("it connects to the validated numeric address, port 443, 10 s", w.dials))
rows = w.rows()
must(len(rows) == 1 and rows[0]["result"] == "allowed" and rows[0]["reason"] in ("closed", "idle") and rows[0]["host"] == "example.com" and rows[0]["port"] == 443, rows)
must(rows[0]["up"] == 20 and rows[0]["down"] == 20, rows)
text = w.audit.read_text(encoding="utf-8")
must("SECRET-PAYLOAD" not in text and "SECRET-HEADER" not in text and "Bearer" not in text and "Authorization" not in text, "no payload and no header in the audit file")
must(all(set(json.loads(line)) == {"host", "port", "result", "reason", "up", "down"} for line in text.splitlines()), "the audit schema is exact")
w.stop()

# bytes a client sends right behind its head (no wait for the 200) are not lost: they reach the upstream first
w = World()
w.start_upstream()
c = w.client()
c.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\nEARLY-BYTES")
head = b""
while b"\r\n\r\n" not in head:
    head += c.recv(512)
echo = head.split(b"\r\n\r\n", 1)[1]
while len(echo) < 11:
    echo += c.recv(64)
must(head.startswith(b"HTTP/1.1 200 ") and echo == b"EARLY-BYTES", (head, echo))
c.close()
w.stop()

# ------------------------------------------------------------------------------------------------ upstream trouble: 502 and 504
w = World()
w.start_upstream()
w.answers["example.com"] = OSError(errno.ENOENT, "gone")
must(w.connect_status("example.com:443") == 502, "a failed lookup is 502")
w.answers["example.com"] = []
must(w.connect_status("example.com:443") == 502, "an empty answer is 502")
w.answers["example.com"] = [PUBLIC]
w.fail_dial = ConnectionRefusedError(errno.ECONNREFUSED, "refused")
must(w.connect_status("example.com:443") == 502, "a refused connect is 502")
w.fail_dial = TimeoutError("timed out")
must(w.connect_status("example.com:443") == 504, "a connect timeout is 504")
w.fail_dial = None
must(w.connect_status("example.com:443") == 200, "and a good one still works after the failures")
reasons = {r["reason"] for r in w.rows()}
must({"resolve_failed", "connect_failed", "connect_timeout"} <= reasons, reasons)
w.stop()

# ------------------------------------------------------------------------------------------------ the limits
w = World(limits={"tunnels_total": 3})
w.start_upstream()
for _ in range(3):
    must(w.connect_status("example.com:443") == 200, "within the run's tunnel budget")
must(w.connect_status("example.com:443") == 403, "the 4th tunnel of a run of 3 is refused")
must("limit" in {r["reason"] for r in w.rows()}, w.rows())
w.stop()
must(E.LIMITS["tunnels_total"] == 100, "the run budget is 100")

w = World(limits={"tunnels_live": 2})
w.start_upstream()
held = []
for _ in range(2):
    c = w.client()
    c.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
    must(c.recv(512).startswith(b"HTTP/1.1 200"), "a live tunnel")
    held.append(c)
must(w.connect_status("example.com:443") == 403, "the 3rd live tunnel (limit 2) is refused")
held[0].close()
time.sleep(0.5)
must(w.connect_status("example.com:443") == 200, "a closed tunnel frees its place")
for c in held:
    c.close()
w.stop()

w = World(limits={"bytes_total": 100})
w.start_upstream()
c = w.client()
c.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
must(c.recv(512).startswith(b"HTTP/1.1 200"), "opened")
c.sendall(b"x" * 400)
got = 0
c.settimeout(3)
try:
    while True:
        chunk = c.recv(1024)
        if not chunk:
            break
        got += len(chunk)
except OSError:
    pass
c.close()
must(got <= 100, ("the tunnel is closed at the run's byte limit", got))
rows = w.rows()
must(rows and rows[-1]["reason"] == "run_limit" and rows[-1]["up"] + rows[-1]["down"] <= 100, rows)
must(w.connect_status("example.com:443") == 403, "a run that used its bytes opens no new tunnel")
w.stop()

w = World(limits={"idle_seconds": 1})
w.start_upstream()
c = w.client()
c.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
must(c.recv(512).startswith(b"HTTP/1.1 200"), "opened")
started = time.monotonic()
c.settimeout(6)
try:
    closed = c.recv(1024) == b""
except OSError:
    closed = True
c.close()
must(closed and time.monotonic() - started < 5, "an idle tunnel is closed")
must(w.rows()[-1]["reason"] == "idle", w.rows())
w.stop()

# ------------------------------------------------------------------------------------------------ the configuration and the activated socket
folder = BASE / "creds"
folder.mkdir()
(folder / "run.json").write_text(json.dumps({"allowed_hosts": ["example.com"], "own": [], "gateways": [], "fqdn": ""}), encoding="utf-8")
must(E.read_config(str(folder))["allowed_hosts"] == ["example.com"], "run.json is read")
(folder / "run.json").write_text("[1]", encoding="utf-8")
try:
    E.read_config(str(folder))
except TypeError:
    pass
else:
    raise AssertionError("a config that is not an object is refused")
must(E.listener_from_systemd() is None, "no LISTEN_FDS: no activated socket")
text = (ROOT / "scripts" / "sandbox-egress.py").read_text(encoding="utf-8")
must("bind((\"0.0.0.0\"" not in text and "0.0.0.0\", " not in text.replace('"0.0.0.0/8"', ""), "the program never listens on 0.0.0.0")
# ------------------------------------------------------------------------------------------------ 1.18.25: every own name, not only the fqdn
NAT_PUBLIC = "198.51.100.77"  # a documentation address standing in for the NAT'd server's public address (on no local interface)
answers = {"example.com": [PUBLIC], "api.example.com": [PUBLIC], "api.example.test": [NAT_PUBLIC], "rmm.example.test": [NAT_PUBLIC],
           "mesh.example.test": ["198.51.100.78"], "hairpin.example.com": [NAT_PUBLIC], "late.example.com": [PUBLIC]}
w = World(answers=answers, fqdn="", extra={"own_names": ["api.example.test", "rmm.example.test", "mesh.example.test"],
                                           "allowed_hosts": ["example.com", "api.example.test", "hairpin.example.com", "late.example.com"]})
w.start_upstream()
w.lookups.clear()
for name in ("api.example.test", "rmm.example.test", "mesh.example.test", "API.EXAMPLE.TEST"):
    before = (len(w.lookups), len(w.dials))
    must(w.connect_status(f"{name}:443") == 403, f"{name} is refused")
    must((len(w.lookups), len(w.dials)) == before, "an own name is refused with no lookup and no dial")
reasons = [r["reason"] for r in w.rows()]
must(reasons[:3] == ["own_name"] * 3, reasons)  # api.example.test is also in allowed_hosts: still own_name
# an allowed host that resolves to the NAT public address of an own name: the start-up lookup of the own names found it
must(w.proxy.fqdn_addresses >= {NAT_PUBLIC, "198.51.100.78"}, w.proxy.fqdn_addresses)
w.dials.clear()
must(w.connect_status("hairpin.example.com:443") == 403 and not w.dials, "a host that resolves to an own name's address is address_blocked")
must(w.rows()[-1]["reason"] == "address_blocked", w.rows()[-1])
w.stop()

# an address handed in only through own_name_addresses is refused (the name does not resolve in the proxy's own start-up lookup)
w = World(answers={"example.com": [PUBLIC], "hairpin.example.com": ["198.51.100.99"]}, fqdn="",
          extra={"own_names": ["gone.example.test"], "own_name_addresses": ["198.51.100.99"], "allowed_hosts": ["example.com", "hairpin.example.com"]})
w.start_upstream()
must(w.connect_status("hairpin.example.com:443") == 403 and not w.dials, "an address of own_name_addresses is refused")
must(w.rows()[-1]["reason"] == "address_blocked", w.rows()[-1])
must(w.connect_status("example.com:443") == 200, "the positive control still gets 200")
w.stop()

# a name that resolves only at proxy start-up is refused: the answer changes after start-up
late = {"example.com": [PUBLIC], "late.example.com": ["198.51.100.55"], "own.example.test": ["198.51.100.55"]}
w = World(answers=late, fqdn="", extra={"own_names": ["own.example.test"], "allowed_hosts": ["example.com", "late.example.com"]})
w.start_upstream()
w.answers["own.example.test"] = OSError(errno.ENOENT, "gone")  # it no longer resolves, the start-up result is what counts
must(w.connect_status("late.example.com:443") == 403 and not w.dials, "an address found only at start-up is refused")
w.stop()

# the old fqdn key still works as an own name
w = World(fqdn="core.example.test", extra={"allowed_hosts": ["example.com", "core.example.test"]})
must(w.connect_status("core.example.test:443") == 403 and w.rows()[-1]["reason"] == "own_name", "fqdn is an own name")
w.stop()

# a config with no own names still behaves as in 1.18.24 and the audit schema keeps its six keys
w = World(fqdn="")
w.start_upstream()
must(w.connect_status("example.com:443") == 200, "no own names: the positive control gets 200")
must(set(w.rows()[-1]) == {"host", "port", "result", "reason", "up", "down"}, w.rows()[-1])
w.stop()
print("[TEST] PASS sandbox egress proxy 1.18.25")
