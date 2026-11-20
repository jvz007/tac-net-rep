#!/usr/bin/python3
"""The egress door of core.sandbox (Core 1.18.24, AD-65 Patch B, item 2): a small HTTP CONNECT proxy, one per run.

A run has its own, empty network space. Its only way out is one AF_UNIX door; behind the door is this program, started by systemd's socket
activation (``tec-tac-sandbox-egress@<run id>.socket`` and ``.service``, written by install.sh) as its own unprivileged dynamic user, with the run's
configuration (``run.json``) handed in through LoadCredential. It runs on the host side, so it is the only part that resolves names or opens a
connection, and every rule below is applied here before any upstream socket exists.

Protocol: HTTP CONNECT only. A request is refused, with no upstream connection, when

* the method is not CONNECT (403) or the request line is malformed (400); the head is over 8 KiB or slower than 10 s (400);
* the port is not 443 (403);
* the host is an IP literal in any spelling (dotted, decimal, hex, octal, bracketed IPv6), a single label, or ends .local, .internal,
  .localhost or .lan (403);
* the host is one of this server's own names (its FQDN, Tactical's API, RMM and Mesh names; reason ``own_name``, 403), even when it is listed (1.18.25);
* the host is not an exact lower-case match in the run's ``allowed_hosts`` (403);
* the run already has 16 live tunnels or has used 100 tunnels (403).

The name is then resolved here (never in the run). Every address it resolves to must be global: not private, loopback, link-local, multicast,
carrier-grade NAT (100.64.0.0/10), 0.0.0.0/8, 240.0.0.0/4, 198.18.0.0/15, 192.0.0.0/24 or unspecified; not one of this server's own addresses or
gateways; not an address of this server's own name; and not an address this server can bind (a bind() probe that works means the address is
local). One bad address refuses the whole name (403). The proxy then connects to the validated numeric address, never to the name again, so a
second DNS answer cannot change where it goes (no rebinding). A failed lookup or connect is 502, a connect that times out 504.

Limits: 16 tunnels at once, 100 per run, 256 MiB per run in both directions (the tunnel is closed at the limit), 10 s to connect, 60 s idle.

It never logs a payload, a header beyond the request line, or a credential. Audit: one JSON line per CONNECT in ``audit.jsonl`` inside the
service's RuntimeDirectory: host (at most 253 letters, digits, '.' and '-', else ``<invalid>``), port, allowed or refused, a reason code, bytes up and
bytes down. The root helper reads that file after the run.
"""
from __future__ import annotations

import errno
import ipaddress
import json
import os
import re
import select
import signal
import socket
import sys
import threading
import time

LIMITS = {"tunnels_live": 16, "tunnels_total": 100, "bytes_total": 256 * 1024 * 1024, "connect_seconds": 10, "idle_seconds": 60, "head_bytes": 8192,
          "head_seconds": 10}
HOST_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".lan")
HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
AUDIT_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
AUDIT_ROWS_MAX = 400  # the root helper keeps 200 and marks the rest as truncated
ALLOWED_PORT = 443
BLOCKED_NETWORKS = tuple(ipaddress.ip_network(item) for item in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"))


def clean_host(host):
    """The host as it goes into the audit file: at most 253 letters, digits, '.' and '-', else ``<invalid>``."""
    return host if isinstance(host, str) and AUDIT_HOST_RE.fullmatch(host) else "<invalid>"


def looks_like_ip(host):
    """True for an IP literal in any spelling: bracketed or colon IPv6, dotted, a single decimal or hex number, octal parts. A real name never ends
    in a label that is all digits or a 0x number, so one rule covers every spelling the C library would accept."""
    if not host or host.startswith("[") or ":" in host:
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    last = host.rstrip(".").split(".")[-1]
    return last.isdigit() or (last.startswith("0x") and all(ch in "0123456789abcdef" for ch in last[2:])) or last == ""


def blocked_address(address):
    """None when an address may be connected to, else a short reason. Looks through an IPv4-mapped IPv6 address."""
    try:
        parsed = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return "address_blocked"
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if parsed.is_unspecified or not parsed.is_global:
        return "address_blocked"
    if any(parsed.version == net.version and parsed in net for net in BLOCKED_NETWORKS):
        return "address_blocked"
    return None


def can_bind(address):
    """True when this host accepts a bind() on the address (a local address) or the probe cannot tell; False only for EADDRNOTAVAIL (not local)."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    family = socket.AF_INET if parsed.version == 4 else socket.AF_INET6
    try:
        probe = socket.socket(family, socket.SOCK_STREAM)
    except OSError:
        return True  # cannot probe: fail closed, the address is treated as local
    try:
        probe.bind((address, 0))
        return True
    except OSError as exc:
        return exc.errno != errno.EADDRNOTAVAIL  # only EADDRNOTAVAIL proves the address is not this server's
    finally:
        probe.close()


def parse_head(data):
    """(method, target) from the first line of the request head. ValueError for a malformed line."""
    line = data.split(b"\r\n", 1)[0]
    if len(line) > 1024 or b"\x00" in line:
        raise ValueError("line")
    parts = line.decode("ascii").split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise ValueError("line")
    return parts[0], parts[1]


def split_target(target):
    """(host, port text) from ``host:port``. A bracketed or bare IPv6 form is returned with its brackets so it is refused as an IP literal."""
    if target.startswith("["):
        return target, ""
    host, _sep, port = target.rpartition(":")
    return (host, port) if _sep else (target, "")


class Egress:
    """One run's proxy. ``resolve`` (getaddrinfo), ``dial`` (the connect to a validated address) and ``probe_bind`` are replaced by a test."""

    def __init__(self, config, audit_path, *, resolve=None, dial=None, probe_bind=None, clock=time.monotonic):
        limits = dict(LIMITS)
        limits.update({k: v for k, v in (config.get("limits") or {}).items() if k in LIMITS and isinstance(v, int) and not isinstance(v, bool) and v > 0})
        self.limits = limits
        self.allowed = {h for h in config.get("allowed_hosts", []) if isinstance(h, str)}
        self.own = {str(a) for a in config.get("own", [])} | {str(a) for a in config.get("gateways", [])}
        self.fqdn = str(config.get("fqdn") or "")
        # 1.18.25: every name this server answers to (its own FQDN, Tactical's API, RMM and Mesh names) and the addresses the helper saw for them
        self.own_names = {str(n).lower() for n in (config.get("own_names") or []) if isinstance(n, str) and n} | ({self.fqdn.lower()} if self.fqdn else set())
        self.own_name_addresses = {str(a).split("%", 1)[0] for a in (config.get("own_name_addresses") or []) if isinstance(a, str)}
        self.audit_path = audit_path
        self.resolve = resolve or socket.getaddrinfo
        self.dial = dial or self._dial
        self.probe_bind = probe_bind or can_bind
        self.clock = clock
        self.lock = threading.Lock()
        self.live = 0
        self.total = 0
        self.bytes = 0
        self.rows = 0
        self.stopping = threading.Event()
        self.fqdn_addresses = self._fqdn_addresses()

    def _fqdn_addresses(self):
        """Addresses of every own name, looked up once at start-up and merged with the ones the helper handed in (a NAT'd server's public address
        is on no local interface, so only a name lookup finds it)."""
        found = set(self.own_name_addresses)
        for name in sorted(self.own_names):
            try:
                found |= {str(item[4][0]).split("%", 1)[0] for item in self.resolve(name, None)}
            except OSError:
                continue
        return found

    @staticmethod
    def _dial(address, port, timeout):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((address, port))
        except BaseException:
            sock.close()
            raise
        return sock

    # ------------------------------------------------------------------------------------------------------ audit
    def audit(self, host, port, result, reason, up=0, down=0):
        """One line per CONNECT. Never a header, a payload or a credential."""
        row = {"host": clean_host(host), "port": port if isinstance(port, int) and 0 <= port <= 65535 else 0, "result": result, "reason": reason,
               "up": int(up), "down": int(down)}
        with self.lock:
            if self.rows >= AUDIT_ROWS_MAX:
                return
            self.rows += 1
            try:
                with open(self.audit_path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(row, sort_keys=True) + "\n")
            except OSError:
                pass

    # ---------------------------------------------------------------------------------------------------- the rules
    def check(self, method, target):
        """(status, reason, host, port) for a parsed request. Status 0 means every request rule passed."""
        if method != "CONNECT":
            return 403, "method", clean_host(target.rpartition(":")[0] or target), 0
        host, port_text = split_target(target)
        port = int(port_text) if port_text.isdigit() and len(port_text) <= 5 else 0
        if looks_like_ip(host):
            return 403, "ip_literal", host, port
        if port != ALLOWED_PORT or port_text != str(ALLOWED_PORT):
            return 403, "port", host, port
        if "." not in host.strip(".") or any(host.endswith(suffix) for suffix in HOST_BLOCKED_SUFFIXES):
            return 403, "local_name", host, port
        if not all(HOST_LABEL_RE.fullmatch(label) for label in host.split(".")):
            return 403, "not_listed", host, port
        if host.lower() in self.own_names:
            return 403, "own_name", host, port
        if host not in self.allowed:
            return 403, "not_listed", host, port
        return 0, "listed", host, port

    def address_problem(self, address):
        """None when the address may be used, else the reason code. One address that fails refuses the whole name."""
        if blocked_address(address) is not None:
            return "address_blocked"
        plain = str(address).split("%", 1)[0]
        if plain in self.own or plain in self.fqdn_addresses or self.probe_bind(plain):
            return "address_blocked"
        return None

    def resolve_host(self, host):
        """(addresses, reason). Every resolved address is vetted; the first bad one refuses the name."""
        try:
            found = self.resolve(host, ALLOWED_PORT, 0, socket.SOCK_STREAM)
        except OSError:
            return [], "resolve_failed"
        addresses = []
        for item in found:
            address = item[4][0]
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            return [], "resolve_failed"
        for address in addresses:
            if self.address_problem(address):
                return [], "address_blocked"
        return addresses, ""

    # ------------------------------------------------------------------------------------------------------- reads
    def read_head(self, client):
        """The request head as bytes, or ('head_too_large' | 'head_too_slow') as a str. Reads at most 8 KiB, for at most 10 s in all."""
        deadline = self.clock() + self.limits["head_seconds"]
        data = b""
        while b"\r\n\r\n" not in data:
            left = deadline - self.clock()
            if left <= 0:
                return "head_too_slow"
            ready, _w, _x = select.select([client], [], [], min(left, 1.0))
            if not ready:
                continue
            try:
                chunk = client.recv(2048)
            except OSError:
                return "head_too_slow"
            if not chunk:
                return "head_too_slow"
            data += chunk
            if len(data) > self.limits["head_bytes"]:
                return "head_too_large"
        return data

    @staticmethod
    def reply(client, code, text):
        try:
            client.sendall(f"HTTP/1.1 {code} {text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode("ascii"))
        except OSError:
            pass

    # ----------------------------------------------------------------------------------------------------- one request
    def handle(self, client):
        """Serve one connection and close it. Never raises."""
        host, port = "<invalid>", 0
        try:
            head = self.read_head(client)
            if isinstance(head, str):
                self.reply(client, 400, "Bad Request")
                self.audit(host, port, "refused", head)
                return
            head, _sep, early = head.partition(b"\r\n\r\n")  # bytes a client sent right behind its head are kept and go to the upstream first
            try:
                method, target = parse_head(head)
            except (ValueError, UnicodeDecodeError):
                self.reply(client, 400, "Bad Request")
                self.audit(host, port, "refused", "malformed")
                return
            status, reason, host, port = self.check(method, target)
            if status:
                self.reply(client, status, "Forbidden")
                self.audit(host, port, "refused", reason)
                return
            with self.lock:
                if self.live >= self.limits["tunnels_live"] or self.total >= self.limits["tunnels_total"] or self.bytes >= self.limits["bytes_total"]:
                    over = True
                else:
                    over = False
                    self.live += 1
                    self.total += 1
            if over:
                self.reply(client, 403, "Forbidden")
                self.audit(host, port, "refused", "limit")
                return
            try:
                self.tunnel(client, host, port, early)
            finally:
                with self.lock:
                    self.live -= 1
        except (OSError, ValueError, TypeError, LookupError, RuntimeError):  # one broken connection never takes the door down
            self.audit(host, port, "refused", "closed")
        finally:
            try:
                client.close()
            except OSError:
                pass

    def tunnel(self, client, host, port, early=b""):
        addresses, problem = self.resolve_host(host)
        if problem:
            self.reply(client, 403 if problem == "address_blocked" else 502, "Forbidden" if problem == "address_blocked" else "Bad Gateway")
            self.audit(host, port, "refused", problem)
            return
        upstream, timed_out = None, False
        for address in addresses:
            try:
                upstream = self.dial(address, ALLOWED_PORT, self.limits["connect_seconds"])
                break
            except TimeoutError:
                timed_out = True
            except OSError:
                continue
        if upstream is None:
            self.reply(client, 504 if timed_out else 502, "Gateway Timeout" if timed_out else "Bad Gateway")
            self.audit(host, port, "refused", "connect_timeout" if timed_out else "connect_failed")
            return
        up = down = 0
        reason = "closed"
        try:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if early:
                with self.lock:
                    self.bytes += len(early)
                upstream.sendall(early)
                up += len(early)
            more_up, down, reason = self.relay(client, upstream)
            up += more_up
        except OSError:
            pass
        finally:
            upstream.close()
            self.audit(host, port, "allowed", reason, up, down)

    def relay(self, client, upstream):
        """Copy bytes both ways until one side closes, 60 s of silence, or the run's byte limit. Returns (up, down, reason)."""
        up = down = 0
        sockets = {client: upstream, upstream: client}
        idle_until = self.clock() + self.limits["idle_seconds"]
        reason = "closed"
        while not self.stopping.is_set():
            left = idle_until - self.clock()
            if left <= 0:
                reason = "idle"
                break
            ready, _w, _x = select.select(list(sockets), [], [], min(left, 1.0))
            for source in ready:
                try:
                    data = source.recv(16384)
                except OSError:
                    data = b""
                if not data:
                    return up, down, reason
                with self.lock:
                    room = self.limits["bytes_total"] - self.bytes
                    if room <= 0:
                        return up, down, "run_limit"
                    data = data[:room]
                    self.bytes += len(data)
                try:
                    sockets[source].sendall(data)
                except OSError:
                    return up, down, reason
                if source is client:
                    up += len(data)
                else:
                    down += len(data)
                idle_until = self.clock() + self.limits["idle_seconds"]
        return up, down, reason

    # -------------------------------------------------------------------------------------------------------- loop
    def serve(self, listener, *, max_connections=None):
        """Accept connections until stopped. One thread per connection; at most 16 tunnels are live, so the thread count stays inside the unit's
        TasksMax. ``max_connections`` (a test) ends the loop after that many accepts."""
        listener.settimeout(0.5)
        threads, accepted = [], 0
        while not self.stopping.is_set():
            try:
                client, _addr = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            accepted += 1
            thread = threading.Thread(target=self.handle, args=(client,), daemon=True)
            thread.start()
            threads.append(thread)
            threads = [t for t in threads if t.is_alive()]
            if max_connections is not None and accepted >= max_connections:
                break
        for thread in threads:
            thread.join(2)


def read_config(folder):
    """The run's configuration from the LoadCredential folder (``run.json``). OSError when it is missing, ValueError when it is not JSON, TypeError when it is not an object."""
    with open(os.path.join(folder, "run.json"), "rb") as handle:
        data = json.loads(handle.read(65536).decode("utf-8"))
    if not isinstance(data, dict):
        raise TypeError("config")
    return data


def listener_from_systemd():
    """The activated socket (file descriptor 3, from LISTEN_FDS and LISTEN_PID), or None."""
    try:
        if int(os.environ.get("LISTEN_PID", "0")) != os.getpid() or int(os.environ.get("LISTEN_FDS", "0")) < 1:
            return None
    except ValueError:
        return None
    return socket.socket(fileno=3)


def main():
    credentials = os.environ.get("CREDENTIALS_DIRECTORY", "")
    state = os.environ.get("RUNTIME_DIRECTORY", "")
    try:
        config = read_config(credentials)
    except (OSError, ValueError, TypeError):
        sys.stderr.write("sandbox-egress: the run configuration could not be read\n")
        return 70
    listener = listener_from_systemd()
    if listener is None or not state:
        sys.stderr.write("sandbox-egress: no activated socket or runtime directory\n")
        return 70
    audit_path = os.path.join(state.split(":")[0], "audit.jsonl")
    proxy = Egress(config, audit_path)
    signal.signal(signal.SIGTERM, lambda *_args: proxy.stopping.set())
    signal.signal(signal.SIGINT, lambda *_args: proxy.stopping.set())
    proxy.serve(listener)
    return 0


if __name__ == "__main__":
    sys.exit(main())
