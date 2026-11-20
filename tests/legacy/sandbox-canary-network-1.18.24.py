#!/usr/bin/python3
"""Core 1.18.24: the Patch B exit list, run through the real launch path. DEV SERVER ONLY, as root, after Core 1.18.24 is installed.

    sudo bash tests/sandbox-canary-1.18.24.sh            (step 5t starts this file)
    sudo bash tests/sandbox-canary-1.18.24.sh network    (the guards, the selftest and this step only)

Why (AD-65): since Patch B a run has its own, empty network space and one proxy door. The 29 rows that 1.18.23 showed before the wall
(12 of them ATTACK SUCCEEDED) must now ALL read OK, the seven proxy rows included, with no NOT RUN and no ATTACK SUCCEEDED. A row may be SKIPPED
only when ITS OWN host control is missing (for example pb-tcp-443-ipv6 on a server with no IPv6 route): every attack row has its own control
(host tcp 443 to 1.1.1.1, tcp 80 to 1.1.1.1, tcp 443 to 9.9.9.9, tcp 443 to the allowed host's address, udp 53 to 9.9.9.9, udp 53 to the first
listed name server), so an OK is never read from a path the host itself could not use.

How: the INSTALLED helper (/usr/local/lib/tec-tac/sandbox/sandbox-helper.py) is loaded the way the script loads it. This file builds the plan (the
host controls, this server's own addresses and gateways, the host's listening ports), starts the group ``patchb_network`` of the installed canary
runner with the helper's own ``canary_row`` (given ``allowed_hosts`` so the run has its door) and ``launch`` (the real unit properties of this build)
and prints the table in the helper's own format. The group is not in the helper's CANARY_GROUPS, so the group choice is added to this run's copy of
the row. It never touches the kill switch, writes nothing outside the helper's own canary run files and removes nothing.

The listener row (1.18.24): the run listens on 0.0.0.0 inside its own network space and prints the port. This driver then reads the HOST's own
``ss -ltnH`` as root: a LISTEN socket on that port in the host's namespace is ATTACK SUCCEEDED (before Patch B the run's listener lived there and any
peer the old filter did not deny could reach it); not listed there is OK. The host's own connect attempts stay as detail only.

Exit 0: every row is OK (or SKIPPED with its control missing). Exit 1: any other result. Exit 2: the unit could not be started.
"""
from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

INSTALLED_HELPER = "/usr/local/lib/tec-tac/sandbox/sandbox-helper.py"
GROUP = "patchb_network"
WALL = "Patch B network"
RUN_SECONDS = 45  # the probes run in parallel; the listener waits 8 s; a slow connect is cut at 2.5 s; the host-service probes stop at 15 s
LISTEN_SECONDS = 8
HOST_PROBE_SECONDS = 3.0
SS_DELAY = 0.4  # the host looks at its own listening sockets this long after the run printed its port
CONNECT_TRIES = 3  # the host connects to the listener this many times, CONNECT_PAUSE seconds apart (detail only; a test sets the pause to 0)
CONNECT_PAUSE = 1.0
DEFAULT_ALLOWED_HOST = "example.com"
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
PUBLIC_V4 = ("1.1.1.1", "9.9.9.9")
PUBLIC_V6 = "2606:4700:4700::1111"

OK = "ok"
# (runner row name, stable row id, the plan key of the row's OWN host control or None). Every row is expected OK after Patch B.
ROWS = (
    ("public tcp 443 to 1.1.1.1", "pb-public-tcp-443-1-1-1-1", "host_tcp443_1111"),
    ("public tcp 80 to 1.1.1.1", "pb-public-tcp-80-1-1-1-1", "host_tcp80_1111"),
    ("public tcp 443 to 9.9.9.9", "pb-public-tcp-443-9-9-9-9", "host_tcp443_9999"),
    ("tcp 443 to the allowed host's own address, no proxy", "pb-direct-allowed-host-443", "host_tcp443_allowed"),
    ("resolv.conf lists a name server", "pb-dns-resolv-conf-listed", "host_dns"),
    ("getaddrinfo resolves example.com", "pb-dns-getaddrinfo", "host_dns"),
    ("udp 53 answered by the listed name server", "pb-dns-listed-server-answers", "host_udp53_listed"),
    ("udp 53 answered by public 9.9.9.9", "pb-dns-public-9-9-9-9-answers", "host_udp53_9999"),
    ("listener reachable from the host", "pb-listener-from-host", None),
    ("proc net tcp lists host sockets", "pb-proc-net-tcp", None),
    ("proc net udp lists host sockets", "pb-proc-net-udp", None),
    ("network interfaces other than lo visible", "pb-interfaces-beyond-lo", None),
    ("default route visible", "pb-default-route", None),
    ("AF_PACKET socket", "pb-sock-af-packet", None),
    ("raw ICMP socket", "pb-sock-raw-icmp", None),
    ("AF_NETLINK route socket", "pb-sock-af-netlink", None),
    ("AF_INET6 socket creation", "pb-sock-af-inet6", None),
    ("ICMP ping socket echo to 1.1.1.1", "pb-ping-socket-echo", "host_ping"),
    ("tcp 443 to 2606:4700:4700::1111", "pb-tcp-443-ipv6", "host_ipv6"),
    ("host loopback services", "pb-host-loopback-services", "loopback_ports"),
    ("own address tcp 22, 80, 443", "pb-own-address", "own"),
    ("default gateway tcp 80, 443", "pb-default-gateway", "gateways"),
    ("proxy CONNECT to the allowed host on 443 answers 200", "pb-proxy-allowed-443", "host_tcp443_allowed"),
    ("proxy refuses a host not in allowed_hosts", "pb-proxy-refuse-host", None),
    ("proxy refuses an IP literal", "pb-proxy-refuse-ip-literal", None),
    ("proxy refuses a private address", "pb-proxy-refuse-private", None),
    ("proxy refuses this server's own address", "pb-proxy-refuse-own-address", "own"),
    ("proxy refuses the allowed host on port 80", "pb-proxy-refuse-port-80", None),
    ("proxy refuses the allowed host on port 22", "pb-proxy-refuse-port-22", None),
)
EXIT_LIST_FORMER_ATTACK = ("pb-public-tcp-443-1-1-1-1", "pb-public-tcp-80-1-1-1-1", "pb-public-tcp-443-9-9-9-9", "pb-direct-allowed-host-443",
                           "pb-dns-resolv-conf-listed", "pb-dns-getaddrinfo", "pb-dns-listed-server-answers", "pb-dns-public-9-9-9-9-answers",
                           "pb-proc-net-tcp", "pb-proc-net-udp", "pb-interfaces-beyond-lo", "pb-default-route")
EXIT_LIST_PROXY = ("pb-proxy-allowed-443", "pb-proxy-refuse-host", "pb-proxy-refuse-ip-literal", "pb-proxy-refuse-private", "pb-proxy-refuse-own-address",
                   "pb-proxy-refuse-port-80", "pb-proxy-refuse-port-22")
EXIT_LIST_ALSO = ("pb-listener-from-host", "pb-ping-socket-echo")
CONTROL_OF = {rid: key for _name, rid, key in ROWS}
NAME_BY_ID = {rid: name for name, rid, _key in ROWS}
LISTEN_ID = "pb-listener-from-host"


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


# ------------------------------------------------------------------------------------------------ what the host itself can do (the controls)
def host_tcp(host, port, family=socket.AF_INET):
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
    except OSError:
        return False
    try:
        s.settimeout(HOST_PROBE_SECONDS)
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def host_resolve(name):
    """IPv4 addresses of ``name`` as the host resolves them, with a time limit (getaddrinfo has none)."""
    found = []

    def work():
        try:
            found.extend(item[4][0] for item in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM))
        except OSError:
            pass

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(5)
    return list(found)


def host_dns_ask(address, name="example.com"):
    """True when the HOST gets a DNS answer from ``address`` on udp 53 (the control of the two 'udp 53 answered' rows)."""
    query = struct.pack(">HHHHHH", 0x7A31, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        query += bytes([len(part)]) + part.encode()
    query += b"\x00" + struct.pack(">HH", 1, 1)
    try:
        s = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        s.settimeout(3)
        s.sendto(query, (address, 53))
        data, _peer = s.recvfrom(2048)
        return len(data) >= 12 and data[:2] == query[:2] and bool(data[2] & 0x80)
    except OSError:
        return False
    finally:
        s.close()


def host_ping(address):
    ping = shutil.which("ping")
    if not ping:
        return False
    try:
        done = subprocess.run([ping, "-c", "1", "-W", "2", address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def host_ss():
    """``ss -ltnH`` text of the host (empty when it cannot run)."""
    ss = shutil.which("ss")
    if not ss:
        return ""
    try:
        done = subprocess.run([ss, "-ltnH"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout


def host_name_server():
    """The first name server the host itself lists in /etc/resolv.conf ('' when none)."""
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as handle:
            for line in handle.read(8192).splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver" and "%" not in parts[1]:
                    return parts[1]
    except OSError:
        pass
    return ""


def build_plan(helper, allowed_host):
    """The plan the group reads on stdin: one host control per row, this server's own addresses and gateways, the host's listening ports."""
    local = helper.local_deny_now()
    own = [a for a in local.get("addresses", []) if ":" not in a and not a.startswith("127.")][:4]
    gateways = [g for g in local.get("gateways", []) if ":" not in g][:4]
    ports, _by_address = helper.parse_listening(host_ss())
    addresses = host_resolve(allowed_host)
    first = addresses[0] if addresses else ""
    listed = host_name_server()
    return {
        "host_tcp443_1111": host_tcp("1.1.1.1", 443),
        "host_tcp80_1111": host_tcp("1.1.1.1", 80),
        "host_tcp443_9999": host_tcp("9.9.9.9", 443),
        "host_tcp443_allowed": bool(first) and host_tcp(first, 443),
        "host_dns": bool(host_resolve("example.com")),
        "host_udp53_listed": bool(listed) and host_dns_ask(listed),
        "host_udp53_9999": host_dns_ask("9.9.9.9"),
        "host_ping": host_ping(PUBLIC_V4[0]),
        "host_ipv6": host_tcp(PUBLIC_V6, 443, socket.AF_INET6),
        "loopback_ports": list(ports),
        "own": own,
        "gateways": gateways,
        "listed_name_server": listed,
        "allowed_host": allowed_host,
        "allowed_host_address": first,
        "listen_seconds": LISTEN_SECONDS,
    }


# ------------------------------------------------------------------------------------------------ the run
class Watch:
    """Collects the unit's stdout. On the first ``CANARYLISTEN<TAB>port`` line it (a) reads the HOST's own listening sockets as root and records
    whether that port is listed there (the verdict of the listener row), and (b) connects from the host (detail only)."""

    def __init__(self, own):
        self.own = list(own)[:1]
        self.stdout = b""
        self.port = None
        self.host_listing = None  # True: the port is a LISTEN socket in the host namespace; False: it is not; None: never looked
        self.attempts = []
        self.tried = threading.Event()
        self.thread = None
        self.helper = None
        self._buffer = b""

    def feed(self, data):
        self.stdout += data
        self._buffer += data
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            parts = line.decode("ascii", "replace").rstrip("\r").split("\t")
            if len(parts) == 2 and parts[0] == "CANARYLISTEN" and parts[1].isdigit() and self.port is None:
                self.port = int(parts[1])
                self.thread = threading.Thread(target=self.look, args=(self.port,), daemon=True)
                self.thread.start()

    def look(self, port):
        time.sleep(SS_DELAY)
        text = host_ss()
        if text.strip():
            listed, _by_address = self.helper.parse_listening(text) if self.helper else (set(), {})
            self.host_listing = port in listed
        self.tried.set()
        for _ in range(CONNECT_TRIES):  # detail only: the old way of looking, kept so the output shows both
            for host in ["127.0.0.1", *self.own]:
                self.attempts.append(f"{host}:{port} " + ("connected" if host_tcp(host, port) else "no"))
            time.sleep(CONNECT_PAUSE)


def run_group(helper, plan, watch, status, allowed_host=DEFAULT_ALLOWED_HOST):
    """The group through the helper's own ``launch`` (what ``collect_run`` does), with the group choice and the allowed host added to this run's copy
    of the row (so the run has its door). Returns (end frame, refusal code)."""
    row = helper.canary_row(run_seconds=RUN_SECONDS)
    group = dict(row["parameters"]["group"])
    group["choices"] = [*group["choices"], GROUP]  # a new list: the helper's own constant is never changed
    row["parameters"] = {**row["parameters"], "group": group}
    row["allowed_hosts"] = [allowed_host]
    end = {}

    def emit(frame):
        if frame["t"] == "out":
            watch.feed(base64.b64decode(frame["b"]))
        elif frame["t"] == "end":
            end["frame"] = frame

    try:
        helper.launch(row, run_id=secrets.token_hex(16), person="canary-network", parameters={"group": GROUP}, credentials={},
                      input_data=json.dumps(plan).encode("utf-8"), emit=emit, slots_n=None, person_n=helper.PERSON_SLOTS, status=status)
    except helper.Refusal as exc:
        return None, exc.code
    return end.get("frame"), None


def listener_entry(printed, watch):
    """The verdict of the listener row, decided from the host's own view (never from a connect that the old filter could not carry)."""
    if watch.port is None:
        return {"actual": printed["actual"], "verdict": printed["verdict"]} if printed else {"actual": "the probe printed no result", "verdict": "NOT RUN"}
    detail = ("; host connect attempts: " + ", ".join(watch.attempts[:4])) if watch.attempts else ""
    if watch.host_listing is None:
        return {"actual": "the host could not list its listening sockets (ss), so this row proves nothing", "verdict": "NOT RUN"}
    if watch.host_listing:
        return {"actual": f"a LISTEN socket on port {watch.port} exists in the host's own network namespace" + detail, "verdict": "ATTACK SUCCEEDED"}
    return {"actual": f"no LISTEN socket on port {watch.port} in the host's network namespace (the run's listener is private)" + detail, "verdict": "OK"}


def build_table(helper, stdout, watch):
    """The table: one entry per expected row (a missing row is NOT RUN), then any row the runner printed that is not in the list."""
    printed = {r["attack"]: r for r in helper.parse_runner_rows(stdout)}
    table = []
    for name, rid, _key in ROWS:
        found = printed.pop(name, None)
        if rid == LISTEN_ID:
            entry = listener_entry({"actual": found["actual"], "verdict": helper.classify_tag(found["tag"])} if found else None, watch)
        elif found is None:
            entry = {"actual": "the probe printed no result", "verdict": "NOT RUN"}
        else:
            entry = {"actual": found["actual"], "verdict": helper.classify_tag(found["tag"])}
        table.append({"id": rid, "wall": WALL, "attack": name, "expected": "OK (Patch B exit list)", **entry})
    for attack, found in printed.items():  # an unlisted row is shown and fails: the driver and the runner have drifted apart
        table.append({"wall": WALL, "attack": attack, "expected": "not in the driver's list", "actual": found["actual"], "verdict": "NOT RUN"})
    return table


def classify(table, ids, plan):
    """[(row id, attack, verdict, label, problem)]. OK passes. SKIPPED passes only when the row's OWN host control is missing in the plan."""
    out = []
    for entry, rid in zip(table, ids):
        verdict = entry["verdict"]
        label, problem = "OK", False
        if rid not in CONTROL_OF:
            label, problem = "UNEXPECTED (not a row the driver knows)", True
        elif verdict == "SKIPPED":
            key = CONTROL_OF[rid]
            if key is not None and not plan.get(key):
                label = "skipped (this row's own host control is missing)"
            else:
                label, problem = "UNEXPECTED (SKIPPED although its host control exists, or the row has none)", True
        elif verdict == "ATTACK SUCCEEDED":
            label, problem = "ATTACK SUCCEEDED (a real hole: do not turn the sandbox on)", True
        elif verdict == "NOT RUN":
            label, problem = "NOT RUN (the probe did not run)", True
        elif verdict != "OK":
            label, problem = "UNEXPECTED (" + verdict + ")", True
        out.append((rid, entry["attack"], verdict, label, problem))
    return out


def summary_line(table):
    attacks = sum(1 for e in table if e["verdict"] == "ATTACK SUCCEEDED")
    notrun = sum(1 for e in table if e["verdict"] == "NOT RUN")
    skipped = sum(1 for e in table if e["verdict"] == "SKIPPED")
    return (f"PATCH B EXIT LIST: {attacks} ATTACK SUCCEEDED, {notrun} NOT RUN, {skipped} SKIPPED; required OK: the 12 former ATTACK rows "
            f"{', '.join(EXIT_LIST_FORMER_ATTACK)}; the 7 proxy rows {', '.join(EXIT_LIST_PROXY)}; rows {', '.join(EXIT_LIST_ALSO)}; every other row OK")


def main(helper=None, out=print):
    if helper is None:
        if os.geteuid() != 0:
            out("FAIL this driver must run as root (it is started by tests/sandbox-canary-1.18.24.sh)")
            return 2
        try:
            helper = load("tec_tac_sandbox_helper", INSTALLED_HELPER)
        except (OSError, SyntaxError, ImportError) as exc:
            out(f"FAIL the installed helper could not be loaded: {type(exc).__name__}")
            return 2
    allowed_host = os.environ.get("TECTAC_CANARY_ALLOWED_HOST", DEFAULT_ALLOWED_HOST).strip().lower()
    if not HOST_RE.match(allowed_host):
        out("FAIL TECTAC_CANARY_ALLOWED_HOST is not a plain host name")
        return 2
    status = helper.read_status()
    if status.get("ready") is not True:
        out("FAIL the sandbox selftest is not ready: run the selftest first (sudo /usr/local/sbin/tec-tac-sandbox --selftest)")
        return 2
    plan = build_plan(helper, allowed_host)
    out(f"== Patch B exit list: allowed host {allowed_host} -> {plan['allowed_host_address'] or 'not resolved'}")
    out("host controls: " + ", ".join(f"{k}={plan[k]}" for k in sorted(plan) if k.startswith("host_"))
        + f"; own addresses {len(plan['own'])}, gateways {len(plan['gateways'])}, host listening ports {len(plan['loopback_ports'])}")
    watch = Watch(plan["own"])
    watch.helper = helper
    end, refused = run_group(helper, plan, watch, status, allowed_host)
    if refused or end is None:
        out(f"FAIL the unit could not be started ({refused or 'no end frame'})")
        return 2
    if watch.thread is not None:
        watch.thread.join(CONNECT_TRIES * (CONNECT_PAUSE + HOST_PROBE_SECONDS * 2) + 5)
    table = build_table(helper, watch.stdout, watch)
    ids = helper.assign_row_ids(table)
    out(helper.format_table(table))
    for line in helper.row_lines(table):
        out(line)
    for line in helper.detail_lines(table):
        out(line)
    results = classify(table, ids, plan)
    for rid, _attack, verdict, label, problem in results:
        out(f"{'FAIL' if problem else 'ok  '} {rid}: {verdict}: {label}")
    out(summary_line(table))
    return 1 if any(problem for *_rest, problem in results) else 0


if __name__ == "__main__":
    sys.exit(main())
