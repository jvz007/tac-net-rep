#!/usr/bin/python3
"""Core 1.18.23: the Patch B network rows, run through the real launch path. DEV SERVER ONLY, as root, after Core 1.18.23 is installed.

    sudo bash tests/sandbox-canary-1.18.23.sh            (step 5t starts this file)
    sudo bash tests/sandbox-canary-1.18.23.sh network    (the guards, the selftest and this step only)

Why (AD-65, canary rows first): Patch B will put a run into its own network namespace with one proxy door. Before that wall exists, the rows that will
prove it must be seen to work on today's build: the rows Patch B changes must show ATTACK SUCCEEDED now, the rows that already hold must show OK
(they become regression guards), and the seven proxy-door rows cannot run yet (NOT RUN, 'no proxy yet (Patch B)'). A row that shows OK where it is
expected to show ATTACK SUCCEEDED proves nothing and breaks the rule.

How: the INSTALLED helper (/usr/local/lib/tec-tac/sandbox/sandbox-helper.py) is loaded the way the script loads it. This file builds the plan
(host controls, this server's own addresses and gateways, the host's listening ports), starts the group ``patchb_network`` of the installed canary
runner with the helper's own ``canary_row`` and ``launch`` (the real unit properties of the current build) and prints the table in the helper's own
format. The group is not in the helper's CANARY_GROUPS (the helper stays byte-identical), so the group choice is added to this run's copy of the
row. It never touches the kill switch, writes nothing outside the helper's own canary run files and removes nothing.

Exit 0: the table matches the expectation. Exit 1: an expected-OK row shows ATTACK SUCCEEDED (a real hole today), an expected-ATTACK row shows OK
(the row proves nothing), or a row other than a proxy row is NOT RUN. Exit 2: the unit could not be started.
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
import subprocess
import sys
import threading
import time

INSTALLED_HELPER = "/usr/local/lib/tec-tac/sandbox/sandbox-helper.py"
GROUP = "patchb_network"
WALL = "Patch B network"
RUN_SECONDS = 45  # the probes run in parallel; the listener waits 8 s; a slow public connect is cut at 2.5 s
LISTEN_SECONDS = 8
HOST_PROBE_SECONDS = 3.0
CONNECT_TRIES = 3  # the host connects to the listener this many times, CONNECT_PAUSE seconds apart (a test sets the pause to 0)
CONNECT_PAUSE = 1.0
DEFAULT_ALLOWED_HOST = "example.com"
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
ID_RE = re.compile(r"^[a-z0-9-]{1,40}$")
PUBLIC_V4 = ("1.1.1.1", "9.9.9.9")
PUBLIC_V6 = "2606:4700:4700::1111"

ATTACK, OK, NOTRUN, EITHER = "attack", "ok", "notrun", "either"
# (runner row name, stable row id, what today's build is expected to show). The names are the runner's NETWORK_ROW_NAMES, in the same order.
ROWS = (
    ("public tcp 443 to 1.1.1.1", "pb-public-tcp-443-1-1-1-1", ATTACK),
    ("public tcp 80 to 1.1.1.1", "pb-public-tcp-80-1-1-1-1", ATTACK),
    ("public tcp 443 to 9.9.9.9", "pb-public-tcp-443-9-9-9-9", ATTACK),
    ("tcp 443 to the allowed host's own address, no proxy", "pb-direct-allowed-host-443", ATTACK),
    ("resolv.conf lists a name server", "pb-dns-resolv-conf-listed", ATTACK),
    ("getaddrinfo resolves example.com", "pb-dns-getaddrinfo", ATTACK),
    ("udp 53 answered by the listed name server", "pb-dns-listed-server-answers", ATTACK),
    ("udp 53 answered by public 9.9.9.9", "pb-dns-public-9-9-9-9-answers", ATTACK),
    # Either result today: systemd's IPAddressDeny filters received packets too, and the host reaches the listener only from 127.0.0.1 or its own
    # address, both of which the current build denies. Patch B must show OK; today it may show either.
    ("listener reachable from the host", "pb-listener-from-host", EITHER),
    ("proc net tcp lists host sockets", "pb-proc-net-tcp", ATTACK),
    ("proc net udp lists host sockets", "pb-proc-net-udp", ATTACK),
    ("network interfaces other than lo visible", "pb-interfaces-beyond-lo", ATTACK),
    ("default route visible", "pb-default-route", ATTACK),
    ("AF_PACKET socket", "pb-sock-af-packet", OK),
    ("raw ICMP socket", "pb-sock-raw-icmp", OK),
    ("AF_NETLINK route socket", "pb-sock-af-netlink", OK),
    ("AF_INET6 socket creation", "pb-sock-af-inet6", OK),
    ("ICMP ping socket echo to 1.1.1.1", "pb-ping-socket-echo", EITHER),  # depends on net.ipv4.ping_group_range
    ("tcp 443 to 2606:4700:4700::1111", "pb-tcp-443-ipv6", OK),
    ("host loopback services", "pb-host-loopback-services", OK),
    ("own address tcp 22, 80, 443", "pb-own-address", OK),
    ("default gateway tcp 80, 443", "pb-default-gateway", OK),
    ("proxy CONNECT to the allowed host on 443 answers 200", "pb-proxy-allowed-443", NOTRUN),
    ("proxy refuses a host not in allowed_hosts", "pb-proxy-refuse-host", NOTRUN),
    ("proxy refuses an IP literal", "pb-proxy-refuse-ip-literal", NOTRUN),
    ("proxy refuses a private address", "pb-proxy-refuse-private", NOTRUN),
    ("proxy refuses this server's own address", "pb-proxy-refuse-own-address", NOTRUN),
    ("proxy refuses the allowed host on port 80", "pb-proxy-refuse-port-80", NOTRUN),
    ("proxy refuses the allowed host on port 22", "pb-proxy-refuse-port-22", NOTRUN),
)
EXPECTED_ATTACK_TODAY = tuple(rid for _name, rid, kind in ROWS if kind == ATTACK)
EXPECTED_OK_TODAY = tuple(rid for _name, rid, kind in ROWS if kind == OK)
EXPECTED_NOT_RUN_TODAY = tuple(rid for _name, rid, kind in ROWS if kind == NOTRUN)
EITHER_TODAY = tuple(rid for _name, rid, kind in ROWS if kind == EITHER)
EXPECTED_BY_ID = {rid: kind for _name, rid, kind in ROWS}
NAME_BY_ID = {rid: name for name, rid, _kind in ROWS}
NO_PROXY_TEXT = "no proxy yet (Patch B)"
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


def build_plan(helper, allowed_host):
    """The plan the group reads on stdin. Host controls, this server's own addresses and gateways, the host's listening ports."""
    local = helper.local_deny_now()
    own = [a for a in local.get("addresses", []) if ":" not in a and not a.startswith("127.")][:4]
    gateways = [g for g in local.get("gateways", []) if ":" not in g][:4]
    ports, _by_address = helper.parse_listening(host_ss())
    addresses = host_resolve(allowed_host)
    return {
        "host_public": all(host_tcp(host, 443) for host in PUBLIC_V4),
        "host_dns": bool(host_resolve("example.com")),
        "host_ping": host_ping(PUBLIC_V4[0]),
        "host_ipv6": host_tcp(PUBLIC_V6, 443, socket.AF_INET6),
        "loopback_ports": list(ports),
        "own": own,
        "gateways": gateways,
        "allowed_host": allowed_host,
        "allowed_host_address": addresses[0] if addresses else "",
        "listen_seconds": LISTEN_SECONDS,
    }


# ------------------------------------------------------------------------------------------------ the run
class Watch:
    """Collects the unit's stdout and, on the first ``CANARYLISTEN<TAB>port`` line, connects from the host (loopback and the first own address)."""

    def __init__(self, own):
        self.own = list(own)[:1]
        self.stdout = b""
        self.seen = False
        self.tried = threading.Event()
        self.thread = None
        self._buffer = b""

    def feed(self, data):
        self.stdout += data
        self._buffer += data
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            parts = line.decode("ascii", "replace").rstrip("\r").split("\t")
            if len(parts) == 2 and parts[0] == "CANARYLISTEN" and parts[1].isdigit() and not self.seen:
                self.seen = True
                self.thread = threading.Thread(target=self.connect, args=(int(parts[1]),), daemon=True)
                self.thread.start()

    def connect(self, port):
        self.tried.set()
        time.sleep(CONNECT_PAUSE * 0.3)
        for _ in range(CONNECT_TRIES):
            for host in ["127.0.0.1", *self.own]:
                host_tcp(host, port)
            time.sleep(CONNECT_PAUSE)


def run_group(helper, plan, watch, status):
    """The group through the helper's own ``launch`` (what ``collect_run`` does), with the group choice added to this run's copy of the row.
    Returns (end frame, refusal code)."""
    row = helper.canary_row(run_seconds=RUN_SECONDS)
    group = dict(row["parameters"]["group"])
    group["choices"] = [*group["choices"], GROUP]  # a new list: the helper's own constant is never changed
    row["parameters"] = {**row["parameters"], "group": group}
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


def build_table(helper, stdout, watch):
    """The table: one entry per expected row (a missing row is NOT RUN), then any row the runner printed that is not in the list."""
    printed = {r["attack"]: r for r in helper.parse_runner_rows(stdout)}
    table = []
    for name, rid, _kind in ROWS:
        found = printed.pop(name, None)
        if found is None:
            entry = {"actual": "the probe printed no result", "verdict": "NOT RUN"}
        else:
            entry = {"actual": found["actual"], "verdict": helper.classify_tag(found["tag"])}
            if rid == LISTEN_ID and entry["verdict"] in ("OK", "ATTACK SUCCEEDED") and not watch.tried.is_set():
                entry = {"actual": "the host never tried to connect, so this row proves nothing", "verdict": "NOT RUN"}
        table.append({"id": rid, "wall": WALL, "attack": name, "expected": expected_text(rid), **entry})
    for attack, found in printed.items():  # an unlisted row is shown and fails: the driver and the runner have drifted apart
        table.append({"wall": WALL, "attack": attack, "expected": "not in the driver's list", "actual": found["actual"], "verdict": "NOT RUN"})
    return table


def expected_text(rid):
    return {ATTACK: "ATTACK SUCCEEDED today (Patch B changes it)", OK: "OK today (guard, must stay OK)", NOTRUN: "NOT RUN today (no proxy yet)",
            EITHER: "either today"}[EXPECTED_BY_ID[rid]]


def classify(table, ids):
    """[(row id, attack, verdict, label, problem)]: label is 'as expected', 'skipped', 'UNEXPECTED' or 'proves nothing'; problem is True when it fails."""
    out = []
    for entry, rid in zip(table, ids):
        kind, verdict = EXPECTED_BY_ID.get(rid), entry["verdict"]
        label, problem = "as expected", False
        if kind is None:
            label, problem = "UNEXPECTED (not a row the driver knows)", True
        elif verdict == "SKIPPED":
            label = "skipped (no control on this host)"
        elif kind == NOTRUN:
            if verdict == "ATTACK SUCCEEDED":
                label, problem = "UNEXPECTED (a refusal row shows the proxy opening a tunnel: a real hole)", True
            elif verdict != "NOT RUN":
                label = "changed (a proxy answers: this is a Patch B result, not a today result)"
        elif verdict == "NOT RUN":
            label, problem = "UNEXPECTED (the probe did not run)", True
        elif kind == OK and verdict == "ATTACK SUCCEEDED":
            label, problem = "UNEXPECTED (a real hole today)", True
        elif kind == ATTACK and verdict != "ATTACK SUCCEEDED":
            label, problem = "proves nothing (it must show ATTACK SUCCEEDED before the fix)", True
        elif verdict not in ("OK", "ATTACK SUCCEEDED"):
            label, problem = "UNEXPECTED (" + verdict + ")", True
        out.append((rid, entry["attack"], verdict, label, problem))
    return out


def summary_line(table):
    attacks = sum(1 for e in table if e["verdict"] == "ATTACK SUCCEEDED")
    notrun = sum(1 for e in table if e["verdict"] == "NOT RUN")
    skipped = sum(1 for e in table if e["verdict"] == "SKIPPED")
    return (f"PATCH B NETWORK ROWS: {attacks} ATTACK SUCCEEDED, {notrun} NOT RUN, {skipped} SKIPPED, expected before Patch B: rows "
            f"{', '.join(EXPECTED_ATTACK_TODAY)} ATTACK SUCCEEDED; rows {', '.join(EXPECTED_NOT_RUN_TODAY)} NOT RUN; "
            f"rows {', '.join(EITHER_TODAY)} either; every other row OK")


def main(helper=None, out=print):
    if helper is None:
        if os.geteuid() != 0:
            out("FAIL this driver must run as root (it is started by tests/sandbox-canary-1.18.23.sh)")
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
    out(f"== Patch B network rows (canary first): allowed host stand-in {allowed_host} -> {plan['allowed_host_address'] or 'not resolved'}")
    out("host controls: " + ", ".join(f"{k}={plan[k]}" for k in ("host_public", "host_dns", "host_ping", "host_ipv6"))
        + f"; own addresses {len(plan['own'])}, gateways {len(plan['gateways'])}, host listening ports {len(plan['loopback_ports'])}")
    watch = Watch(plan["own"])
    end, refused = run_group(helper, plan, watch, status)
    if refused or end is None:
        out(f"FAIL the unit could not be started ({refused or 'no end frame'})")
        return 2
    if watch.thread is not None:
        watch.thread.join(10)
    table = build_table(helper, watch.stdout, watch)
    ids = helper.assign_row_ids(table)
    out(helper.format_table(table))
    for line in helper.row_lines(table):
        out(line)
    for line in helper.detail_lines(table):
        out(line)
    results = classify(table, ids)
    for rid, _attack, verdict, label, problem in results:
        out(f"{'FAIL' if problem else 'ok  '} {rid}: {verdict}: {label}")
    out(summary_line(table))
    return 1 if any(problem for *_rest, problem in results) else 0


if __name__ == "__main__":
    sys.exit(main())
