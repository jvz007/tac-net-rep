"""Shared helper for the 1.17.120 core.sandbox tests (not a test: the tests load it by path, so no module and no bytecode is left behind).

``Fake`` is a ``UnitRunner`` stand-in that answers each selftest probe by name (the technique of tests/sandbox-selftest-1.17.116.py), with the
1.17.120 credential answer (content, ``mode uid gid``, the unit's uid, the unit's gid). ``run_selftest(sh, run_root, base, fake, resolv)``
writes a resolv.conf and runs the helper's ``selftest`` against the fake.

Not runnable here: real systemd. The dev02 canary (tests/sandbox-canary-1.17.120.sh) proves the real behaviour.
"""
from __future__ import annotations

import socket
import tempfile
import time
from pathlib import Path

CREDS_ROOT = Path(tempfile.mkdtemp(prefix="tectac-fake-credentials-"))  # 1.18.14: stands in for /run/credentials


def hand_in(unit, source, remove=True):
    """1.18.14: what systemd does at start: copy the source into the unit's own credential folder. The helper (not the fake) must then
    remove the source folder; the fake waits for that, up to 5 s. ``remove`` False means the unit never shows its copy."""
    token = source.read_text(encoding="utf-8")
    if remove and unit:
        folder = CREDS_ROOT / f"{unit}.service"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / source.name).write_text(token, encoding="utf-8")
        deadline = time.monotonic() + 5
        while source.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
    return token


IP_ADDR = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
           "2: eth0    inet 129.232.197.50/24 brd 129.232.197.255 scope global eth0\\       valid_lft forever preferred_lft forever\n")
IP_ROUTE4 = "default via 129.232.197.1 dev eth0 proto static\n"
PUBLIC = "nameserver 156.38.225.225\noptions edns0\n"


class Fake:
    """Answers each probe by name. ``script`` maps a name to (code, stdout), a callable(properties, command) or a keyword."""

    def __init__(self, **overrides):
        self.calls = []
        self.script = {
            "systemctl": (0, "systemd 255 (255.4-1ubuntu8)\n+PAM +AUDIT +BPF_FRAMEWORK +SYSVINIT\n"),
            "stat": (0, "cgroup2fs\n"),
            "transient": (0, "tectac-probe\n"),
            "dynamic_user": (0, "61500\n"),
            "filesystem_view": (0, "ok\n"),
            "credential": "credential",
            "real_unit_shape": "real_shape",  # 1.18.13
            "proc_hidden": (0, "ok\n"),
            # 1.18.24 (AD-65 Patch B): the network probes. The control reaches this server's loopback listener, the wall sees only lo and reaches nothing.
            "network_control": "net_control",
            "network_private": lambda properties, command: (0, f"ifaces lo\nconnect 1.1.1.1 443 ENETUNREACH\nconnect 127.0.0.1 {command[-1]} ECONNREFUSED\nresolv absent\n", ""),
            "pipe_streams": lambda properties, command: (0, "out", "err"),
        }
        # 1.18.24: what the selftest's egress probe sees (HTTP status per request); run_selftest hands these to the helper's egress hooks
        self.egress = {"listed": 200, "unlisted": 403, "literal": 403, "port80": 403, "start_fails": False, "started": [], "stopped": []}
        self.script.update(overrides)
        # 1.17.123: what `ip` says (the dev02 shape: loopback, a public address, its gateway)
        self.ip = {"addr": IP_ADDR, "route4": IP_ROUTE4, "route6": ""}
        # 1.17.122: the default is the real dev02 shape (root:root, mode 440, ACL user:<unit uid>:r--, mask r--). acl: None builds that ACL line
        # from unit_uid, False leaves the line out (a missing answer), a string is sent as it is.
        self.credential = {"mode": "440", "uid": "0", "gid": "0", "unit_uid": "61500", "unit_gid": "61500", "stat": None, "token": None, "remove": True,
                           "acl": None}

    def run_cmd(self, argv, *, timeout=15):
        if argv[0] == "ip":
            key = "addr" if argv[1] == "-o" else ("route4" if argv[1] == "-4" else "route6")
            return 0, self.ip[key], ""
        answer = self.script["systemctl" if argv[0] == "systemctl" else "stat"]
        return (answer[0], answer[1], "")

    def run_unit(self, name, properties, command, *, timeout=30, unit=None):
        self.calls.append((name, tuple(properties), tuple(command)))
        answer = self.script[name]
        if answer == "connect":
            socket.create_connection(("127.0.0.1", int(command[-1])), timeout=2).close()
            return 0, "connected\n", ""
        if answer == "net_control":  # 1.18.24: no wall: the run sees the host's interfaces, reaches 1.1.1.1 and this server's loopback listener
            port = int(command[-1])
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
            return 0, f"ifaces lo,eth0\nconnect 1.1.1.1 443 connected\nconnect 127.0.0.1 {port} connected\nresolv present\n", ""
        if answer == "leak":  # a wall that does not hold: it reaches the listener, and says so
            port = int(command[-1])
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
            return 0, f"ifaces lo\nconnect 1.1.1.1 443 ENETUNREACH\nconnect 127.0.0.1 {port} connected\nresolv absent\n", ""
        if answer == "real_shape":  # 1.18.13: the real unit shape hands the token in through LoadCredential and removes the source
            source = None
            for item in properties:
                if item.startswith("LoadCredential=probe:"):
                    source = Path(item.split(":", 1)[1])
            token = hand_in(unit, source)
            return 0, token, ""
        if answer == "credential":
            source = None
            for item in properties:
                if item.startswith("LoadCredential=probe:"):
                    source = Path(item.split(":", 1)[1])
            token = hand_in(unit, source, self.credential["remove"])
            if self.credential["token"] is not None:
                token = self.credential["token"]
            c = self.credential
            stat_line = c["stat"] if c["stat"] is not None else f"{c['mode']} {c['uid']} {c['gid']}"
            acl = c["acl"]
            if acl is None:
                acl = f"ACL user::r--,user:{c['unit_uid']}:r--,group::r--,mask::r--,other::---"
            tail = f"{acl}\n" if acl is not False else ""
            return 0, f"{token}\n{stat_line}\n{c['unit_uid']}\n{c['unit_gid']}\n{tail}", ""
        if callable(answer):
            return answer(properties, command)
        return answer[0], answer[1], "err text" if answer[0] else ""


def run_selftest(sh, run_root, base, fake, resolv=PUBLIC):
    path = Path(base) / f"resolv-{len(list(Path(base).glob('resolv-*')))}.conf"
    path.write_text(resolv, encoding="utf-8")
    sh.CREDENTIALS_RUNTIME = CREDS_ROOT
    # 1.18.24: the egress door is real systemd and a real socket; here the helper's hooks answer from ``fake.egress`` (the tests of the proxy itself are
    # tests/sandbox-egress-proxy-1.18.24.py, the units are tests/sandbox-egress-units-1.18.24.py)
    saved = (sh.egress_start, sh.egress_stop, sh.egress_clean, sh.egress_exchange, sh.egress_door_socket)
    state = fake.egress

    def start(row, run_id, local, **kw):
        state["started"].append(run_id)
        if state["start_fails"]:
            raise sh.Refusal("sandbox_unavailable", "the egress door could not be started")
        return True

    def exchange(sock_path, request, **kw):
        head = request.split(b"\r\n", 1)[0].decode("ascii")
        target = head.split(" ")[1]
        if target == "example.com:443":
            return state["listed"]
        if target == "example.net:443":
            return state["unlisted"]
        if target == "1.1.1.1:443":
            return state["literal"]
        if target == "example.com:80":
            return state["port80"]
        return 0

    sh.egress_start, sh.egress_exchange = start, exchange
    sh.egress_stop = lambda run_id, **kw: state["stopped"].append(run_id)
    sh.egress_clean = lambda run_id: None
    sh.egress_door_socket = lambda run_id: Path(base) / "door.sock"
    try:
        return sh.selftest(fake, resolv_conf_path=path, run_root=run_root)
    finally:
        sh.egress_start, sh.egress_stop, sh.egress_clean, sh.egress_exchange, sh.egress_door_socket = saved
