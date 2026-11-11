"""Shared helper for the 1.17.120 core.sandbox tests (not a test: the tests load it by path, so no module and no bytecode is left behind).

``Fake`` is a ``UnitRunner`` stand-in that answers each selftest probe by name (the technique of tests/sandbox-selftest-1.17.116.py), with the
1.17.120 credential answer (content, ``mode uid gid``, the unit's uid, the unit's gid). ``run_selftest(sh, run_root, base, fake, resolv)``
writes a resolv.conf and runs the helper's ``selftest`` against the fake.

Not runnable here: real systemd. The dev02 canary (tests/sandbox-canary-1.17.120.sh) proves the real behaviour.
"""
from __future__ import annotations

import socket
from pathlib import Path


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
            "proc_hidden": (0, "ok\n"),
            "address_filter_control": "connect",
            "address_filter_loopback": (0, "blocked\n"),
            "address_filter_private": (0, "10.255.255.254 eperm\n172.31.255.254 eperm\n192.168.255.254 eperm\n100.127.255.254 eperm\n169.254.169.254 eperm\n"),
            "pipe_streams": lambda properties, command: (0, "out", "err"),
            "address_filter_local_control": lambda properties, command: (0, "".join(f"{a} sent\n" for a in command[4:]), ""),
            "address_filter_local": lambda properties, command: (0, "".join(f"{a} eperm\n" for a in command[4:]), ""),
            "dns": (0, "reply 0\n"),
        }
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

    def run_unit(self, name, properties, command, *, timeout=30):
        self.calls.append((name, tuple(properties), tuple(command)))
        answer = self.script[name]
        if answer == "connect":
            socket.create_connection(("127.0.0.1", int(command[-1])), timeout=2).close()
            return 0, "connected\n", ""
        if answer == "leak":  # a filter that does not hold: it connects, and says so
            socket.create_connection(("127.0.0.1", int(command[-1])), timeout=2).close()
            return 0, "connected\n", ""
        if answer == "credential":
            source = None
            for item in properties:
                if item.startswith("LoadCredential=probe:"):
                    source = Path(item.split(":", 1)[1])
            token = self.credential["token"] if self.credential["token"] is not None else source.read_text(encoding="utf-8")
            if self.credential["remove"]:
                source.unlink()
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
    return sh.selftest(fake, resolv_conf_path=path, run_root=run_root, upstream_path=Path(base) / "no-upstream-file.conf")  # 1.17.123: upstream missing, so the file above is the fallback
