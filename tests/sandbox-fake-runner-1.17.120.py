"""Shared helper for the 1.17.120 core.sandbox tests (not a test: the tests load it by path, so no module and no bytecode is left behind).

``Fake`` is a ``UnitRunner`` stand-in that answers each selftest probe by name (the technique of tests/sandbox-selftest-1.17.116.py), with the
1.17.120 credential answer (content, ``mode uid gid``, the unit's uid, the unit's gid). ``run_selftest(sh, run_root, base, fake, resolv)``
writes a resolv.conf and runs the helper's ``selftest`` against the fake.

Not runnable here: real systemd. The dev02 canary (tests/sandbox-canary-1.17.120.sh) proves the real behaviour.
"""
from __future__ import annotations

import socket
from pathlib import Path


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
            "dns": (0, "reply 0\n"),
        }
        self.script.update(overrides)
        self.credential = {"mode": "400", "uid": "61500", "gid": "61500", "unit_uid": "61500", "unit_gid": "61500", "stat": None, "token": None, "remove": True}

    def run_cmd(self, argv, *, timeout=15):
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
            return 0, f"{token}\n{stat_line}\n{c['unit_uid']}\n{c['unit_gid']}\n", ""
        if callable(answer):
            return answer(properties, command)
        return answer[0], answer[1], "err text" if answer[0] else ""


def run_selftest(sh, run_root, base, fake, resolv="nameserver 127.0.0.53\noptions edns0\n"):
    path = Path(base) / f"resolv-{len(list(Path(base).glob('resolv-*')))}.conf"
    path.write_text(resolv, encoding="utf-8")
    return sh.selftest(fake, resolv_conf_path=path, run_root=run_root)
