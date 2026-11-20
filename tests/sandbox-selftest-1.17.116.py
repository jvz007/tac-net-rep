#!/usr/bin/env python3
"""1.18.24 note: updated in place for AD-65 Patch B. The address filter, own-address and DNS probes are retired; the selftest now probes the network wall
(network_private) and the egress proxy (egress_proxy), see tests/sandbox-selftest-network-1.18.24.py. Everything else here (version, cgroup, dynamic user,
file view, credential, proc, pipes, status.json) is unchanged. tests/sandbox-skeleton-root-1.18.12.py loads the first part of this file as its harness.

1.17.116 regression: the selftest logic of scripts/sandbox-helper.py (core.sandbox Patch 1, part 2).

The selftest only talks to a ``UnitRunner``. Here a fake runner answers each probe by name, so the logic is tested without systemd:

* systemd version parsing; resolv.conf parsing (systemd-resolved stub, LAN resolver, none, comments, zone ids, duplicates, at most three);
* the probe property list is a golden list: the address filter is exactly section 15 of the plan; (1.17.123) nothing is ever allowed by
  address, the upstream resolvers are probed directly under the full deny list, and a resolver in a denied range is not ready;
* status.json says ready only when every probe passes; (1.17.120: -BPF_FRAMEWORK alone is information only) a LoadCredential failure, cgroup v1, an old or missing
  systemd, a control probe that cannot connect, a private-range send that succeeds or cannot be judged, and a DNS probe without any reply
  each give ``ready: false`` with a plain reason, and never a weaker mode;
* any DNS reply counts (NXDOMAIN, SERVFAIL); no reply does not;
* the loopback probe must also leave the helper's own listener without a connection;
* status.json is written atomically (root-owned 0644, no stray temp file), read back only when root-trusted, small and valid.

Not runnable here: systemd, cgroups, root, the real probes. They are covered by tests/sandbox-selftest-runtime-1.17.116.sh (dev02).
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import stat
import sys
import tempfile
import time
import types
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import load_helper  # noqa: E402  (1.18.26: the helper and sandbox-selftest.py as one object)
ROOT = Path(__file__).resolve().parents[1]
BASE = Path(tempfile.mkdtemp(prefix="tectac-sandbox-selftest-"))


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


# the fake file-system layer (only status.json uses it)
def norm(path):
    return os.path.normcase(os.path.abspath(str(path)))


NOTROOT, WRITABLE, SYMLINKS, FD_PATH, CHMODS, CHOWNS = set(), set(), set(), {}, {}, {}
_real = {name: getattr(os, name) for name in ("stat", "lstat", "fstat", "open", "chmod", "replace")}
_VISIBLE = ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime")


def _fake(st, path, *, link=False):
    key = norm(path)
    kind = stat.S_IFLNK if (link and key in SYMLINKS) else stat.S_IFMT(st.st_mode)
    perms = 0o755 if stat.S_ISDIR(st.st_mode) else 0o644
    if key in WRITABLE:
        perms |= 0o020
    fields = list(st)[:10]
    fields[0], fields[4] = kind | perms, (1000 if key in NOTROOT else 0)
    extras = {name: getattr(st, name) for name in dir(st) if name.startswith("st_") and name not in _VISIBLE}
    return os.stat_result(fields, extras)


def _open(path, flags, *a, **k):
    fd = _real["open"](path, flags, *a, **k)
    FD_PATH[fd] = norm(path)
    return fd


def _replace(src, dst, *a, **k):
    _real["replace"](src, dst, *a, **k)
    CHMODS[norm(dst)], CHOWNS[norm(dst)] = CHMODS.get(norm(src)), CHOWNS.get(norm(src))


def _chmod(path, mode, *a, **k):
    CHMODS[norm(path)] = mode
    try:
        _real["chmod"](path, mode)
    except OSError:
        pass


os.stat = lambda path, *a, **k: _fake(_real["stat"](path, *a, **k), path)
os.lstat = lambda path, *a, **k: _fake(_real["lstat"](path, *a, **k), path, link=True)
os.fstat = lambda fd: _fake(_real["fstat"](fd), FD_PATH.get(fd, "?"))
os.open, os.replace, os.chmod = _open, _replace, _chmod
os.chown = lambda path, uid, gid, *a, **k: CHOWNS.__setitem__(norm(path), (uid, gid))
os.geteuid = lambda: 0

HELPER = ROOT / "scripts" / "sandbox-helper.py"
sh = load_helper(ROOT, "sandbox_helper_selftest")
STATE, RUN, LIB = BASE / "state", BASE / "run", BASE / "lib"
for folder in (STATE, RUN, LIB):
    folder.mkdir()
sh._ROOT_LAYOUT_ERROR = None
sh.STATE_ROOT, sh.RUN_ROOT, sh.LIB_ROOT = STATE, RUN, LIB
sh.RUNNERS_ROOT, sh.REGISTRY_ROOT = LIB / "runners", LIB / "registry"
sh.STATUS_FILE, sh.AUDIT_FILE = STATE / "status.json", STATE / "audit.jsonl"
# 1.18.8 (updated in place): the allow-list root and the host's /etc and merged-/usr names are not on this PC; the skeleton check and the base-file
# check are replaced here (tests/sandbox-file-view-1.18.8.py tests check_skeleton and file_view_properties with a fake file system)
sh.check_skeleton = lambda *a, **k: None
_real_file_view = sh.file_view_properties
sh.file_view_properties = lambda exists=None: _real_file_view(lambda path: True)

# ------------------------------------------------------------------------------------------------ parsing
V = sh.parse_systemd_version
must(V("systemd 252 (252.22-1~deb12u1)\n+PAM +AUDIT") == 252 and V("systemd 249 (249.11-0ubuntu3)") == 249 and V("systemd 255 (255.4-1ubuntu8)") == 255, "versions")
must(V("") is None and V(None) is None and V("not systemd 5") is None and V("systemd abc") is None, "no version")
R = sh.parse_resolvers
must(R("# comment\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch lan\n") == ["127.0.0.53"], "systemd-resolved stub")
must(R("nameserver 192.168.1.1\nnameserver 1.1.1.1\n") == ["192.168.1.1", "1.1.1.1"], "LAN resolver then public")
must(R("") == [] and R("search lan\n# nameserver 1.1.1.1\n") == [] and R(None) == [], "none")
must(R("nameserver 1.1.1.1 # trailing\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 9.9.9.9\n") == ["1.1.1.1", "8.8.8.8", "8.8.4.4"], "unique, at most three")
must(R("nameserver fe80::1%eth0\nnameserver not-an-address\nnameserver 2606:4700:4700::1111\n") == ["2606:4700:4700::1111"], "zone ids and junk are skipped")
must(R("nameserver\nnameserver ::1\n") == ["::1"], "bare keyword")

# ------------------------------------------------------------------------------------------------ the golden list (plan section 15)
must(sh.ADDRESS_DENY == "127.0.0.0/8 ::1/128 169.254.0.0/16 fe80::/10 224.0.0.0/4 ff00::/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7", sh.ADDRESS_DENY)
must(sh.PROBE_PROPERTIES == {
    "transient": (),
    "dynamic_user": ("DynamicUser=yes",),
    "credential": ("DynamicUser=yes",),
    "proc_hidden": ("DynamicUser=yes", "ProtectProc=invisible", "ProcSubset=pid"),
    "network_control": ("DynamicUser=yes",),
    "network_private": ("DynamicUser=yes", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_INET AF_UNIX"),
    "pipe_streams": ("DynamicUser=yes",),
}, sh.PROBE_PROPERTIES)
must(sh.PRIVATE_PROBE_TARGETS == ("10.255.255.254", "172.31.255.254", "192.168.255.254", "100.127.255.254", "169.254.169.254"), "private probe targets, metadata included")
must(sh.MIN_SYSTEMD_VERSION == 249 and sh.RESOLVERS_MAX == 3, "floor and resolver cap")
must("IPAddressDeny" not in json.dumps(sh.PROBE_PROPERTIES), "1.18.24: no unit probe carries an address filter")
for forbidden in ("nft", "iptables", "HTTPS_PROXY", "allowed_hosts"):
    must(forbidden not in "".join(sh.PROBE_PROPERTIES[k][i] for k in sh.PROBE_PROPERTIES for i in range(len(sh.PROBE_PROPERTIES[k]))), forbidden)


# ------------------------------------------------------------------------------------------------ the fake runner
IP_ADDR = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
           "2: eth0    inet 129.232.197.50/24 brd 129.232.197.255 scope global eth0\\       valid_lft forever preferred_lft forever\n")
IP_ROUTE4 = "default via 129.232.197.1 dev eth0 proto static\n"
PUBLIC = "nameserver 156.38.225.225\noptions edns0\n"


class Fake:
    """Answers each probe by name. ``script`` maps a name to (code, stdout) or a callable(properties, command)."""

    def __init__(self, **overrides):
        self.calls = []
        self.cmds = []
        self.script = {
            "systemctl": (0, "systemd 252 (252.22-1~deb12u1)\n+PAM +AUDIT +BPF_FRAMEWORK +SYSVINIT\n"),
            "stat": (0, "cgroup2fs\n"),
            "transient": (0, "tectac-probe\n"),
            "dynamic_user": (0, "61500\n"),
            "filesystem_view": (0, "ok\n"),
            "credential": "credential",
            "real_unit_shape": "real_shape",  # 1.18.13
            "proc_hidden": (0, "ok\n"),
            "network_control": "net_control",  # 1.18.24: no wall: the unit reaches this server's loopback listener
            "network_private": lambda properties, command: (0, f"ifaces lo\nconnect 1.1.1.1 443 ENETUNREACH\nconnect 127.0.0.1 {command[-1]} ECONNREFUSED\nresolv absent\n", ""),
            "pipe_streams": lambda properties, command: (0, "out", "err"),   # 1.17.118: stdout and stderr on separate pipes
        }
        self.egress = {"listed": 200, "unlisted": 403, "literal": 403, "port80": 403, "start_fails": False, "started": [], "stopped": []}
        self.ip = {"addr": IP_ADDR, "route4": IP_ROUTE4, "route6": ""}
        self.script.update(overrides)
        self.credential = {"mode": "400", "uid": "61500", "gid": "61500", "stat": None, "token": None, "remove": True}

    def run_cmd(self, argv, *, timeout=15):
        self.cmds.append(argv)
        if argv[0] == "ip":  # 1.17.123: the live addresses and default routes
            key = "addr" if argv[1] == "-o" else ("route4" if argv[1] == "-4" else "route6")
            return 0, self.ip[key], ""
        answer = self.script["systemctl" if argv[0] == "systemctl" else "stat"]
        return (answer[0], answer[1], "")

    def run_unit(self, name, properties, command, *, timeout=30, unit=None):
        self.calls.append((name, tuple(properties), tuple(command)))
        answer = self.script[name]
        if answer == "net_control":   # a real connection to the helper's own listener, as a unit without the wall would make
            socket.create_connection(("127.0.0.1", int(command[-1])), timeout=2).close()
            return 0, f"ifaces lo,eth0\nconnect 1.1.1.1 443 connected\nconnect 127.0.0.1 {command[-1]} connected\nresolv present\n", ""
        if answer == "leak":      # a wall that does not hold: it reaches the listener, and says so
            socket.create_connection(("127.0.0.1", int(command[-1])), timeout=2).close()
            return 0, f"ifaces lo\nconnect 1.1.1.1 443 ENETUNREACH\nconnect 127.0.0.1 {command[-1]} connected\nresolv absent\n", ""
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
            must(source is not None and not any(p.startswith("Exec") for p in properties), properties)
            token = hand_in(unit, source, self.credential["remove"])
            if self.credential["token"] is not None:
                token = self.credential["token"]
            c = self.credential
            stat_line = c["stat"] if c["stat"] is not None else f"{c['mode']} {c['uid']} {c['gid']}"
            return 0, f"{token}\n{stat_line}\n61500\n61500\nACL none\n", ""
        if callable(answer):
            return answer(properties, command)
        return answer[0], answer[1], "err text" if answer[0] else ""



CREDS_ROOT = Path(tempfile.mkdtemp(prefix="tectac-fake-credentials-"))  # 1.18.14: stands in for /run/credentials


def hand_in(unit, source, remove=True):
    """1.18.14: systemd copies the source into the unit's own folder; the helper must then remove the source folder (the fake waits up to 5 s)."""
    token = source.read_text(encoding="utf-8")
    if remove and unit:
        folder = CREDS_ROOT / f"{unit}.service"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / source.name).write_text(token, encoding="utf-8")
        deadline = time.monotonic() + 5
        while source.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
    return token


def selftest(fake, resolv=PUBLIC):
    sh.CREDENTIALS_RUNTIME = CREDS_ROOT
    path = BASE / f"resolv-{len(list(BASE.glob('resolv-*')))}.conf"
    if resolv is not None:
        path.write_text(resolv, encoding="utf-8")
    # 1.18.24: the egress door is real systemd and a real socket; the helper's hooks answer from ``fake.egress``
    saved = (sh.egress_start, sh.egress_stop, sh.egress_clean, sh.egress_exchange, sh.egress_door_socket)
    state = fake.egress

    def start(row, run_id, local, **kw):
        state["started"].append(run_id)
        if state["start_fails"]:
            raise sh.Refusal("sandbox_unavailable", "the egress door could not be started")
        return True

    def exchange(sock_path, request, **kw):
        target = request.split(b"\r\n", 1)[0].decode("ascii").split(" ")[1]
        return {"example.com:443": state["listed"], "example.net:443": state["unlisted"], "1.1.1.1:443": state["literal"], "example.com:80": state["port80"]}.get(target, 0)

    sh.egress_start, sh.egress_exchange = start, exchange
    sh.egress_stop = lambda run_id, **kw: state["stopped"].append(run_id)
    sh.egress_clean = lambda run_id: None
    sh.egress_door_socket = lambda run_id: BASE / "door.sock"
    try:
        return sh.selftest(fake, resolv_conf_path=path, run_root=RUN)
    finally:
        sh.egress_start, sh.egress_stop, sh.egress_clean, sh.egress_exchange, sh.egress_door_socket = saved


# ---- everything passes
fake = Fake()
status = selftest(fake)
must(status["ready"] is True and status["reason"] == "ready" and status["enabled"] is False, status)
must(status["systemd_version"] == 252 and status["address_filter_ok"] is True and status["dns_ok"] is True and status["network_private_ok"] is True and status["egress_ok"] is True, status)
must(status["resolver"] == "" and status["resolvers"] == [] and status["dns_method"] == "", status)  # 1.18.24: kept as empty values for every status reader
must(status["selftest_at"].endswith("Z"), status["selftest_at"])
must(sorted(status["checks"]) == sorted(["systemd_version", "bpf_framework", "cgroup_v2", "transient_unit", "dynamic_user", "filesystem_view", "sandbox_root", "sandbox_root_after", "credential", "real_unit_shape", "proc_hidden",
                                         "network_private", "pipe_streams", "egress_proxy", "memory_zswap", "local_addresses"]), sorted(status["checks"]))
must(all(row["ok"] for row in status["checks"].values()), status["checks"])
must(json.dumps(status) and "token" not in json.dumps(status).lower().replace("tectac-probe", ""), "no credential-like text in the status")
# the probes ran in this order, each with exactly its golden properties
names = [call[0] for call in fake.calls]
must(names == ["transient", "dynamic_user", "filesystem_view", "credential", "real_unit_shape", "proc_hidden", "network_control", "network_private", "pipe_streams"], names)
for name, properties, command in fake.calls:
    expected = sh.PROBE_PROPERTIES.get(name, ())
    if name == "filesystem_view":  # 1.18.8: the REAL file view, from the one function the unit builder uses
        must(properties == ("DynamicUser=yes", *sh.file_view_properties()) and "RootDirectory=" + str(sh.SANDBOX_ROOT) in properties and "MountAPIVFS=yes" in properties, properties)
    elif name == "credential":
        must(properties[:1] == expected and len(properties) == 2, properties)  # 1.18.14: DynamicUser and LoadCredential only, no property command
    elif name == "real_unit_shape":  # 1.18.13
        must(properties[:len(sh.file_view_properties())] == tuple(sh.file_view_properties()) and "DynamicUser=yes" in properties and len(properties) == len(sh.file_view_properties()) + 2, properties)
    elif name == "network_private":  # 1.18.24: the real network properties and the real file view (so there is no resolv.conf to see)
        must(properties == (*expected, *sh.file_view_properties()), properties)
    else:
        must(properties == expected, (name, properties))
must([c for c in fake.cmds] == [["systemctl", "--version"], ["stat", "-fc", "%T", "/sys/fs/cgroup"], ["ip", "-o", "addr", "show"],
                         ["ip", "-4", "route", "show", "default"], ["ip", "-6", "route", "show", "default"]], fake.cmds)
must(not list(RUN.iterdir()), "the credential probe folder is removed")
must("IPAddressAllow" not in json.dumps([call[1] for call in fake.calls]) and "IPAddressDeny" not in json.dumps([call[1] for call in fake.calls]), "no address filter in any probe")
must(len(fake.egress["started"]) == 1 and fake.egress["stopped"] == fake.egress["started"], "the throw-away egress door was started and stopped once")

# ---- failures: ready false, a plain reason, never a weaker mode
def check_fail(label, reason_part, fake=None, resolv=PUBLIC, expect_check=None):
    status = selftest(fake or Fake(), resolv)
    must(status["ready"] is False and status["enabled"] is False, (label, status))
    must(reason_part in status["reason"], (label, reason_part, status["reason"]))
    must(status["reason"] != "ready" and "Traceback" not in status["reason"], label)
    if expect_check:
        must(status["checks"][expect_check]["ok"] is False, (label, status["checks"]))
    return status


check_fail("no systemd", "systemd is not available", Fake(systemctl=(127, "")), expect_check="systemd_version")
check_fail("old systemd", "systemd 248 is older than 249", Fake(systemctl=(0, "systemd 248 (248.3)\n+BPF_FRAMEWORK\n")), expect_check="systemd_version")
# 1.17.120: -BPF_FRAMEWORK is information only; readiness comes from the probes (tests/sandbox-bpf-info-1.17.120.py covers all three cases)
status = selftest(Fake(systemctl=(0, "systemd 252 (252)\n+PAM -BPF_FRAMEWORK\n")))
must(status["ready"] is True and status["checks"]["bpf_framework"]["ok"] is True and "information only" in status["checks"]["bpf_framework"]["detail"], status)
check_fail("cgroup v1", "cgroup v2", Fake(stat=(0, "tmpfs\n")), expect_check="cgroup_v2")
check_fail("no stat", "cgroup v2", Fake(stat=(1, "")), expect_check="cgroup_v2")
check_fail("transient", "transient unit", Fake(transient=(1, "")), expect_check="transient_unit")
check_fail("dynamic user is root", "dynamic user", Fake(dynamic_user=(0, "0\n")), expect_check="dynamic_user")
check_fail("dynamic user fails", "dynamic user", Fake(dynamic_user=(1, "")), expect_check="dynamic_user")
check_fail("filesystem view", "allow-list file system", Fake(filesystem_view=(0, "bad\n")), expect_check="filesystem_view")
check_fail("proc visible", "ProtectProc", Fake(proc_hidden=(0, "bad 40\n")), expect_check="proc_hidden")
check_fail("proc fails", "ProtectProc", Fake(proc_hidden=(1, "")), expect_check="proc_hidden")

# LoadCredential failure: the unit does not start, the token does not arrive, the mode is wrong, the source cannot be removed
check_fail("credential unit fails", "LoadCredential did not work", Fake(credential=(1, "")), expect_check="credential")
fake = Fake()
fake.credential["token"] = "someone else's text"
check_fail("credential wrong content", "did not arrive", fake, expect_check="credential")
fake = Fake()
fake.credential["mode"] = "640"
check_fail("credential mode", "mode is 640", fake, expect_check="credential")
fake = Fake()
fake.credential["remove"] = False
check_fail("credential source stays", "not removed by the helper", fake, expect_check="credential")
must(not list(RUN.iterdir()), "the probe folder is removed after each failure too")
check_fail("credential too few lines", "LoadCredential did not work", Fake(credential=(0, "just one line\n")), expect_check="credential")

# ---- 1.17.118: the pipe_streams row (plan section 10, item 1) and slots_total in the status
must(isinstance(status["slots_total"], int) and 1 <= status["slots_total"] <= 6, status["slots_total"])
check_fail("streams merged", "stdout and stderr apart", Fake(pipe_streams=lambda properties, command: (0, "outerr", "")), expect_check="pipe_streams")
check_fail("streams swapped", "stdout and stderr apart", Fake(pipe_streams=lambda properties, command: (0, "err", "out")), expect_check="pipe_streams")
check_fail("streams unit fails", "stdout and stderr apart", Fake(pipe_streams=(1, "")), expect_check="pipe_streams")

# ---- the network wall (1.18.24): a missing wall shows as a loopback that stays reachable (tests/sandbox-selftest-network-1.18.24.py has every case)
status = check_fail("wall leaks", "reached an address", Fake(network_private="leak"), expect_check="network_private")
must(status["address_filter_ok"] is False and status["network_private_ok"] is False, status)
check_fail("wall probe errors", "PrivateNetwork", Fake(network_private=(1, "")), expect_check="network_private")
check_fail("control cannot connect", "could not be checked", Fake(network_control=(0, "ifaces lo\n")), expect_check="network_private")
listener_checks = selftest(Fake())["checks"]
must("interfaces lo" in listener_checks["network_private"]["detail"] and "resolv.conf absent" in listener_checks["network_private"]["detail"], listener_checks["network_private"])

# ---- the egress proxy (1.18.24): the stand-in host answers 200, refusals answer 403, a private resolver fails closed
bad_egress = Fake()
bad_egress.egress["listed"] = 502
bad = check_fail("proxy cannot tunnel", "could not open a tunnel", bad_egress, expect_check="egress_proxy")
must(bad["dns_ok"] is False and bad["egress_ok"] is False and bad["address_filter_ok"] is True, bad)
check_fail("private resolver", "systemd-resolved stub", Fake(), resolv="nameserver 10.0.0.2\n", expect_check="egress_proxy")
check_fail("no resolver", "no name server is listed", Fake(), resolv="search lan\n", expect_check="egress_proxy")
check_fail("no resolv.conf", "no name server is listed", Fake(), resolv=None, expect_check="egress_proxy")
ok = selftest(Fake(), "nameserver 127.0.0.53\n")
must(ok["ready"] is True and ok["egress_ok"] is True, ok)  # the systemd-resolved stub is the one local resolver the proxy may use

# ---- several failures: the reason is the first failing check, and the checks table lists all of them
many = selftest(Fake(stat=(0, "tmpfs\n"), proc_hidden=(0, "bad 9\n")))
must(many["ready"] is False and "cgroup v2" in many["reason"] and many["checks"]["proc_hidden"]["ok"] is False, many)
# the probe never raises on a missing program
must(sh.UnitRunner().run_unit("x", (), ["/definitely/not/here"], timeout=5)[0] != 0, "a missing systemd-run is a failure, not an exception")

# ------------------------------------------------------------------------------------------------ status.json
def read():
    return sh.read_status()


with contextlib.redirect_stdout(io.StringIO()):
    sh.ensure_layout()
status = selftest(Fake())
sh.write_status(status)
path = sh.STATUS_FILE
must(json.loads(path.read_text(encoding="utf-8")) == status, "written as given")
must(CHMODS[norm(path)] == 0o644 and CHOWNS[norm(path)] == (0, 0), "root-owned 0644")
must(not [p for p in STATE.iterdir() if p.name.endswith(".tmp")], "no stray temp file (atomic replace)")
must(read()["ready"] is True and read()["enabled"] is False, "read back")
# an update replaces atomically: the old content is never half-written
sh.write_status({**status, "ready": False, "reason": "later"})
must(read()["reason"] == "later" and not [p for p in STATE.iterdir() if p.name.endswith(".tmp")], "replaced")
# root-trust and shape checks on read
sh.write_status(status)
for label, bucket in (("not root-owned", NOTROOT), ("group writable", WRITABLE), ("symlink", SYMLINKS)):
    bucket.add(norm(path))
    try:
        got = read()
    finally:
        bucket.discard(norm(path))
    must(got["ready"] is False and "cannot be read" in got["reason"] and got["enabled"] is False, (label, got))
path.write_text("{not json", encoding="utf-8")
must(read()["ready"] is False, "corrupt")
path.write_text("[1,2]", encoding="utf-8")
must(read()["ready"] is False, "not an object")
path.write_text(json.dumps({"ready": True, "pad": "x" * 70000}), encoding="utf-8")
must(read()["ready"] is False, "oversize")
path.unlink()
must(read()["ready"] is False and "selftest has not run" in read()["reason"], "missing")
path.write_text(json.dumps({"ready": True, "enabled": True}), encoding="utf-8")
must(read()["enabled"] is False, "a status file can never switch the sandbox on: the constant decides")

# ---- run_selftest: writes status.json, audits, exits 0 only when ready
real_selftest = sh.selftest
for ready, code in ((True, 0), (False, 1)):
    sh.selftest = lambda *a, _r=ready, **k: {**status, "ready": _r, "reason": "ready" if _r else "why not"}
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        must(sh.run_selftest() == code, ready)
    must(json.loads(out.getvalue())["ready"] is ready and json.loads(path.read_text(encoding="utf-8"))["ready"] is ready, "printed and written")
sh.selftest = real_selftest
events = [json.loads(line) for line in sh.AUDIT_FILE.read_text(encoding="utf-8").splitlines()]
must([row["event"] for row in events].count("selftest") == 2 and all("token" not in json.dumps(row) for row in events), events)

print("[TEST] PASS sandbox selftest 1.17.116")
