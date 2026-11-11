#!/usr/bin/env python3
"""1.17.116 regression: the selftest logic of scripts/sandbox-helper.py (core.sandbox Patch 1, part 2).

The selftest only talks to a ``UnitRunner``. Here a fake runner answers each probe by name, so the logic is tested without systemd:

* systemd version parsing; resolv.conf parsing (systemd-resolved stub, LAN resolver, none, comments, zone ids, duplicates, at most three);
* the probe property list is a golden list: the address filter is exactly section 15 of the plan, and the resolvers are allowed by
  address, one ``IPAddressAllow=`` each, only in the DNS probe;
* status.json says ready only when every probe passes; a missing cgroup BPF, a LoadCredential failure, cgroup v1, an old or missing
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
import types
from pathlib import Path

sys.dont_write_bytecode = True
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
sh = types.ModuleType("sandbox_helper_selftest")
sh.__file__ = str(HELPER)
exec(compile(HELPER.read_text(encoding="utf-8"), str(HELPER), "exec"), sh.__dict__)
STATE, RUN, LIB = BASE / "state", BASE / "run", BASE / "lib"
for folder in (STATE, RUN, LIB):
    folder.mkdir()
sh._ROOT_LAYOUT_ERROR = None
sh.STATE_ROOT, sh.RUN_ROOT, sh.LIB_ROOT = STATE, RUN, LIB
sh.RUNNERS_ROOT, sh.REGISTRY_ROOT = LIB / "runners", LIB / "registry"
sh.STATUS_FILE, sh.AUDIT_FILE = STATE / "status.json", STATE / "audit.jsonl"

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
must(sh.ADDRESS_DENY == "localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7", sh.ADDRESS_DENY)
must(sh.PROBE_PROPERTIES == {
    "transient": (),
    "dynamic_user": ("DynamicUser=yes",),
    "filesystem_view": ("DynamicUser=yes", "TemporaryFileSystem=/etc:ro", "BindReadOnlyPaths=/etc/passwd"),
    "credential": ("DynamicUser=yes",),
    "proc_hidden": ("DynamicUser=yes", "ProtectProc=invisible", "ProcSubset=pid"),
    "address_filter_control": ("DynamicUser=yes",),
    "address_filter_loopback": ("DynamicUser=yes", "IPAddressDeny=localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7"),
    "address_filter_private": ("DynamicUser=yes", "IPAddressDeny=localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7"),
    "dns": ("DynamicUser=yes", "IPAddressDeny=localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7"),
}, sh.PROBE_PROPERTIES)
must(sh.PRIVATE_PROBE_TARGETS == ("10.255.255.254", "172.31.255.254", "192.168.255.254", "100.127.255.254", "169.254.169.254"), "private probe targets, metadata included")
must(sh.MIN_SYSTEMD_VERSION == 249 and sh.RESOLVERS_MAX == 3, "floor and resolver cap")
must("IPAddressDeny=any" not in json.dumps(sh.PROBE_PROPERTIES), "Patch 1 does not use the Patch 2 plan-3.4 filter")
for forbidden in ("nft", "iptables", "HTTPS_PROXY", "allowed_hosts"):
    must(forbidden not in "".join(sh.PROBE_PROPERTIES[k][i] for k in sh.PROBE_PROPERTIES for i in range(len(sh.PROBE_PROPERTIES[k]))), forbidden)


# ------------------------------------------------------------------------------------------------ the fake runner
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
            "proc_hidden": (0, "ok\n"),
            "address_filter_control": "connect",
            "address_filter_loopback": (0, "blocked\n"),
            "address_filter_private": (0, "10.255.255.254 eperm\n172.31.255.254 eperm\n192.168.255.254 eperm\n100.127.255.254 eperm\n169.254.169.254 eperm\n"),
            "dns": (0, "reply 0\n"),
        }
        self.script.update(overrides)
        self.credential = {"mode": "400", "token": None, "remove": True}

    def run_cmd(self, argv, *, timeout=15):
        self.cmds.append(argv)
        answer = self.script["systemctl" if argv[0] == "systemctl" else "stat"]
        return (answer[0], answer[1], "")

    def run_unit(self, name, properties, command, *, timeout=30):
        self.calls.append((name, tuple(properties), tuple(command)))
        answer = self.script[name]
        if answer == "connect":   # a real connection to the helper's own listener, as an unfiltered unit would make
            socket.create_connection(("127.0.0.1", int(command[-1])), timeout=2).close()
            return 0, "connected\n", ""
        if answer == "leak":      # a filter that does not hold: connects, and says so
            socket.create_connection(("127.0.0.1", int(command[-1])), timeout=2).close()
            return 0, "connected\n", ""
        if answer == "lie":       # says blocked, but the listener sees a connection anyway
            socket.create_connection(("127.0.0.1", int(command[-1])), timeout=2).close()
            return 0, "blocked\n", ""
        if answer == "credential":
            source = None
            for item in properties:
                if item.startswith("LoadCredential=probe:"):
                    source = Path(item.split(":", 1)[1])
            must(source is not None and any(p.startswith("ExecStartPost=+/bin/rm -f ") for p in properties), properties)
            token = self.credential["token"] if self.credential["token"] is not None else source.read_text(encoding="utf-8")
            if self.credential["remove"]:
                source.unlink()
            return 0, f"{token}\n{self.credential['mode']}\n", ""
        if callable(answer):
            return answer(properties, command)
        return answer[0], answer[1], "err text" if answer[0] else ""


def selftest(fake, resolv="nameserver 127.0.0.53\noptions edns0\n"):
    path = BASE / f"resolv-{len(list(BASE.glob('resolv-*')))}.conf"
    if resolv is not None:
        path.write_text(resolv, encoding="utf-8")
    return sh.selftest(fake, resolv_conf_path=path, run_root=RUN)


# ---- everything passes
fake = Fake()
status = selftest(fake)
must(status["ready"] is True and status["reason"] == "ready" and status["enabled"] is False, status)
must(status["systemd_version"] == 252 and status["address_filter_ok"] is True and status["dns_ok"] is True, status)
must(status["resolver"] == "127.0.0.53" and status["resolvers"] == ["127.0.0.53"] and status["dns_method"] == "ip_address_allow", status)
must(status["selftest_at"].endswith("Z"), status["selftest_at"])
must(sorted(status["checks"]) == sorted(["systemd_version", "bpf_framework", "cgroup_v2", "transient_unit", "dynamic_user", "filesystem_view", "credential", "proc_hidden",
                                         "address_filter_control", "address_filter_loopback", "address_filter_private", "dns"]), sorted(status["checks"]))
must(all(row["ok"] for row in status["checks"].values()), status["checks"])
must(json.dumps(status) and "token" not in json.dumps(status).lower().replace("tectac-probe", ""), "no credential-like text in the status")
# the probes ran in this order, each with exactly its golden properties
names = [call[0] for call in fake.calls]
must(names == ["transient", "dynamic_user", "filesystem_view", "credential", "proc_hidden", "address_filter_control", "address_filter_loopback", "address_filter_private", "dns"], names)
for name, properties, command in fake.calls:
    expected = sh.PROBE_PROPERTIES[name]
    if name == "credential":
        must(properties[:1] == expected and len(properties) == 3, properties)
    elif name == "dns":
        must(properties == expected + ("IPAddressAllow=127.0.0.53",), properties)   # the resolver is allowed by address, exactly
    else:
        must(properties == expected, (name, properties))
must([c for c in fake.cmds] == [["systemctl", "--version"], ["stat", "-fc", "%T", "/sys/fs/cgroup"]], fake.cmds)
must(not list(RUN.iterdir()), "the credential probe folder is removed")
# only the DNS probe carries an Allow, and every probe command is a fixed program with no shell string from outside
must(sum(1 for call in fake.calls for p in call[1] if p.startswith("IPAddressAllow=")) == 1, "one Allow, in the DNS probe")
must(fake.calls[-1][2][-2:] == ("127.0.0.53", "example.com"), fake.calls[-1][2])

# ---- failures: ready false, a plain reason, never a weaker mode
def check_fail(label, reason_part, fake=None, resolv="nameserver 127.0.0.53\n", expect_check=None):
    status = selftest(fake or Fake(), resolv)
    must(status["ready"] is False and status["enabled"] is False, (label, status))
    must(reason_part in status["reason"], (label, reason_part, status["reason"]))
    must(status["reason"] != "ready" and "Traceback" not in status["reason"], label)
    if expect_check:
        must(status["checks"][expect_check]["ok"] is False, (label, status["checks"]))
    return status


check_fail("no systemd", "systemd is not available", Fake(systemctl=(127, "")), expect_check="systemd_version")
check_fail("old systemd", "systemd 248 is older than 249", Fake(systemctl=(0, "systemd 248 (248.3)\n+BPF_FRAMEWORK\n")), expect_check="systemd_version")
status = check_fail("no BPF framework", "without cgroup BPF", Fake(systemctl=(0, "systemd 252 (252)\n+PAM -BPF_FRAMEWORK\n")), expect_check="bpf_framework")
check_fail("cgroup v1", "cgroup v2", Fake(stat=(0, "tmpfs\n")), expect_check="cgroup_v2")
check_fail("no stat", "cgroup v2", Fake(stat=(1, "")), expect_check="cgroup_v2")
check_fail("transient", "transient unit", Fake(transient=(1, "")), expect_check="transient_unit")
check_fail("dynamic user is root", "dynamic user", Fake(dynamic_user=(0, "0\n")), expect_check="dynamic_user")
check_fail("dynamic user fails", "dynamic user", Fake(dynamic_user=(1, "")), expect_check="dynamic_user")
check_fail("filesystem view", "hidden file system", Fake(filesystem_view=(0, "bad\n")), expect_check="filesystem_view")
check_fail("proc visible", "ProtectProc", Fake(proc_hidden=(0, "bad 40\n")), expect_check="proc_hidden")
check_fail("proc fails", "ProtectProc", Fake(proc_hidden=(1, "")), expect_check="proc_hidden")

# LoadCredential failure: the unit does not start, the token does not arrive, the mode is wrong, the source cannot be removed
check_fail("credential unit fails", "LoadCredential did not work", Fake(credential=(1, "")), expect_check="credential")
fake = Fake()
fake.credential["token"] = "someone else's text"
check_fail("credential wrong content", "did not arrive", fake, expect_check="credential")
fake = Fake()
fake.credential["mode"] = "440"
check_fail("credential mode", "mode is 440", fake, expect_check="credential")
fake = Fake()
fake.credential["remove"] = False
check_fail("credential source stays", "not removable", fake, expect_check="credential")
must(not list(RUN.iterdir()), "the probe folder is removed after each failure too")
check_fail("credential too few lines", "LoadCredential did not work", Fake(credential=(0, "just one line\n")), expect_check="credential")

# ---- the address filter: a missing BPF shows as a loopback that stays reachable
status = check_fail("filter leaks", "reaching the server itself", Fake(address_filter_loopback="leak"), expect_check="address_filter_loopback")
must(status["address_filter_ok"] is False, status)
check_fail("filter lies", "reaching the server itself", Fake(address_filter_loopback="lie"), expect_check="address_filter_loopback")
check_fail("loopback probe errors", "reaching the server itself", Fake(address_filter_loopback=(1, "")), expect_check="address_filter_loopback")
check_fail("control cannot connect", "could not be checked", Fake(address_filter_control=(0, "blocked\n")), expect_check="address_filter_control")
check_fail("private send succeeds", "private-range", Fake(address_filter_private=(0, "10.255.255.254 sent\n172.31.255.254 eperm\n")), expect_check="address_filter_private")
check_fail("private unjudgeable", "private-range", Fake(address_filter_private=(0, "10.255.255.254 other\n172.31.255.254 other\n")), expect_check="address_filter_private")
check_fail("private probe fails", "private-range", Fake(address_filter_private=(1, "")), expect_check="address_filter_private")
# one conclusive refusal among unroutable ranges is enough
ok = selftest(Fake(address_filter_private=(0, "10.255.255.254 other\n192.168.255.254 eperm\n169.254.169.254 eperm\n")))
must(ok["ready"] is True and ok["address_filter_ok"] is True, ok)
# the helper's listener really saw the control connection and nothing from the filtered probe
listener_checks = selftest(Fake())["checks"]
must("connected" in listener_checks["address_filter_control"]["detail"] and listener_checks["address_filter_loopback"]["detail"] == "blocked", listener_checks)

# ---- DNS: any reply counts, no reply does not
for reply in ("reply 0", "reply 3", "reply 2", "reply 5"):
    ok = selftest(Fake(dns=(0, reply + "\n")))
    must(ok["ready"] is True and ok["dns_ok"] is True, (reply, ok))   # NXDOMAIN (3) and SERVFAIL (2) are replies
bad = check_fail("dns no reply", "no DNS reply", Fake(dns=(0, "noreply\n")), expect_check="dns")
must(bad["dns_ok"] is False and bad["resolver"] == "", bad)
check_fail("dns unit fails", "no DNS reply", Fake(dns=(1, "")), expect_check="dns")
check_fail("no resolver", "no name server", Fake(), resolv="search lan\n", expect_check="dns")
check_fail("no resolv.conf", "no name server", Fake(), resolv=None, expect_check="dns")
# a LAN resolver is allowed by its own address; a second resolver that answers is found and recorded
fake = Fake(dns=lambda properties, command: (0, "reply 0\n", "") if command[-2] == "1.1.1.1" else (0, "noreply\n", ""))
ok = selftest(fake, "nameserver 192.168.1.1\nnameserver 1.1.1.1\n")
must(ok["ready"] is True and ok["resolver"] == "1.1.1.1" and ok["resolvers"] == ["192.168.1.1", "1.1.1.1"], ok)
dns_calls = [call for call in fake.calls if call[0] == "dns"]
must(len(dns_calls) == 2 and all({p for p in call[1] if p.startswith("IPAddressAllow=")} == {"IPAddressAllow=192.168.1.1", "IPAddressAllow=1.1.1.1"} for call in dns_calls), dns_calls)
# a server that is offline: its stub resolver still replies (SERVFAIL), so the sandbox is not turned off for that reason
offline = selftest(Fake(dns=(0, "reply 2\n")))
must(offline["ready"] is True, offline)

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
