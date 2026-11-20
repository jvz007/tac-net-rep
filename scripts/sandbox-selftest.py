#!/usr/bin/python3 -I
"""Root-only selftest and canary for core.sandbox (Core 1.18.26, AD-65 Patch C).

Until 1.18.25 the selftest and the canary lived inside ``sandbox-helper.py``, the file the Tactical account may run as root through sudo. They
are test code: they plant files, open sockets and run attack programs. They no longer need to be reachable through sudo, so since 1.18.26 they are
here, in a file that ``install.sh`` installs as root:root 0700 and that sudoers never names (it is not linked into /usr/local/sbin either).

* ``python3 -I /usr/local/lib/tec-tac/sandbox/sandbox-selftest.py --selftest`` (root: install.sh, an administrator): proves systemd, cgroup v2,
  DynamicUser, the allow-list file system, credential hand-in, separate stdout and stderr pipes, ProtectProc, the private network wall and the
  egress proxy work here, and writes ``status.json`` (the same keys as before the split);
* ``... --selftest --canary`` (root): the full attack test with an in-memory runner ``core.canary``; writes ``canary.json``;
* ``... --canary-launch`` (root, started by the canary itself for its cancel rows): the helper's own start path for ``core.canary`` only.

The file loads the installed helper by path (its sibling ``sandbox-helper.py``) and uses the helper's own constants, launch code and unit builder
through the name ``H``: the canary runs exactly the code a real run uses. The helper no longer defines ``canary_row`` or ``core.canary``: the row
reaches ``start_command`` only through its ``row=`` argument, which only this file passes. Nothing here is imported by Django.
"""
from __future__ import annotations

import base64
import glob
import importlib.util
import io
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
from pathlib import Path

HELPER_FILE = Path(__file__).resolve().with_name("sandbox-helper.py")  # the installed helper sits beside this file; so does the source copy


def _load_helper(path=None):
    """The helper module, loaded by path (never run as a program, so its own main does not start)."""
    spec = importlib.util.spec_from_file_location("tec_tac_sandbox_helper", str(path or HELPER_FILE))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = _load_helper()


# ----------------------------------------------------------------------------------------------------- the selftest rules
MIN_SYSTEMD_VERSION = 249  # Ubuntu 22.04, the oldest server Tec-Tac supports (plan section 10)


PRIVATE_PROBE_TARGETS = ("10.255.255.254", "172.31.255.254", "192.168.255.254", "100.127.255.254", "169.254.169.254")


DNS_PROBE_NAME = "example.com"  # 1.18.24: the stand-in host of the egress proxy selftest


STUB_RESOLVER = "127.0.0.53"  # 1.18.24: systemd-resolved's stub, the one local address the egress proxy may reach (its second wall allows it by address)


MEMORY_BLOCK_MIB = 16  # kept for older callers; 1.17.124 no longer allows a block of slack over MemoryMax


PROBE_PROPERTIES = {
    "transient": (),
    "dynamic_user": ("DynamicUser=yes",),
    "credential": ("DynamicUser=yes",),  # plus LoadCredential, which carries the run's own path
    "proc_hidden": ("DynamicUser=yes", "ProtectProc=invisible", "ProcSubset=pid"),
    "network_control": ("DynamicUser=yes",),
    "network_private": ("DynamicUser=yes", *H.NETWORK_PROPERTIES),
    "pipe_streams": ("DynamicUser=yes",),
}


# The python the probes run inside a unit. Each prints one plain word or line and nothing else.
_PROBE_CONNECT = (
    "import socket,sys\n"
    "s=socket.socket();s.settimeout(3)\n"
    "try:\n s.connect(('127.0.0.1',int(sys.argv[1])));print('connected')\n"
    "except Exception as e:\n print('blocked')\n"
)


_PROBE_NETWORK = (
    "import errno,os,socket,sys\n"
    "names=[l.split(':')[0].strip() for l in open('/proc/self/net/dev').read().splitlines()[2:] if ':' in l]\n"
    "print('ifaces',','.join(names))\n"
    "for h,p in(('1.1.1.1',443),('127.0.0.1',int(sys.argv[1]))):\n"
    " s=socket.socket();s.settimeout(3)\n"
    " try:\n  s.connect((h,p));r='connected'\n"
    " except Exception as e:\n  r=errno.errorcode.get(getattr(e,'errno',0) or 0,'timeout' if isinstance(e,TimeoutError) else 'error')\n"
    " s.close();print('connect',h,p,r)\n"
    "print('resolv','present' if os.path.exists('/etc/resolv.conf') else 'absent')\n"
)


# ----------------------------------------------------------------------------------------------------------- the selftest
def parse_systemd_version(text):
    """The major version from ``systemctl --version`` output ("systemd 252 (252.22-1~deb12u1)"), or None."""
    match = re.match(r"\s*systemd\s+(\d+)\b", text or "")
    return int(match.group(1)) if match else None


def _check(table, name, ok, detail):
    table[name] = {"ok": bool(ok), "detail": str(detail)[:300]}
    return bool(ok)


def selftest(runner=None, *, resolv_conf_path="/etc/resolv.conf", run_root=None):
    """Probe this server and return the status dict that ``status.json`` carries. Never raises for a failed probe: a failed probe is
    ``ready: false`` with a plain reason. There is no weaker mode."""
    runner = runner or H.UnitRunner()
    run_root = Path(run_root) if run_root else H.RUN_ROOT
    checks = {}
    reasons = []
    started_at = time.monotonic()  # 1.18.24: the selftest time is recorded in status.json (the install-speed request depends on it)

    def fail(name, reason):
        reasons.append(reason)
        return False

    # systemd version and features
    code, out, err = runner.run_cmd(["systemctl", "--version"])
    version = parse_systemd_version(out) if code == 0 else None
    if version is None:
        _check(checks, "systemd_version", False, "systemctl --version gave no version")
        fail("systemd_version", "systemd is not available here")
    elif version < MIN_SYSTEMD_VERSION:
        _check(checks, "systemd_version", False, f"systemd {version}")
        fail("systemd_version", f"systemd {version} is older than {MIN_SYSTEMD_VERSION}")
    else:
        _check(checks, "systemd_version", True, f"systemd {version}")
    # 1.17.123: information. MemoryZSwapMax=0 is only handed to a unit from systemd 255, an older systemd would refuse the unknown property
    if version is not None:
        _check(checks, "memory_zswap", True, (f"MemoryZSwapMax=0 is set (systemd {version})" if version >= H.ZSWAP_MIN_SYSTEMD
                                              else f"MemoryZSwapMax=0 is not set: systemd {version} is older than {H.ZSWAP_MIN_SYSTEMD} (information only)"))
    # 1.17.120: information only. The address filter uses kernel cgroup BPF, which systemd's own BPF framework flag does not describe; the
    # control, loopback and private-range probes below decide readiness, so a server that cannot filter still ends ready=false.
    if "-BPF_FRAMEWORK" in (out or ""):
        _check(checks, "bpf_framework", True, "systemd is built without its BPF framework (information only; the address filter uses kernel cgroup BPF and is proved by the probes)")
    else:
        _check(checks, "bpf_framework", True, "BPF_FRAMEWORK is not disabled")
    # cgroup v2
    code, out, err = runner.run_cmd(["stat", "-fc", "%T", "/sys/fs/cgroup"])
    if not _check(checks, "cgroup_v2", code == 0 and out.strip() == "cgroup2fs", out.strip() or err.strip() or "no answer"):
        fail("cgroup_v2", "the server does not use the unified cgroup v2 hierarchy")
    # a harmless transient unit
    code, out, err = runner.run_unit("transient", PROBE_PROPERTIES["transient"], ["/bin/echo", "tectac-probe"])
    if not _check(checks, "transient_unit", code == 0 and out.strip() == "tectac-probe", err.strip()[:200] or out.strip()):
        fail("transient_unit", "systemd-run could not start a transient unit")
    # DynamicUser
    code, out, err = runner.run_unit("dynamic_user", PROBE_PROPERTIES["dynamic_user"], ["/usr/bin/id", "-u"])
    uid = out.strip()
    dyn_ok = code == 0 and uid.isdigit() and int(uid) >= 61184
    if not _check(checks, "dynamic_user", dyn_ok, f"uid {uid}" if uid else err.strip()[:200]):
        fail("dynamic_user", "a unit could not run as a dynamic user")
    # 1.18.8: the allow-list root. The skeleton must match this server, then the REAL view (the same properties the builder uses) is probed.
    view = None
    try:
        H.check_skeleton()
        skeleton_ok = True
    except H.Refusal as exc:
        skeleton_ok = False
        _check(checks, "sandbox_root", False, exc.message)
        _check(checks, "filesystem_view", False, "not run: the sandbox root folder is wrong")
        fail("sandbox_root", exc.message)
    if skeleton_ok:
        _check(checks, "sandbox_root", True, "the sandbox root folder matches this server")
        try:
            view = H.file_view_properties()
        except H.Refusal as exc:
            view = None
            _check(checks, "filesystem_view", False, exc.message)
            fail("filesystem_view", exc.message)
        if view is not None:
            script = ("if test -r /etc/passwd && ! test -e /etc/shadow && ! test -e /etc/tec-tac && ! test -e /rmm && ! test -e /opt/tec-tac/etc "
                      "&& ! test -e /usr/local/lib/tec-tac/sandbox/registry; then bad=; for n in $(ls -A /); do case \"$n\" in "
                      + "|".join(CANARY_VIEW_ALLOWED["/"]) + ") ;; *) bad=\"$bad $n\";; esac; done; "
                      "if [ -z \"$bad\" ]; then echo ok; else echo \"bad:$bad\"; fi; else echo bad; fi")
            code, out, err = runner.run_unit("filesystem_view", ["DynamicUser=yes", *view], ["/bin/sh", "-c", script])
            if not _check(checks, "filesystem_view", code == 0 and out.strip() == "ok", out.strip() or err.strip()[:200]):
                fail("filesystem_view", "a unit could not be given the allow-list file system with read-only binds")
    # credential hand-in
    ok, detail = _probe_credential(runner, run_root)
    if not _check(checks, "credential", ok, detail):
        fail("credential", "LoadCredential did not work: " + detail)
    # 1.18.13: one probe with the real unit shape, so an entry only the real shape makes (run/systemd/incoming) shows up before sandbox_root_after
    if skeleton_ok:
        ok, detail = _probe_real_shape(runner, run_root)
        if not _check(checks, "real_unit_shape", ok, detail):
            fail("real_unit_shape", "a unit with the real run shape did not work: " + detail)
    else:
        _check(checks, "real_unit_shape", False, "not run: the sandbox root folder is wrong")
    # ProtectProc and ProcSubset
    script = ("n=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l); "
              "if [ \"$n\" -le 6 ] && [ ! -e /proc/cpuinfo ]; then echo ok; else echo bad $n; fi")
    code, out, err = runner.run_unit("proc_hidden", PROBE_PROPERTIES["proc_hidden"], ["/bin/sh", "-c", script])
    if not _check(checks, "proc_hidden", code == 0 and out.strip() == "ok", out.strip() or err.strip()[:200]):
        fail("proc_hidden", "ProtectProc=invisible or ProcSubset=pid is not working")
    # 1.17.123: this server's own addresses and gateways, read the way a start reads them (1.18.24: they go to the egress proxy, never to a unit)
    local = None
    try:
        local = H.read_local_deny(runner.run_cmd)
        _check(checks, "local_addresses", True, f"own addresses: {', '.join(local['addresses'])}; gateways: {', '.join(local['gateways']) or 'none'}; "
                                                f"handed to the egress proxy at each start")
    except ValueError as exc:
        _check(checks, "local_addresses", False, str(exc))
        fail("local_addresses", f"{exc}, so the egress proxy cannot be given this server's own addresses")
    # 1.18.24 (AD-65 Patch B): the network wall. A run has its own empty network space; a control run without it must reach this server first.
    network_ok, detail = _probe_network(runner, checks, view)
    if not network_ok:
        fail("network_private", detail)
    # stdout and stderr arrive on separate pipes through systemd-run --pipe (plan section 10, item 1)
    command = ["/usr/bin/python3", "-I", "-c", "import sys;sys.stdout.write('out');sys.stdout.flush();sys.stderr.write('err')"]
    code, out, err = runner.run_unit("pipe_streams", PROBE_PROPERTIES["pipe_streams"], command)
    if not _check(checks, "pipe_streams", code == 0 and out.strip() == "out" and err.strip() == "err", f"out={out.strip()[:40]!r} err={err.strip()[:40]!r}"):
        fail("pipe_streams", "systemd-run --pipe did not keep stdout and stderr apart")
    # 1.18.24: the one door. The proxy units start for a throw-away run id with one stand-in host; a listed host answers 200, a refusal 403.
    egress_ok, detail = _probe_egress(runner, checks, local, resolv_conf_path)
    if not egress_ok:
        fail("egress_proxy", detail)
    # 1.18.12: the probe units run with ProtectHome=yes, which makes systemd add the /root mount point inside the sandbox root. The skeleton lists it;
    # anything else a probe left there is a refusal, so a pass is never logged on a skeleton a probe changed.
    try:
        H.check_skeleton()
        _check(checks, "sandbox_root_after", True, "the sandbox root folder is unchanged after the probe units")
    except H.Refusal as exc:
        _check(checks, "sandbox_root_after", False, exc.message)
        fail("sandbox_root_after", f"{exc.message} (a probe unit changed the sandbox root folder)")
    ready = not reasons
    return {
        "ready": ready, "reason": "ready" if ready else reasons[0], "enabled": bool(H.SANDBOX_ENABLED), "systemd_version": version,
        # 1.18.24: the old keys keep their names for every reader and change meaning: address_filter_ok = the network wall is proven,
        # dns_ok = the egress proxy resolves names and opens a tunnel; resolver, resolvers and dns_method stay as empty values.
        "address_filter_ok": network_ok, "dns_ok": egress_ok, "network_private_ok": network_ok, "egress_ok": egress_ok,
        "resolver": "", "resolvers": [], "dns_method": "", "selftest_at": H.now(), "selftest_ms": int((time.monotonic() - started_at) * 1000), "checks": checks,
        "slots_total": H.slot_count(H.mem_available_kib(), H.LIMITS["memory_mb"][0]),
    }


DYNAMIC_GID_MIN = 61184  # systemd's dynamic user range starts here (the same floor the dynamic_user probe uses for uids)


# 1.17.122: the in-unit program that reads the credential file's POSIX ACL (system.posix_acl_access) with the standard library only, so the
# probe does not need getfacl. It prints one line: 'ACL none', 'ACL error' or 'ACL ' and the entries as tag:id:perm (the id is empty for the
# owner, group, mask and other entries). No single quote, '%' or '$' in the text: it travels inside 'sh -c' and a systemd command line.
_PROBE_ACL = (
    "import os,struct,sys\n"
    "try:\n"
    " d=os.getxattr(sys.argv[1],\"system.posix_acl_access\")\n"
    "except OSError as e:\n"
    " print(\"ACL none\" if e.errno in (61,95) else \"ACL error\");sys.exit(0)\n"
    "if len(d)<12 or len(d)&7!=4 or struct.unpack(\"<I\",d[:4])[0]!=2:\n"
    " print(\"ACL error\");sys.exit(0)\n"
    "names={1:\"user\",2:\"user\",4:\"group\",8:\"group\",16:\"mask\",32:\"other\"}\n"
    "out=[]\n"
    "for i in range(4,len(d),8):\n"
    " t,p,q=struct.unpack(\"<HHI\",d[i:i+8])\n"
    " if t not in names or p>7:\n"
    "  print(\"ACL error\");sys.exit(0)\n"
    " out.append(names[t]+\":\"+(str(q) if t in (2,8) else \"\")+\":\"+(\"r\" if p&4 else \"-\")+(\"w\" if p&2 else \"-\")+(\"x\" if p&1 else \"-\"))\n"
    "print(\"ACL \"+\",\".join(out))\n"
)


_ACL_ENTRY = re.compile(r"(user|group|mask|other):(\d*):([r-][w-][x-])")


def parse_acl(acl_line):
    """The in-unit ACL answer as a list of (tag, id, perms), [] for 'no ACL', or None when the answer is missing, garbled or truncated."""
    text = str(acl_line or "").strip()
    if text == "ACL none":
        return []
    if not text.startswith("ACL ") or text == "ACL error":
        return None
    entries = []
    for part in text[4:].split(","):
        match = _ACL_ENTRY.fullmatch(part)
        if not match:
            return None
        tag, qual, perms = match.groups()
        if tag in ("mask", "other") and qual:
            return None
        entries.append((tag, qual, perms))
    return entries


def credential_found_text(stat_line, acl_line):
    """Plain information: owner, group, mode and every ACL entry, as found. Never the token or the path."""
    parts = str(stat_line).split()
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        found = "owner, group and mode unreadable"
    else:
        found = f"owner {'root' if int(parts[1]) == 0 else parts[1]}, group {'root' if int(parts[2]) == 0 else parts[2]}, mode {parts[0]}"
    entries = parse_acl(acl_line)
    if entries is None:
        return found + ", ACL answer missing or garbled"
    return found + ", ACL " + (", ".join(f"{tag}:{qual}:{perms}" for tag, qual, perms in entries) if entries else "none")


def _credential_acl_problem(entries, uid):
    """The ACL rule (1.17.122): the only named entry is user:<the unit's uid> with read only; no named group; the mask and every entry except
    the owner entry carry no write; no entry carries execute; 'other' grants nothing. A missing owner, group or other entry fails closed."""
    kinds = [(tag, qual) for tag, qual, _perms in entries]
    for need in (("user", ""), ("group", ""), ("other", "")):
        if kinds.count(need) != 1:
            return "the credential file's ACL is incomplete"
    if kinds.count(("mask", "")) > 1:
        return "the credential file's ACL is garbled"
    named = [(tag, qual, perms) for tag, qual, perms in entries if tag in ("user", "group") and qual]
    if any(tag == "group" for tag, _qual, _perms in named):
        return "the credential file has an ACL entry for a named group"
    if len(named) > 1 or any(qual != str(uid) or perms != "r--" for _tag, qual, perms in named):
        return "the credential file has an ACL entry for a user that is not the unit's own, or one that is not read only"
    if named and ("mask", "") not in kinds:
        return "the credential file's ACL has no mask"
    for tag, qual, perms in entries:
        if perms[2] == "x":
            return "the credential file's ACL grants execute"
        if perms[1] == "w" and not (tag == "user" and not qual):
            return "the credential file's ACL grants write"
        if tag == "other" and perms != "---":
            return "the credential file's ACL gives other users access"
    return ""


def credential_mode_problem(stat_line, uid_line, gid_line, acl_line):
    """The credential file inside the unit is mode exactly 0400 or 0440 (no 'other' bit); the owner is root or the unit's uid; the group is
    root or the unit's own gid; the unit's own uid and gid are in the dynamic range (>= 61184); and the POSIX ACL is absent or holds one named
    entry only, user:<unit uid>, read only (see _credential_acl_problem). 1.17.123: group root is accepted only when that named entry exists.
    Anything else, and any missing or garbled answer, fails closed. Returns a plain problem text naming what was found, or '' when acceptable."""
    parts = stat_line.split()
    if len(parts) != 3 or not all(part.isdigit() for part in parts) or not uid_line.strip().isdigit() or not gid_line.strip().isdigit():
        return "the credential file's mode and owner could not be read"
    mode, owner, group = parts[0], int(parts[1]), int(parts[2])
    uid, gid = int(uid_line.strip()), int(gid_line.strip())
    found = " (found: " + credential_found_text(stat_line, acl_line) + ")"
    if not re.fullmatch(r"[0-7]{3,4}", mode) or int(mode, 8) & 0o007:
        return f"the credential file mode is {mode}: other users could read it" + found
    if mode not in ("400", "440"):
        return f"the credential file mode is {mode}, not 400 or 440" + found
    if uid < DYNAMIC_GID_MIN or gid < DYNAMIC_GID_MIN:
        return f"the unit's own user or group id (uid {uid}, gid {gid}) is not in the dynamic range" + found
    if owner not in (0, uid) or group not in (0, gid):
        return f"the credential file mode is {mode} but its owner or group is not root or the unit's own" + found
    entries = parse_acl(acl_line)
    if entries is None:
        return "the credential file's ACL answer is missing or garbled" + found
    if entries:
        problem = _credential_acl_problem(entries, uid)
        if problem:
            return problem + found
    # 1.17.123: group root is only acceptable when the ACL is what lets the unit read the file: a named read-only entry for its uid.
    # Mode 400 or 440 root:root with no such entry could not be read by the unit at all, so it is refused with that reason.
    if group == 0 and ("user", str(uid), "r--") not in entries:
        return f"the credential file's group is root and its ACL has no read-only entry for the unit's own user (uid {uid}), so the unit could not read it" + found
    return ""


def _run_probe_unit(runner, name, properties, command, folder, slots):
    """1.18.14: run one probe unit under a name the helper knows, and remove the probe's credential folder the way a real run does: the
    helper itself, once the unit holds its own copy (no ``+`` property command, which cannot see the host). The probe fails if the
    token does not still arrive after the source is gone."""
    unit = f"tectac-selftest-{secrets.token_hex(6)}"
    stop = threading.Event()
    remover = threading.Thread(target=H.remove_credentials_when_active, args=(unit, folder, slots), kwargs={"stop": stop}, daemon=True)
    remover.start()
    try:
        return runner.run_unit(name, properties, command, unit=unit)
    finally:
        stop.set()
        remover.join(5)


def _probe_credential(runner, run_root):
    """A random token in a root-only folder arrives through LoadCredential, is readable only by the unit's user, and the source can be
    removed after start. Returns (ok, plain detail)."""
    folder = Path(run_root) / (H.SELFTEST_PREFIX + secrets.token_hex(6))
    try:
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, 0o700)
        source = folder / "probe"
        token = secrets.token_hex(16)
        source.write_text(token, encoding="utf-8")
        os.chmod(source, 0o600)
        properties = list(PROBE_PROPERTIES["credential"]) + [f"LoadCredential=probe:{source}"]
        # 1.17.122: line 1 the content, line 2 "mode uid gid" of the file, line 3 the unit's uid, line 4 the unit's gid, line 5 the ACL
        script = ('sleep 1; cat "$CREDENTIALS_DIRECTORY/probe"; echo; stat -c "%a %u %g" "$CREDENTIALS_DIRECTORY/probe"; id -u; id -g; '
                  f"/usr/bin/python3 -I -c '{_PROBE_ACL}' \"$CREDENTIALS_DIRECTORY/probe\"")
        code, out, err = _run_probe_unit(runner, "credential", properties, ["/bin/sh", "-c", script], folder, ["probe"])
        lines = out.strip().splitlines()
        if code != 0 or len(lines) < 4:
            return False, (err.strip()[:200] or "the unit did not start, or the credential answer was incomplete")
        if lines[0] != token:
            return False, "the credential did not arrive"
        acl_line = lines[4] if len(lines) > 4 else ""
        problem = credential_mode_problem(lines[1], lines[2], lines[3], acl_line)
        if problem:
            return False, problem
        if source.exists():
            return False, "the source file was not removed by the helper once the unit was active"
        return True, "arrived, " + credential_found_text(lines[1], acl_line) + ", source removed"
    except OSError as exc:
        return False, f"cannot prepare the probe folder ({exc.strerror or 'error'})"
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _probe_real_shape(runner, run_root):
    """1.18.13: one unit with the shape of a real run: the allow-list root and read-only binds (file_view_properties, the same function the
    builder uses), DynamicUser, and a LoadCredential whose source folder the helper removes once the unit is active (1.18.14). Only this shape makes systemd create
    run/systemd/incoming inside the root (dev02, 19 November 2026); a probe without the credential never showed it. The probe is honest only as
    far as real systemd shows it: the dev02 re-run decides. The caller's sandbox_root_after check reports any entry this unit made that is not
    on the list. Returns (ok, plain detail); neither the token nor any output or path goes into the detail."""
    folder = Path(run_root) / (H.SELFTEST_PREFIX + secrets.token_hex(6))
    try:
        view = H.file_view_properties()
    except H.Refusal as exc:
        return False, exc.message
    try:
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, 0o700)
        source = folder / "probe"
        token = secrets.token_hex(16)
        source.write_text(token, encoding="utf-8")
        os.chmod(source, 0o600)
        properties = [*view, *PROBE_PROPERTIES["credential"], f"LoadCredential=probe:{source}"]
        script = 'sleep 1; cat "$CREDENTIALS_DIRECTORY/probe"'
        code, out, _err = _run_probe_unit(runner, "real_unit_shape", properties, ["/bin/sh", "-c", script], folder, ["probe"])
        if code != 0:
            return False, "the unit did not start or did not finish"
        if out.strip() != token:
            return False, "the credential did not arrive in the real unit shape"
        if source.exists():
            return False, "the source file was not removed by the helper once the unit was active"
        return True, "the credential arrived, source removed"
    except OSError as exc:
        return False, f"cannot prepare the probe folder ({exc.strerror or 'error'})"
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _probe_network(runner, checks, view):
    """1.18.24: a unit with the real network properties sees only ``lo``, cannot connect to a public address or to a loopback port of this server,
    and has no resolv.conf; the same probe without the wall must reach the loopback listener (the control: a probe that cannot connect anyway is
    never read as a pass). ``view`` is the real file view (file_view_properties) or None when the skeleton is wrong. Returns (ok, plain reason)."""
    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(0.5)
        port = listener.getsockname()[1]
    except OSError as exc:
        listener.close()
        _check(checks, "network_private", False, f"cannot open a loopback listener ({exc.strerror or 'error'})")
        return False, "the selftest could not open a loopback listener"

    def accepted():
        seen = 0
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return seen
            conn.close()
            seen += 1

    def read(out):
        found = {"ifaces": "", "connect": {}, "resolv": ""}
        for line in out.strip().splitlines():
            parts = line.split()
            if parts[:1] == ["ifaces"]:
                found["ifaces"] = parts[1] if len(parts) > 1 else ""
            elif len(parts) == 4 and parts[0] == "connect":
                found["connect"][f"{parts[1]}:{parts[2]}"] = parts[3]
            elif len(parts) == 2 and parts[0] == "resolv":
                found["resolv"] = parts[1]
        return found

    try:
        command = ["/usr/bin/python3", "-I", "-c", _PROBE_NETWORK, str(port)]
        code, out, err = runner.run_unit("network_control", PROBE_PROPERTIES["network_control"], command)
        control = read(out)
        control_ok = code == 0 and control["connect"].get(f"127.0.0.1:{port}") == "connected" and accepted() >= 1
        if view is None:
            _check(checks, "network_private", False, "not run: the sandbox root folder is wrong")
            return False, "the network wall could not be checked (the sandbox root folder is wrong)"
        properties = [*PROBE_PROPERTIES["network_private"], *view]
        code, out, err = runner.run_unit("network_private", properties, command)
        found = read(out)
    finally:
        listener.close()
    names = [name for name in found["ifaces"].split(",") if name]
    only_lo = names == ["lo"]
    public = found["connect"].get("1.1.1.1:443", "")
    local_try = found["connect"].get(f"127.0.0.1:{port}", "")
    ok_connect = public not in ("connected", "") and local_try not in ("connected", "")
    resolv_gone = found["resolv"] == "absent"
    ok = code == 0 and only_lo and ok_connect and resolv_gone
    detail = (f"interfaces {','.join(names) or 'none'}; 1.1.1.1:443 {public or 'no answer'}; this server's loopback port {local_try or 'no answer'}; "
              f"resolv.conf {found['resolv'] or 'no answer'}") if code == 0 else (err.strip()[:200] or out.strip()[:200] or "the unit did not finish")
    _check(checks, "network_private", ok and control_ok, detail)
    if not control_ok:
        return False, "the network probe could not be checked (a loopback connection without the wall did not work)"
    if not ok:
        return False, "a unit with PrivateNetwork=yes still saw a network, reached an address or had a resolv.conf: " + detail
    return True, "private network space, nothing reachable"


def resolver_problem(text):
    """'' when the host's own resolver list works for the egress proxy, else a plain reason. The proxy's own wall allows exactly one local
    address, the systemd-resolved stub 127.0.0.53, so another resolver inside a private or loopback range makes the proxy fail closed (never an
    automatic allow). No listed server at all is a problem too."""
    listed = H.parse_resolvers(text, limit=8)
    if not listed:
        return "no name server is listed in /etc/resolv.conf, so the egress proxy could not look up names"
    for address in listed:
        if address != STUB_RESOLVER and H.denied_by_ranges(address):
            return (f"the name server {address} is inside a loopback or private range; the egress proxy may only reach the systemd-resolved stub "
                    f"{STUB_RESOLVER} or a public resolver, so point the server at one of them")
    return ""


def egress_exchange(sock_path, request, *, timeout=15, connector=None):
    """Send one request to a door socket as the root helper does for the selftest and read the first line of the answer. Returns the HTTP status
    as an int, 0 for an unreadable answer, or None when the door cannot be reached. ``connector`` is replaced by a test."""
    try:
        sock = connector(sock_path) if connector else socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if not connector:
            sock.settimeout(timeout)
            sock.connect(sock_path)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        sock.sendall(request)
        head = sock.recv(512).split(b"\r\n", 1)[0].split()
        return int(head[1]) if len(head) >= 2 and head[0].startswith(b"HTTP/") and head[1].isdigit() else 0
    except OSError:
        return 0
    finally:
        sock.close()


def connect_request(host, port):
    return f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("ascii", "replace")


def _probe_egress(runner, checks, local, resolv_conf_path, *, exchange=None):
    """1.18.24: start the template units for a throw-away run id with one stand-in host (example.com); a CONNECT to it must answer 200, a CONNECT to
    a host that is not listed and one to an IP literal must answer 403, and the units are always stopped and cleaned. A host whose resolver the
    proxy's own wall cannot reach fails closed with a plain reason. Returns (ok, plain reason)."""
    exchange = exchange or egress_exchange
    try:
        text = Path(resolv_conf_path).read_text(encoding="utf-8", errors="replace")[:8192]
    except OSError:
        text = ""
    problem = resolver_problem(text)
    if problem:
        _check(checks, "egress_proxy", False, problem)
        return False, problem
    if local is None:
        _check(checks, "egress_proxy", False, "not run: this server's own addresses could not be read")
        return False, "the egress proxy could not be checked (this server's own addresses could not be read)"
    run_id = secrets.token_hex(16)
    row = {"allowed_hosts": [DNS_PROBE_NAME]}
    try:
        H.egress_start(row, run_id, local, run_cmd=runner.run_cmd)
        door = str(H.egress_door_socket(run_id))
        listed = exchange(door, connect_request(DNS_PROBE_NAME, 443))
        unlisted = exchange(door, connect_request("example.net", 443))
        literal = exchange(door, connect_request("1.1.1.1", 443))
        wrong_port = exchange(door, connect_request(DNS_PROBE_NAME, 80))
    except H.Refusal as exc:
        _check(checks, "egress_proxy", False, exc.message)
        return False, "the egress proxy did not start: " + exc.message
    finally:
        H.egress_stop(run_id, run_cmd=runner.run_cmd)
        H.egress_clean(run_id)
    refusals_ok = unlisted == 403 and literal == 403 and wrong_port == 403
    detail = f"listed host {listed}; unlisted host {unlisted}; IP literal {literal}; port 80 {wrong_port}"
    if listed == 200 and refusals_ok:
        _check(checks, "egress_proxy", True, detail)
        return True, ""
    if refusals_ok:
        why = f"the egress proxy refuses what it should, but it could not open a tunnel to {DNS_PROBE_NAME} (answer {listed}): this server needs DNS and a public route"
    else:
        why = "the egress proxy did not refuse a request it must refuse (policy wall)"
    _check(checks, "egress_proxy", False, detail)
    return False, why


def run_selftest():
    H.ensure_layout()
    status = selftest()
    H.write_status(status)
    H.append_audit("selftest", detail={"ready": status["ready"], "reason": status["reason"], "systemd_version": status["systemd_version"]})
    print(json.dumps(status, sort_keys=True))
    return 0 if status["ready"] else 1


CANARY_RUNNER_FILE = H.CANARY_DIR / "sandbox-canary-runner.py"


EGRESS_START_SECONDS = 20


HELPER_COMMAND = "/usr/local/sbin/tec-tac-sandbox"


def parse_memory_events(text):
    """``oom_kill`` and ``oom`` from memory.events text. Anything that is not ``<word> <digits>`` is ignored. Returns (oom_kill, oom), each None when absent."""
    found = H.parse_memory_counters(text)
    return found.get("oom_kill"), found.get("oom")


def read_cgroup_memory(run_id):
    """(oom_kill count, memory.peak in bytes) from the unit's own cgroup while it still exists. 1.18.8: the
    fixed path first (same as CgroupWatch); if no file is there, 1.17.124's lookup through ``systemctl show -P ControlGroup`` still runs, so a
    server whose slice nests differently does not lose the evidence. Either value is None when it cannot be read (a missing file is never an error)."""
    watch = H.CgroupWatch(run_id)
    watch.sample(force=True)
    if watch.oom_kill is not None or watch.peak is not None:
        return watch.oom_kill, watch.peak
    code, out, _err = H.systemctl("show", H.unit_name(run_id) + ".service", "-P", "ControlGroup")
    path = out.strip() if code == 0 else ""
    if not path.startswith("/") or ".." in path.split("/") or "\x00" in path:
        return None, None
    folder = H.CGROUP_ROOT / path.lstrip("/")
    oom_kills, peak = None, None
    try:
        oom_kills = parse_memory_events((folder / "memory.events").read_text(encoding="ascii", errors="replace"))[0]
    except (OSError, ValueError):
        pass
    try:
        text = (folder / "memory.peak").read_text(encoding="ascii", errors="replace").strip()
        peak = int(text) if text.isdigit() else None
    except (OSError, ValueError):
        pass
    return oom_kills, peak


# ======================================================================================================== the canary (attack test)
# ``--selftest --canary`` (root only, never in the sudo rule) runs every wall of plan 8.2 and section 15 against this server with an
# in-memory runner ``core.canary`` that is never written to the registry. It uses the same ``launch`` as ``--start`` and bypasses only
# the kill-switch constant, because nothing else can start a run while the switch is off. The result table goes to stdout and a
# secret-free summary to /var/lib/tec-tac/sandbox/canary.json, which status() reports as canary_ok and canary_at.
CANARY_RUNNER_ID = "core.canary"


CANARY_GROUPS = ("files", "rootview", "work_hold", "work_peer", "sockets", "loopback", "lan", "privilege", "writes", "processes",
                 "mem", "fork", "loop", "scratch", "flood", "abstract", "cred", "sleep", "noop", "runview")


CANARY_LATENCY_RUNS = 50


CANARY_LATENCY_TARGET_MS = 400


CANARY_MARKER_DIRS = ("/etc", "/var", "/opt", "/srv", "/mnt", "/media", "/home", "/root", "/etc/tactical", "/etc/tec-tac", "/opt/tec-tac",
                      "/rmm", "/usr/local/lib/tec-tac", "/var/lib/tec-tac", "/run/tec-tac", "/rmmbackups", "/backup", "/backups", "/snap")


CANARY_VIEW_FOLDERS = ("/", "/etc", "/var", "/opt", "/opt/tec-tac", "/opt/tec-tac/runtimes", "/run", "/usr/local", "/usr/local/lib",
                       "/usr/local/lib/tec-tac", "/usr/local/lib/tec-tac/sandbox")


CANARY_VIEW_ALLOWED = {  # 1.18.8: the names a run may see in each folder; the canary run has no module runtime, so runtimes allows nothing
    "/": ("usr", "bin", "sbin", "lib", "lib64", "lib32", "libx32", "etc", "var", "opt", "run", "tmp", "proc", "sys", "dev", "work", "root"),
    "/etc": ("ssl", "ca-certificates", "passwd", "group", "ld.so.cache", "nsswitch.conf", "localtime"),
    "/var": ("tmp",), "/opt": ("tec-tac",), "/opt/tec-tac": ("runtimes",), "/opt/tec-tac/runtimes": (), "/run": ("credentials", "systemd", "egress"),
    "/usr/local": ("lib",), "/usr/local/lib": ("tec-tac",), "/usr/local/lib/tec-tac": ("sandbox",),
    "/usr/local/lib/tec-tac/sandbox": ("runners", "canary", "sandbox-launcher.py"),
}


CANARY_VIEW_NAMES_MAX = 200


CANARY_VIEW_NAME_LENGTH = 100


CANARY_VIEW_BUDGET = 49152  # characters of the json plan: keeps it under the runner's 64 KiB stdin read


CANARY_REAL_FILES = ("/rmm/api/tacticalrmm/tacticalrmm/local_settings.py", "/etc/tec-tac/config-path", "/opt/tec-tac/etc/tec-tac.conf",
                     "/etc/shadow")


CANARY_LAN_TARGETS = ("10.255.255.254", "172.31.255.254", "192.168.255.254", "100.127.255.254", "169.254.169.254")


CANARY_PUBLIC_TARGET = "1.1.1.1"


VERDICTS = ("OK", "ATTACK SUCCEEDED", "SKIPPED", "NOT RUN", "WARN")


CANARY_STUB = "127.0.0.53"  # 1.17.123: systemd-resolved's stub; no longer allowed for anyone, so every port on it must refuse


CANARY_STUB_PORTS = (22, 80, 443, 1024, 4430, 4433)  # the six rows that connected in the 1.17.122 dev02 run


ACTUAL_COLUMN_MAX = 140


CANARY_ABSTRACT_MAX = 200


CANARY_ABSTRACT_SECONDS = 60


CANARY_ABSTRACT_BUDGET = 49152  # characters of json.dumps(list of names): keeps the whole plan under the runner's 64 KiB stdin read


CANARY_LOOPBACK_SECONDS = 60  # the loopback group's run time (under the Core ceiling); probes stop at loopback_seconds inside it


CANARY_LOOPBACK_DEADLINE = 40


CANARY_SKIP_ALLOWED = ()  # 1.18.24: the 'public tcp 443' row is retired (the network group covers it); no row of the normal table may be SKIPPED


CANARY_REQUIRED = {  # group -> (exact attack names, [(prefix, minimum count)])
    "rootview": (["view " + folder for folder in CANARY_VIEW_FOLDERS] + ["/ lists only the allowed set"], []),
    "sockets": (["unix door path without a door", "socketpair round trip", "pipe round trip", "child process with stdio pipes"], [("unix /", 13)]),
    "privilege": (["setuid(0)", "ptrace attach to parent", "mount", "unshare", "mknod", "raw socket", "write /proc/sys", "load a kernel module"], []),
    "writes": ([], [("write /", 9)]),
    "processes": (["host processes invisible", "pid 1 invisible"], []),
    "mem": (["memory beyond MemoryMax"], []), "fork": (["fork bomb"], []), "scratch": (["scratch past its size"], []),
    "cred": (["credential arrives", "credential mode", "credential not in environment"], []),
    "abstract": ([], [("abstract sockets (", 1)]),
    "work_peer": (["another run's /work"], []), "lan": ([], [("udp ", 5), ("tcp ", 5), ("own address ", 4)]),
    "loopback": ([], [("loopback ", 1), ("loopback " + CANARY_STUB + ":", len(CANARY_STUB_PORTS))]),
}


def canary_row(**limit_overrides):
    """The in-memory canary runner record. Limits are small and always under the Core ceilings. Never written to the registry."""
    limits = {"memory_mb": 256, "cpu_percent": 100, "tasks": 64, "run_seconds": 20, "stdout_kib": 64, "stderr_kib": 16, "scratch_mb": 16,
              "input_kib": 16, "queue_seconds": 3}
    limits.update(limit_overrides)
    for name, value in limits.items():
        if value > H.LIMITS[name][1]:
            raise RuntimeError(f"canary limit {name} is over the Core ceiling")
    try:
        digest = H._sha256_nofollow(CANARY_RUNNER_FILE)
    except (OSError, RuntimeError):
        digest = ""
    return {
        "id": CANARY_RUNNER_ID, "owner_module": H.CANARY_OWNER, "version": "core", "revision": "1", "description": "Core's own attack test",
        "executable": str(CANARY_RUNNER_FILE), "executable_sha256": digest, "argv": [{"param": "group"}],
        "parameters": {"group": {"type": "enum", "choices": list(CANARY_GROUPS)}}, "environment": {}, "runtime_roots": [],
        "credential_files": ["auth"], "credential_return": True, "limits": limits, "runtime_verified": True, "registered_by": H.REGISTERED_BY,
    }


def parse_runner_rows(data):
    """CANARYROW lines from the (untrusted) in-unit program. Anything else is ignored."""
    rows = []
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0] == "CANARYROW" and parts[1]:
            rows.append({"attack": parts[1][:200], "tag": parts[2], "actual": parts[3][:300]})
    return rows


def classify_tag(tag):
    """OK stays OK, SUCCEEDED is a finding, SKIP is SKIPPED (never OK). Any other word from the unit is NOT RUN, which also fails."""
    return {"OK": "OK", "SUCCEEDED": "ATTACK SUCCEEDED", "SKIP": "SKIPPED"}.get(tag, "NOT RUN")


def group_table(wall, group, expected, runner_rows, plan_names=()):
    """Table rows for one group of attacks. A row the program was expected to print and did not is NOT RUN."""
    table = [{"wall": wall, "attack": r["attack"], "expected": expected, "actual": r["actual"], "verdict": classify_tag(r["tag"])} for r in runner_rows]
    names = [r["attack"] for r in runner_rows]
    exact, prefixes = CANARY_REQUIRED.get(group, ([], []))
    for name in list(exact) + list(plan_names):
        if name not in names:
            table.append({"wall": wall, "attack": name, "expected": expected, "actual": "the probe printed no result", "verdict": "NOT RUN"})
    for prefix, minimum in prefixes:
        found = sum(1 for name in names if name.startswith(prefix))
        if found < minimum:
            table.append({"wall": wall, "attack": prefix.strip() + " probes", "expected": expected, "actual": f"{found} of {minimum} results", "verdict": "NOT RUN"})
    if not table:
        table.append({"wall": wall, "attack": group, "expected": expected, "actual": "the probe printed no result", "verdict": "NOT RUN"})
    return table


def _skipped_security(table):
    """SKIPPED rows that count as a failure: every one except 'public tcp 443' (a server with no public route)."""
    return [entry for entry in table if entry["verdict"] == "SKIPPED" and entry.get("attack") not in CANARY_SKIP_ALLOWED]


def canary_summary(table):
    """(passed, counts). PASSED only when no row is ATTACK SUCCEEDED, none is NOT RUN and no security row is SKIPPED (1.17.123: only
    'public tcp 443' may be skipped, because a server may have no public route). WARN never fails it and is never OK."""
    counts = {verdict: 0 for verdict in VERDICTS}
    for entry in table:
        counts[entry["verdict"] if entry["verdict"] in counts else "NOT RUN"] += 1
    return counts["ATTACK SUCCEEDED"] == 0 and counts["NOT RUN"] == 0 and not _skipped_security(table), counts


def canary_record(table, passed, counts):
    """canary.json: counts and failing rows only. No marker, no credential, no path of a secret. A SKIPPED security row is listed as failing."""
    failing = [{"wall": e["wall"], "attack": e["attack"], "verdict": e["verdict"]} for e in table
               if e["verdict"] in ("ATTACK SUCCEEDED", "NOT RUN") or e in _skipped_security(table)]
    return {"ok": bool(passed), "at": H.now(), "counts": counts, "failing": failing[:50], "skipped": [e["attack"] for e in table if e["verdict"] == "SKIPPED"][:20]}


def parse_abstract_sockets(data):
    """1.17.123: the names of the host's abstract unix listeners from /proc/net/unix text (bytes or str): entries in the listening state whose
    path starts with '@', without that '@', as latin-1 text so every byte survives a JSON round trip (the kernel prints a NUL inside a name as
    '@' too, which cannot be told apart). Pathname sockets are ignored, names are unique, at most CANARY_ABSTRACT_MAX."""
    raw = data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8", "surrogateescape")
    names = []
    for line in bytes(raw).splitlines()[1:]:
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[7].startswith(b"@"):
            continue
        try:
            listening = int(parts[3], 16) & 0x10000
        except ValueError:
            continue
        name = parts[7][1:].decode("latin-1")
        if listening and name not in names:
            names.append(name)
        if len(names) >= CANARY_ABSTRACT_MAX:
            break
    return names


def fit_abstract_names(names, budget=CANARY_ABSTRACT_BUDGET):
    """1.17.124: (kept, left_out_count). Names are added in order while the exact ``json.dumps`` length of the kept list stays within the
    budget (the plan is sent with ensure_ascii, so a latin-1 byte costs up to six characters and 200 long names can pass the runner's 64 KiB
    read, which would make the plan unreadable). A left-out name is still covered by the 'unix socket creation refused' rows."""
    kept = []
    for name in names:
        if len(json.dumps(kept + [name])) > budget:
            break
        kept.append(name)
    return kept, len(names) - len(kept)


def read_abstract_names(path="/proc/net/unix"):
    """The host's abstract listener names, or None when root cannot read them (the row is then NOT RUN, never SKIPPED)."""
    try:
        return parse_abstract_sockets(Path(path).read_bytes())
    except OSError:
        return None


def open_abstract_listener():
    """Root's own throw-away abstract listener, for the information row that shows whether the abstract namespace is shared at all.
    (listener or None, its name or '')."""
    try:
        name = "tectac-canary-" + secrets.token_hex(8)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind("\0" + name)
        listener.listen(4)
        return listener, name
    except (OSError, AttributeError):
        return None, ""


def parse_listening(text):
    """(ports, {address: ports}) from ``ss -ltnH`` output. A wildcard address belongs to every address."""
    ports, by_address = set(), {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        host, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        host = host.strip("[]")
        ports.add(int(port))
        by_address.setdefault(host, set()).add(int(port))
    return sorted(ports)[:200], by_address


def resolver_ports(by_address, resolver):
    wild = set()
    for host in ("*", "0.0.0.0", "::"):
        wild |= by_address.get(host, set())
    return sorted(by_address.get(resolver, set()) | wild)[:200]


def collect_run(group, plan, *, person="canary", slots_n=None, person_n=H.PERSON_SLOTS, credentials=None, status=None, run_id=None, **limit_overrides):
    """One canary run through the same ``launch`` as ``--start``. Returns {stdout, stderr, end, refused}. Never raises for a refusal."""
    out = {"stdout": b"", "stderr": b"", "end": None, "refused": None, "run_id": run_id or secrets.token_hex(16), "frames": []}
    row = canary_row(**limit_overrides)

    def emit(frame):
        out["frames"].append(frame["t"])
        if frame["t"] in ("out", "err"):
            out["stdout" if frame["t"] == "out" else "stderr"] += base64.b64decode(frame["b"])
        elif frame["t"] == "end":
            out["end"] = frame

    data = json.dumps(plan).encode("utf-8")
    try:
        H.launch(row, run_id=out["run_id"], person=person, parameters={"group": group}, credentials=credentials or {}, input_data=data,
               emit=emit, slots_n=slots_n, person_n=person_n, status=status)
    except H.Refusal as exc:
        out["refused"] = exc.code
    return out


def view_clean(name):
    """One file name as the runner will see it after the same cleaning (control characters and non-ASCII become '?', at most 100 characters)."""
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(name))[:CANARY_VIEW_NAME_LENGTH]


def view_plan(scandir=os.scandir, limit=CANARY_VIEW_NAMES_MAX):
    """1.18.8: the HOST's own entries (names only, read as root with os.scandir, at most ``limit`` per folder, cleaned) for every folder of
    CANARY_VIEW_FOLDERS. A folder that cannot be read gives an empty list. The in-unit runner prints a row per folder: any name the host
    has that the unit also sees and that is not in the allowed list is ATTACK SUCCEEDED."""
    plan = {}
    for folder in CANARY_VIEW_FOLDERS:
        try:
            with scandir(folder) as entries:
                names = sorted(view_clean(entry.name) for entry in entries)
        except OSError:
            names = []
        plan[folder] = names[:limit]
    return plan


def rootview_plan(scandir=os.scandir):
    """The plan of the ``rootview`` group: host listings plus the allowed names, cut down in steps if the json would not fit the runner's stdin read."""
    limit = CANARY_VIEW_NAMES_MAX
    while True:
        host = view_plan(scandir, limit)
        plan = {"view": {folder: {"host": host[folder], "allowed": list(CANARY_VIEW_ALLOWED[folder])} for folder in CANARY_VIEW_FOLDERS}}
        if len(json.dumps(plan)) <= CANARY_VIEW_BUDGET or limit <= 10:
            return plan
        limit = max(10, limit * 3 // 4)


def _create_marker(path, content):
    """A marker file made with O_CREAT|O_EXCL|O_NOFOLLOW and an explicit mode on the open descriptor (no path chmod, no symlink followed, an
    existing name is refused: the lesson of 1.18.7-1). Returns True when it was created."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError:
        return False
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o644)
        os.write(fd, content.encode("utf-8"))
    except OSError:
        return False
    finally:
        os.close(fd)
    return True


def _plant_markers():
    """Random-content 0644 markers in the places a run must never see. The list is written first, so a crash leaves it for the sweep.
    1.18.8: every marker is created exclusively without following a link; a fresh root-made folder ``/tectac-canary-<12 hex>`` (0755) holds one
    more, so a server whose own folders are all closed to a run still shows whether the root view hides a folder it should hide."""
    planned = []
    for folder in CANARY_MARKER_DIRS:
        if Path(folder).is_dir():
            planned.append((str(Path(folder) / (".tectac-canary-" + secrets.token_hex(6))), secrets.token_hex(16)))
    standin = os.path.join(H.CANARY_STANDIN_PARENT, "tectac-canary-" + secrets.token_hex(6))
    planned.append((os.path.join(standin, ".tectac-canary-" + secrets.token_hex(6)), secrets.token_hex(16)))
    H._write_private(H.CANARY_MARKERS_FILE, H._json_bytes({"paths": [path for path, _ in planned], "folders": [standin]}))
    made_folder = False
    try:
        os.mkdir(standin, 0o755)
        os.chmod(standin, 0o755)
        made_folder = True
    except OSError:
        pass
    entries = []
    for path, content in planned:
        if os.path.dirname(path) == standin and not made_folder:
            continue
        if _create_marker(path, content):
            entries.append({"path": path, "content": content})
    H._write_private(H.CANARY_MARKERS_FILE, H._json_bytes({"paths": [e["path"] for e in entries], "folders": [standin] if made_folder else []}))
    for real in CANARY_REAL_FILES:
        if os.path.exists(real):
            entries.append({"path": real, "content": None})  # None: being able to read it at all is the finding
    return entries


def _percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def _holders_search(token, unit):
    """Where the credential token shows up on the host while a run is live: other processes' command lines and environments, ps,
    systemctl show, journald. Returns the list of places (empty is the pass)."""
    found = []
    for pattern in ("/proc/[0-9]*/cmdline", "/proc/[0-9]*/environ"):
        try:
            for path in glob.glob(pattern):
                try:
                    with open(path, "rb") as handle:
                        if token.encode() in handle.read(262144):
                            found.append(path)
                except OSError:
                    continue
        except OSError:
            continue
    runner = H.UnitRunner()
    for label, argv in (("ps", ["ps", "-eo", "args"]), ("systemctl show", [*H.SYSTEMCTL, "show", unit + ".service"]),
                        ("journald", ["journalctl", "-u", unit + ".service", "-o", "cat", "--no-pager"])):
        _code, out, err = runner.run_cmd(argv)
        if token in (out or "") or token in (err or ""):
            found.append(label)
    return found


def run_canary(*, status=None, collect=None, outside=None):
    """Run every row and return the table. ``collect`` and ``outside`` can be replaced by a test."""
    collect = collect or collect_run
    outside = outside or H.UnitRunner()
    status = status or H.read_status()
    table = []
    if status.get("ready") is not True:
        return [{"wall": "Selftest", "attack": "selftest ready", "expected": "ready", "actual": status.get("reason", "not ready"), "verdict": "NOT RUN"}]
    _c, ss_text, _e = outside.run_cmd(["ss", "-ltnH"])
    ports, _by_address = parse_listening(ss_text)
    try:
        local = H.read_local_deny(outside.run_cmd)
    except ValueError as exc:
        local = {"addresses": [], "gateways": [], "extra": []}
        table.append({"wall": "LAN", "attack": "own addresses and gateway", "expected": "read", "actual": str(exc)[:200], "verdict": "NOT RUN"})
    own = [a for a in local["addresses"] if ":" not in a and not a.startswith("127.")][:4]
    gateways = [g for g in local["gateways"] if ":" not in g][:4]
    lan_names = [f"own address {a} tcp {port}" for a in own for port in (22, 80, 443)] + [f"own address {a} udp" for a in own]
    lan_names += [f"gateway {g} tcp {port}" for g in gateways for port in (80, 443)] + [f"gateway {g} udp" for g in gateways]
    abstract_names = read_abstract_names()
    abstract_plan = {"abstract_seconds": CANARY_ABSTRACT_SECONDS - 20}
    if abstract_names is not None:
        abstract_plan["abstract"], abstract_plan["abstract_left_out"] = fit_abstract_names(abstract_names)
    listener, listener_name = open_abstract_listener()
    if listener_name:
        abstract_plan["abstract_probe"] = listener_name

    def group(wall, name, expected, plan=None, plan_names=(), **kwargs):
        result = collect(name, plan or {}, status=status, **kwargs)
        if result["refused"]:
            table.append({"wall": wall, "attack": name, "expected": expected, "actual": "refused: " + str(result["refused"]), "verdict": "NOT RUN"})
            return result
        table.extend(group_table(wall, name, expected, parse_runner_rows(result["stdout"]), plan_names))
        return result

    markers = []
    try:
        markers = _plant_markers()
        group("Files", "files", "not found or other content", {"markers": markers}, plan_names=["read " + m["path"] for m in markers])
        group("Files", "rootview", "only the allowed names are visible", rootview_plan())
        peer_token = secrets.token_hex(8)
        holder = threading.Thread(target=collect, args=("work_hold", {"work_token": peer_token, "hold_seconds": 4}),
                                  kwargs={"person": "canary-hold", "status": status}, daemon=True)
        holder.start()
        time.sleep(1.5)
        group("Files", "work_peer", "not found", {"work_token": peer_token}, person="canary-peer")
        holder.join(10)
        group("Sockets", "sockets", "not present or refused")
        stub_ports = list(CANARY_STUB_PORTS) + [p for p in sorted(set(ports)) if p not in CANARY_STUB_PORTS]  # the six stub ports come first
        group("Loopback", "loopback", "connection refused",
              {"ports": ports, "stub": CANARY_STUB, "stub_ports": stub_ports[:200], "loopback_seconds": CANARY_LOOPBACK_DEADLINE},
              run_seconds=CANARY_LOOPBACK_SECONDS)
        group("LAN", "lan", "dropped (EPERM)", {"lan": list(CANARY_LAN_TARGETS), "own": own, "gateways": gateways}, plan_names=lan_names)
        group("Privilege", "privilege", "EPERM")
        marker = RUN_MARKER_PREFIX + secrets.token_hex(8)
        written = group("Writes", "writes", "read-only or private", {"run_marker": marker})
        table_private_run(table, written, marker, collect, status)
        group("Processes", "processes", "host processes invisible")
        group("Abstract sockets", "abstract", "none reachable (Medium finding R1 otherwise)", abstract_plan, run_seconds=CANARY_ABSTRACT_SECONDS)
        table.extend(_limit_rows(collect, status))
        table.extend(_credential_rows(collect, status))
        table.extend(_cancel_rows(collect, status))
        table.extend(_concurrency_rows(collect, status))
        table.extend(_latency_rows(collect, status))
    finally:
        H.remove_markers()
        if listener is not None:
            listener.close()
    return table


RUN_MARKER_PREFIX = ".tectac-run-marker-"


RUN_MARKER_RE = re.compile(r"^\.tectac-run-marker-[0-9a-f]{16}$")


RUN_PRIVATE_TEXT = "written, private per-run /run: not in the skeleton, not seen by the next run"


def parse_tab_values(data, marker):
    """The values of every exact ``<marker><TAB><value>`` line (never a table row); the value is kept as text up to 200 characters."""
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    found = []
    for line in text.splitlines():
        parts = line.split("	")
        if len(parts) == 2 and parts[0] == marker:
            found.append(parts[1][:200])
    return found


def parse_run_marker(data):
    """The marker name the writes probe reported, or None: only a name of the exact shape the helper chose counts (the probe is untrusted)."""
    names = [v for v in parse_tab_values(data, "CANARYRUNMARKER") if RUN_MARKER_RE.match(v)]
    return names[-1] if names else None


def parse_run_seen(data):
    """1.18.16: what the next run said about the marker: True (``CANARYRUNSEEN<TAB>1``), False (``0``) or None (no exact line with 0 or 1). The
    last exact line counts; a table-shaped or partial line never does."""
    values = [v for v in parse_tab_values(data, "CANARYRUNSEEN") if v in ("0", "1")]
    return None if not values else values[-1] == "1"


def skeleton_run_names(list_dir=os.listdir):
    """The names inside the skeleton's run/ folder (SANDBOX_ROOT/run, an empty mount point), or None when it cannot be read."""
    try:
        return sorted(list_dir(H.SANDBOX_ROOT / "run"))
    except OSError:
        return None


def run_private_row(runner_row, marker, skeleton, following):
    """1.18.15: the 'write /run' row after the proof. ``runner_row`` is the table row the probe's own line gave; a refused write (OK) stays as
    it is. A write that worked (ATTACK SUCCEEDED so far) is judged on evidence: OK only when the marker is NOT in the skeleton's run/ folder
    (``skeleton``: list of names, None when unreadable) and the next run says the marker is NOT in its /run (``following``: 1.18.16, True when
    seen, False when absent, None when that run could not say). The marker in either place stays ATTACK SUCCEEDED; a check that cannot be made
    is NOT RUN."""
    if runner_row.get("verdict") != "ATTACK SUCCEEDED":
        return runner_row
    row = dict(runner_row, expected="read-only or a private per-run /run (the marker stays in the unit)")
    if marker is None:
        row.update(actual="written, but the probe reported no marker name, so privacy was not checked", verdict="NOT RUN")
    elif skeleton is None:
        row.update(actual="written; the skeleton's run/ folder could not be listed", verdict="NOT RUN")
    elif following is None:
        row.update(actual="written; the next run could not report on /run", verdict="NOT RUN")
    elif marker in skeleton:
        row.update(actual="written, and the marker is in the skeleton's run/ folder", verdict="ATTACK SUCCEEDED")
    elif following:
        row.update(actual="written, and the next run sees the marker", verdict="ATTACK SUCCEEDED")
    else:
        row.update(actual=RUN_PRIVATE_TEXT, verdict="OK")
    return row


def table_private_run(table, written, marker, collect, status, list_dir=os.listdir):
    """Replace the 'write /run' row of ``table`` by the proof row. The extra run (``runview``) only happens when /run could be written."""
    for index, entry in enumerate(table):
        if entry.get("attack") == "write /run":
            break
    else:
        return
    if entry.get("verdict") != "ATTACK SUCCEEDED":
        return
    reported = parse_run_marker((written or {}).get("stdout", b""))
    if reported != marker:  # the probe must name exactly the file the helper chose
        reported = None
    skeleton = skeleton_run_names(list_dir)
    following = None
    if reported is not None:
        nxt = collect("runview", {"run_marker": reported}, status=status)
        following = None if nxt.get("refused") else parse_run_seen(nxt.get("stdout", b""))
    table[index] = run_private_row(entry, reported, skeleton, following)


def parse_progress(data, marker="CANARYMEM"):
    """The last ``<marker><TAB><number>`` line of the in-unit program's output, as an integer, or None when there is none."""
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    found = None
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[0] == marker and parts[1].isdigit():
            found = int(parts[1])
    return found


def parse_end_word(data, marker="CANARYEND"):
    """1.17.124: the last ``CANARYEND<TAB><word>`` line (same exact-line rule as parse_progress, never a table row): how the memory probe
    ended (memoryerror, enomem, other:<ExceptionName>, done), or None when it printed none (a SIGKILL cannot print)."""
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    found = None
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[0] == marker and re.fullmatch(r"[A-Za-z0-9_:.?-]{1,60}", parts[1]):
            found = parts[1]
    return found


def _first_line(data, limit=80):
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data or "")
    for line in text.splitlines():
        if line.strip():
            return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in line.strip())[:limit]
    return ""


def memory_row(result, memory_mb, block=MEMORY_BLOCK_MIB):
    """1.17.124: the 'memory beyond MemoryMax' row, judged on evidence, never on a label alone.

    OK only when (A) the kernel stopped the run (end reason 'oom', or the end frame's oom_kills >= 1 from the cgroup's memory.events) or the
    probe itself reported a refused allocation (CANARYEND memoryerror or enomem) AND (B) the allocated MiB and the memory peak, whichever are
    known, are at or below MemoryMax (no slack) and at least one of them is known.
    ATTACK SUCCEEDED: allocated or peak above MemoryMax, the probe finished the whole allocation (CANARYEND done), or a normal exit 0.
    NOT RUN, never OK: no end frame, no evidence at all (the 1.17.123 hole: OK with nothing to show), or an end nothing explains, for example
    dev02's 'exited (exit 1)' with no oom_kills and no CANARYEND (systemd-run --wait returns 1 for a unit ended by a signal).

    1.18.17: the end frame also carries systemd's own unit result (``unit_result``, whitelisted) and the signal that ended the program; a unit
    result of oom-kill with the end reason 'oom' is proof by itself (the cgroup counters are gone by the time the helper looks). The end of the
    unit's main process is shown ('exit N' or 'killed by signal N'), never systemd-run's code. That process is the launcher (1.18.22 wording):
    'killed by signal 9' means the launcher was ended by signal 9, because the cgroup OOM kill took the whole unit. The memory.events max proof counts only when the kernel
    ended the run (reason 'oom' or 'exited'): a timeout, a cancel or an output limit is not the memory limit."""
    row = {"wall": "Limits", "attack": "memory beyond MemoryMax", "expected": f"stopped by the kernel at or below {memory_mb} MiB"}
    end = result.get("end") or {}
    if result.get("refused") or not end:
        row.update(actual="refused: " + str(result["refused"]) if result.get("refused") else "no end frame", verdict="NOT RUN")
        return row
    stdout = result.get("stdout", b"")
    allocated = parse_progress(stdout)
    word = parse_end_word(stdout)
    reason, code, peak, oom_kills = end.get("reason"), end.get("exit"), end.get("peak_mb"), end.get("oom_kills")
    evidence = end.get("evidence") if end.get("evidence") in ("poll", "finish", "unit_result", "service_result") else None  # 1.18.8: where the kill count came from
    peak = peak if isinstance(peak, (int, float)) and not isinstance(peak, bool) else None
    oom_kills = oom_kills if isinstance(oom_kills, int) and not isinstance(oom_kills, bool) else None
    counters = _end_counters(end.get("memory_events"))
    unit_word = _unit_result_word(end.get("unit_result"))
    signal_number = _signal_number(end.get("signal"))
    killed = reason == "oom" or (oom_kills is not None and oom_kills >= 1)
    kernel_end = reason in ("oom", "exited")  # 1.18.17: the only ends the memory limit can have caused
    refused_alloc = word in ("memoryerror", "enomem")
    over = (allocated is not None and allocated > memory_mb) or (peak is not None and peak > memory_mb)
    finished = word == "done" or (reason == "exited" and code == 0)
    how = f"ended {reason}" + (f" (exit {code})" if reason == "exited" and code is not None else "") + (f", probe {word}" if word else "")
    if signal_number is not None:
        how += f", killed by signal {signal_number}"
    if unit_word:
        how += f", unit result {unit_word}"
    if word in ("memoryerror", "enomem") and allocated is not None:  # 1.18.15: the refused allocation is named in the table, with the size held
        how += f", {'MemoryError' if word == 'memoryerror' else 'enomem'} at {allocated} MiB"
    row["actual"] = (f"allocated {allocated} MiB" if allocated is not None else "no allocation reported") + f", {how}, oom_kills " + \
        (str(oom_kills) if oom_kills is not None else "unknown") + (f", peak {peak} MiB" if peak is not None else ", no peak") + \
        (f", evidence {evidence}" if evidence else "")
    if counters:  # 1.18.16: the kernel's own counters are always shown when they were read
        row["actual"] += ", memory.events " + ", ".join(f"{name} {counters[name]}" for name in H.MEMORY_COUNTERS if name in counters)
    err = _first_line(result.get("stderr", b""))  # 1.18.16: the probe's first stderr line, whenever there is one (a SIGKILL prints none)
    if err:
        row["actual"] += f"; stderr: {err}"
    cap_hit = counters.get("max")
    name = None
    if over or finished:
        row["verdict"] = "ATTACK SUCCEEDED"
    elif killed and (allocated is not None or peak is not None):
        if oom_kills is not None and oom_kills >= 1:
            name = f"oom_kill {oom_kills} (memory.events)"
        elif unit_word == "oom-kill" and reason == "oom":
            name = "systemd unit result oom-kill"
        else:
            name = "oom_kill (end reason oom)"
    elif refused_alloc and (allocated is not None or peak is not None):
        label = "MemoryError" if word == "memoryerror" else "enomem"
        name = f"probe {label}" + (f" at {allocated} MiB" if allocated is not None else "")
    elif cap_hit is not None and cap_hit >= 1 and kernel_end and peak is not None and allocated is not None:
        name = f"memory.events max {cap_hit}, peak {peak} MiB <= {memory_mb} MiB"  # over and finished were ruled out above
    if name:
        row["verdict"] = "OK"
        row["actual"] += f"; proof: {name}"
    elif not (over or finished):
        row["verdict"] = "NOT RUN"
        if killed or refused_alloc:
            why = "no allocation or peak to check against the limit"
        elif cap_hit is not None and cap_hit >= 1 and not kernel_end:
            why = f"ended by {reason}, not by the memory limit"
        elif cap_hit is not None and cap_hit >= 1:
            why = "memory.events max seen, but no peak or allocation to check it against the limit"
        else:
            why = "no evidence of how it ended"
        row["actual"] += f"; {why}"
    return row


def _unit_result_word(value):
    """The ``unit_result`` of an end frame, kept only when it is one of systemd's known result words."""
    return value if isinstance(value, str) and value in H.UNIT_RESULTS else None


def _signal_number(value):
    """The ``signal`` of an end frame, kept only when it is a whole number from 1 to 64."""
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 64 else None


def _end_counters(value):
    """The ``memory_events`` of an end frame, kept only when it is a dict of known counter names with whole, non-negative numbers."""
    if not isinstance(value, dict):
        return {}
    return {name: value[name] for name in H.MEMORY_COUNTERS
            if isinstance(value.get(name), int) and not isinstance(value.get(name), bool) and value[name] >= 0}


CANARY_MEMORY_MB = 128  # the memory row's MemoryMax


MEMORY_ALLOC_FACTOR = 2  # 1.18.15: the probe tries to hold twice MemoryMax, in 4 MiB steps


def _limit_rows(collect, status):
    rows = []

    def one(attack, group, plan, expected_reason, **limits):
        result = collect(group, plan, status=status, **limits)
        end = result.get("end") or {}
        reason = result.get("refused") or end.get("reason") or "no end frame"
        verdict = "OK" if reason == expected_reason else "ATTACK SUCCEEDED"
        if result.get("refused") or not end:
            verdict = "NOT RUN"
        rows.append({"wall": "Limits", "attack": attack, "expected": expected_reason, "actual": str(reason), "verdict": verdict})
        return result

    rows.append(memory_row(collect("mem", {"alloc_mb": CANARY_MEMORY_MB * MEMORY_ALLOC_FACTOR}, status=status, memory_mb=CANARY_MEMORY_MB), CANARY_MEMORY_MB))
    fork = collect("fork", {"forks": 300}, status=status, tasks=64)
    rows.extend(group_table("Limits", "fork", "EAGAIN before 64 tasks", parse_runner_rows(fork["stdout"])))
    one("infinite loop", "loop", {}, "timeout", run_seconds=4)
    scratch = collect("scratch", {"fill_mb": 32}, status=status, scratch_mb=8)
    rows.extend(group_table("Limits", "scratch", "ENOSPC or EFBIG", parse_runner_rows(scratch["stdout"])))
    one("stdout past its cap", "flood", {"flood_kib": 64}, "output_limit", stdout_kib=16)
    return rows


_FOREIGN_READ = ("import errno, sys\n"
                 "try:\n"
                 "    open(sys.argv[1], 'rb').read(1)\n"
                 "    print('READ')\n"
                 "except PermissionError as error:\n"
                 "    print('DENIED' if error.errno in (errno.EACCES, errno.EPERM) else 'ERROR')\n"
                 "except (FileNotFoundError, NotADirectoryError):\n"
                 "    print('MISSING')\n"
                 "except OSError:\n"
                 "    print('ERROR')\n")


def _foreign_credential_probe(unit):
    """1.17.120: while the credential run is live, a second transient unit (its own dynamic user, nothing shared) tries to read that run's
    credential file. 1.17.121: returns 'READ', 'DENIED' or 'MISSING' (the file was not there); only READ and DENIED can count as a result,
    anything else is ''. Never prints the content or the path."""
    path = f"/run/credentials/{unit}.service/cred0"  # 1.18.8: the fixed slot name; the canary's one credential is slot 0
    code, out, _err = H.UnitRunner().run_unit("credential_foreign", ("DynamicUser=yes",), [H.UNIT_PYTHON, "-I", "-c", _FOREIGN_READ, path])
    word = (out or "").strip()
    if code != 0:
        return ""
    return word if word in ("READ", "DENIED", "MISSING") else ""


def _credential_file_ready(unit):
    """1.17.121: root-side check that the credential run's file exists and its unit is active, so a denial can only mean 'refused', not 'absent'."""
    try:
        return os.path.exists(f"/run/credentials/{unit}.service/cred0") and H.systemctl("is-active", unit + ".service")[0] == 0
    except (OSError, RuntimeError, ValueError):
        return False


def _foreign_row(foreign, before, after):
    """1.17.121: the 'another dynamic user reads the credential file' row. OK only on DENIED with the file and unit proven present before and after."""
    row = {"wall": "Credential", "attack": "another dynamic user reads the credential file", "expected": "denied"}
    if not before:
        row.update(actual="credential file or unit was not there when the probe would have run", verdict="NOT RUN")
    elif foreign == "READ":
        row.update(actual="read it", verdict="ATTACK SUCCEEDED")
    elif foreign == "DENIED" and after:
        row.update(actual="denied", verdict="OK")
    elif foreign == "DENIED":
        row.update(actual="denied, but the credential file or unit was gone afterwards, so the denial proves nothing", verdict="NOT RUN")
    elif foreign == "MISSING":
        row.update(actual="the probe found no credential file", verdict="NOT RUN")
    else:
        row.update(actual="probe unit did not start or gave no usable answer", verdict="NOT RUN")
    return row


# 1.17.122: how long the credential run stays alive so the root-side checks and the foreign reader can finish; it stays under canary_row's
# 20 s run_seconds, so the run ends on its own and the limit never fires first.
CANARY_CRED_HOLD_SECONDS = 10


NONCE_FRAME_RE = re.compile(rb"[0-9a-f]{32} CRED ")


def credential_leak_findings(token, result):
    """1.17.123: what the launcher's credential frame or the secrets left in the places a caller sees. Looks for the real thing, not a word:
    the nonce-shaped frame start (32 hex digits, ' CRED '), the launcher header text, the token and the refreshed token (plain and base64).
    Searches stdout, stderr and every field of the end frame except ``credential_b64`` (the one place that value belongs), and the refusal.
    A runner line that merely says CREDENTIALS_DIRECTORY or CRED is not a finding. Returns plain findings such as 'stdout: token'."""
    token_bytes = str(token).encode()
    refreshed = b"refreshed-" + token_bytes
    needles = {"the nonce frame": None, "the launcher header": b"TECTAC-SBX-LAUNCHER", "the token": token_bytes, "the refreshed token": refreshed,
               "the token (base64)": base64.b64encode(token_bytes), "the refreshed token (base64)": base64.b64encode(refreshed)}
    end = {key: value for key, value in (result.get("end") or {}).items() if key != "credential_b64"}
    places = {"stdout": bytes(result.get("stdout", b"")), "stderr": bytes(result.get("stderr", b"")),
              "end frame": json.dumps(end, sort_keys=True, default=str).encode(), "refusal": str(result.get("refused") or "").encode()}
    found = []
    for place, data in places.items():
        for label, needle in needles.items():
            if (NONCE_FRAME_RE.search(data) if needle is None else (bool(needle) and needle in data)):
                found.append(f"{place}: {label}")
    return found


def _live_exec_properties(unit):
    """1.18.14: the Exec* properties of the live unit as systemd shows them: {name: text}. An empty text means no command is set."""
    found = {}
    for name in ("ExecStartPre", "ExecStartPost", "ExecStopPost"):
        code, out, _err = H.systemctl("show", unit + ".service", "-P", name)
        found[name] = out.strip() if code == 0 else "unreadable"
    return found


def credential_cleanup_rows(folder_present, exec_properties, active):
    """1.18.14: the two canary rows for the credential clean-up. ``folder_present`` is whether secrets/<run id> still exists while the unit
    is active; ``exec_properties`` the live unit's Exec* values; ``active`` whether the unit was proven active (otherwise NOT RUN)."""
    if not active:
        return [{"wall": "Credential", "id": row_id, "attack": name, "expected": expected, "actual": "the unit was not proven active", "verdict": "NOT RUN"}
                for row_id, name, expected in (("credential-source-gone", "credential source folder is gone while the run is still active", "absent"),
                                               ("no-host-command-property", "no host command property on the live unit", "all empty"))]
    set_ones = sorted(name for name, text in exec_properties.items() if text and text != "unreadable")
    unreadable = not exec_properties or any(text == "unreadable" for text in exec_properties.values())
    return [
        {"wall": "Credential", "id": "credential-source-gone", "attack": "credential source folder is gone while the run is still active", "expected": "absent",
         "actual": "still present" if folder_present else "absent", "verdict": "ATTACK SUCCEEDED" if folder_present else "OK"},
        {"wall": "Credential", "id": "no-host-command-property", "attack": "no host command property on the live unit", "expected": "ExecStartPre, ExecStartPost, ExecStopPost empty",
         "actual": ("set: " + ", ".join(set_ones)) if set_ones else ("could not be read" if unreadable else "all empty"),
         "verdict": "ATTACK SUCCEEDED" if set_ones else ("NOT RUN" if unreadable else "OK")},
    ]


def _credential_rows(collect, status, probe=None, ready=None, exec_properties=None):
    probe = probe or _foreign_credential_probe
    ready = ready or _credential_file_ready
    exec_properties = exec_properties or _live_exec_properties
    token = secrets.token_hex(16)
    cred_run = secrets.token_hex(16)
    box = {}

    def live():
        box["result"] = collect("cred", {"credential_token": token, "hold_seconds": CANARY_CRED_HOLD_SECONDS}, status=status, credentials={"auth": token.encode()},
                                person="canary-cred", run_id=cred_run)

    thread = threading.Thread(target=live, daemon=True)
    thread.start()
    time.sleep(1.5)
    leaks = _holders_search(token, H.unit_name(cred_run))
    foreign, after = "", False
    try:
        before = bool(ready(H.unit_name(cred_run)))
    except Exception:  # noqa: BLE001 - a pre-check that breaks is NOT RUN
        before = False
    cleanup = None
    if before:
        try:  # 1.18.14: written first, while the unit is proven active
            cleanup = credential_cleanup_rows((H.SECRETS_ROOT / cred_run).exists(), exec_properties(H.unit_name(cred_run)), True)
        except Exception:  # noqa: BLE001 - a check that breaks is NOT RUN
            cleanup = None
        try:
            foreign = probe(H.unit_name(cred_run))
        except Exception:  # noqa: BLE001 - a probe that breaks is NOT RUN, never a pass
            foreign = ""
        try:
            after = bool(ready(H.unit_name(cred_run)))
        except Exception:  # noqa: BLE001
            after = False
    thread.join(30)
    result = box.get("result") or {"stdout": b"", "end": None, "refused": "no result"}
    rows = []
    if result.get("refused"):
        return [{"wall": "Credential", "attack": "credential hand-in", "expected": "arrives", "actual": "refused: " + str(result["refused"]), "verdict": "NOT RUN"}]
    rows.extend(cleanup or credential_cleanup_rows(False, {}, False))
    rows.extend(group_table("Credential", "cred", "only under CREDENTIALS_DIRECTORY", parse_runner_rows(result["stdout"])))
    rows.append(_foreign_row(foreign, before, after))
    rows.append({"wall": "Credential", "attack": "token in ps, /proc/*/cmdline, systemctl show, journald", "expected": "absent",
                 "actual": ", ".join(leaks) or "absent", "verdict": "ATTACK SUCCEEDED" if leaks else "OK"})
    left = [p.name for p in H.SECRETS_ROOT.iterdir()] if H.SECRETS_ROOT.is_dir() else []
    rows.append({"wall": "Credential", "attack": "nothing left in secrets folder", "expected": "empty", "actual": f"{len(left)} left",
                 "verdict": "ATTACK SUCCEEDED" if left else "OK"})
    expected_back = "refreshed-" + token
    end = result.get("end") or {}
    back = end.get("credential_b64")
    got = base64.b64decode(back).decode("utf-8", "replace") if back else ""
    rows.append({"wall": "Credential", "attack": "credential_return round trip", "expected": "refreshed token back",
                 "actual": "came back" if got == expected_back else "missing or wrong", "verdict": "OK" if got == expected_back else "ATTACK SUCCEEDED"})
    found = credential_leak_findings(token, result)
    rows.append({"wall": "Credential", "attack": "credential frame stripped from output", "expected": "no frame, header, token or refreshed token in stdout, stderr or events",
                 "actual": ("found: " + "; ".join(found)) if found else "stripped (checked stdout, stderr and the end frame for the nonce frame, the launcher header, the token and the refreshed token)",
                 "verdict": "ATTACK SUCCEEDED" if found else "OK"})
    return rows


def _unit_gone(run_id, seconds=5.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if H.systemctl("is-active", H.unit_name(run_id) + ".service")[0] != 0:
            return True
        time.sleep(0.25)
    return False


def _cancel_rows(collect, status):
    rows = []
    box = {}
    run_id = secrets.token_hex(16)

    def worker():
        row = canary_row(run_seconds=30)
        frames = []
        try:
            H.launch(row, run_id=run_id, person="canary-cancel", parameters={"group": "sleep"}, credentials={}, input_data=b'{"hold_seconds": 25}',
                   emit=frames.append, status=status)
        except H.Refusal as exc:
            box["refused"] = exc.code
        box["frames"] = frames

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    time.sleep(2)
    H.stop_command(io.BytesIO(run_id.encode() + b"\n"), out=io.StringIO())
    gone = _unit_gone(run_id)
    thread.join(15)
    end = next((f for f in box.get("frames", []) if f.get("t") == "end"), {})
    rows.append({"wall": "Cancel", "attack": "stop mid-run", "expected": "unit gone within 5 s, reason cancelled",
                 "actual": f"gone={gone} reason={end.get('reason')}", "verdict": "OK" if gone and end.get("reason") == "cancelled" else "ATTACK SUCCEEDED"})
    for label, how in (("SIGKILL the helper", "kill"), ("kill the caller (stdin closes)", "eof")):
        run_id = secrets.token_hex(16)
        header = json.dumps({"runner_id": CANARY_RUNNER_ID, "run_id": run_id, "person": "canary-" + how, "parameters": {"group": "sleep"},
                             "input_bytes": len(b'{"hold_seconds": 25}')}).encode() + b"\n" + b'{"hold_seconds": 25}'
        child = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__), "--canary-launch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL)
        child.stdin.write(header)
        child.stdin.flush()
        time.sleep(2.5)
        if how == "kill":
            child.kill()
        else:
            child.stdin.close()
        gone = _unit_gone(run_id)
        try:
            child.wait(10)
        except subprocess.TimeoutExpired:
            child.kill()
        rows.append({"wall": "Cancel", "attack": label, "expected": "unit gone within 5 s", "actual": f"gone={gone}", "verdict": "OK" if gone else "ATTACK SUCCEEDED"})
    H.sweep(min_age=0)  # the canary is the only thing running: anything left over for a stopped unit goes now
    leftovers = [p.name for folder in (H.SECRETS_ROOT, H.HANDOFF_ROOT, H.RUNS_ROOT) if folder.is_dir() for p in folder.iterdir()]
    rows.append({"wall": "Cancel", "attack": "nothing left after cancel and kills", "expected": "no secrets, handoff or run files",
                 "actual": f"{len(leftovers)} left", "verdict": "OK" if not leftovers else "ATTACK SUCCEEDED"})
    return rows


def _concurrency_rows(collect, status):
    rows = []

    def trio(person_for, **kwargs):
        results, threads = [None] * 3, []
        for k in range(3):
            def go(k=k):
                results[k] = collect("sleep", {"hold_seconds": 4}, status=status, person=person_for(k), queue_seconds=1, **kwargs)
            thread = threading.Thread(target=go, daemon=True)
            threads.append(thread)
            thread.start()
            time.sleep(0.4)
        for thread in threads:
            thread.join(30)
        return [(r or {}).get("refused") or "ran" for r in results]

    server = trio(lambda k: f"canary-s{k}", slots_n=2)
    rows.append({"wall": "Concurrency", "attack": "3 starts on 2 slots", "expected": "2 run, 1 busy", "actual": ", ".join(server),
                 "verdict": "OK" if sorted(server) == ["busy", "ran", "ran"] else "ATTACK SUCCEEDED"})
    person = trio(lambda k: "canary-one-person", slots_n=4)
    rows.append({"wall": "Concurrency", "attack": "per-person limit", "expected": "2 run, 1 person_busy", "actual": ", ".join(person),
                 "verdict": "OK" if sorted(person) == ["person_busy", "ran", "ran"] else "ATTACK SUCCEEDED"})
    return rows


def _latency_rows(collect, status):
    times = []
    for _ in range(CANARY_LATENCY_RUNS):
        started = time.monotonic()
        result = collect("noop", {}, status=status, person="canary-latency")
        if result.get("refused") or not result.get("end"):
            return [{"wall": "Latency", "attack": "no-op runs", "expected": f"p95 under {CANARY_LATENCY_TARGET_MS} ms", "actual": "a run did not finish", "verdict": "NOT RUN"}]
        times.append((time.monotonic() - started) * 1000)
    p50, p95 = _percentile(times, 0.5), _percentile(times, 0.95)
    return [{"wall": "Latency", "attack": f"{CANARY_LATENCY_RUNS} no-op runs", "expected": f"p95 under {CANARY_LATENCY_TARGET_MS} ms",
             "actual": f"p50 {p50:.0f} ms, p95 {p95:.0f} ms", "verdict": "OK" if p95 <= CANARY_LATENCY_TARGET_MS else "WARN"}]


def format_table(table):
    widths = {key: max([len(key)] + [len(str(entry[key])) for entry in table]) for key in ("wall", "attack", "expected", "actual", "verdict")}
    widths = {key: min(width, ACTUAL_COLUMN_MAX if key == "actual" else 60) for key, width in widths.items()}  # 1.17.124: the actual column keeps its end (peak, stderr)
    header = "  ".join(key.upper().ljust(widths[key]) for key in widths)
    lines = [header.rstrip(), "-" * len(header)]  # 1.17.122: no line ends in padding, so a consumer can match the verdict at the line end
    for entry in table:
        lines.append("  ".join(str(entry[key])[:widths[key]].ljust(widths[key]) for key in widths).rstrip())
    return "\n".join(lines)


ROW_ID_MAX = 40


DETAIL_TEXT_MAX = 600


ROW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


def row_slug(label):
    """1.18.15: a stable short id from a label: lower case, every other run of characters becomes one '-', at most 40 characters, no edge '-'."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(label).lower()).strip("-")[:ROW_ID_MAX].strip("-")
    return slug or "row"


def assign_row_ids(table):
    """1.18.15: one unique id per table row, in table order. A row's own ``id`` (set where the row is built, [a-z0-9-], at most 40 characters)
    wins; any other row gets the slug of its label. A repeated id gets '-2', '-3' and so on (still at most 40 characters). The id is what the
    canary script reads: the printed label is cut at 60 characters, an id never is. Never a path or module text."""
    seen, ids = set(), []
    for entry in table:
        base = entry.get("id") if isinstance(entry.get("id"), str) and ROW_ID_RE.match(entry["id"]) else row_slug(entry.get("attack", ""))
        candidate, n = base, 1
        while candidate in seen:
            n += 1
            suffix = f"-{n}"
            candidate = base[:ROW_ID_MAX - len(suffix)].rstrip("-") + suffix
        seen.add(candidate)
        ids.append(candidate)
    return ids


def row_lines(table):
    """1.18.15: one machine line per row, ``ROW <id> <verdict>``, for the canary script (the table is for people)."""
    return [f"ROW {row_id} {entry['verdict']}" for row_id, entry in zip(assign_row_ids(table), table)]


def detail_lines(table):
    """1.18.22: ``DETAIL <row id> <actual>`` for every row whose 'actual' text is longer than the table's actual column (format_table cut it).

    The table is for people and keeps its width. The canary script reads the full text here (dev02 canary of 1.18.21: the memory row's
    '; proof: ...' was cut off at 140 characters). One line, printable ASCII only, at most 600 characters. Same ids as row_lines."""
    lines = []
    for row_id, entry in zip(assign_row_ids(table), table):
        text = str(entry.get("actual", ""))
        if len(text) > ACTUAL_COLUMN_MAX:
            lines.append(f"DETAIL {row_id} " + "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)[:DETAIL_TEXT_MAX])
    return lines


def run_canary_command():
    H.ensure_layout()
    table = run_canary()
    passed, counts = canary_summary(table)
    print(format_table(table))
    for line in row_lines(table):
        print(line)
    for line in detail_lines(table):
        print(line)
    print(f"\n{counts['OK']} OK, {counts['ATTACK SUCCEEDED']} ATTACK SUCCEEDED, {counts['NOT RUN']} NOT RUN, {counts['SKIPPED']} SKIPPED, {counts['WARN']} WARN")
    print("CANARY PASSED" if passed else "CANARY FAILED")
    H._write_root_file(H.CANARY_FILE, H._json_bytes(canary_record(table, passed, counts)), 0o644)
    H.append_audit("canary", detail={"passed": passed, "counts": counts})
    return 0 if passed else 1


def start_canary(stdin=None, *, out_stream=None):
    """``--canary-launch``: the helper's start path for ``core.canary`` only. The header must name the canary runner; the row comes from this file."""
    return H.start_command(stdin, row=canary_row(), out_stream=out_stream)


def usage():
    raise SystemExit("usage: sandbox-selftest.py --selftest [--canary] | --canary-launch")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv not in (["--selftest"], ["--selftest", "--canary"], ["--canary-launch"]):
        usage()
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if argv == ["--canary-launch"]:
        return start_canary()
    if argv == ["--selftest"]:
        return run_selftest()
    return run_canary_command()


if __name__ == "__main__":
    sys.exit(main())
