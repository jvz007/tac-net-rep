#!/usr/bin/python3
"""In-unit attack program for the core.sandbox canary (Core 1.17.118, Patch 2, plan 8.2 and section 15).

Runs inside a sandbox unit, as the unit's unprivileged user, started by ``tec-tac-sandbox --selftest --canary``. The first argument names
one group of attacks; the root helper's JSON plan (planted marker files, listening ports, resolver and gateway addresses) arrives on stdin.
Each attack prints exactly one line

    CANARYROW<TAB><attack><TAB><OK|SUCCEEDED|SKIP><TAB><what happened>

OK means the wall held. SUCCEEDED means the attack worked (a finding). SKIP means the probe could not run, with the reason. The root helper
never trusts these lines: it decides the verdict itself, treats an unknown word as a failure and a missing line as ``NOT RUN``.
This program holds no secret and writes nothing outside the unit's own /work.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROWS = []
ROW_LOCK = threading.Lock()  # 1.17.124: the loopback probes run in threads; one lock keeps every line whole
LOOPBACK_WORKERS = 12
LOOPBACK_PROBE_SECONDS = 1.0


def clean(value, limit):
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(value))[:limit]


def row(attack, tag, actual):
    """One result line. Every field is cleaned, so a path with a tab or a newline in it cannot break the line format."""
    line = f"CANARYROW\t{clean(attack, 200)}\t{clean(tag, 20)}\t{clean(actual, 300)}\n"
    with ROW_LOCK:
        sys.stdout.write(line)
        sys.stdout.flush()


def libc():
    return ctypes.CDLL(None, use_errno=True)


def tcp_connect(host, port, timeout=1.5, family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return "connected"
    except TimeoutError:
        return "timeout"
    except OSError as exc:
        return errno.errorcode.get(exc.errno, "error")
    finally:
        s.close()


def udp_send(host, port=9):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        s.connect((host, port))
        s.send(b"x")
        return "sent"
    except PermissionError:
        return "eperm"
    except OSError as exc:
        return errno.errorcode.get(exc.errno, "error")
    finally:
        s.close()


def dns_query(address, name="example.com"):
    q = struct.pack(">HHHHHH", 0x7A31, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(q, (address, 53))
        data, _ = s.recvfrom(2048)
        return len(data) >= 12 and data[:2] == q[:2] and bool(data[2] & 0x80)
    except OSError:
        return False
    finally:
        s.close()


def g_files(plan):
    for item in plan.get("markers", []):
        path, content = item["path"], item["content"]
        try:
            with open(path, "r", encoding="utf-8") as handle:
                found = handle.read(200)
            hit = content is None or found == content  # None: a real file, readable at all is the finding
            row("read " + path, "SUCCEEDED" if hit else "OK", "readable" if hit else "other content")
        except OSError as exc:
            row("read " + path, "OK", errno.errorcode.get(exc.errno, "error"))


VIEW_NAME_LENGTH = 100  # the helper cleans the host's names the same way (view_clean)
VIEW_LISTED_MAX = 10
RUNTIMES_FOLDER = "/opt/tec-tac/runtimes"


def _view_names(folder):
    """The names this unit sees in ``folder``, cleaned like the helper cleans the host's. (names, raw names) or (None, errno name)."""
    try:
        raw = os.listdir(folder)
    except OSError as exc:
        return None, errno.errorcode.get(exc.errno, "error")
    return [clean(name, VIEW_NAME_LENGTH) for name in raw], raw


def _is_empty_dir(path):
    try:
        return os.path.isdir(path) and not os.path.islink(path) and not os.listdir(path)
    except OSError:
        return False


def g_rootview(plan):
    """1.18.8: root lists the HOST's own entries of a fixed set of folders (names only) and the allowed names for each; this unit lists its own
    view of the same folders. A name that the host has, this unit sees and is not allowed is a finding (the first ten are named). A second
    row checks this unit's own ``/`` against the allowed set, whatever the host has."""
    view = plan.get("view")
    if not isinstance(view, dict) or not view:
        row("rootview plan", "NOTRUN", "the plan held no folder listing")
        return
    for folder, entry in view.items():
        if not isinstance(entry, dict):
            continue
        host, allowed = set(entry.get("host") or []), set(entry.get("allowed") or [])
        seen, raw = _view_names(folder)
        if seen is None:
            row("view " + folder, "OK", f"not visible ({raw})")
            continue
        leaked = []
        for shown, name in zip(seen, raw):
            if shown in host and shown not in allowed:
                if folder == RUNTIMES_FOLDER and shown == name and _is_empty_dir(os.path.join(folder, name)):
                    continue  # an empty mount point, not the host's runtime folder
                leaked.append(shown)
        leaked.sort()
        if leaked:
            more = f" (+{len(leaked) - VIEW_LISTED_MAX} more)" if len(leaked) > VIEW_LISTED_MAX else ""
            row("view " + folder, "SUCCEEDED", "visible: " + ", ".join(leaked[:VIEW_LISTED_MAX]) + more)
        else:
            row("view " + folder, "OK", f"{len(seen)} entries, none of the host's unlisted names")
    root_entry = view.get("/") if isinstance(view.get("/"), dict) else {}
    allowed_root = set(root_entry.get("allowed") or [])
    own, raw = _view_names("/")
    if own is None or not allowed_root:
        row("/ lists only the allowed set", "NOTRUN", "the unit could not list / or the plan had no allowed set")
        return
    extra = sorted(name for name in own if name not in allowed_root)
    if extra:
        row("/ lists only the allowed set", "SUCCEEDED", "outside the set: " + ", ".join(extra[:VIEW_LISTED_MAX]))
    else:
        row("/ lists only the allowed set", "OK", f"{len(own)} entries, all allowed")


def g_work_hold(plan):
    token = plan.get("work_token", "")
    with open(os.path.join(os.environ["SANDBOX_WORK"], "peer-" + token), "w", encoding="utf-8") as handle:
        handle.write(token)
    time.sleep(float(plan.get("hold_seconds", 4)))
    row("hold", "OK", "held")


def g_work_peer(plan):
    token = plan.get("work_token", "")
    name = "peer-" + token
    seen = os.path.exists(os.path.join(os.environ["SANDBOX_WORK"], name))
    for pid in [p for p in os.listdir("/proc") if p.isdigit() and int(p) != os.getpid()]:
        seen = seen or os.path.exists(f"/proc/{pid}/root/work/{name}")
    row("another run's /work", "SUCCEEDED" if seen else "OK", "visible" if seen else "not found")


def _errname(exc):
    return errno.errorcode.get(exc.errno, "error")


def g_sockets(plan):
    """Pathname unix sockets of the host's services. 1.18.24 (AD-65 Patch B): a run may create AF_UNIX sockets (only the egress door needs them), so
    every connect is tried for real: host path sockets do not exist in the run's root view and abstract names are private to its own network space,
    so each must fail to connect. Only a connect that works is SUCCEEDED. All 13 rows are always printed, then the door row."""
    paths = ["/var/run/postgresql/.s.PGSQL.5432", "/run/postgresql/.s.PGSQL.5432", "/var/run/redis/redis-server.sock",
             "/run/redis/redis-server.sock", "/run/redis/redis.sock", "/var/run/redis/redis.sock", "/run/nats/nats.sock",
             "/rmm/api/tacticalrmm/tacticalrmm.sock", "/run/tactical/tacticalrmm.sock", "/run/uwsgi/tactical.sock",
             "/var/run/docker.sock", "/run/dbus/system_bus_socket", "/run/systemd/private"]
    for path in paths:
        s = None
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(path)
            row("unix " + path, "SUCCEEDED", "connected")
        except OSError as exc:
            row("unix " + path, "OK", ("socket creation refused: " if s is None else "") + _errname(exc))
        finally:
            if s is not None:
                s.close()
    door_row()
    control_rows()


DOOR_PATH = "/run/egress/door.sock"  # the one pathname that may connect, and only for a run whose runner declares allowed_hosts
R_DOOR_NONE = "unix door path without a door"


def door_row():
    """1.18.24: this run has no allowed_hosts, so no egress door is bound into it: the door path must not connect. (A run with a door shows the
    door working in the proxy rows of the network group; every other pathname fails in the 13 rows above.)"""
    s = None
    try:
        s = make_socket(getattr(socket, "AF_UNIX", 1), socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(DOOR_PATH)
        row(R_DOOR_NONE, "SUCCEEDED", "connected: a door exists for a run that declares no allowed_hosts")
    except OSError as exc:
        row(R_DOOR_NONE, "OK", ("socket creation refused: " if s is None else "") + _errname(exc))
    finally:
        if s is not None:
            s.close()


def _control(name, check):
    """A positive control: it must work. Anything else is NOTRUN ('control failed'), never an attack, and it fails the canary."""
    try:
        detail = check()
    except BaseException as exc:  # a control must never take the group down
        row(name, "NOTRUN", "control failed: " + type(exc).__name__)
        return
    if detail:
        row(name, "OK", detail)
    else:
        row(name, "NOTRUN", "control failed")


def _socketpair_check():
    a, b = socket.socketpair()
    try:
        a.settimeout(2)
        b.settimeout(2)
        a.sendall(b"ping")
        got = b.recv(16)
        b.sendall(b"pong")
        return "worked" if got == b"ping" and a.recv(16) == b"pong" else ""
    finally:
        a.close()
        b.close()


def _pipe_check():
    r, w = os.pipe()
    try:
        os.write(w, b"ping")
        return "worked" if os.read(r, 16) == b"ping" else ""
    finally:
        os.close(r)
        os.close(w)


def _child_pipes_check():
    data = b"canary\x00\xff" * 100
    done = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()[::-1])"], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
    return "worked" if done.returncode == 0 and done.stdout == data[::-1] else ""


def control_rows():
    """1.17.124 positive controls: what the CLIs rely on must still work without AF_UNIX (socketpair() and pipes are not covered by the
    address family filter, and a child process gets its stdio over pipes)."""
    _control("socketpair round trip", _socketpair_check)
    _control("pipe round trip", _pipe_check)
    _control("child process with stdio pipes", _child_pipes_check)


def g_loopback(plan):
    """Every listening port on 127.0.0.1 and the whole stub (1.17.123), probed in parallel (1.17.124). A dropped SYN times out instead of
    failing, so one at a time the 20 s budget ran out before the stub rows. Stub probes go first, then 127.0.0.1, then ::1; at most 12 workers
    (TasksMax counts threads); about 1 s per probe; a probe that would start or finish after ``loopback_seconds`` prints nothing and the helper's
    table says NOT RUN. Result words are unchanged: connected is SUCCEEDED, a timeout or an errno is OK."""
    ports = [int(p) for p in plan.get("ports", []) if int(p) != NET_PROXY_DEFAULT[1]]  # 1.18.24: 3128 is the in-unit forwarder, never a host service
    stub = plan.get("stub", "")
    jobs = []
    if stub:
        jobs += [(stub, int(p), socket.AF_INET) for p in plan.get("stub_ports", [])]
    jobs += [("127.0.0.1", p, socket.AF_INET) for p in ports]
    jobs += [("::1", p, socket.AF_INET6) for p in ports]
    deadline = time.monotonic() + float(plan.get("loopback_seconds", 15))

    def probe(job):
        host, port, family = job
        if time.monotonic() >= deadline:
            return
        try:
            result = tcp_connect(host, port, timeout=LOOPBACK_PROBE_SECONDS, family=family)
        except OSError as exc:
            result = errno.errorcode.get(exc.errno, "error")
        if time.monotonic() >= deadline:
            return
        row(f"loopback {host}:{port}", "SUCCEEDED" if result == "connected" else "OK", result)

    with ThreadPoolExecutor(max_workers=LOOPBACK_WORKERS) as pool:
        list(pool.map(probe, jobs))


def _reached(tcp_result):
    """A TCP answer that proves the packet got to a host: connected, or refused (a reset only comes back from a host that was reached)."""
    return tcp_result in ("connected", "ECONNREFUSED")


def g_lan(plan):
    targets = list(plan.get("lan", []))
    for target in targets:
        result = udp_send(target)
        row("udp " + target, "SUCCEEDED" if result == "sent" else "OK", result)
        tcp = tcp_connect(target, 80, timeout=1.0)
        row("tcp " + target + ":80", "SUCCEEDED" if tcp == "connected" else "OK", tcp)
    # 1.17.123: this server's own addresses and its gateways are denied by address, whatever the next hop is
    for address in plan.get("own", []):
        for port in (22, 80, 443):
            tcp = tcp_connect(address, port, timeout=1.0)
            row(f"own address {address} tcp {port}", "SUCCEEDED" if _reached(tcp) else "OK", tcp)
        sent = udp_send(address)
        row(f"own address {address} udp", "SUCCEEDED" if sent == "sent" else "OK", sent)
    for address in plan.get("gateways", []):
        for port in (80, 443):
            tcp = tcp_connect(address, port, timeout=1.0)
            row(f"gateway {address} tcp {port}", "SUCCEEDED" if _reached(tcp) else "OK", tcp)
        sent = udp_send(address)
        row(f"gateway {address} udp", "SUCCEEDED" if sent == "sent" else "OK", sent)


def _syscall_row(name, number, args):
    ctypes.set_errno(0)
    res = libc().syscall(number, *args)
    err = ctypes.get_errno()
    if res == -1:
        row(name, "OK", errno.errorcode.get(err, "error"))
    else:
        row(name, "SUCCEEDED", f"returned {res}")


def g_privilege(plan):
    lib = libc()
    ctypes.set_errno(0)
    res = lib.setuid(0)
    row("setuid(0)", "OK" if res == -1 else "SUCCEEDED", errno.errorcode.get(ctypes.get_errno(), f"returned {res}"))
    _syscall_row("ptrace attach to parent", 101, (16, os.getppid(), 0, 0))  # x86-64 numbers; others report EPERM or ENOSYS
    ctypes.set_errno(0)
    res = lib.mount(b"none", b"/work", b"tmpfs", 0, None)
    row("mount", "OK" if res == -1 else "SUCCEEDED", errno.errorcode.get(ctypes.get_errno(), f"returned {res}"))
    ctypes.set_errno(0)
    res = lib.unshare(0x10000000 | 0x00020000)  # CLONE_NEWUSER | CLONE_NEWNS
    row("unshare", "OK" if res == -1 else "SUCCEEDED", errno.errorcode.get(ctypes.get_errno(), f"returned {res}"))
    try:
        os.mknod(os.path.join(os.environ["SANDBOX_WORK"], "node"), 0o600 | 0o020000, os.makedev(1, 3))
        row("mknod", "SUCCEEDED", "created a device node")
    except OSError as exc:
        row("mknod", "OK", errno.errorcode.get(exc.errno, "error"))
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
        row("raw socket", "SUCCEEDED", "opened")
    except OSError as exc:
        row("raw socket", "OK", errno.errorcode.get(exc.errno, "error"))
    try:
        with open("/proc/sys/kernel/hostname", "w") as handle:
            handle.write("canary")
        row("write /proc/sys", "SUCCEEDED", "written")
    except OSError as exc:
        row("write /proc/sys", "OK", errno.errorcode.get(exc.errno, "error"))
    _syscall_row("load a kernel module", 175, (0, 0, 0))  # init_module on x86-64


RUN_MARKER_PREFIX = ".tectac-run-marker-"


def run_marker_name(plan):
    """1.18.15: the marker file name the root helper chose for /run (prefix plus 16 hex digits). Anything else is ignored: the plan can name a
    file, never a path."""
    name = plan.get("run_marker") if isinstance(plan, dict) else None
    if isinstance(name, str) and name.startswith(RUN_MARKER_PREFIX) and len(name) == len(RUN_MARKER_PREFIX) + 16 \
            and all(ch in "0123456789abcdef" for ch in name[len(RUN_MARKER_PREFIX):]):
        return name
    return None


def g_writes(plan):
    marker = run_marker_name(plan)
    for folder in ("/usr", "/usr/local", "/usr/bin", "/etc", "/var", "/boot", "/opt", "/run", "/sys"):
        keep = folder == "/run" and marker is not None
        path = os.path.join(folder, marker if keep else ".tectac-write-test")
        try:
            with open(path, "w") as handle:
                handle.write("x")
            if keep:  # 1.18.15: /run is left written. The marker lives in the unit's tmpfs; the helper checks from outside that it stays there
                print(f"CANARYRUNMARKER\t{marker}", flush=True)
            else:
                os.unlink(path)
            row("write " + folder, "SUCCEEDED", "written")
        except OSError as exc:
            row("write " + folder, "OK", errno.errorcode.get(exc.errno, "error"))


def g_runview(plan):
    """1.18.16: the next run after ``writes`` answers one question: is the marker the writes run left (named by the helper in the plan) in this
    run's /run? One line, ``CANARYRUNSEEN<TAB>1`` or ``0``; no listing, so no cut can hide the marker. Not a table row. No valid marker name in
    the plan, or a /run that cannot be checked, prints nothing (the helper then reports NOT RUN)."""
    marker = run_marker_name(plan)
    if marker is None:
        return
    try:
        seen = marker in os.listdir("/run")
    except OSError:
        return
    print(f"CANARYRUNSEEN	{1 if seen else 0}", flush=True)


def g_processes(plan):
    pids = [p for p in os.listdir("/proc") if p.isdigit()]
    row("host processes invisible", "OK" if len(pids) <= 6 else "SUCCEEDED", f"{len(pids)} process entries")
    row("pid 1 invisible", "SUCCEEDED" if os.path.exists("/proc/1/cmdline") else "OK", "visible" if os.path.exists("/proc/1/cmdline") else "not found")


MEM_STEP_MIB = 4  # 1.18.15: small steps, so the last number printed is close to where the kernel stopped the run
MEM_STEP_SLEEP = 0.02  # 1.18.15: lets the helper's fast poll see the cgroup while it still exists


def allocate_block(mib):
    """One block with every page written (a copy of one byte is touched, not just reserved). A test replaces this name."""
    return bytearray(b"\x01") * (mib * 1024 * 1024)


def g_mem(plan):
    """Allocate in 4 MiB steps, writing every page, up to the plan's ``alloc_mb`` (the helper sends twice MemoryMax), and report the total after
    each step (flushed), so the helper still knows how far the run got when the kernel kills it. The lines are not table rows: the root helper
    reads the last CANARYMEM number and the CANARYEND word, which names how the probe ended (memoryerror, enomem, other:<ExceptionName>, done).
    A refused allocation prints the row 'MemoryError at <N> MiB' (or 'enomem at <N> MiB'): N is what was held before the refused step. A
    SIGKILL from the kernel prints no end word; the helper then needs the kernel's own oom_kill counter."""
    blocks = []
    ended = "done"
    try:
        for _ in range(int(plan.get("alloc_mb", 600)) // MEM_STEP_MIB):
            blocks.append(allocate_block(MEM_STEP_MIB))
            print(f"CANARYMEM\t{len(blocks) * MEM_STEP_MIB}", flush=True)
            time.sleep(MEM_STEP_SLEEP)
        row("memory beyond MemoryMax", "SUCCEEDED", f"allocated {len(blocks) * MEM_STEP_MIB} MiB")
    except MemoryError:
        ended = "memoryerror"
        row("memory beyond MemoryMax", "OK", f"MemoryError at {len(blocks) * MEM_STEP_MIB} MiB")
    except OSError as exc:
        if exc.errno == errno.ENOMEM:
            ended = "enomem"
            row("memory beyond MemoryMax", "OK", f"enomem at {len(blocks) * MEM_STEP_MIB} MiB")
        else:
            ended = "other:" + type(exc).__name__
            raise
    except BaseException as exc:
        ended = "other:" + type(exc).__name__
        raise
    finally:
        print(f"CANARYEND\t{clean(ended, 60)}", flush=True)


def g_fork(plan):
    children, error = [], "none"
    try:
        for _ in range(int(plan.get("forks", 300))):
            pid = os.fork()
            if pid == 0:
                time.sleep(30)
                os._exit(0)
            children.append(pid)
    except OSError as exc:
        error = errno.errorcode.get(exc.errno, "error")
    count = len(children)
    for pid in children:
        try:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        except OSError:
            pass
    row("fork bomb", "OK" if error != "none" else "SUCCEEDED", f"{count} children, then {error}")


def g_loop(plan):
    while True:
        pass


def g_scratch(plan):
    path = os.path.join(os.environ["SANDBOX_WORK"], "fill")
    written = 0
    try:
        with open(path, "wb") as handle:
            for _ in range(int(plan.get("fill_mb", 64))):
                handle.write(b"\x02" * (1024 * 1024))
                handle.flush()
                written += 1
        row("scratch past its size", "SUCCEEDED", f"wrote {written} MiB")
    except OSError as exc:
        row("scratch past its size", "OK", f"{errno.errorcode.get(exc.errno, 'error')} after {written} MiB")


def g_flood(plan):
    chunk = b"x" * 1024
    for _ in range(int(plan.get("flood_kib", 256))):
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
    row("stdout past its cap", "SUCCEEDED", "wrote everything")


def _abstract_connect(name):
    """How an abstract unix socket (the name's bytes are kept exactly, latin-1) answers: ('connected', ''), ('unreachable', '') when a socket
    was made and the connect failed, or ('refused', <errno name>) when no socket could be made at all (1.17.124: AF_UNIX is not allowed).
    Stream and seqpacket are both tried. It never raises for a creation failure."""
    address = b"\0" + name.encode("latin-1", "replace")
    refused, tried = "", False
    for kind in (socket.SOCK_STREAM, getattr(socket, "SOCK_SEQPACKET", socket.SOCK_STREAM)):
        try:
            s = socket.socket(socket.AF_UNIX, kind)
        except OSError as exc:
            refused = errno.errorcode.get(exc.errno, "error")
            continue
        tried = True
        s.settimeout(0.3)
        try:
            s.connect(address)
            return "connected", ""
        except OSError:
            pass
        finally:
            s.close()
    if not tried and refused:
        return "refused", refused
    return "unreachable", ""


def g_abstract(plan):
    """1.17.123: root lists the host's abstract listeners before the run (this unit cannot read /proc/net/unix) and passes them in the plan;
    every one is tried here and only a name and a verdict are printed, never any content. No list in the plan prints nothing (the table says
    NOT RUN). Information only: whether a throw-away listener of root's own is reachable shows whether the abstract namespace is shared.
    1.17.124: with AF_UNIX refused, creating the socket failed; every name refused at creation is OK 'all refused'. 1.18.24 (AD-65 Patch B):
    AF_UNIX is allowed again, for the egress door only; abstract names belong to the run's own network space, so a host name must not connect
    ('none reachable'); a name that connects is SUCCEEDED. The plan may say how many names root left out to keep the plan under the 64 KiB
    stdin read (abstract_left_out); the count is shown."""
    probe = plan.get("abstract_probe")
    if probe:
        state, why = _abstract_connect(probe)
        row("abstract probe listener (information)", "OK",
            "reachable: the abstract namespace is shared with the host" if state == "connected"
            else f"not reachable from this unit (socket refused: {why})" if state == "refused" else "not reachable from this unit")
    left_out = int(plan.get("abstract_left_out") or 0)
    if "abstract_left_out" in plan:
        row("abstract sockets left out (information)", "OK", f"{left_out} left out (covered by the unix socket creation rows)")
    if "abstract" not in plan:
        return
    names = [str(n) for n in plan.get("abstract", [])]
    deadline = time.monotonic() + float(plan.get("abstract_seconds", 40))
    reached, refused, tried = [], [], 0
    for name in names:
        if time.monotonic() > deadline:
            break
        tried += 1
        state, why = _abstract_connect(name)
        if state == "connected":
            reached.append(name)
        elif state == "refused":
            refused.append(why)
    counts = f"{len(names)} listed, {left_out} left out"
    if tried < len(names):
        row(f"abstract sockets ({len(names)} listed)", "NOTRUN", f"only {tried} of {len(names)} could be tried in time")
        return
    if reached:
        row(f"abstract sockets ({len(names)} listed)", "SUCCEEDED",
            "Medium finding R1, connected to: " + ", ".join("@" + n for n in reached[:5]) + f" ({counts})")
    elif names and len(refused) == len(names):
        row(f"abstract sockets ({len(names)} listed)", "OK", f"all refused: {refused[0]} ({counts})")
    else:
        row(f"abstract sockets ({len(names)} listed)", "OK", f"none reachable ({counts})")


def g_cred(plan):
    folder = os.environ.get("CREDENTIALS_DIRECTORY", "")
    token = plan.get("credential_token", "")
    try:
        with open(os.path.join(folder, "auth"), "r", encoding="utf-8") as handle:
            same = handle.read() == token
        row("credential arrives", "OK" if same else "SUCCEEDED", "arrived in CREDENTIALS_DIRECTORY" if same else "wrong content")
        row("credential mode", "OK" if oct(os.stat(os.path.join(folder, "auth")).st_mode & 0o777) in ("0o400", "0o440") else "SUCCEEDED",
            oct(os.stat(os.path.join(folder, "auth")).st_mode & 0o777))
    except OSError as exc:
        row("credential arrives", "SUCCEEDED", f"not readable ({errno.errorcode.get(exc.errno, 'error')})")
    leak = [k for k, v in os.environ.items() if token and token in v]
    row("credential not in environment", "SUCCEEDED" if leak else "OK", "found in " + ",".join(leak) if leak else "absent")
    for path in ("/run/tec-tac/sandbox/secrets", "/run/tec-tac"):
        row("secrets folder " + path, "SUCCEEDED" if os.path.exists(path) else "OK", "visible" if os.path.exists(path) else "not found")
    with open(os.path.join(os.environ["SANDBOX_OUT"], "credential"), "w", encoding="utf-8") as handle:
        handle.write("refreshed-" + token)
    time.sleep(float(plan.get("hold_seconds", 0)))


def g_sleep(plan):
    time.sleep(float(plan.get("hold_seconds", 10)))


def g_noop(plan):
    return None


GROUPS = {
    "files": g_files, "rootview": g_rootview, "work_hold": g_work_hold, "work_peer": g_work_peer, "sockets": g_sockets, "loopback": g_loopback, "lan": g_lan,
    "privilege": g_privilege, "writes": g_writes, "processes": g_processes, "mem": g_mem,
    "runview": g_runview, "fork": g_fork, "loop": g_loop, "scratch": g_scratch, "flood": g_flood, "abstract": g_abstract, "cred": g_cred, "sleep": g_sleep,
    "noop": g_noop,
}


# ------------------------------------------------------------------------------------------------ Patch B network rows (1.18.23, flipped in 1.18.24)
# These probes describe what a run can do on the network. They live in NETWORK_GROUPS, not GROUPS, so the root helper's CANARY_GROUPS and its normal
# table stay as they are; the root driver tests/sandbox-canary-network-1.18.24.py starts this group through the real launch path, with an allowed
# host so the run has its egress door. Row rule: SUCCEEDED when the run can do what Patch B forbids, OK when it cannot, SKIP when the host itself
# cannot do the thing (the row's OWN control is missing), NOTRUN when the probe proves nothing. After Patch B every row must be OK.
NET_PUBLIC_TARGET = "1.1.1.1"
NET_PUBLIC_OTHER = "9.9.9.9"  # a host no runner is allowed to reach
NET_PUBLIC_V6 = "2606:4700:4700::1111"
NET_PROXY_DEFAULT = ("127.0.0.1", 3128)  # Patch B's in-unit forwarder; its own port is never counted as a host service
NET_PUBLIC_SECONDS = 2.5
NET_LOCAL_SECONDS = 0.5  # one host-service connect; NET_HOST_PORTS_MAX x this stays well under the run's time limit (45 s) even if nothing ran in parallel
NET_LOCAL_DEADLINE = 15.0  # no host-service probe starts after this many seconds; what is done is printed, never an empty row
NET_HOST_PORTS_MAX = 40
NET_LISTEN_SECONDS = 8.0
NET_LISTEN_BIND = "0.0.0.0"  # inside the unit's own network space only; a test on a development PC passes 127.0.0.1
NET_REFUSED_CREATE = (errno.EAFNOSUPPORT, errno.EPERM, errno.EACCES)
NET_NO_DOOR = "the proxy door is not reachable from the run (no listener on 127.0.0.1:3128)"
NET_CHECK_SECONDS = 5.0

R_PUB_443 = "public tcp 443 to 1.1.1.1"
R_PUB_80 = "public tcp 80 to 1.1.1.1"
R_PUB_OTHER = "public tcp 443 to 9.9.9.9"
R_PUB_DIRECT = "tcp 443 to the allowed host's own address, no proxy"
R_DNS_LISTED = "resolv.conf lists a name server"
R_DNS_GAI = "getaddrinfo resolves example.com"
R_DNS_LISTED_ASK = "udp 53 answered by the listed name server"
R_DNS_PUBLIC_ASK = "udp 53 answered by public 9.9.9.9"
R_LISTEN = "listener reachable from the host"
R_PROC_TCP = "proc net tcp lists host sockets"
R_PROC_UDP = "proc net udp lists host sockets"
R_IFACES = "network interfaces other than lo visible"
R_ROUTE = "default route visible"
R_PACKET = "AF_PACKET socket"
R_RAW = "raw ICMP socket"
R_NETLINK = "AF_NETLINK route socket"
R_INET6 = "AF_INET6 socket creation"
R_PING = "ICMP ping socket echo to 1.1.1.1"
R_V6_443 = "tcp 443 to 2606:4700:4700::1111"
R_LOOPBACK = "host loopback services"
R_OWN = "own address tcp 22, 80, 443"
R_GATEWAY = "default gateway tcp 80, 443"
R_PROXY_OK = "proxy CONNECT to the allowed host on 443 answers 200"
R_PROXY_HOST = "proxy refuses a host not in allowed_hosts"
R_PROXY_IP = "proxy refuses an IP literal"
R_PROXY_PRIVATE = "proxy refuses a private address"
R_PROXY_OWN = "proxy refuses this server's own address"
R_PROXY_80 = "proxy refuses the allowed host on port 80"
R_PROXY_22 = "proxy refuses the allowed host on port 22"
R_PROXY_OWN_NAME = "proxy refuses this server's own domain"  # 1.18.25
NETWORK_ROW_NAMES = (R_PUB_443, R_PUB_80, R_PUB_OTHER, R_PUB_DIRECT, R_DNS_LISTED, R_DNS_GAI, R_DNS_LISTED_ASK, R_DNS_PUBLIC_ASK, R_LISTEN, R_PROC_TCP,
                     R_PROC_UDP, R_IFACES, R_ROUTE, R_PACKET, R_RAW, R_NETLINK, R_INET6, R_PING, R_V6_443, R_LOOPBACK, R_OWN, R_GATEWAY, R_PROXY_OK,
                     R_PROXY_HOST, R_PROXY_IP, R_PROXY_PRIVATE, R_PROXY_OWN, R_PROXY_80, R_PROXY_22, R_PROXY_OWN_NAME)


def make_socket(family, kind, proto=0):
    """The one place a probe socket is made (a test replaces this name)."""
    return socket.socket(family, kind, proto)


def read_proc(path):
    """A /proc file as text, or None when it cannot be read (a test replaces this name)."""
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            return handle.read(1024 * 1024)
    except OSError:
        return None


def if_names():
    """Interface names: if_nameindex() first, /proc/self/net/dev when that is refused (glibc needs netlink for it). None when neither works."""
    try:
        return [name for _index, name in socket.if_nameindex()]
    except (OSError, AttributeError):
        pass
    text = read_proc("/proc/self/net/dev")
    if text is None:
        return None
    return [line.split(":", 1)[0].strip() for line in text.splitlines()[2:] if ":" in line]


def resolve_v4(name):
    """Addresses of ``name`` through the system resolver, with a time limit (getaddrinfo has none). [] when it did not resolve."""
    found = []

    def work():
        try:
            found.extend(item[4][0] for item in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM))
        except OSError:
            pass

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(NET_CHECK_SECONDS)
    return list(found)


def icmp_echo(address):
    """'reply', 'noreply' or an errno name when the ping socket (SOCK_DGRAM, IPPROTO_ICMP) cannot be made or used."""
    try:
        s = make_socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError as exc:
        return _errname(exc)
    try:
        s.settimeout(2)
        body = struct.pack(">BBHHH", 8, 0, 0, 0, 1) + b"tectac"
        total = sum(struct.unpack(f">{len(body) // 2}H", body))
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        packet = struct.pack(">BBHHH", 8, 0, (~total) & 0xFFFF, 0, 1) + b"tectac"
        s.sendto(packet, (address, 0))
        data, _peer = s.recvfrom(1024)
        return "reply" if data else "noreply"
    except TimeoutError:
        return "noreply"
    except OSError as exc:
        return _errname(exc)
    finally:
        s.close()


def proxy_status(proxy, target_host, target_port):
    """The HTTP status the proxy answers a CONNECT with: an int, 0 for a closed or unreadable answer, or None when the proxy cannot be reached."""
    try:
        s = make_socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    try:
        s.settimeout(3)
        try:
            s.connect(proxy)
        except OSError:
            return None
        try:
            s.sendall(f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n".encode("ascii", "replace"))
            head = s.recv(512).split(b"\r\n", 1)[0].split()
        except OSError:
            return 0
        return int(head[1]) if len(head) >= 2 and head[0].startswith(b"HTTP/") and head[1].isdigit() else 0
    finally:
        s.close()


def proxy_address():
    """HTTPS_PROXY (``http://host:port``) when the run has one, else Patch B's default 127.0.0.1:3128."""
    value = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    rest = value.split("://", 1)[-1].split("/", 1)[0]
    host, _, port = rest.rpartition(":")
    if host and port.isdigit():
        return host, int(port)
    return NET_PROXY_DEFAULT


def net_row(name, probe):
    """Run one probe that returns (tag, text) and print its row once. A probe that raises is NOTRUN, never a missing line."""
    try:
        tag, text = probe()
    except (OSError, ValueError, TypeError, LookupError, AttributeError, RuntimeError, struct.error) as exc:  # one broken probe must not take the group down
        tag, text = "NOTRUN", "probe failed: " + type(exc).__name__
    row(name, tag, text)


def _skip_unless(flag, why):
    return None if flag else ("SKIP", why)


def _reach(host, port, flag, why, family=socket.AF_INET, timeout=NET_PUBLIC_SECONDS):
    skipped = _skip_unless(flag, why)
    if skipped:
        return skipped
    try:
        result = tcp_connect(host, port, timeout=timeout, family=family)
    except OSError as exc:
        result = _errname(exc)
    return ("SUCCEEDED", "connected: the run can reach it") if result == "connected" else ("OK", result)


def _sock_refused(family_name, kind_name, proto=0):
    """One socket creation that Patch B forbids: refused (EAFNOSUPPORT, EPERM, EACCES) is OK, created is SUCCEEDED, any other error NOTRUN."""
    family, kind = getattr(socket, family_name, None), getattr(socket, kind_name, None)
    if family is None or kind is None:
        return "NOTRUN", "cannot try: " + family_name + " is not available here"
    try:
        s = make_socket(family, kind, proto)
    except OSError as exc:
        if exc.errno in NET_REFUSED_CREATE:
            return "OK", "refused: " + _errname(exc)
        return "NOTRUN", "unexpected error " + _errname(exc)
    s.close()
    return "SUCCEEDED", "the socket was created"


def _proc_rows(proc_tables):
    """Rows from the /proc/self/net tables, read before any probe socket exists (so a private network namespace shows none of its own)."""
    out = {}
    for name, files in ((R_PROC_TCP, ("tcp", "tcp6")), (R_PROC_UDP, ("udp", "udp6"))):
        listen = other = 0
        readable = False
        for file in files:
            text = proc_tables.get(file)
            if text is None:
                continue
            readable = True
            for line in text.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                if parts[1].rpartition(":")[2].upper() == f"{NET_PROXY_DEFAULT[1]:04X}":
                    continue  # Patch B's own forwarder is not a host socket
                if parts[3] == "0A":
                    listen += 1
                else:
                    other += 1
        if not readable:
            out[name] = ("OK", "not readable")
        elif listen + other:
            out[name] = ("SUCCEEDED", f"{listen} LISTEN and {other} other socket lines of the host are visible")
        else:
            out[name] = ("OK", "no socket lines visible")
    return out


def _route_row(text):
    if text is None:
        return "OK", "not readable"
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 8 and parts[1] == "00000000" and parts[7] == "00000000":
            return "SUCCEEDED", "a default route is visible"
    return "OK", "no default route visible"


def _iface_row():
    names = if_names()
    if names is None:
        return "OK", "the interface list cannot be read"
    others = [n for n in names if n != "lo"]
    if others:
        return "SUCCEEDED", "visible: " + ", ".join(others[:5]) + (f" (+{len(others) - 5} more)" if len(others) > 5 else "")
    return "OK", "only lo is visible"


def _listen_row(seconds, bind_host=NET_LISTEN_BIND):
    """Bind ``bind_host`` (0.0.0.0 inside the unit), print ``CANARYLISTEN<TAB>port`` so the root driver can look for the port in the HOST's own
    network namespace, and accept for ``seconds``. A connection from the host is SUCCEEDED too, but the driver decides this row from ``ss``."""
    try:
        srv = make_socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return ("OK", "socket refused: " + _errname(exc)) if exc.errno in NET_REFUSED_CREATE else ("NOTRUN", "unexpected error " + _errname(exc))
    try:
        srv.bind((bind_host, 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        with ROW_LOCK:
            sys.stdout.write(f"CANARYLISTEN\t{port}\n")
            sys.stdout.flush()
        srv.settimeout(seconds)
        try:
            conn, peer = srv.accept()
        except TimeoutError:
            return "OK", f"no connection arrived in {seconds:g} s"
        conn.close()
        return "SUCCEEDED", "a connection from " + clean(peer[0], 40) + " arrived: the host can reach a run's listener"
    except OSError as exc:
        return ("OK", "bind refused: " + _errname(exc)) if exc.errno in NET_REFUSED_CREATE else ("NOTRUN", "unexpected error " + _errname(exc))
    finally:
        srv.close()


def _dns_rows(plan, run):
    """The DNS rows. Each has its own host control: the host resolved (rows 1 and 2), asked its listed name server (row 3) or asked 9.9.9.9 (row 4)."""
    ok = bool(plan.get("host_dns"))
    why = "the host itself cannot resolve, so this row has no control"
    listed = []
    text = read_proc("/etc/resolv.conf") or ""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            listed.append(parts[1])

    def resolves():
        found = resolve_v4("example.com")
        return ("SUCCEEDED", "resolved to " + found[0]) if found else ("OK", "did not resolve")

    def ask(address):
        return ("SUCCEEDED", "answered by " + address) if dns_query(address) else ("OK", "no answer from " + address)

    run(R_DNS_LISTED, lambda: _skip_unless(ok, why) or (("SUCCEEDED", "listed: " + ", ".join(listed[:3])) if listed else ("OK", "no name server listed")))
    run(R_DNS_GAI, lambda: _skip_unless(ok, why) or resolves())
    run(R_DNS_LISTED_ASK, lambda: _skip_unless(plan.get("host_udp53_listed"), "the host itself got no answer from its first listed name server, so this row has no control")
        or (ask(plan.get("listed_name_server") or listed[0]) if (plan.get("listed_name_server") or listed) else ("OK", "no name server listed")))
    run(R_DNS_PUBLIC_ASK, lambda: _skip_unless(plan.get("host_udp53_9999"), "the host itself got no answer from 9.9.9.9, so this row has no control")
        or ask(NET_PUBLIC_OTHER))


def _host_rows(plan, run, side):
    """The host-services rows. Their probes are split into separate pool jobs (``side``) with a deadline, so 40 slow ports can never eat the run's
    time; the row is printed after the pool finished, from what was done (a partial result says how many ports were tried)."""
    ports = [int(p) for p in plan.get("loopback_ports", []) if int(p) != NET_PROXY_DEFAULT[1]][:NET_HOST_PORTS_MAX]
    own = [str(a) for a in plan.get("own", []) if ":" not in str(a)][:4]
    gateways = [str(g) for g in plan.get("gateways", []) if ":" not in str(g)][:4]
    deadline = time.monotonic() + NET_LOCAL_DEADLINE
    done = {"loop": {}, "own": {}, "gateway": {}}

    def attempt(kind, host, port, reached_test):
        if time.monotonic() >= deadline:
            return
        done[kind][(host, port)] = reached_test(tcp_connect(host, port, timeout=NET_LOCAL_SECONDS))

    for port in ports:
        side.append(lambda port=port: attempt("loop", "127.0.0.1", port, lambda result: result == "connected"))
    for address in own:
        for port in (22, 80, 443):
            side.append(lambda address=address, port=port: attempt("own", address, port, _reached))
    for address in gateways:
        for port in (80, 443):
            side.append(lambda address=address, port=port: attempt("gateway", address, port, _reached))

    def summary(kind, total, empty, dropped):
        def probe():
            if not total:
                return "SKIP", empty
            hits = sorted(f"{host}:{port}" for (host, port), reached in done[kind].items() if reached)
            tried = len(done[kind])
            if hits:
                return "SUCCEEDED", "reached " + ", ".join(hits[:5])
            note = "" if tried >= total else f" (partial: {tried} of {total} tried before the deadline)"
            return "OK", dropped + note
        return probe

    run(R_LOOPBACK, summary("loop", len(ports), "the plan listed no listening port of the host", f"none of {len(ports)} ports connected"), after_pool=True)
    run(R_OWN, summary("own", len(own) * 3, "the plan listed no address of this server", f"dropped or refused by address ({len(own)} address(es))"), after_pool=True)
    run(R_GATEWAY, summary("gateway", len(gateways) * 2, "the plan listed no default gateway", f"dropped or refused by address ({len(gateways)} gateway(s))"), after_pool=True)


def _proxy_rows(plan, run):
    """The proxy door (1.18.24). The positive control is one CONNECT to the allowed host: 200 is OK, and it is SKIPPED when the host itself cannot
    reach that host (a control that cannot work is never OK). Each refusal row sends a CONNECT that must be refused: a 200 is SUCCEEDED. A door
    that cannot be reached is NOTRUN."""
    proxy = proxy_address()
    allowed = str(plan.get("allowed_host") or "")
    own = [str(a) for a in plan.get("own", []) if ":" not in str(a)]
    other = "example.net" if allowed != "example.net" else "example.org"
    cases = ((R_PROXY_HOST, other, 443), (R_PROXY_IP, NET_PUBLIC_TARGET, 443), (R_PROXY_PRIVATE, "10.255.255.254", 443),
             (R_PROXY_OWN, own[0] if own else "", 443), (R_PROXY_80, allowed, 80), (R_PROXY_22, allowed, 22))
    state = {}

    def up():
        if "up" not in state:
            state["up"] = proxy_status(proxy, NET_PUBLIC_TARGET, 443) is not None
        return state["up"]

    def positive():
        if not plan.get("host_tcp443_allowed"):
            return "SKIP", "the host itself cannot reach the allowed host on 443 (no public route), so this positive control cannot work"
        if not allowed or not up():
            return "NOTRUN", NET_NO_DOOR
        status = proxy_status(proxy, allowed, 443)
        if status is None:
            return "NOTRUN", NET_NO_DOOR
        return ("OK", "answered 200") if status == 200 else ("NOTRUN", f"the positive control answered {status or 'nothing'}, not 200")

    def refusal(host, port):
        if not host:
            return "SKIP", "the plan named no host for this row (no address of this server was listed)"
        if not up():
            return "NOTRUN", NET_NO_DOOR
        status = proxy_status(proxy, host, port)
        if status is None:
            return "NOTRUN", NET_NO_DOOR
        return ("SUCCEEDED", f"the proxy opened a tunnel (200) to {host}:{port}") if status == 200 else ("OK", f"refused ({status or 'closed'})")

    def own_domain():
        """1.18.25: CONNECT to one of this server's own names, which the plan also lists in allowed_hosts. 403 is OK (the host driver then checks the
        audit reason is own_name); 200 is SUCCEEDED (a hairpin back to this server). A plan with no own domain is NOTRUN with the helper's plain reason."""
        name = str(plan.get("own_domain") or "")
        if not name:
            return "NOTRUN", str(plan.get("own_domain_reason") or "the plan named no own domain of this server")[:200]
        if not up():
            return "NOTRUN", NET_NO_DOOR
        status = proxy_status(proxy, name, 443)
        if status is None:
            return "NOTRUN", NET_NO_DOOR
        return ("SUCCEEDED", f"the proxy opened a tunnel (200) to {name}:443") if status == 200 else ("OK", f"refused ({status or 'closed'})")

    run(R_PROXY_OK, positive)
    for name, host, port in cases:
        run(name, lambda host=host, port=port: refusal(host, port))
    run(R_PROXY_OWN_NAME, own_domain)


def g_patchb_network(plan):
    # 1. what the kernel shows, read first: no probe socket exists yet
    tables = {name: read_proc("/proc/self/net/" + name) for name in ("tcp", "tcp6", "udp", "udp6")}
    for name, result in _proc_rows(tables).items():
        row(name, *result)
    net_row(R_ROUTE, lambda: _route_row(read_proc("/proc/self/net/route")))
    net_row(R_IFACES, _iface_row)
    # 2. the listener waits in its own thread while the host looks for its port
    try:
        seconds = float(plan.get("listen_seconds") or NET_LISTEN_SECONDS)
    except (TypeError, ValueError):
        seconds = NET_LISTEN_SECONDS
    bind_host = str(plan.get("listen_bind") or NET_LISTEN_BIND)
    listener = threading.Thread(target=net_row, args=(R_LISTEN, lambda: _listen_row(seconds, bind_host)), daemon=True)
    listener.start()
    # 3. every other probe, in a small pool (TasksMax counts threads)
    jobs, side, after = [], [], []

    def run(name, probe, after_pool=False):
        (after if after_pool else jobs).append((name, probe))

    why = "the host itself cannot reach it, so this row has no control"
    run(R_PUB_443, lambda: _reach(NET_PUBLIC_TARGET, 443, plan.get("host_tcp443_1111"), why))
    run(R_PUB_80, lambda: _reach(NET_PUBLIC_TARGET, 80, plan.get("host_tcp80_1111"), why))
    run(R_PUB_OTHER, lambda: _reach(NET_PUBLIC_OTHER, 443, plan.get("host_tcp443_9999"), why))
    address = str(plan.get("allowed_host_address") or "")
    run(R_PUB_DIRECT, lambda: _reach(address, 443, plan.get("host_tcp443_allowed") and bool(address), "the allowed host did not resolve on the host, or the host cannot reach it"))
    _dns_rows(plan, run)
    run(R_PACKET, lambda: _sock_refused("AF_PACKET", "SOCK_RAW", 3))
    run(R_RAW, lambda: _sock_refused("AF_INET", "SOCK_RAW", getattr(socket, "IPPROTO_ICMP", 1)))
    run(R_NETLINK, lambda: _sock_refused("AF_NETLINK", "SOCK_RAW", 0))
    run(R_INET6, lambda: _sock_refused("AF_INET6", "SOCK_STREAM"))

    def ping():
        skipped = _skip_unless(plan.get("host_ping"), "the host itself cannot ping it, so this row has no control")
        if skipped:
            return skipped
        result = icmp_echo(NET_PUBLIC_TARGET)
        return ("SUCCEEDED", "an echo reply came back") if result == "reply" else ("OK", result)

    def v6():
        skipped = _skip_unless(plan.get("host_ipv6"), "the host itself has no IPv6 route, so this row has no control")
        if skipped:
            return skipped
        try:
            return _reach(NET_PUBLIC_V6, 443, True, "", family=socket.AF_INET6)
        except OSError as exc:
            return "OK", _errname(exc)

    run(R_PING, ping)
    run(R_V6_443, v6)
    _host_rows(plan, run, side)
    _proxy_rows(plan, run)
    with ThreadPoolExecutor(max_workers=LOOPBACK_WORKERS) as pool:
        futures = [pool.submit(net_row, *job) for job in jobs]
        futures += [pool.submit(_quiet, work) for work in side]  # the host-service probes: one connect each, in parallel, each with the deadline inside it
        for future in futures:
            future.result()
    for job in after:  # printed from what the side jobs finished
        net_row(*job)
    listener.join(seconds + 5)


def _quiet(work):
    try:
        work()
    except (OSError, ValueError, TypeError, LookupError, RuntimeError):
        pass


NETWORK_GROUPS = {"patchb_network": g_patchb_network}


# ------------------------------------------------------------------------------------------------ Patch C canary rows (1.18.25, AD-65 canary-first)
# Rows only: nothing here fixes anything. These groups live in PATCHC_GROUPS, not GROUPS, so the root helper's CANARY_GROUPS and its normal canary are
# unchanged and nothing reaches them through --start; the host-side driver tests/sandbox-canary-patchc-1.18.25.py adds the group choice to its own copy
# of the canary row, exactly as the Patch B network group was added.
PC_ARCH = {  # raw syscall numbers per machine: (io_uring_setup, userfaultfd, keyctl)
    "x86_64": {"io_uring_setup": 425, "userfaultfd": 323, "keyctl": 250},
    "aarch64": {"io_uring_setup": 425, "userfaultfd": 282, "keyctl": 219},
}
PC_IO_URING = "io_uring_setup reachable"
PC_USERFAULTFD = "userfaultfd reachable"
PC_KEYCTL = "keyctl reachable"
PATCHC_SYSCALL_ROW_NAMES = (PC_IO_URING, PC_USERFAULTFD, PC_KEYCTL)
PC_PARAMS_SIZE = 256  # struct io_uring_params is 120 bytes; the buffer is bigger, and it is the only pointer a probe passes
PC_UFFD_USER_MODE_ONLY = 1  # UFFD_USER_MODE_ONLY: an unprivileged caller may use it even when vm.unprivileged_userfaultfd is 0, so EPERM then comes from the filter
PC_KEY_SPEC_SESSION_KEYRING = -3
PC_LEFTOVER_MARKER = "patchc-leftover-marker"


def machine_name():
    """The machine architecture (a test replaces this name)."""
    try:
        return os.uname().machine
    except AttributeError:
        return ""


def raw_syscall(number, *args):
    """One raw syscall through libc. Returns (result, errno). Arguments are integers or ctypes buffers; a test replaces this name."""
    lib = libc()
    lib.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = lib.syscall(ctypes.c_long(number), *args)
    return int(result), ctypes.get_errno()


def _syscall_verdict(name, number, args, closes_fd, context=""):
    """OK when the filter refused the call (EPERM), SUCCEEDED for any other answer that came from the kernel (success or an errno that is not EPERM),
    SKIP when the kernel has no such call (ENOSYS)."""
    result, err = raw_syscall(number, *args)
    if result >= 0:
        if closes_fd:
            try:
                os.close(result)
            except OSError:
                pass
        return "SUCCEEDED", f"the call was not refused: it returned {result if not closes_fd else 'a descriptor (closed at once)'}"
    if err == errno.ENOSYS:
        return "NOTRUN", f"the kernel has no {name} (ENOSYS)"
    if err == errno.EPERM:
        return "OK", "refused (EPERM)" + context
    return "SUCCEEDED", f"the filter did not refuse it: the kernel answered {errno.errorcode.get(err, err)}"


def g_patchc_syscalls(plan):
    numbers = PC_ARCH.get(machine_name())
    if numbers is None:
        for name in PATCHC_SYSCALL_ROW_NAMES:
            row(name, "NOTRUN", f"unknown machine architecture {clean(machine_name(), 20)!r}: no syscall numbers for it")
        return
    disabled = (read_proc("/proc/sys/kernel/io_uring_disabled") or "").strip()

    def io_uring():
        if disabled == "2":
            return "NOTRUN", "kernel.io_uring_disabled=2: the kernel itself refuses io_uring, so this row cannot show the filter"
        params = ctypes.create_string_buffer(PC_PARAMS_SIZE)
        return _syscall_verdict("io_uring_setup", numbers["io_uring_setup"], (ctypes.c_ulong(1), ctypes.byref(params)), True)

    def userfaultfd():
        return _syscall_verdict("userfaultfd", numbers["userfaultfd"], (ctypes.c_ulong(PC_UFFD_USER_MODE_ONLY),), True)

    def keyctl():
        # KEYCTL_GET_KEYRING_ID (0), the session keyring, create flag 0: reads nothing, creates nothing
        return _syscall_verdict("keyctl", numbers["keyctl"], (ctypes.c_ulong(0), ctypes.c_ulong(PC_KEY_SPEC_SESSION_KEYRING & 0xFFFFFFFFFFFFFFFF), ctypes.c_ulong(0)), False)

    for name, probe in ((PC_IO_URING, io_uring), (PC_USERFAULTFD, userfaultfd), (PC_KEYCTL, keyctl)):
        try:
            tag, actual = probe()
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            tag, actual = "NOTRUN", f"the probe could not run ({type(exc).__name__})"
        row(name, tag, actual)


def g_patchc_leftover(plan):
    """Writes a credential, forks a leftover that outlives this runner and keeps replacing the credential file with a marker for a few seconds. The
    host-side driver decides: a returned credential that carries the marker means the launcher read it while a leftover was alive."""
    marker = clean(plan.get("marker") or PC_LEFTOVER_MARKER, 64)
    try:
        seconds = max(1.0, min(float(plan.get("leftover_seconds") or 5), 10.0))
    except (TypeError, ValueError):
        seconds = 5.0
    folder = os.environ.get("SANDBOX_OUT", "")
    target = os.path.join(folder, "credential")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("original-" + marker[:8])
    pid = os.fork()
    if pid == 0:  # the leftover
        try:
            os.setsid()
            end = time.monotonic() + seconds
            count = 0
            while time.monotonic() < end:
                count += 1
                tmp = os.path.join(folder, f".leftover-{count % 2}")
                try:
                    with open(tmp, "w", encoding="utf-8") as handle:
                        handle.write(marker)
                    os.replace(tmp, target)
                except OSError:
                    pass
                time.sleep(0.02)
        finally:
            os._exit(0)
    time.sleep(0.3)  # the runner returns while the leftover is still alive


PATCHC_GROUPS = {"patchc_syscalls": g_patchc_syscalls, "patchc_leftover": g_patchc_leftover}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or (args[0] not in GROUPS and args[0] not in NETWORK_GROUPS and args[0] not in PATCHC_GROUPS):
        print("usage: sandbox-canary-runner <group>", file=sys.stderr)
        return 64
    raw = sys.stdin.read(65536)
    try:
        plan = json.loads(raw) if raw.strip() else {}
    except ValueError:
        plan = None
    if not isinstance(plan, dict):  # 1.17.124: a plan cut at the 64 KiB read must never look like an absent row
        row("plan unreadable", "NOTRUN", f"the plan for {args[0]} did not parse ({len(raw)} characters read)")
        return 0
    (GROUPS.get(args[0]) or NETWORK_GROUPS.get(args[0]) or PATCHC_GROUPS[args[0]])(plan)  # the Patch B (1.18.23) and Patch C (1.18.25) groups are kept out of GROUPS (the helper's CANARY_GROUPS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
