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
    """Pathname unix sockets of the host's services. 1.17.124: runs no longer get AF_UNIX (RestrictAddressFamilies=AF_INET), so socket() itself is
    refused (EAFNOSUPPORT) before any connect; the socket is therefore made inside the try and a refusal at creation is OK. Only a connect that
    works is SUCCEEDED. All 13 rows are always printed."""
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
    unix_creation_rows()
    control_rows()


UNIX_KINDS = (("stream", "SOCK_STREAM"), ("dgram", "SOCK_DGRAM"), ("seqpacket", "SOCK_SEQPACKET"))
UNIX_REFUSED = (errno.EAFNOSUPPORT, errno.EPERM)


def unix_creation_rows():
    """1.17.124: the filter itself. Creating an AF_UNIX socket must fail with EAFNOSUPPORT or EPERM; a socket that is created means the
    address family filter is not in force (ATTACK SUCCEEDED). Any other error is not evidence (NOTRUN)."""
    for label, constant in UNIX_KINDS:
        name = f"unix socket creation refused ({label})"
        try:
            s = socket.socket(socket.AF_UNIX, getattr(socket, constant, 0))
        except OSError as exc:
            if exc.errno in UNIX_REFUSED:
                row(name, "OK", _errname(exc))
            else:
                row(name, "NOTRUN", "unexpected error " + _errname(exc))
        except (AttributeError, ValueError) as exc:
            row(name, "NOTRUN", "cannot try: " + type(exc).__name__)
        else:
            s.close()
            row(name, "SUCCEEDED", "the socket was created: the address family filter is not in force")
    name = "unix pathname socket refused"
    path = os.path.join(os.environ.get("SANDBOX_WORK", "/work"), "canary.sock")
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as exc:
        if exc.errno in UNIX_REFUSED:
            row(name, "OK", _errname(exc))
        else:
            row(name, "NOTRUN", "unexpected error " + _errname(exc))
        return
    try:
        s.bind(path)
        row(name, "SUCCEEDED", "bound a unix socket in /work")
    except OSError as exc:
        row(name, "SUCCEEDED", "the socket was created (bind failed: " + _errname(exc) + ")")
    finally:
        s.close()
        try:
            os.unlink(path)
        except OSError:
            pass


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
    ports = [int(p) for p in plan.get("ports", [])]
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


def g_dns(plan):
    allowed = plan.get("resolver", "")
    if allowed:
        ok = dns_query(allowed)
        row("allowed resolver answers", "OK" if ok else "SUCCEEDED", "answered" if ok else "no answer (DNS broken)")
    for address in plan.get("other_resolvers", []):  # 1.17.123: the host's own resolv.conf entries; none given means the table says NOT RUN
        answered = dns_query(address)
        row(f"other resolver {address} dropped", "SUCCEEDED" if answered else "OK", "answered" if answered else "dropped")


def g_public(plan):
    result = tcp_connect(plan.get("public", "1.1.1.1"), 443, timeout=4)
    if result == "connected":
        row("public tcp 443", "OK", "connected")
    else:
        row("public tcp 443", "SKIP", f"no public route from this server ({result})")


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


def g_writes(plan):
    for folder in ("/usr", "/usr/local", "/usr/bin", "/etc", "/var", "/boot", "/opt", "/run", "/sys"):
        path = os.path.join(folder, ".tectac-write-test")
        try:
            with open(path, "w") as handle:
                handle.write("x")
            os.unlink(path)
            row("write " + folder, "SUCCEEDED", "written")
        except OSError as exc:
            row("write " + folder, "OK", errno.errorcode.get(exc.errno, "error"))


def g_processes(plan):
    pids = [p for p in os.listdir("/proc") if p.isdigit()]
    row("host processes invisible", "OK" if len(pids) <= 6 else "SUCCEEDED", f"{len(pids)} process entries")
    row("pid 1 invisible", "SUCCEEDED" if os.path.exists("/proc/1/cmdline") else "OK", "visible" if os.path.exists("/proc/1/cmdline") else "not found")


def g_mem(plan):
    """Allocate in 16 MiB blocks and report the total after each one (flushed), so the helper still knows how far the run got when the kernel
    kills it. The lines are not table rows: the root helper reads the last CANARYMEM number and the CANARYEND word, which names how the
    probe ended (memoryerror, enomem, other:<ExceptionName>, done). A SIGKILL from the kernel prints no end word; the helper then needs the
    kernel's own oom_kill counter."""
    blocks = []
    ended = "done"
    try:
        for _ in range(int(plan.get("alloc_mb", 600)) // 16):
            blocks.append(bytearray(b"\x01") * (16 * 1024 * 1024))
            print(f"CANARYMEM\t{len(blocks) * 16}", flush=True)
        row("memory beyond MemoryMax", "SUCCEEDED", f"allocated {len(blocks) * 16} MiB")
    except MemoryError:
        ended = "memoryerror"
        row("memory beyond MemoryMax", "OK", f"MemoryError after {len(blocks) * 16} MiB")
    except OSError as exc:
        ended = "enomem" if exc.errno == errno.ENOMEM else "other:" + type(exc).__name__
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
    1.17.124: with AF_UNIX gone, creating the socket is refused; every name refused at creation is OK 'all refused', a name that connects is
    SUCCEEDED. The plan may say how many names root left out to keep the plan under the 64 KiB stdin read (abstract_left_out); the count is
    shown, and every left-out name is covered by the 'unix socket creation refused' rows."""
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
    "files": g_files, "work_hold": g_work_hold, "work_peer": g_work_peer, "sockets": g_sockets, "loopback": g_loopback, "lan": g_lan,
    "dns": g_dns, "public": g_public, "privilege": g_privilege, "writes": g_writes, "processes": g_processes, "mem": g_mem,
    "fork": g_fork, "loop": g_loop, "scratch": g_scratch, "flood": g_flood, "abstract": g_abstract, "cred": g_cred, "sleep": g_sleep,
    "noop": g_noop,
}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0] not in GROUPS:
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
    GROUPS[args[0]](plan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
