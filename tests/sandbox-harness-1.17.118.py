"""Shared set-up for the 1.17.118 core.sandbox tests (not a test: the tests exec it, so no module and no bytecode is left behind).

It gives a test: a fake file-system layer (everything is root-owned and not writable, the technique of sandbox-helper-register-1.17.116.py),
the helper loaded as ``sh`` with every fixed location moved into a temp folder, a fake ``systemd-run`` and ``systemctl`` (small Python
programs that run the launcher and the runner as plain child processes, keep a log of what they were asked, and honour a stop request), a
runner registry row and a runner program, ``status.json`` and ``resolv.conf``.

Not runnable here: real systemd, cgroups, the unit's hidden file system and the address filter. That is what the dev02 canary proves.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import threading
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
BASE = Path(tempfile.mkdtemp(prefix="tectac-sbx118-"))


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


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
_SPEC = importlib.util.spec_from_file_location("sandbox_helper_118", HELPER)
sh = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sh)

EXT, LIB, STATE, RUN, ETC = BASE / "ext", BASE / "lib", BASE / "state", BASE / "run", BASE / "etc"
for folder in (EXT, LIB, STATE, RUN, ETC):
    folder.mkdir()
sh._ROOT_LAYOUT_ERROR = None
sh.EXTENSIONS_ROOT, sh.LIB_ROOT = EXT, LIB
sh.RUNNERS_ROOT, sh.REGISTRY_ROOT = LIB / "runners", LIB / "registry"
sh.STATE_ROOT, sh.RUN_ROOT = STATE, RUN
sh.STATUS_FILE, sh.AUDIT_FILE = STATE / "status.json", STATE / "audit.jsonl"
sh.SLOTS_ROOT, sh.PERSON_SLOTS_ROOT = RUN / "slots", RUN / "slots" / "person"
sh.SECRETS_ROOT, sh.HANDOFF_ROOT, sh.RUNS_ROOT = RUN / "secrets", RUN / "handoff", RUN / "runs"
sh.CANARY_FILE, sh.CANARY_MARKERS_FILE = STATE / "canary.json", RUN / "canary-markers.json"
sh.CANARY_DIR = LIB / "canary"
sh.CANARY_RUNNER_FILE = sh.CANARY_DIR / "sandbox-canary-runner.py"
sh.LAUNCHER_FILE = ROOT / "scripts" / "sandbox-launcher.py"
sh.WORK_DIR = str(BASE / "work")
sh.RESOLV_CONF = str(BASE / "resolv.conf")
sh.RESOLV_UPSTREAM = str(BASE / "upstream-resolv.conf")  # 1.17.123: the upstream list a start builds Core's own resolv.conf from
# 1.17.123: what `ip` would say about this server (a public address, its gateway, loopback); no real `ip` here
LOCAL = {"addresses": ["203.0.113.5", "127.0.0.1"], "gateways": ["203.0.113.1"], "extra": ["203.0.113.5/32", "203.0.113.1/32"]}
sh.local_deny_now = lambda: LOCAL
# the folders of this fake server are Windows paths here (a drive letter and backslashes); the real check refuses those, so only paths
# under BASE are let through, every other path still goes through the real rule
_real_bind_safe = sh._bind_path_safe
sh._bind_path_safe = lambda path: str(path).startswith(str(BASE)) or _real_bind_safe(path)
sh.PROC_MEMINFO = str(BASE / "meminfo")
(BASE / "work").mkdir()
(BASE / "meminfo").write_text("MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\n", encoding="utf-8")
(BASE / "resolv.conf").write_text("nameserver 127.0.0.53\noptions edns0\n", encoding="utf-8")
(BASE / "upstream-resolv.conf").write_text("nameserver 9.9.9.9" + chr(10) + "options edns0" + chr(10), encoding="utf-8")
for name in ("ssl-certs", "passwd", "group", "ld.so.cache", "ca-certificates", "nsswitch.conf", "localtime"):
    (ETC / name).write_text("x", encoding="utf-8")
sh.BASE_BINDS_REQUIRED = tuple(str(ETC / n) for n in ("ssl-certs", "passwd", "group", "ld.so.cache"))
sh.BASE_BINDS_OPTIONAL = tuple(str(ETC / n) for n in ("ca-certificates", "nsswitch.conf", "localtime"))

# ---------------------------------------------------------------------------------------------------------- fake systemd
FAKE_RUN = BASE / "fake-systemd-run.py"
FAKE_CTL = BASE / "fake-systemctl.py"
FAKE_RUN.write_text(r'''
import json, os, re, shutil, subprocess, sys, threading, time
base = os.environ["FAKE_BASE"]
args = sys.argv[1:]
unit, props, setenv, command = None, [], {}, []
for i, a in enumerate(args):
    if a == "--":
        # 1.17.120: systemd turns '$$' into '$' in ExecStart; so does this fake. '%' is left alone (the helper refuses it before any start)
        command = [re.sub(r"\$\$", lambda m: m.group()[0], item) for item in args[i + 1:]]
        break
    if a.startswith("--unit="):
        unit = a[7:]
    elif a.startswith("--property="):
        props.append(a[11:])
    elif a.startswith("--setenv="):
        k, v = a[9:].split("=", 1)
        setenv[k] = v
for d in ("log", "pids", "stop", "creds", "work"):
    os.makedirs(os.path.join(base, d), exist_ok=True)
with open(os.path.join(base, "log", unit + ".json"), "w") as h:
    json.dump({"args": args, "props": props, "setenv": setenv, "command": command, "environ_keys": sorted(os.environ)}, h)
workroot = os.environ["FAKE_WORK"]
per = os.path.join(base, "work", unit)
os.makedirs(per, exist_ok=True)
env = dict(os.environ)
for k, v in setenv.items():
    env[k] = per + v[len(workroot):] if v.startswith(workroot) else v
creds = [p for p in props if p.startswith("LoadCredential=")]
if creds:
    cd = os.path.join(base, "creds", unit)
    os.makedirs(cd, exist_ok=True)
    for c in creds:
        name, path = c[len("LoadCredential="):].split(":", 1)
        shutil.copyfile(path, os.path.join(cd, name))
    env["CREDENTIALS_DIRECTORY"] = cd
    for p in props:
        if p.startswith("ExecStartPost=+/bin/rm -rf "):
            shutil.rmtree(p.split("rm -rf ", 1)[1], ignore_errors=True)
idx = command.index("--")
if command[idx + 1].endswith(".py"):
    command[idx + 1:idx + 1] = [sys.executable]
opts = {"start_new_session": True} if os.name == "posix" else {}
child = subprocess.Popen(command, env=env, **opts)
with open(os.path.join(base, "pids", unit), "w") as h:
    h.write(str(child.pid))
stopped = {"v": False}
def watch():
    flag = os.path.join(base, "stop", unit)
    while child.poll() is None:
        if os.path.exists(flag):
            stopped["v"] = True
            if os.name == "posix":
                import signal
                os.killpg(child.pid, signal.SIGKILL)
            else:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(child.pid)], capture_output=True)
            return
        time.sleep(0.05)
threading.Thread(target=watch, daemon=True).start()
code = child.wait()
try:
    os.unlink(os.path.join(base, "pids", unit))
except OSError:
    pass
result = os.environ.get("FAKE_RESULT") or ("signal" if stopped["v"] else "success")
os.makedirs(os.environ["FAKE_HANDOFF"], exist_ok=True)
rid = unit[len("tectac-sbx-"):]
with open(os.path.join(os.environ["FAKE_HANDOFF"], rid + ".json"), "w") as h:
    json.dump({"memory_peak": 52428800, "cpu_ns": 1000, "result": result}, h)
sys.exit(code if code >= 0 else 1)
''', encoding="utf-8")
FAKE_CTL.write_text(r'''
import os, sys
base = os.environ["FAKE_BASE"]
args = sys.argv[1:]
if args[:1] == ["stop"]:
    os.makedirs(os.path.join(base, "stop"), exist_ok=True)
    unit = args[1][:-len(".service")]
    open(os.path.join(base, "stop", unit), "w").write("1")
    open(os.path.join(base, "stops.log"), "a").write(unit + "\n")
    sys.exit(0)
if args[:1] == ["is-active"]:
    unit = args[1][:-len(".service")]
    sys.exit(0 if os.path.exists(os.path.join(base, "pids", unit)) else 3)
if args[:1] == ["show"]:
    print("52428800")
    print("1000")
    sys.exit(0)
sys.exit(1)
''', encoding="utf-8")
sh.SYSTEMD_RUN = [sys.executable, str(FAKE_RUN)]
sh.SYSTEMCTL = [sys.executable, str(FAKE_CTL)]
sh.UNIT_PYTHON = sys.executable
sh.CHILD_ENV = {"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), "FAKE_BASE": str(BASE),
                "FAKE_WORK": sh.WORK_DIR, "FAKE_HANDOFF": str(sh.HANDOFF_ROOT)}


def stops():
    path = BASE / "stops.log"
    return path.read_text(encoding="utf-8").split() if path.is_file() else []


def unit_log(run_id):
    return json.loads((BASE / "log" / f"tectac-sbx-{run_id}.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------------------------ fixtures
def runner_program(body):
    return "import os, sys, time\n" + body + "\n"


def make_runner(runner_id="ai.chat", *, body="print('hello')", limits=None, parameters=None, argv=None, credential_files=(), credential_return=False,
                verified=True, environment=None, roots=()):
    owner = runner_id.split(".")[0]
    folder = sh.RUNNERS_ROOT / owner
    folder.mkdir(parents=True, exist_ok=True)
    exe = folder / (runner_id.split(".", 1)[1] + ".py")
    data = runner_program(body).encode("utf-8")
    exe.write_bytes(data)
    all_limits = {name: default for name, (default, _ceiling) in sh.LIMITS.items()}
    all_limits.update({"queue_seconds": 1, "run_seconds": 20})
    all_limits.update(limits or {})
    row = {
        "id": runner_id, "owner_module": owner, "version": "1.0.0", "revision": "1", "description": "test runner", "executable": str(exe),
        "executable_sha256": hashlib.sha256(data).hexdigest(), "argv": argv if argv is not None else [], "parameters": parameters or {},
        "environment": environment or {}, "runtime_roots": list(roots), "credential_files": list(credential_files),
        "credential_return": credential_return, "limits": all_limits, "runtime_verified": verified, "runtime_reason": "" if verified else "root 1: x",
        "registered_by": sh.REGISTERED_BY,
    }
    sh.REGISTRY_ROOT.mkdir(parents=True, exist_ok=True)
    (sh.REGISTRY_ROOT / f"{runner_id}.json").write_text(json.dumps(row), encoding="utf-8")
    return row


def write_ready_status(**over):
    status = {"ready": True, "reason": "ready", "enabled": False, "systemd_version": 252, "resolver": "9.9.9.9", "resolvers": ["9.9.9.9"],
              "address_filter_ok": True, "dns_ok": True, "selftest_at": "2026-11-11T10:00:00Z"}
    status.update(over)
    sh.STATE_ROOT.mkdir(parents=True, exist_ok=True)
    sh.write_status(status)
    return status


with contextlib.redirect_stdout(io.StringIO()):
    sh.ensure_layout()
write_ready_status()


def header(runner_id="ai.chat", run_id=None, person="user:7", parameters=None, credentials=None, input_bytes=0, **extra):
    payload = {"runner_id": runner_id, "run_id": run_id or os.urandom(16).hex(), "person": person, "input_bytes": input_bytes}
    if parameters is not None:
        payload["parameters"] = parameters
    if credentials is not None:
        payload["credentials"] = {k: base64.b64encode(v if isinstance(v, bytes) else v.encode()).decode() for k, v in credentials.items()}
    payload.update(extra)
    return payload


class HoldOpen(io.BytesIO):
    """A stdin that gives its bytes and then blocks until closed by the test, like the pipe Django keeps open as the liveness line."""

    def __init__(self, data):
        super().__init__(data)
        self.done = threading.Event()

    def read(self, n=-1):
        got = super().read(n)
        if got:
            return got
        self.done.wait(60)
        return b""


def start(hdr, input_data=b"", *, hold=True, stdin_bytes=None):
    """Run the helper's ``--start`` in-process with a fake stdin and a captured stdout. Returns (exit code, frames list)."""
    raw = stdin_bytes if stdin_bytes is not None else json.dumps(hdr).encode("utf-8") + b"\n" + input_data
    stdin = HoldOpen(raw) if hold else io.BytesIO(raw)
    out = io.BytesIO()
    result = {}

    def go():
        result["code"] = sh.start_command(stdin, out_stream=out)
    thread = threading.Thread(target=go, daemon=True)
    thread.start()
    thread.join(60)
    if isinstance(stdin, HoldOpen):
        stdin.done.set()
    must(not thread.is_alive(), "start did not finish")
    frames = [json.loads(line) for line in out.getvalue().decode("utf-8").splitlines() if line.strip()]
    return result["code"], frames


def joined(frames, tag):
    return b"".join(base64.b64decode(f["b"]) for f in frames if f["t"] == tag)


def end_of(frames):
    ends = [f for f in frames if f["t"] == "end"]
    must(len(ends) == 1, frames)
    return ends[0]


def leftovers():
    """Anything a finished run must not leave: secrets, handoff, run record, cancel flag."""
    found = []
    for folder in (sh.SECRETS_ROOT, sh.HANDOFF_ROOT, sh.RUNS_ROOT):
        if folder.is_dir():
            found += [p.name for p in folder.iterdir()]
    return found


def audit_text():
    return sh.AUDIT_FILE.read_text(encoding="utf-8") if sh.AUDIT_FILE.is_file() else ""
