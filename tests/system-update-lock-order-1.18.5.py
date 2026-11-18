#!/usr/bin/env python3
"""Regression: a System Update job shows its final status only after it released both locks (Core 1.18.5)."""
import contextlib
import errno
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "system-update-helper.py"
assert b"\r" not in HELPER.read_bytes()
events = []


class FakeFcntl(types.ModuleType):
    LOCK_EX, LOCK_NB, LOCK_UN = 2, 4, 8

    def __init__(self):
        super().__init__("fcntl")
        self.busy_polls = 0  # busy for this many calls, then free
        self.mode = "free"

    def flock(self, fd, flags):
        if flags & self.LOCK_UN:
            events.append(("unlock", fd))
            return
        if self.mode == "rofs":
            raise OSError(errno.EROFS, "Read-only file system")
        if self.busy_polls > 0:
            self.busy_polls -= 1
            raise BlockingIOError(errno.EAGAIN, "busy")
        events.append(("lock", fd))


fake = FakeFcntl()
real_fcntl = None
try:
    import fcntl as real_fcntl
except ImportError:
    sys.modules["fcntl"] = fake
for name in ("grp", "pwd"):
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = types.ModuleType(name)


def load():
    src = HELPER.read_text(encoding="utf-8")
    if real_fcntl is None:
        src = src.replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"')
    mod = types.ModuleType("suh_1185")
    mod.__file__ = str(HELPER)
    exec(compile(src, str(HELPER), "exec"), mod.__dict__)  # noqa: S102 - the helper under test
    mod.fcntl = fake
    return mod


update = load()
src = HELPER.read_text(encoding="utf-8")
# static: release sits first in run_job's finally; module helpers untouched
fin = src[src.index("        finally:\n            # Reuse the config-derived"):src.index("def mark_failed(")]
assert fin.index("release_lifecycle_lock()") < fin.index("LOCK_UN") < fin.index("atomic_json(path, job")
assert "acquire_lifecycle_lock(wait_seconds=LIFECYCLE_WAIT_SECONDS)" in src
assert src.count("wait_seconds=") == 2  # the definition's default and run_job only
for other in ("module-job-helper.py", "module-v2-job-helper.py", "module-hotfix-job-helper.py"):
    p = ROOT / "scripts" / other
    if p.exists():
        assert "release_lifecycle_lock" not in p.read_text(encoding="utf-8", errors="replace")


class Handle:
    def __init__(self, n):
        self.n, self.closed = n, False

    def fileno(self):
        return self.n

    def close(self):
        self.closed = True
        events.append(("close", self.n))


class FakePath:
    handles = []

    def __init__(self, n=50):
        self.parent = types.SimpleNamespace(mkdir=lambda **kw: None)
        self.n = n

    def open(self, mode):
        h = Handle(self.n)
        FakePath.handles.append(h)
        return h


# ---- (c) acquire with and without a wait, fake clock
clock = {"t": 0.0}
sleeps = []


def fsleep(s):
    sleeps.append(s)
    clock["t"] += s


def fclock():
    return clock["t"]


update.LIFECYCLE_LOCK_PATH = FakePath()
fake.mode, fake.busy_polls = "free", 2
events.clear()
FakePath.handles.clear()
sleeps.clear()
clock["t"] = 0.0
update.acquire_lifecycle_lock(wait_seconds=2, _sleep=fsleep, _clock=fclock)
assert sleeps == [0.25, 0.25] and update._LIFECYCLE_LOCK_HANDLE is FakePath.handles[-1]
assert [h.closed for h in FakePath.handles] == [True, True, False]
update.release_lifecycle_lock()

fake.busy_polls = 10 ** 6
clock["t"] = 0.0
sleeps.clear()
FakePath.handles.clear()
try:
    update.acquire_lifecycle_lock(wait_seconds=2, _sleep=fsleep, _clock=fclock)
    raise AssertionError("must refuse after the cap")
except RuntimeError as exc:
    assert "another Tec-Tac lifecycle operation is already running" in str(exc)
assert len(sleeps) == 8 and all(h.closed for h in FakePath.handles) and update._LIFECYCLE_LOCK_HANDLE is None

clock["t"] = 0.0
sleeps.clear()
FakePath.handles.clear()  # wait_seconds=0: one try, no sleep
try:
    update.acquire_lifecycle_lock(_sleep=fsleep, _clock=fclock)
    raise AssertionError("must refuse at once")
except RuntimeError:
    assert sleeps == [] and len(FakePath.handles) == 1

fake.mode, fake.busy_polls = "rofs", 0
sleeps.clear()
FakePath.handles.clear()
try:
    update.acquire_lifecycle_lock(wait_seconds=5, _sleep=fsleep, _clock=fclock)
    raise AssertionError("non-busy error must be raised")
except OSError as exc:
    assert exc.errno == errno.EROFS
assert sleeps == [] and len(FakePath.handles) == 1 and FakePath.handles[0].closed
fake.mode = "free"

# ---- (d) release is idempotent
update.acquire_lifecycle_lock()
events.clear()
update.release_lifecycle_lock()
update.release_lifecycle_lock()
assert [e[0] for e in events] == ["unlock", "close"] and update._LIFECYCLE_LOCK_HANDLE is None

# ---- (a) run_job, success and failure
JOB = "11111111-1111-1111-1111-111111111111"


def drive(fail):
    events.clear()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        target = tmp / "framework"
        target.mkdir()
        (target / "VERSION").write_text("1.18.4\n", encoding="utf-8")
        pkg_dir = tmp / "src"
        pkg_dir.mkdir()
        (pkg_dir / "VERSION").write_text("1.18.5\n", encoding="utf-8")
        for d in ("logs", "history"):
            (tmp / d).mkdir()
        package = tmp / "p.zip"
        package.write_bytes(b"x")
        job_path = tmp / "job.json"
        immutable = {"id": JOB, "action": "install", "component": "framework", "package_path": str(package), "version": "1.18.5", "source": "t"}
        cfg = {"TEC_TAC_FRAMEWORK_SOURCE": str(target), "TEC_TAC_ROOT": str(tmp / "rt"), "TACTICAL_USER": "tactical"}
        u = load()
        u.LIFECYCLE_LOCK_PATH = FakePath(60)
        u.LOCK_PATH = tmp / "update.lock"
        u.LOGS_ROOT, u.HISTORY_ROOT = tmp / "logs", tmp / "history"
        u.load_job = lambda j: (job_path, {"status": "dispatched", "stage": "queued", "created_at": "n"})
        u.load_running_request = lambda j: (tmp / "r.json", dict(immutable))
        u.load_config = lambda: dict(cfg)
        u.tactical_gid = lambda c: 1
        u.running_request_path = lambda j: tmp / "r.json"
        u._source_commit = lambda s: None
        u.installed_version = lambda comp, c: "1.18.4"

        def atomic(path, payload, *a, **k):
            events.append(("write", Path(path).parent.name, payload.get("status")))
        u.atomic_json = atomic

        @contextlib.contextmanager
        def work(j=None):
            yield pkg_dir
        u.private_update_work_dir = work
        u.install_stage = lambda *a, **k: work()
        u.extract_archive = (lambda *a, **k: (_ for _ in ()).throw(RuntimeError("forced"))) if fail else (lambda *a, **k: None)
        u.detect_root = lambda w, c: pkg_dir
        u._root_verify_tree = lambda *a, **k: {"signed": False, "root_policy": {}}
        u.prepare_source_checkout = lambda *a, **k: {"head": "abc", "branch": "dev", "restored_changes": []}
        u.backup_root = lambda *a, **k: tmp / "bk"
        u.stage_release_tree = lambda *a, **k: pkg_dir
        u.verify_staged_tree = lambda *a, **k: {"file_count": 1}
        u.snapshot_dynamic_plugins = lambda *a, **k: {}
        u.run_install = lambda *a, **k: 0
        for n in ("repin_framework_source", "verify", "verify_dynamic_plugins", "enforce_runtime_ownership",
                  "verify_source_runtime_layout", "write_provenance", "restore_source_checkout"):
            setattr(u, n, lambda *a, **k: None)
        u.run_job(JOB)
    return list(events)


for fail, final in ((False, "succeeded"), (True, "failed")):
    ev = drive(fail)
    finals = [i for i, e in enumerate(ev) if e[0] == "write" and e[2] == final]
    assert finals, ev
    first_final = finals[0]
    before = [e for e in ev[:first_final] if e[0] == "unlock"]
    assert any(e[1] == 60 for e in before), ev  # lifecycle.lock
    assert len(before) >= 2, ev  # and update.lock
    history = [i for i, e in enumerate(ev) if e[0] == "write" and e[1] == "history"]
    assert history and history[0] > first_final - 1 and all(i > max(j for j, e in enumerate(ev) if e[0] == "unlock") for i in history), ev
    assert not [e for e in ev[first_final:] if e[0] == "unlock" and e[1] == 60], ev

# ---- (b) mark_failed releases first and fills installed_version
u = load()
u.LIFECYCLE_LOCK_PATH = FakePath(70)
u.acquire_lifecycle_lock()
events.clear()
job = {"id": JOB, "action": "install", "component": "framework", "status": "dispatched"}
u.load_job = lambda j: ("p", job)
u.load_config = lambda: {}
u.installed_version = lambda comp, c: "1.18.4"
u.atomic_json = lambda path, payload, *a, **k: events.append(("write", "x", payload["status"]))
u.mark_failed(JOB, RuntimeError("busy"))
assert [e[0] for e in events][:2] == ["unlock", "close"] and events[-1][2] == "failed"
assert job["installed_version"] == "1.18.4" and job["status"] == "failed"
job2 = {"id": JOB, "component": "framework", "status": "dispatched"}
u.load_job = lambda j: ("p", job2)


def boom(*a):
    raise OSError("unreadable")


u.installed_version = boom
u.mark_failed(JOB, RuntimeError("x"))
assert job2["status"] == "failed" and "installed_version" not in job2
job3 = {"id": JOB, "component": "framework", "status": "dispatched", "installed_version": "9.9.9"}
u.load_job = lambda j: ("p", job3)
u.installed_version = lambda *a: "1.0.0"
u.mark_failed(JOB, RuntimeError("x"))
assert job3["installed_version"] == "9.9.9"

# ---- Linux only: a real flock proves the lock is free the moment it is released
if real_fcntl is not None:
    with tempfile.TemporaryDirectory() as td:
        lp = Path(td) / "lifecycle.lock"
        real = load()
        real.fcntl = real_fcntl
        real.LIFECYCLE_LOCK_PATH = lp
        real.acquire_lifecycle_lock()
        other = lp.open("a+")
        try:
            real_fcntl.flock(other.fileno(), real_fcntl.LOCK_EX | real_fcntl.LOCK_NB)
            raise AssertionError("must be held")
        except BlockingIOError:
            pass
        real.release_lifecycle_lock()
        real_fcntl.flock(other.fileno(), real_fcntl.LOCK_EX | real_fcntl.LOCK_NB)
        other.close()
else:
    print("note: real flock check skipped (no fcntl on this OS)")

print("system update lock order 1.18.5 regression: PASS")
