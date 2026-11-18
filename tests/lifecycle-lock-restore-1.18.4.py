#!/usr/bin/env python3
"""Regression: a Tec-Tac restore takes lifecycle.lock; a lock failure in --publish-ui-sync is one line, exit 1 (Core 1.18.4)."""
import contextlib
import errno
import io
import re
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
backup_path = ROOT / "scripts" / "server-backup-helper.py"
update_path = ROOT / "scripts" / "system-update-helper.py"
backup_src = backup_path.read_text(encoding="utf-8")
update_src = update_path.read_text(encoding="utf-8")

for p in (backup_path, update_path):
    assert b"\r" not in p.read_bytes(), f"{p.name} must stay LF"

# ---- static: placement in the restore
start = backup_src.index("def operation_restore_backup(")
end = backup_src.index("\ndef delete_local(", start)
restore = backup_src[start:end]
lock_at = restore.index("acquire_lifecycle_lock()")
assert restore.count("acquire_lifecycle_lock()") == 1
assert 'if mode in {"full", "tec_tac"}:' in restore[lock_at - 400:lock_at]
assert restore.index("security_snapshot = ") > lock_at
for later in ("create_pre_restore_snapshot(", "service_stop_for_restore(", "run_post_restore_tec_tac(", "restore_script_source"):
    for m in re.finditer(re.escape(later), restore):
        assert m.start() > lock_at, f"{later} before the lifecycle lock"
assert restore.index("lock=acquire_lock(config)") < lock_at  # server-backup.lock first, then lifecycle.lock

# deadlock guard: the --install-restored child never takes the lock
branch_at = update_src.index('sys.argv[1] == "--install-restored"')
branch = update_src[branch_at:update_src.index('sys.argv[1] in {"--dispatch", "--run"}', branch_at)]
assert "acquire_lifecycle_lock()" not in branch
assert "install_restored_component(" in branch
func = update_src[update_src.index("def install_restored_component("):]
func = func[:func.index('"""', func.index('"""') + 3)]
assert "never takes the lock itself" in func

# same lock file in both helpers
rx = re.compile(r'LIFECYCLE_LOCK_PATH = Path\("([^"]+)"\)')
assert rx.search(backup_src).group(1) == rx.search(update_src).group(1) == "/var/lib/tec-tac/lifecycle.lock"

# busy is the only exit-0 skip, and it comes first
pub_at = update_src.index('sys.argv[1] == "--publish-ui-sync"')
pub = update_src[pub_at:update_src.index('sys.argv[1] == "--install-restored"', pub_at)]
assert pub.index("except RuntimeError:") < pub.index("except OSError as exc:") < pub.index("publish_ui_sync_from_checkout()")


# ---- load the helpers (no fcntl on Windows: inject a fake with flock)
class FakeFcntl(types.ModuleType):
    LOCK_EX, LOCK_NB, LOCK_UN = 2, 4, 8

    def __init__(self):
        super().__init__("fcntl")
        self.mode = "free"
        self.held = False

    def flock(self, fd, flags):
        if self.mode == "busy" or (self.mode == "free" and self.held):
            raise BlockingIOError(errno.EAGAIN, "busy")
        if self.mode == "rofs":
            raise OSError(errno.EROFS, "Read-only file system")
        self.held = True


real_fcntl = None
try:
    import fcntl as real_fcntl
except ImportError:
    pass
fake = FakeFcntl()
if real_fcntl is None:
    sys.modules["fcntl"] = fake


for _posix_only in ("grp", "pwd"):  # missing on Windows; the helpers only import them
    if _posix_only not in sys.modules:
        try:
            __import__(_posix_only)
        except ImportError:
            sys.modules[_posix_only] = types.ModuleType(_posix_only)


def load(name, path):
    """Import a helper from source; off Linux, skip the import-time lookup of a root-owned bash (the tests never run it)."""
    src = path.read_text(encoding="utf-8")
    if real_fcntl is None:
        src = src.replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"')
    mod = types.ModuleType(name)
    mod.__file__ = str(path)
    exec(compile(src, str(path), "exec"), mod.__dict__)  # noqa: S102 - the helper under test, not user input
    return mod


class FakeHandle:
    def __init__(self):
        self.closed = False

    def fileno(self):
        return 99

    def close(self):
        self.closed = True


class FakePath:
    def __init__(self, handle, open_error=None):
        self.parent = types.SimpleNamespace(mkdir=lambda **kw: None)
        self.handle, self.open_error = handle, open_error

    def open(self, mode):
        if self.open_error:
            raise self.open_error
        return self.handle


def use_fake(mod, mode="free"):
    mod.fcntl = fake
    fake.mode, fake.held = mode, False
    mod._LIFECYCLE_LOCK_HANDLE = None


backup = load("backup_1184", backup_path)
update = load("update_1184", update_path)

# ---- backup helper lock: free, then a second acquire refuses while held
use_fake(backup)
h = FakeHandle()
backup.LIFECYCLE_LOCK_PATH = FakePath(h)
backup.acquire_lifecycle_lock()
assert backup._LIFECYCLE_LOCK_HANDLE is h and not h.closed
h2 = FakeHandle()
backup.LIFECYCLE_LOCK_PATH = FakePath(h2)
try:
    backup.acquire_lifecycle_lock()
    raise AssertionError("second acquire must refuse while held")
except RuntimeError as exc:
    assert "the restore was not started" in str(exc) and "already running" in str(exc)
assert h2.closed and backup._LIFECYCLE_LOCK_HANDLE is h

# other OS error and open error: one-line RuntimeError, handle closed
use_fake(backup, "rofs")
h3 = FakeHandle()
backup.LIFECYCLE_LOCK_PATH = FakePath(h3)
try:
    backup.acquire_lifecycle_lock()
    raise AssertionError("must refuse")
except RuntimeError as exc:
    assert "Read-only file system" in str(exc) and "restore was not started" in str(exc) and "\n" not in str(exc)
assert h3.closed
use_fake(backup)
backup.LIFECYCLE_LOCK_PATH = FakePath(None, PermissionError(errno.EACCES, "Permission denied"))
try:
    backup.acquire_lifecycle_lock()
    raise AssertionError("must refuse")
except RuntimeError as exc:
    assert "Permission denied" in str(exc) and "restore was not started" in str(exc)

# ---- restore driven with stubs: busy refuses before anything destructive
STOP = "stop-after-lock"
STUBBED = (
    "parse_backup_ref", "validate_destination", "acquire_lock", "roots", "download_destination", "ensure_regular",
    "max_backup_bytes", "verify_archive_hash_companion", "validate_recovery_bundle", "_restore_version_transition",
    "validate_target_preflight", "_target_effectively_ready", "atomic_json", "job_path", "acquire_lifecycle_lock",
    "_capture_restore_security_state", "create_pre_restore_snapshot", "service_stop_for_restore",
    "run_post_restore_tec_tac", "_prepare_tactical_restore_script",
)


def drive(mode, lock_error):
    calls, closed = [], []
    saved = {k: getattr(backup, k) for k in STUBBED}
    tmp = Path(tempfile.mkdtemp())
    try:
        backup.parse_backup_ref = lambda ref: ("local", "tec-tac-backup-x.tgz")
        backup.validate_destination = lambda d, c: d
        backup.acquire_lock = lambda c: types.SimpleNamespace(close=lambda: closed.append(1))
        backup.roots = lambda c: {"staging": tmp}
        backup.download_destination = lambda *a: None
        backup.ensure_regular = lambda path, **kw: Path(path).write_bytes(b"x")
        backup.max_backup_bytes = lambda c: 10
        backup.verify_archive_hash_companion = lambda *a: {"status": "verified"}
        backup.validate_recovery_bundle = lambda *a, **k: ({"components": {}}, {})
        backup._restore_version_transition = lambda c, mf: {}
        backup.validate_target_preflight = lambda *a, **k: None
        backup._target_effectively_ready = lambda p: True
        backup.atomic_json = lambda *a: None
        backup.job_path = lambda *a: tmp / "job.json"

        def lock():
            calls.append("lifecycle")
            if lock_error:
                raise RuntimeError(lock_error)
        backup.acquire_lifecycle_lock = lock

        def make(name):
            def stub(*a, **k):
                calls.append(name)
                raise KeyError(STOP)
            return stub
        for name in ("_capture_restore_security_state", "create_pre_restore_snapshot", "service_stop_for_restore",
                     "run_post_restore_tec_tac", "_prepare_tactical_restore_script"):
            setattr(backup, name, make(name))
        job = {"id": "j", "request": {"backup_ref": "local:x", "restore_mode": mode,
                                       "destination": {"id": "local", "type": "local"}}}
        outcome = None
        try:
            backup.operation_restore_backup({}, job, io.StringIO())
        except KeyError as exc:
            outcome = "next-step" if STOP in str(exc) else repr(exc)
        except RuntimeError as exc:
            outcome = str(exc)
        return calls, closed, outcome
    finally:
        for k, v in saved.items():
            setattr(backup, k, v)


busy_text = "another Tec-Tac lifecycle operation is already running; the restore was not started"
calls, closed, outcome = drive("full", busy_text)
assert calls == ["lifecycle"], calls  # no snapshot, no service stop, no installer
assert outcome == busy_text and closed == [1], (outcome, closed)  # server-backup.lock still released

calls, closed, outcome = drive("tec_tac", None)
assert calls[:2] == ["lifecycle", "_capture_restore_security_state"], calls
calls, closed, outcome = drive("full", None)
assert calls[:2] == ["lifecycle", "_capture_restore_security_state"], calls
calls, closed, outcome = drive("tactical", "must not be called")
assert "lifecycle" not in calls, calls  # Tactical-only restore is unchanged

# ---- system update helper: acquire closes the handle on a non-busy error, keeps the busy RuntimeError
use_fake(update, "rofs")
uh = FakeHandle()
update.LIFECYCLE_LOCK_PATH = FakePath(uh)
try:
    update.acquire_lifecycle_lock()
    raise AssertionError("must raise")
except OSError as exc:
    assert not isinstance(exc, BlockingIOError)
assert uh.closed and update._LIFECYCLE_LOCK_HANDLE is None
use_fake(update, "busy")
uh = FakeHandle()
update.LIFECYCLE_LOCK_PATH = FakePath(uh)
try:
    update.acquire_lifecycle_lock()
    raise AssertionError("must raise")
except RuntimeError:
    pass
assert uh.closed


# ---- --publish-ui-sync: the helper's __main__ block runs at module level, so run a patched copy of the source
def run_publish(path_obj, mode):
    published = []
    patched = update_src.replace(
        'LIFECYCLE_LOCK_PATH = Path("/var/lib/tec-tac/lifecycle.lock")', "LIFECYCLE_LOCK_PATH = _TEST_PATH", 1
    ).replace("def publish_ui_sync_from_checkout(", "def _orig_publish_ui_sync_from_checkout(", 1)
    if real_fcntl is None:
        patched = patched.replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"')
    patched = patched.replace("os.geteuid() != 0", "False")  # the __main__ block refuses non-root; the test is not root
    assert "_TEST_PATH" in patched and "_orig_publish" in patched
    fake.mode, fake.held = mode, False
    saved_argv, saved_fcntl = sys.argv, sys.modules.get("fcntl")
    sys.modules["fcntl"] = fake
    sys.argv = ["system-update-helper.py", "--publish-ui-sync"]
    scope = {"__name__": "__main__", "__file__": str(update_path), "_TEST_PATH": path_obj,
             "publish_ui_sync_from_checkout": lambda: published.append(1)}
    out, err = io.StringIO(), io.StringIO()
    code = None
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            exec(compile(patched, str(update_path), "exec"), scope)  # noqa: S102 - the helper under test, not user input
    except SystemExit as exc:
        code = exc.code
    finally:
        sys.argv = saved_argv
        if saved_fcntl is None:
            sys.modules.pop("fcntl", None)
        else:
            sys.modules["fcntl"] = saved_fcntl
    return code, out.getvalue(), err.getvalue(), published


cases = (
    (FakePath(FakeHandle(), PermissionError(errno.EACCES, "Permission denied")), "free", "Permission denied"),
    (FakePath(FakeHandle(), FileNotFoundError(errno.ENOENT, "No such file or directory")), "free", "No such file"),
    (FakePath(FakeHandle()), "rofs", "Read-only file system"),
)
for path_obj, mode, needle in cases:
    code, out, err, published = run_publish(path_obj, mode)
    assert code == 1 and out == "" and published == [], (code, out, err, published)
    lines = err.splitlines()
    assert len(lines) == 1 and lines[0].startswith("[TEC-TAC] UI module sync script not published: ") and needle in lines[0], err
    assert "Traceback" not in err

code, out, err, published = run_publish(FakePath(FakeHandle()), "busy")
assert code == 0 and err == "" and published == [], (code, err)
assert out.startswith("[TEC-TAC] UI module sync script not published: a System Update"), out

# free lock: the publish runs
code, out, err, published = run_publish(FakePath(FakeHandle()), "free")
assert published == [1] and err == "", (code, err, published)

if real_fcntl is not None:
    with tempfile.TemporaryDirectory() as d:
        lp = Path(d) / "lifecycle.lock"
        backup.fcntl = real_fcntl
        backup._LIFECYCLE_LOCK_HANDLE = None
        backup.LIFECYCLE_LOCK_PATH = lp
        holder = lp.open("a+")
        real_fcntl.flock(holder.fileno(), real_fcntl.LOCK_EX)
        try:
            backup.acquire_lifecycle_lock()
            raise AssertionError("must refuse while another handle holds the lock")
        except RuntimeError as exc:
            assert "restore was not started" in str(exc)
        real_fcntl.flock(holder.fileno(), real_fcntl.LOCK_UN)
        holder.close()
        backup.acquire_lifecycle_lock()
else:
    print("note: no fcntl here; the real flock path is checked on Linux only, the logic ran against a fake fcntl")

print("lifecycle lock restore 1.18.4 regression: PASS")
