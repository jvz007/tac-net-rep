#!/usr/bin/env python3
"""1.18.8 regression: the allow-list file view of a sandbox unit (core.sandbox Patch A, part 1).

* the unit's property list is golden: ``RootDirectory=<skeleton>``, ``MountAPIVFS=yes``, read-only binds of /usr, of the merged-/usr names that are
  real folders on the host and of the base files, an empty /usr/local over the host's own; there is no ``HIDDEN_FOLDERS`` list and no
  TemporaryFileSystem deny list; the binds are exactly the allowed set;
* ``file_view_properties`` is the one function the builder and the selftest probe share;
* ``check_skeleton`` accepts a correct fake skeleton for a merged-/usr host and for a host with real folders, and refuses: a symlinked root, a
  group- or world-writable root, a root owned by someone else, a missing mount point, a wrong entry type, an extra top-level entry, a wrong
  form of a merged-/usr name, a symlink with another target, a mount point that holds something, a bad runtime mount-point name;
* ``ensure_runtime_mountpoint`` refuses a symlink, a non-root parent, a writable parent, an invalid id and a mount point that is a file;
* the selftest is not ready, with the plain reason, when the skeleton is wrong (fail closed, no weaker mode), and ``launch`` refuses before any
  unit is started.

Not runnable here: systemd's own handling of RootDirectory= (dev02: tests/sandbox-canary-1.18.8.sh).
"""
from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_188f", HERE / "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
REAL_CHECK = load("sandbox_helper_188_real", HERE.parent / "scripts" / "sandbox-helper.py")  # an untouched copy: the harness replaced check_skeleton in ``sh``
check_skeleton, ensure_runtime_mountpoint = REAL_CHECK.check_skeleton, REAL_CHECK.ensure_runtime_mountpoint
Refusal = REAL_CHECK.Refusal
PLAIN = "the sandbox root folder does not match this server; run the Core install again"

# ---- 1. the golden property list
RUN_ID = "ab" * 16
row = H.make_runner("ai.chat", roots=[{"path": "/opt/tec-tac/runtimes/ai/claude", "tree_sha256_file": "sandbox/t.txt", "listing_sha256": "0" * 64}])
EXISTS = lambda path: str(path).startswith(str(BASE)) or str(path).startswith("/opt/tec-tac/runtimes/ai") or str(path) == str(sh.LAUNCHER_FILE)
props = sh.build_properties(row, RUN_ID, credential_names=[], exists=EXISTS)
must(props.count(f"RootDirectory={sh.SANDBOX_ROOT}") == 1 and props.count("MountAPIVFS=yes") == 1, props)
must(props.index(f"RootDirectory={sh.SANDBOX_ROOT}") < props.index("MountAPIVFS=yes"), "root first")
must(not hasattr(sh, "HIDDEN_FOLDERS"), "no hidden-folder list")
must(REAL_CHECK.SANDBOX_ROOT.as_posix().endswith("/usr/local/lib/tec-tac/sandbox/root"), "the skeleton lives in the lib folder")
tmpfs = [p for p in props if p.startswith("TemporaryFileSystem=")]
must(sorted(tmpfs) == sorted(["TemporaryFileSystem=/usr/local:ro", f"TemporaryFileSystem={sh.WORK_DIR}:rw,nosuid,nodev,size={row['limits']['scratch_mb']}M,mode=1777"]), tmpfs)
for kept in ("ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "ProtectProc=invisible", "ProcSubset=pid"):
    must(props.count(kept) == 1, kept)
binds = [p.split("=", 1)[1] for p in props if p.startswith("BindReadOnlyPaths=")]
allowed_binds = {"/usr", *sh.BASE_BINDS_REQUIRED, *(p for p in sh.BASE_BINDS_OPTIONAL), "/opt/tec-tac/runtimes/ai", str(sh.RUNNERS_ROOT / "ai"), str(sh.LAUNCHER_FILE),
                 f"{sh.core_resolv_file()}:/etc/resolv.conf"}
must(set(binds) == allowed_binds and len(binds) == len(set(binds)), (sorted(set(binds) ^ allowed_binds)))
must(props.index("BindReadOnlyPaths=/usr") < props.index("TemporaryFileSystem=/usr/local:ro") < props.index(f"BindReadOnlyPaths={sh.LAUNCHER_FILE}"), "/usr, then the mask, then what is bound back into it")
# the builder and the probe use one function
view = sh.file_view_properties(EXISTS)
for item in view:
    must(item in props, item)
must(view[:3] == [f"RootDirectory={sh.SANDBOX_ROOT}", "MountAPIVFS=yes", "BindReadOnlyPaths=/usr"] and view[-1] == "TemporaryFileSystem=/usr/local:ro", view)
helper_text = (HERE.parent / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must(helper_text.count("file_view_properties(") >= 4 and "HIDDEN_FOLDERS" not in helper_text, "one shared function, no deny list")
# a host with real folders for the merged names: those are bound, read only
real_view = sh.file_view_properties(lambda path: True)
must("BindReadOnlyPaths=/usr" in real_view, real_view)
must(sh.file_view_properties(lambda path: path in sh.BASE_BINDS_REQUIRED) ==
     [f"RootDirectory={sh.SANDBOX_ROOT}", "MountAPIVFS=yes", "BindReadOnlyPaths=/usr", *[f"BindReadOnlyPaths={p}" for p in sh.BASE_BINDS_REQUIRED], "TemporaryFileSystem=/usr/local:ro"],
     "optional base binds that are absent are left out")
try:
    sh.file_view_properties(lambda path: path != sh.BASE_BINDS_REQUIRED[1])
    raise AssertionError("a missing required base file was accepted")
except sh.Refusal as exc:
    must(exc.code == "sandbox_unavailable", exc.code)
# every base bind has a mount point in the skeleton
skeleton_names = set(REAL_CHECK.SKELETON_DIRS) | set(REAL_CHECK.SKELETON_FILES)
for path in (*REAL_CHECK.BASE_BINDS_REQUIRED, *REAL_CHECK.BASE_BINDS_OPTIONAL, "/etc/resolv.conf"):
    must(path.lstrip("/") in skeleton_names, f"{path} has no mount point")
for folder in ("usr", "work", "tmp", "var/tmp", "proc", "sys", "dev", "run", "opt/tec-tac/runtimes"):
    must(folder in sh.SKELETON_DIRS, folder)


# ---- 2. check_skeleton against a fake file system
class FakeFS:
    """Host and skeleton in one tree. Entries: path -> ("dir"|"file"|"link", uid, mode, target)."""

    def __init__(self, merged=True, absent=()):
        self.root = "/lib/sbx/root"
        self.nodes = {}
        self.host = {}
        for name in ("bin", "sbin", "lib", "lib64", "lib32", "libx32"):
            if name in absent:
                continue
            self.host["/" + name] = ("link", 0, 0o777, "usr/" + name) if merged else ("dir", 0, 0o755, None)
        self.add(self.root, "dir")
        for rel in sh.SKELETON_DIRS:
            self.add(f"{self.root}/{rel}", "dir")
        for rel in sh.SKELETON_FILES:
            self.add(f"{self.root}/{rel}", "file", mode=0o644)
        for path, (kind, uid, mode, target) in self.host.items():
            self.add(f"{self.root}{path}", kind, uid, 0o777 if kind == "link" else 0o755, target)

    def add(self, path, kind, uid=0, mode=0o755, target=None):
        self.nodes[path] = (kind, uid, mode, target)

    def remove(self, rel):
        self.nodes.pop(f"{self.root}/{rel}", None)

    def key(self, path):
        return str(PurePosixPath(str(path).replace("\\", "/")))

    def entry(self, path):
        key = self.key(path)
        if key in self.nodes:
            return self.nodes[key]
        if key in self.host:
            return self.host[key]
        raise FileNotFoundError(key)

    def exists(self, path):
        try:
            self.entry(path)
            return True
        except FileNotFoundError:
            return False

    def lstat(self, path):
        kind, uid, mode, _target = self.entry(path)
        kinds = {"dir": stat.S_IFDIR, "file": stat.S_IFREG, "link": stat.S_IFLNK}
        return os.stat_result((kinds[kind] | mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))

    def readlink(self, path):
        return self.entry(path)[3]

    def listdir(self, path):
        prefix = self.key(path).rstrip("/") + "/"
        if self.key(path) not in self.nodes:
            raise FileNotFoundError(path)
        return sorted({key[len(prefix):].split("/")[0] for key in self.nodes if key.startswith(prefix)})

    def check(self):
        return check_skeleton(self.exists, self.lstat, root=self.root, listdir=self.listdir, readlink=self.readlink)


def refused(fs, label):
    try:
        fs.check()
    except Refusal as exc:
        must(exc.code == "sandbox_unavailable" and exc.message == PLAIN, (label, exc.code, exc.message))
        return
    raise AssertionError(f"{label}: a wrong skeleton was accepted")


FakeFS(merged=True).check()
FakeFS(merged=False).check()  # a host with real folders: empty folders in the skeleton
FakeFS(merged=True, absent=("lib32", "libx32")).check()  # absent on the host = absent in the skeleton
fs = FakeFS()
fs.add(f"{fs.root}/opt/tec-tac/runtimes/ai", "dir")
fs.add(f"{fs.root}/opt/tec-tac/runtimes/wapm-2", "dir")
fs.check()  # one empty mount point per module that has run

fs = FakeFS(); fs.add(fs.root, "link", target="/etc"); refused(fs, "root is a symlink")
fs = FakeFS(); fs.add(fs.root, "dir", mode=0o775); refused(fs, "root is group writable")
fs = FakeFS(); fs.add(fs.root, "dir", mode=0o757); refused(fs, "root is world writable")
fs = FakeFS(); fs.add(fs.root, "dir", uid=1000); refused(fs, "root is owned by someone else")
fs = FakeFS(); fs.remove("etc/ssl/certs"); refused(fs, "a mount point is missing")
fs = FakeFS(); fs.remove("run"); refused(fs, "a top-level mount point is missing")
fs = FakeFS(); fs.remove("etc/resolv.conf"); refused(fs, "a mount file is missing")
fs = FakeFS(); fs.add(f"{fs.root}/etc/passwd", "dir"); refused(fs, "a file is a folder")
fs = FakeFS(); fs.add(f"{fs.root}/etc/ssl/certs", "file"); refused(fs, "a folder is a file")
fs = FakeFS(); fs.add(f"{fs.root}/work", "link", target="/tmp"); refused(fs, "a mount folder is a symlink")
fs = FakeFS(); fs.add(f"{fs.root}/home", "dir"); refused(fs, "an extra top-level entry")
fs = FakeFS(); fs.add(f"{fs.root}/etc/shadow", "file"); refused(fs, "an extra file in /etc")
fs = FakeFS(); fs.add(f"{fs.root}/var/log", "dir"); refused(fs, "an extra folder in /var")
fs = FakeFS(); fs.add(f"{fs.root}/etc/passwd", "file", mode=0o666); refused(fs, "a writable mount file")
fs = FakeFS(); fs.add(f"{fs.root}/usr/stray", "file"); refused(fs, "a mount point that holds something")
fs = FakeFS(); fs.add(f"{fs.root}/opt/tec-tac/runtimes/ai", "dir"); fs.add(f"{fs.root}/opt/tec-tac/runtimes/ai/x", "file"); refused(fs, "a runtime mount point that holds something")
fs = FakeFS(); fs.add(f"{fs.root}/opt/tec-tac/runtimes/bad name", "dir"); refused(fs, "a runtime mount point with a bad name")
fs = FakeFS(); fs.add(f"{fs.root}/opt/tec-tac/runtimes/ai", "file"); refused(fs, "a runtime mount point that is a file")
fs = FakeFS(merged=True); fs.add(f"{fs.root}/lib", "dir"); refused(fs, "host has a link, skeleton has a folder")
fs = FakeFS(merged=False); fs.add(f"{fs.root}/lib", "link", target="usr/lib"); refused(fs, "host has a folder, skeleton has a link")
fs = FakeFS(merged=True); fs.add(f"{fs.root}/lib", "link", target="elsewhere"); refused(fs, "the link points somewhere else")
fs = FakeFS(merged=True, absent=("lib32",)); fs.add(f"{fs.root}/lib32", "dir"); refused(fs, "host has no lib32, skeleton has one")
fs = FakeFS(merged=True); fs.remove("lib64"); refused(fs, "a merged-/usr link is missing")
fs = FakeFS(merged=True); fs.add(f"{fs.root}/bin", "link", uid=1000, target="usr/bin"); refused(fs, "a link not made by root")

# ---- 3. ensure_runtime_mountpoint
fs = FakeFS()
made = []


def fake_mkdir(path, mode=0o777):
    made.append((fs.key(path), mode))
    fs.add(fs.key(path), "dir", mode=mode)


target = ensure_runtime_mountpoint("ai", root=fs.root, lstat=fs.lstat, mkdir=fake_mkdir)
must(made == [(f"{fs.root}/opt/tec-tac/runtimes/ai", 0o755)] and str(target).replace("\\", "/") == f"{fs.root}/opt/tec-tac/runtimes/ai", made)
ensure_runtime_mountpoint("ai", root=fs.root, lstat=fs.lstat, mkdir=fake_mkdir)  # again: nothing new is made
must(len(made) == 1, "idempotent")
for bad_id in ("../x", "a/b", "", "a b", None, 5, "x" * 101, ".hidden"):
    try:
        ensure_runtime_mountpoint(bad_id, root=fs.root, lstat=fs.lstat, mkdir=fake_mkdir)
        raise AssertionError(f"an invalid id was accepted: {bad_id!r}")
    except Refusal as exc:
        must(exc.message == PLAIN, exc.message)
for label, mutate in (("a symlinked parent", lambda f: f.add(f"{f.root}/opt/tec-tac", "link", target="/x")),
                      ("a non-root parent", lambda f: f.add(f"{f.root}/opt/tec-tac/runtimes", "dir", uid=1000)),
                      ("a writable parent", lambda f: f.add(f"{f.root}/opt", "dir", mode=0o777)),
                      ("a symlinked mount point", lambda f: f.add(f"{f.root}/opt/tec-tac/runtimes/ai", "link", target="/x")),
                      ("a mount point that is a file", lambda f: f.add(f"{f.root}/opt/tec-tac/runtimes/ai", "file")),
                      ("a mount point owned by someone else", lambda f: f.add(f"{f.root}/opt/tec-tac/runtimes/ai", "dir", uid=1000)),
                      ("a writable mount point", lambda f: f.add(f"{f.root}/opt/tec-tac/runtimes/ai", "dir", mode=0o777))):
    broken = FakeFS()
    mutate(broken)
    try:
        ensure_runtime_mountpoint("ai", root=broken.root, lstat=broken.lstat, mkdir=lambda p, m=0o777, fs=broken: fs.add(fs.key(p), "dir"))
        raise AssertionError(f"{label} was accepted")
    except Refusal as exc:
        must(exc.message == PLAIN, (label, exc.message))
broken = FakeFS()
try:
    ensure_runtime_mountpoint("ai", root=broken.root, lstat=broken.lstat, mkdir=lambda p, m=0o777: (_ for _ in ()).throw(OSError("read-only")))
    raise AssertionError("a mount point that cannot be made was accepted")
except Refusal as exc:
    must(exc.message == PLAIN, exc.message)
# only a runner with runtime roots needs a mount point
calls = []
real_ensure = REAL_CHECK.ensure_runtime_mountpoint
REAL_CHECK.ensure_runtime_mountpoint = lambda module_id, **k: calls.append(module_id)
REAL_CHECK.prepare_runtime_mount({"owner_module": "ai", "runtime_roots": []})
REAL_CHECK.prepare_runtime_mount({"owner_module": "ai", "runtime_roots": [{"path": "/opt/tec-tac/runtimes/ai/x"}]})
REAL_CHECK.ensure_runtime_mountpoint = real_ensure
must(calls == ["ai"], calls)

# ---- 4. a wrong skeleton: the selftest is not ready, with the plain reason, and a start refuses before any unit exists
fake_mod = REAL_CHECK


class Probe:
    """A runner that passes every probe; it records the unit runs so the test can see that the file view was not probed with a wrong skeleton."""

    def __init__(self):
        self.units = []

    def run_cmd(self, argv, *, timeout=15):
        if argv[0] == "systemctl":
            return 0, "systemd 252 (252)\n+PAM\n", ""
        if argv[0] == "stat":
            return 0, "cgroup2fs\n", ""
        if argv[0] == "ip":
            return 0, ("1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 129.232.197.50/24 scope global eth0\n" if argv[1] == "-o" else ""), ""
        return 1, "", ""

    def run_unit(self, name, properties, command, *, timeout=30):
        self.units.append(name)
        return 1, "", "not important here"


fake_mod.check_skeleton = lambda *a, **k: (_ for _ in ()).throw(Refusal("sandbox_unavailable", PLAIN))
status = fake_mod.selftest(Probe(), resolv_conf_path=BASE / "resolv.conf", run_root=H.RUN)
must(status["ready"] is False and status["enabled"] is False, status)
must(status["checks"]["sandbox_root"] == {"ok": False, "detail": PLAIN} and status["checks"]["filesystem_view"]["ok"] is False, status["checks"])
probe = Probe()
status = fake_mod.selftest(probe, resolv_conf_path=BASE / "resolv.conf", run_root=H.RUN)
must("filesystem_view" not in probe.units, "the real view is not probed on a wrong skeleton")

# the reason that leads is the skeleton one when nothing earlier failed
class OnlySkeleton(Probe):
    def run_unit(self, name, properties, command, *, timeout=30):
        answers = {"transient": (0, "tectac-probe\n", ""), "dynamic_user": (0, "61500\n", "")}
        return answers.get(name, (1, "", "x"))


status = fake_mod.selftest(OnlySkeleton(), resolv_conf_path=BASE / "resolv.conf", run_root=H.RUN)
must(status["ready"] is False and not status["checks"]["sandbox_root"]["ok"] and status["checks"]["sandbox_root"]["detail"] == PLAIN, status)

# launch refuses with the plain reason before anything is built or started
H.write_ready_status()
H.make_runner("ai.skel")
sh.require_skeleton = lambda: (_ for _ in ()).throw(sh.Refusal("sandbox_unavailable", PLAIN))
code, frames = H.start(H.header("ai.skel"), hold=False)
must(frames == [{"t": "refused", "code": "sandbox_unavailable", "message": PLAIN}] and code == 3, frames)
must(not (BASE / "log").exists() or not list((BASE / "log").iterdir()), "no unit was started")
must(not H.leftovers(), H.leftovers())

print("[TEST] PASS sandbox file view 1.18.8")
