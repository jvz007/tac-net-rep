#!/usr/bin/env python3
"""1.17.107: root runs never leave root-owned lock files in the System Update cache (the root cause behind 1.17.106).

On dev02 (3 November 2026) the github-refresh-*.lock and release-cache.lock files in /var/lib/tec-tac/system-updates/cache were
root:tactical 0640, so the Tactical account could not open them for writing and Core fell back to a 26-hour-old branch head. The
installer's `chown -R root:tactical` over the whole System Update folder re-owned the Tactical account's lock files.

1. framwork/tec_tac/system_update.py _file_lock: a root run opens an existing lock read-only and never creates one (no O_CREAT);
   with no lock file it holds nothing (callers fail closed). The Tactical account still creates it 0660. Every open has O_NOFOLLOW.
   A root run does not create the cache folder either.
2. install.sh: no recursive owner change inside the cache folder; root-owned *.lock files there are deleted with one log line;
   release-cache.json is left alone. The prune expression is run here against a real folder (Git Bash / find).
3. Held from 1.17.105: a registry that fails validation is not read as "Licensing not installed" (module_repository.py).
4. Held from 1.17.105: the UI checkout's top-level node_modules and dist are owner-checked without being entered.
"""
from __future__ import annotations

import ast
import contextlib
import io
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# --- 1. _file_lock as root and as the Tactical account
SOURCE = ROOT / "framwork" / "tec_tac" / "system_update.py"
WANTED = {"_running_as_root", "_file_lock", "_PATH_LOCKS", "_PATH_LOCKS_GUARD"}
tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
picked = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in WANTED)
          or (isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id in WANTED)
          or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in WANTED for t in n.targets))]
must(len(picked) == len(WANTED), [getattr(n, "name", None) for n in picked])

O_RDONLY, O_RDWR, O_CREAT, O_NOFOLLOW = 0x0, 0x2, 0x40, 0x20000


class FakeOS:
    O_RDONLY, O_RDWR, O_CREAT, O_NOFOLLOW = O_RDONLY, O_RDWR, O_CREAT, O_NOFOLLOW

    def __init__(self, euid, existing, writable=True):
        self.euid, self.existing, self.writable = euid, set(existing), writable
        self.opens = []

    def geteuid(self):
        return self.euid

    def open(self, path, flags, mode=0o777):
        self.opens.append((path, flags, mode))
        if path not in self.existing:
            if not flags & O_CREAT:
                raise FileNotFoundError(path)
            self.existing.add(path)
            return 7
        if flags & O_RDWR and not self.writable:
            raise PermissionError(path)
        return 7

    def close(self, fd):
        pass


fcntl = types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda fd, op: None)
NS: dict = {"contextlib": contextlib, "threading": threading, "time": time, "Path": Path, "fcntl": fcntl}
exec(compile(ast.Module(body=picked, type_ignores=[]), str(SOURCE), "exec"), NS)  # noqa: S102 - test only
LOCK = "/var/lib/tec-tac/system-updates/cache/github-refresh-abc.lock"


def take(fake):
    NS["os"] = fake
    with NS["_file_lock"](PurePosixPath(LOCK), 0.2) as held:
        return held


fake = FakeOS(0, existing=[])
must(take(fake) is False, "root with no lock file must hold nothing")
must(fake.opens and all(not flags & O_CREAT for _, flags, _ in fake.opens), fake.opens)
must(LOCK not in fake.existing, "root created a lock file")
fake = FakeOS(0, existing=[LOCK])
must(take(fake) is True, "root uses an existing lock")
must([flags for _, flags, _ in fake.opens] == [O_RDONLY | O_NOFOLLOW], fake.opens)
fake = FakeOS(999, existing=[])
must(take(fake) is True and fake.opens == [(LOCK, O_RDWR | O_CREAT | O_NOFOLLOW, 0o660)], fake.opens)
fake = FakeOS(999, existing=[LOCK], writable=False)  # the 1.17.106 fallback for an old root-owned 0640 lock
must(take(fake) is True and [f for _, f, _ in fake.opens] == [O_RDWR | O_CREAT | O_NOFOLLOW, O_RDONLY | O_NOFOLLOW], fake.opens)
NS["os"] = types.SimpleNamespace()  # the development PC: no geteuid
must(NS["_running_as_root"]() is False, "no geteuid means not root")
text = SOURCE.read_text(encoding="utf-8")
must(text.count("if not _running_as_root():  # 1.17.107: root never creates the cache folder") == 2, "cache folder mkdir guard")
must(b"\r" not in SOURCE.read_bytes(), "system_update.py has CR")
print("       1. a root run never creates a cache lock (or the cache folder); the Tactical account creates it 0660; O_NOFOLLOW everywhere")

# --- 2. install.sh
INSTALL = ROOT / "install.sh"
raw = INSTALL.read_bytes()
must(b"\r" not in raw, "install.sh lost its LF line endings")
script = raw.decode("utf-8")
must('chown -R root:"${TACTICAL_GROUP}" "${SYSTEM_UPDATE_ROOT}"' not in script, "the recursive chown over the cache is back")
prune = 'find -P "${SYSTEM_UPDATE_ROOT}" -path "${SYSTEM_UPDATE_ROOT}/cache/*" -prune -o -exec chown -h root:"${TACTICAL_GROUP}" {} +'
repair = """find -P "${SYSTEM_UPDATE_ROOT}/cache" -maxdepth 1 -name '*.lock' -type f -user root -print -delete | wc -l"""
must(prune in script and repair in script, "prune or lock repair missing")
must(script.index(prune) < script.index(repair) < script.index('chmod 2770 "${SYSTEM_UPDATE_ROOT}/staged"'), "order")
must("root-owned System Update cache lock file(s)" in script, "the log line")
bash = shutil.which("bash")
if bash:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "system-updates"
        for rel in ("cache/release-cache.json", "cache/github-refresh-a.lock", "jobs/j.json", "logs/x.log"):
            (base / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / rel).write_text("x", encoding="utf-8")
        probe = prune.replace('chown -h root:"${TACTICAL_GROUP}"', "printf '%s\\n'")
        out = subprocess.run([bash, "-c", probe], env={"SYSTEM_UPDATE_ROOT": base.as_posix(), "PATH": "/usr/bin:/bin"},
                             capture_output=True, text=True, check=True).stdout.split()
        names = {Path(p).relative_to(base.as_posix()).as_posix() if p != base.as_posix() else "." for p in out}
        must({".", "cache", "jobs", "jobs/j.json", "logs", "logs/x.log"} == names, names)
    print("       2. install.sh: the owner change skips the cache folder's contents (checked with find), root-owned locks are deleted, LF kept")
else:
    print("       2. install.sh: text checks passed; bash not found, so the find expression was not run")

# --- 3. a registry validation error is not "Licensing not installed"
BASE = HERE / "licensing-sync-skip-1.17.105.py"
LIC: dict = {"__name__": "licensing_harness", "__file__": str(BASE)}
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):  # the harness prints its own lines
    exec(compile(BASE.read_text(encoding="utf-8"), str(BASE), "exec"), LIC)  # noqa: S102 - the shared test harness


class RegistryError(RuntimeError):
    pass


REG = {"raise": False}


def get_plugins():
    if REG["raise"]:
        raise RegistryError("Duplicate plugin ID 'licensing'.")
    return ()


registry = types.ModuleType("tec_tac.registry")
registry.get_plugins = get_plugins
registry.RegistryError = RegistryError
saved_registry = sys.modules.get("tec_tac.registry")
sys.modules["tec_tac.registry"] = registry
try:
    LIC["write_config"]([LIC["lic_record"]()], defaults_seeded=["tec-tac-licensing"])
    LIC["STATUS"].update({"state": "missing", "raise": False})
    LIC["LOG"].records.clear()
    counts = LIC["run"]({"parameters": {}})
    must(counts.get("licensing_skipped") == 1, counts)
    REG["raise"] = True
    LIC["LOG"].records.clear()
    must(LIC["failed_run"](), "a registry validation error must not skip the Licensing source")
    must(any(level == "warning" and "could not be read" in text for level, text in LIC["LOG"].records), LIC["LOG"].records)
    must(not any(level == "info" and "not installed" in text for level, text in LIC["LOG"].records), LIC["LOG"].records)
finally:
    if saved_registry is not None:
        sys.modules["tec_tac.registry"] = saved_registry
print("       3. a registry that fails validation skips nothing and logs a warning; a real 'not installed' still skips quietly")

# --- 4. the UI's top-level build folders are owner-checked, never entered
BASE = HERE / "system-update-build-folders-1.17.105.py"
BF: dict = {"__name__": "build_folders_harness", "__file__": str(BASE)}
with contextlib.redirect_stdout(io.StringIO()):
    exec(compile(BASE.read_text(encoding="utf-8"), str(BASE), "exec"), BF)  # noqa: S102 - the shared test harness
walk, CHECKOUT, UID = BF["walk"], BF["CHECKOUT"], BF["UID"]
for folder in ("node_modules", "dist"):
    fake, changed, error = walk({f"{folder}/a.js": (False, 0, 2), folder: (True, 4242, 1)})
    must(error and f"{CHECKOUT}/{folder} is owned by uid 4242" in error and "must be owned by tactical" in error, error)
    fake, changed, error = walk({f"{folder}/a.js": (False, 4242, 2), folder: (True, 0, 1)})
    must(error is None and fake.chowned == [], (error, fake.chowned))
    must(fake.nodes[f"{CHECKOUT}/{folder}"].st_uid == 0, "a root-owned build folder changed owner")
    fake, changed, error = walk({f"{folder}/a.js": (False, 4242, 1), folder: (True, UID, 1)})
    must(error is None, error)
fake, changed, error = walk({"src/node_modules": (True, 4242, 1)})
must(error and "is owned by uid 4242" in error, "a deeper node_modules is still walked")
print("       4. UI node_modules and dist: a third-account owner is refused, root or Tactical allowed, contents never entered")
print("[TEST] PASS system update root cache locks 1.17.107")
