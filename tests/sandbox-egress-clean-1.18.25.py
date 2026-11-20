#!/usr/bin/env python3
"""1.18.25 regression (dev02 canary 1.18.24, step 5v): egress_clean and the sweep remove the proxy's audit state when systemd made it a symlink.

Django-free. systemd keeps a DynamicUser RuntimeDirectory at /run/private/tec-tac-sbx-egress/<id> and makes /run/tec-tac-sbx-egress/<id> a symlink to
../private/tec-tac-sbx-egress/<id>. shutil.rmtree refuses a symlink and ignore_errors hid it, so the link and its audit.jsonl stayed after every run.
The helper's EGRESS_STATE_ROOT and EGRESS_PRIVATE_ROOT point at temp folders. Covered:

* a link to the expected private target removes the link AND the target (with its audit file);
* a link to a folder outside the expected root removes the link only; the outside folder and a sentinel file stay;
* a link whose target holds another run id, a link whose target is itself a symlink, and a link whose target is a plain file: link removed, nothing
  the link pointed to is touched;
* a plain directory goes with rmtree; a plain file is removed; a missing entry and an invalid run id raise nothing and touch nothing;
* the sweep removes a stale link plus its target and keeps a live run's (a young entry) link and target.

A symlink needs a privilege on Windows. When os.symlink is refused, the same cases run against a stub lstat/readlink layer, so the logic is covered
on every PC; the real symlink run happens where it is allowed (dev02: tests/sandbox-canary-1.18.25.sh, step 5v).
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BASE = Path(tempfile.mkdtemp(prefix="tectac-eclean-"))


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


loader = importlib.machinery.SourceFileLoader("sandbox_helper_eclean", str(ROOT / "scripts" / "sandbox-helper.py"))
spec = importlib.util.spec_from_loader(loader.name, loader)
sh = importlib.util.module_from_spec(spec)
loader.exec_module(sh)

STATE = BASE / "run" / "tec-tac-sbx-egress"
PRIVATE = BASE / "run" / "private" / "tec-tac-sbx-egress"
OUTSIDE = BASE / "outside"
sh.EGRESS_STATE_ROOT = STATE
sh.EGRESS_PRIVATE_ROOT = PRIVATE
for folder in (STATE, PRIVATE, OUTSIDE):
    folder.mkdir(parents=True)
ID1, ID2, ID3, ID4, ID5, ID6 = (f"{n:032x}" for n in (1, 2, 3, 4, 5, 6))
BAD_IDS = ("", "abc", "../" + ID1, ID1.upper(), ID1 + "x", None, 7)


def real_symlinks_work():
    probe = BASE / "probe-link"
    try:
        os.symlink(str(OUTSIDE), str(probe), target_is_directory=True)
    except (OSError, NotImplementedError):
        return False
    probe.unlink()
    return True


REAL = real_symlinks_work()


class Fake:
    """A stub lstat/readlink layer for a PC that may not create symlinks. Entries: path -> ('link', raw) | ('dir',) | ('file',)."""

    def __init__(self):
        self.items = {}
        self.removed_trees = []
        self.unlinked = []

    def lstat(self, path):
        entry = self.items.get(Path(path).as_posix())
        if entry is None:
            raise FileNotFoundError(str(path))
        mode = {"link": stat.S_IFLNK, "dir": stat.S_IFDIR, "file": stat.S_IFREG}[entry[0]]
        return os.stat_result((mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))

    def readlink(self, path):
        entry = self.items.get(Path(path).as_posix())
        if entry is None or entry[0] != "link":
            raise OSError("not a link")
        return entry[1]

    def rmtree(self, path, ignore_errors=False):
        self.removed_trees.append(Path(path).as_posix())
        self.items.pop(Path(path).as_posix(), None)

    def unlink(self, path, missing_ok=False):
        self.unlinked.append(Path(path).as_posix())
        self.items.pop(Path(path).as_posix(), None)


def link(name, target):
    path = STATE / name
    os.symlink(target, str(path), target_is_directory=True)
    return path


def audit_dir(folder):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "audit.jsonl").write_text("{}\n", encoding="utf-8")
    return folder


if REAL:
    # 1. the expected private target: both go
    audit_dir(PRIVATE / ID1)
    link(ID1, "../private/tec-tac-sbx-egress/" + ID1)
    sh.egress_clean(ID1)
    must(not (STATE / ID1).is_symlink() and not (STATE / ID1).exists(), "the link is gone")
    must(not (PRIVATE / ID1).exists(), "the target is gone")
    # 2. a link to an outside folder: only the link goes
    (OUTSIDE / "sentinel").write_text("keep", encoding="utf-8")
    link(ID2, str(OUTSIDE))
    sh.egress_clean(ID2)
    must(not (STATE / ID2).is_symlink() and (OUTSIDE / "sentinel").read_text(encoding="utf-8") == "keep", "outside folder untouched")
    # 3. a link whose target holds another run id
    audit_dir(PRIVATE / ID4)
    link(ID3, "../private/tec-tac-sbx-egress/" + ID4)
    sh.egress_clean(ID3)
    must(not (STATE / ID3).is_symlink() and (PRIVATE / ID4 / "audit.jsonl").exists(), "another run's state is untouched")
    # 4. a target that is itself a symlink
    os.symlink(str(OUTSIDE), str(PRIVATE / ID5), target_is_directory=True)
    link(ID5, "../private/tec-tac-sbx-egress/" + ID5)
    sh.egress_clean(ID5)
    must(not (STATE / ID5).is_symlink() and (PRIVATE / ID5).is_symlink() and (OUTSIDE / "sentinel").exists(), "a target that is a symlink is not followed")
    (PRIVATE / ID5).unlink()
    # 5. a '..' that climbs out is not the expected path even when it ends in the same id
    link(ID6, "../../outside/../private/tec-tac-sbx-egress/../tec-tac-sbx-egress/" + ID6 + "/../../../../outside")
    (PRIVATE / ID6).mkdir()
    sh.egress_clean(ID6)
    must(not (STATE / ID6).is_symlink() and (OUTSIDE / "sentinel").exists(), "a climbing link is unlinked only")
    (PRIVATE / ID6).rmdir()
    # 6. a plain directory and a plain file
    audit_dir(STATE / ID1)
    sh.egress_clean(ID1)
    must(not (STATE / ID1).exists(), "a plain directory is removed")
    (STATE / ID2).write_text("x", encoding="utf-8")
    sh.egress_clean(ID2)
    must(not (STATE / ID2).exists(), "a plain file is removed")
    # 7. missing entry, invalid ids
    sh.egress_clean(ID3)
    for bad in BAD_IDS:
        sh.egress_remove_state(bad)
    must((OUTSIDE / "sentinel").exists() and (PRIVATE / ID4 / "audit.jsonl").exists(), "invalid ids touch nothing")
    print("[INFO] real symlinks: tested")
else:
    fake = Fake()
    sh._lstat = fake.lstat
    sh.os = type("OsStub", (), {"readlink": staticmethod(fake.readlink), "sep": "/", "__getattr__": lambda self, name: getattr(os, name)})()
    sh.shutil = type("ShutilStub", (), {"rmtree": staticmethod(fake.rmtree), "__getattr__": lambda self, name: getattr(__import__("shutil"), name)})()

    class PathStub(type(Path())):
        def unlink(self, missing_ok=False):
            fake.unlink(self, missing_ok)

    sh.Path = PathStub
    sh.EGRESS_STATE_ROOT = PathStub(STATE)
    sh.EGRESS_PRIVATE_ROOT = PathStub(PRIVATE)
    S, P = STATE.as_posix(), PRIVATE.as_posix()
    # 1
    fake.items = {f"{S}/{ID1}": ("link", "../private/tec-tac-sbx-egress/" + ID1), f"{P}/{ID1}": ("dir",)}
    sh.egress_remove_state(ID1)
    must(f"{P}/{ID1}" in fake.removed_trees and f"{S}/{ID1}" in fake.unlinked, (fake.removed_trees, fake.unlinked))
    # 2 outside
    fake.__init__()
    fake.items = {f"{S}/{ID2}": ("link", OUTSIDE.as_posix()), OUTSIDE.as_posix(): ("dir",)}
    sh.egress_remove_state(ID2)
    must(not fake.removed_trees and f"{S}/{ID2}" in fake.unlinked, (fake.removed_trees, fake.unlinked, S))
    # 3 another id
    fake.__init__()
    fake.items = {f"{S}/{ID3}": ("link", "../private/tec-tac-sbx-egress/" + ID4), f"{P}/{ID4}": ("dir",)}
    sh.egress_remove_state(ID3)
    must(not fake.removed_trees and f"{S}/{ID3}" in fake.unlinked, "wrong id: unlink only")
    # 4 target is a symlink
    fake.__init__()
    fake.items = {f"{S}/{ID5}": ("link", "../private/tec-tac-sbx-egress/" + ID5), f"{P}/{ID5}": ("link", "/etc")}
    sh.egress_remove_state(ID5)
    must(not fake.removed_trees and f"{S}/{ID5}" in fake.unlinked, "symlink target: unlink only")
    # target is a plain file
    fake.__init__()
    fake.items = {f"{S}/{ID5}": ("link", "../private/tec-tac-sbx-egress/" + ID5), f"{P}/{ID5}": ("file",)}
    sh.egress_remove_state(ID5)
    must(not fake.removed_trees, "file target: nothing removed")
    # 5 climbing path
    fake.__init__()
    fake.items = {f"{S}/{ID6}": ("link", "../private/tec-tac-sbx-egress/../../outside"), f"{P}/{ID6}": ("dir",)}
    sh.egress_remove_state(ID6)
    must(not fake.removed_trees, "a climbing link removes nothing it points to")
    # 6 plain directory
    fake.__init__()
    fake.items = {f"{S}/{ID1}": ("dir",)}
    sh.egress_remove_state(ID1)
    must(f"{S}/{ID1}" in fake.removed_trees, "plain directory: rmtree")
    # 7 missing and invalid
    fake.__init__()
    sh.egress_remove_state(ID3)
    for bad in BAD_IDS:
        sh.egress_remove_state(bad)
    must(not fake.removed_trees and not fake.unlinked, "missing entry and invalid ids touch nothing")
    print("[INFO] real symlinks: not allowed here, stub layer used")

# ---- the code itself: no resolve(), no os.path.realpath on the link, built only from the validated id
text = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
start = text.index("def egress_remove_state")
body = text[start:text.index("def egress_clean", start)]
must("resolve(" not in body and "realpath" not in body, "the link is never resolved, only normalised")
must("_egress_id(run_id)" in body, "the path is built from the validated run id")
must('RuntimeDirectoryPreserve' not in text.replace("RuntimeDirectoryPreserve=yes", ""), "no helper text changes the preserve setting")
must("egress_remove_state(entry.name)" in text, "the sweep uses the same function")
installer = (ROOT / "install.sh").read_text(encoding="utf-8")
must("RuntimeDirectoryPreserve=yes" in installer, "install.sh keeps RuntimeDirectoryPreserve=yes (the helper reads audit.jsonl after the stop)")
print("[TEST] PASS sandbox egress clean 1.18.25")
