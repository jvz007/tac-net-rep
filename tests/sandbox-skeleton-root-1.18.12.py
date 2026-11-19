#!/usr/bin/env python3
"""1.18.12 regression: the sandbox root skeleton has an empty `root` mount point (core.sandbox, dev02 canary 19 November 2026).

systemd 255.4 creates `root` inside RootDirectory= because of ProtectHome=yes, so check_skeleton refused every start and the selftest.
* install.sh builds `root` (empty, root:root 0700, idempotent; a 0750 `root` is repaired, a `root` with a child is emptied by the existing rule);
* check_skeleton accepts a tree with `root` and refuses: a missing `root`, a symlink, a non-empty `root`, a group-writable `root`, any other extra
  top-level name (`home`, `snap`): fail closed;
* CANARY_VIEW_ALLOWED['/'] holds `root`, and the selftest's `ls -A /` case list passes a listing with it and rejects `home`;
* the selftest re-checks the skeleton after the probe units (check `sandbox_root_after`): a probe that adds `home` makes it not ready;
* ProtectHome=yes and the unit property list are unchanged.

Not runnable here: systemd itself. Proven for 255.4 by the dev02 log, not by systemd's source.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_helper_1812", ROOT / "scripts" / "sandbox-helper.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

# ---- constants: the three lists and the canary view
must("root" in sh.SKELETON_DIRS and "root" in sh.SKELETON_TOP and sh.SKELETON_ENTRIES["root"] == (), "root is listed three times")
must("root" in sh.CANARY_VIEW_ALLOWED["/"], "the canary view allows root")
for name in ("home", "snap", "boot", "srv", "mnt"):
    must(name not in sh.SKELETON_TOP and name not in sh.CANARY_VIEW_ALLOWED["/"], name)
dirs = re.search(r"for sandbox_entry in (usr work [^;]+); do", INSTALL)
must(dirs and dirs.group(1).split() == list(sh.SKELETON_DIRS), "install.sh lists the helper's folders")
must('"${sandbox_rel}" == "root" ]]; then chmod 0700' in INSTALL, "root is 0700")
must(b"\r" not in (ROOT / "install.sh").read_bytes(), "install.sh keeps LF")

# ---- the install block, run twice and after damage
start = INSTALL.index("SANDBOX_ROOT_DIR=")
block_end = INSTALL.index('ln -sfn "${SANDBOX_LIB}/sandbox-helper.py"', start)
BLOCK = INSTALL[INSTALL.rindex("# 1.18.8: the sandbox root.", 0, start):block_end]
bash = shutil.which("bash")


def run_block(folder):
    script = ("set -euo pipefail\nfail() { echo \"FAIL $*\"; exit 1; }\nchown() { :; }\ninstall() { local last; for last; do :; done; : > \"$last\"; }\n"
              f'SANDBOX_LIB="{Path(folder).as_posix()}"\n' + BLOCK + "\necho BLOCK-DONE\n")
    return subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)


def tree(folder):
    return {p.relative_to(folder).as_posix(): ("d" if p.is_dir() else "f") for p in sorted(Path(folder).rglob("*"))}


if bash:
    with tempfile.TemporaryDirectory() as tmp:
        lib = Path(tmp) / "lib"
        lib.mkdir()
        done = run_block(lib)
        if "BLOCK-DONE" not in done.stdout:
            print("[NOTE] this bash cannot run the block: dynamic cases skipped:", done.stdout[-200:], done.stderr[-200:])
        else:
            skeleton = lib / "root"
            first = tree(skeleton)
            must(first.get("root") == "d" and not any(k.startswith("root/") for k in first), "root is an empty folder")
            if os.name != "nt":
                must(stat.S_IMODE((skeleton / "root").stat().st_mode) == 0o700, "root is 0700")
            must("BLOCK-DONE" in run_block(lib).stdout and tree(skeleton) == first, "idempotent")
            if os.name != "nt":
                (skeleton / "root").chmod(0o750)  # what the dev02 run left behind
                must("BLOCK-DONE" in run_block(lib).stdout and stat.S_IMODE((skeleton / "root").stat().st_mode) == 0o700, "0750 is repaired to 0700")
            (skeleton / "root" / "child").write_text("x", encoding="utf-8")
            again = run_block(lib)
            must("BLOCK-DONE" in again.stdout and tree(skeleton) == first, "a child of root is removed: " + again.stdout + again.stderr)
else:
    print("[NOTE] no bash: install block cases skipped")


# ---- check_skeleton on a real temp tree (root ownership is faked through lstat; no host merged-/usr names)
class St:
    def __init__(self, st):
        self.st_mode, self.st_uid = st.st_mode & ~0o022, 0  # Windows reports 0666: use the mode a root-owned 0755 entry has


def fake_lstat(path):
    return St(os.lstat(path))


def fresh():
    base = Path(tempfile.mkdtemp(prefix="tectac-skel-1812-")) / "root"
    base.mkdir()
    for rel in sh.SKELETON_DIRS:
        (base / rel).mkdir(parents=True, exist_ok=True)
    for rel in sh.SKELETON_FILES:
        (base / rel).write_text("", encoding="utf-8")
    return base


def check(base, lstat=fake_lstat):
    sh.check_skeleton(exists=lambda p: False, lstat=lstat, root=base)


def refused(base, label, lstat=fake_lstat):
    try:
        check(base, lstat)
    except sh.Refusal:
        return
    raise AssertionError(label + " was accepted")


good = fresh()
check(good)
missing = fresh()
(missing / "root").rmdir()
refused(missing, "missing root")
child = fresh()
(child / "root" / "x").write_text("x", encoding="utf-8")
refused(child, "non-empty root")
for extra in ("home", "snap"):
    other = fresh()
    (other / extra).mkdir()
    refused(other, extra)
linked = fresh()
(linked / "root").rmdir()
try:
    os.symlink(str(linked / "usr"), str(linked / "root"))
    refused(linked, "root symlink")
except (OSError, NotImplementedError):
    print("[NOTE] no symlinks on this PC: symlink case skipped")
writable = fresh()


def lstat_writable(path):
    st = St(os.lstat(path))
    if Path(path) == writable / "root":
        st.st_mode |= 0o020
    return st


refused(writable, "group-writable root", lstat_writable)

# ---- the selftest's own ls -A / case list
case_list = "|".join(sh.CANARY_VIEW_ALLOWED["/"])
must("root" in case_list.split("|"), "the case list has root")
pattern = re.compile("^(" + case_list + ")$")
must(all(pattern.match(n) for n in ("root", "usr", "work")) and not pattern.match("home"), "root passes, home is rejected")

# ---- the selftest: take the harness of the 1.17.116 test up to its first case
source = (HERE / "sandbox-selftest-1.17.116.py").read_text(encoding="utf-8").split("# ---- everything passes")[0]
harness_file = Path(tempfile.mkdtemp(prefix="tectac-harness-1812-")) / "selftest_harness_1812.py"
harness_file.write_text(source, encoding="utf-8")
harness_spec = importlib.util.spec_from_file_location("selftest_harness_1812", harness_file)
harness = importlib.util.module_from_spec(harness_spec)
harness.__file__ = str(HERE / "sandbox-selftest-1.17.116.py")  # the harness reads files next to the test it came from
harness_spec.loader.exec_module(harness)
ns = vars(harness)
sh2 = ns["sh"]
Fake, selftest = ns["Fake"], ns["selftest"]
live = fresh()


def skeleton_of_live(*a, **k):
    try:
        sh.check_skeleton(exists=lambda p: False, lstat=fake_lstat, root=live)
    except sh.Refusal as exc:  # the harness loaded its own copy of the helper: its Refusal class is the one the selftest catches
        raise sh2.Refusal(exc.code, exc.message) from None


sh2.check_skeleton = skeleton_of_live


class Probing(Fake):
    def __init__(self, add=None, **kw):
        super().__init__(**kw)
        self.add = add

    def run_unit(self, name, properties, command, *, timeout=30):
        if self.add and name == "pipe_streams":
            (live / self.add).mkdir(exist_ok=True)
        return super().run_unit(name, properties, command, timeout=timeout)


status = selftest(Probing())
must(status["ready"] is True and status["checks"]["sandbox_root_after"]["ok"] is True, status["reason"])
status = selftest(Probing(add="root"))  # the mount point is already there: nothing changes
must(status["ready"] is True and status["checks"]["sandbox_root_after"]["ok"], status["reason"])
status = selftest(Probing(add="home"))
must(status["ready"] is False and status["checks"]["sandbox_root_after"]["ok"] is False, status)
must("sandbox root folder" in status["reason"], status["reason"])
(live / "home").rmdir()

# ---- ProtectHome stays, the property list is the same closed list
must("ProtectHome=yes" in sh.UNIT_FIXED_PROPERTIES, "ProtectHome=yes kept")
must(len(sh.UNIT_FIXED_PROPERTIES) == len(set(sh.UNIT_FIXED_PROPERTIES)), "no duplicate properties")

print("[TEST] PASS sandbox skeleton root 1.18.12")
