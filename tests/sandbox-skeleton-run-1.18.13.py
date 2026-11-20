#!/usr/bin/env python3
"""1.18.13 regression: a real run leaves run/systemd/incoming in the sandbox root (core.sandbox, dev02 canary 19 November 2026).

* the skeleton lists run/systemd and run/systemd/incoming (empty, 0755), install.sh and the helper list the same folders in the same order;
* the install block is idempotent, repairs a wrong mode and removes a child or a stray sibling;
* check_skeleton accepts the new tree and refuses the usual wrong shapes;
* skeleton_changes names a new entry by relative path; the post-run re-check writes one audit row and a not-ready status that names it;
* the selftest probe `real_unit_shape` has the real unit shape and a probe-made entry fails sandbox_root_after;
* the held Low in tests/legacy/version-1.18.11.py line 20 is restored.

Not runnable here: systemd itself (the dev02 re-run decides).
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import load_helper  # noqa: E402  (1.18.26: the helper and sandbox-selftest.py as one object)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


sh = load_helper(ROOT, "sandbox_helper_1813")

# ---- constants
must("run/systemd" in sh.SKELETON_DIRS and "run/systemd/incoming" in sh.SKELETON_DIRS, "listed")
must(sh.SKELETON_ENTRIES["run"] == ("systemd", "egress") and sh.SKELETON_ENTRIES["run/systemd"] == ("incoming",) and sh.SKELETON_ENTRIES["run/systemd/incoming"] == (), "entries")  # 1.18.24: plus run/egress
must("run/egress" in sh.SKELETON_DIRS and sh.SKELETON_ENTRIES["run/egress"] == (), "the egress mount point is an empty folder")
must(sh.CANARY_VIEW_ALLOWED["/run"] == ("credentials", "systemd", "egress"), sh.CANARY_VIEW_ALLOWED["/run"])  # 1.18.24: plus the empty egress mount point
dirs = re.search(r"for sandbox_entry in (usr work [^;]+); do", INSTALL)
must(dirs and dirs.group(1).split() == list(sh.SKELETON_DIRS), "install.sh lists the helper's folders in the same order")
must(b"\r" not in (ROOT / "install.sh").read_bytes() and b"\r" not in (ROOT / "scripts" / "sandbox-helper.py").read_bytes(), "LF line endings")

# ---- the install block
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
            must(first.get("run") == "d" and first.get("run/systemd") == "d" and first.get("run/systemd/incoming") == "d", "folders exist")
            must(sorted(k for k in first if k.startswith("run")) == ["run", "run/egress", "run/systemd", "run/systemd/incoming"], "nothing else in run")  # 1.18.24: plus run/egress
            if os.name != "nt":
                for rel in ("run", "run/systemd", "run/systemd/incoming"):
                    must(stat.S_IMODE((skeleton / rel).stat().st_mode) == 0o755, rel + " is 0755")
            must("BLOCK-DONE" in run_block(lib).stdout and tree(skeleton) == first, "idempotent")
            if os.name != "nt":
                for mode in (0o700, 0o750):
                    (skeleton / "run/systemd/incoming").chmod(mode)
                    must("BLOCK-DONE" in run_block(lib).stdout and stat.S_IMODE((skeleton / "run/systemd/incoming").stat().st_mode) == 0o755, f"{oct(mode)} is repaired")
            (skeleton / "run/systemd/incoming/child").write_text("x", encoding="utf-8")
            again = run_block(lib)
            must("BLOCK-DONE" in again.stdout and tree(skeleton) == first, "a child of incoming is removed: " + again.stdout + again.stderr)
            (skeleton / "run/foo").mkdir()
            (skeleton / "run/systemd/other").mkdir()
            again = run_block(lib)
            must("BLOCK-DONE" in again.stdout and tree(skeleton) == first, "stray run folders are removed: " + again.stdout + again.stderr)
else:
    print("[NOTE] no bash: install block cases skipped")


# ---- check_skeleton on a temp tree (root ownership faked through lstat; no host merged-/usr names)
class St:
    def __init__(self, st):
        self.st_mode, self.st_uid = st.st_mode & ~0o022, 0


def fake_lstat(path):
    return St(os.lstat(path))


def fresh():
    base = Path(tempfile.mkdtemp(prefix="tectac-skel-1813-")) / "root"
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


check(fresh())
missing = fresh()
(missing / "run/systemd/incoming").rmdir()
(missing / "run/systemd").rmdir()
refused(missing, "missing run/systemd")
only = fresh()
(only / "run/systemd/incoming").rmdir()
refused(only, "missing incoming")
full = fresh()
(full / "run/systemd/incoming/x").write_text("x", encoding="utf-8")
refused(full, "non-empty incoming")
asfile = fresh()
(asfile / "run/systemd/incoming").rmdir()
(asfile / "run/systemd/incoming").write_text("x", encoding="utf-8")
refused(asfile, "incoming a file")
try:
    link = fresh()
    (link / "run/systemd/incoming").rmdir()
    os.symlink(str(link / "usr"), str(link / "run/systemd/incoming"))
    refused(link, "incoming a symlink")
except (OSError, NotImplementedError):
    print("[NOTE] no symlinks on this PC: symlink case skipped")
for extra in ("run/credentials", "run/user", "run/systemd/other", "run/foo"):
    other = fresh()
    (other / extra).mkdir()
    refused(other, extra)
writable = fresh()


def lstat_writable(path):
    st = St(os.lstat(path))
    if Path(path) == writable / "run/systemd":
        st.st_mode |= 0o020
    return st


refused(writable, "group-writable run/systemd", lstat_writable)


# ---- skeleton_changes and the post-run re-check
def changes(base, **kw):
    return sh.skeleton_changes(root=base, lstat=fake_lstat, exists=lambda p: False, **kw)


must(changes(fresh()) == [], "a clean tree has no change")
for extra, expected in (("run/systemd/incoming/extra", ["run/systemd/incoming/extra"]), ("run/home", ["run/home"]), ("run/systemd/other", ["run/systemd/other"])):
    tmp_base = fresh()
    target = tmp_base / extra
    if extra.endswith("extra"):
        target.write_text("secret content", encoding="utf-8")
    else:
        target.mkdir()
    must(changes(tmp_base) == expected, (extra, changes(tmp_base)))
many = fresh()
for index in range(30):
    (many / "run" / f"n{index:02d}").mkdir()
must(len(changes(many)) == sh.SKELETON_CHANGES_MAX and changes(many) == sorted(changes(many)), "capped and sorted")
long_name = fresh()
(long_name / "run" / ("x" * 150)).mkdir()
must(all(len(n) <= sh.SKELETON_CHANGE_NAME_LENGTH for n in changes(long_name)) and not any(str(long_name) in n for n in changes(long_name)), "names are capped and relative")


def broken_listdir(path):
    raise OSError("unreadable")


must(changes(fresh(), listdir=broken_listdir) == [], "an unreadable folder does not raise")

# the re-check, with the status and audit calls replaced
state = {"audit": [], "status": None}
live = fresh()
real_changes = sh.skeleton_changes
sh.skeleton_changes = lambda **kw: real_changes(root=live, lstat=fake_lstat, exists=lambda p: False)
sh.append_audit_safely = lambda event, detail: state["audit"].append((event, detail))
sh.read_status = lambda: dict(state["status"] or {"ready": True, "reason": "ready", "selftest_at": "t", "checks": {"credential": {"ok": True}}, "enabled": False})
sh.write_status = lambda status: state.__setitem__("status", dict(status))
row = {"id": "ai.claude"}
sh.recheck_skeleton_after_run(row, "r" * 16)
must(state["audit"] == [] and state["status"] is None, "a clean skeleton writes nothing")
(live / "run/systemd/incoming/extra").write_text("secret content", encoding="utf-8")
sh.recheck_skeleton_after_run(row, "r" * 16)
must(len(state["audit"]) == 1 and state["audit"][0][0] == "skeleton.changed", state["audit"])
must(state["audit"][0][1] == {"run_id": "r" * 16, "runner": "ai.claude", "entries": ["run/systemd/incoming/extra"]}, state["audit"])
must(state["status"]["ready"] is False and state["status"]["reason"] == "a run left a new entry in the sandbox root: run/systemd/incoming/extra", state["status"])
must(state["status"]["checks"] == {"credential": {"ok": True}} and "secret content" not in json.dumps(state["status"]) + json.dumps(state["audit"]), "other fields kept, no content")
try:  # the next start is refused with that reason
    sh.ready_status()
    raise AssertionError("ready_status accepted a not-ready status")
except sh.Refusal as exc:
    must(exc.code == "sandbox_unavailable" and exc.message == state["status"]["reason"], exc.message)
sh.skeleton_changes = lambda **kw: (_ for _ in ()).throw(OSError("boom"))  # a failing walk never raises
sh.recheck_skeleton_after_run(row, "r" * 16)
sh.skeleton_changes = real_changes
sh.read_status = lambda: {"ready": False, "reason": "something else"}  # an ordinary not-ready status keeps the generic text
try:
    sh.ready_status()
    raise AssertionError("accepted")
except sh.Refusal as exc:
    must(exc.message == "the sandbox selftest has not passed on this server", exc.message)

# ---- run.ended is written before the re-check (source order in launch)
source = "\n".join((ROOT / "scripts" / name).read_text(encoding="utf-8") for name in ("sandbox-helper.py", "sandbox-selftest.py"))
must(source.rindex('append_audit_safely("run.ended", run_ended_detail') < source.rindex("recheck_skeleton_after_run(row, run_id)"), "run.ended first")

# ---- the selftest probe: take the harness of the 1.17.116 test up to its first case
harness_src = (HERE / "sandbox-selftest-1.17.116.py").read_text(encoding="utf-8").split("# ---- everything passes")[0]
harness_file = Path(tempfile.mkdtemp(prefix="tectac-harness-1813-")) / "selftest_harness_1813.py"
harness_file.write_text(harness_src, encoding="utf-8")
harness_spec = importlib.util.spec_from_file_location("selftest_harness_1813", harness_file)
harness = importlib.util.module_from_spec(harness_spec)
harness.__file__ = str(HERE / "sandbox-selftest-1.17.116.py")
harness_spec.loader.exec_module(harness)
ns = vars(harness)
sh2 = ns["sh"]
Fake, selftest = ns["Fake"], ns["selftest"]
tree_live = fresh()


def skeleton_of_live(*a, **k):
    try:
        sh.check_skeleton(exists=lambda p: False, lstat=fake_lstat, root=tree_live)
    except sh.Refusal as exc:
        raise sh2.Refusal(exc.code, exc.message) from None


sh2.check_skeleton = skeleton_of_live


class Probing(Fake):
    def __init__(self, add=None, **kw):
        super().__init__(**kw)
        self.add = add

    def run_unit(self, name, properties, command, *, timeout=30, unit=None):
        if self.add and name == "real_unit_shape":
            (tree_live / self.add).mkdir(parents=True, exist_ok=True)
        return super().run_unit(name, properties, command, timeout=timeout, unit=unit)


fake = Probing()
status = selftest(fake)
must(status["ready"] is True and status["checks"]["real_unit_shape"]["ok"] is True and status["checks"]["sandbox_root_after"]["ok"] is True, status["reason"])
shape = [call for call in fake.calls if call[0] == "real_unit_shape"]
must(len(shape) == 1, "one real-shape unit")
properties = shape[0][1]
must(f"RootDirectory={sh2.SANDBOX_ROOT}" in properties and "DynamicUser=yes" in properties, properties)
must(all(item in properties for item in sh2.file_view_properties()), "the real read-only binds")
must(any(p.startswith("LoadCredential=probe:") for p in properties) and not any(p.startswith("Exec") for p in properties), properties)  # 1.18.14: no property command
names = [call[0] for call in fake.calls]
must(names.index("credential") < names.index("real_unit_shape") < names.index("proc_hidden"), names)
must("token" not in json.dumps(status).lower().replace("tectac-probe", ""), "no token in the status")
status = selftest(Probing(add="run/user"))  # the unit made an entry that is not on the list
must(status["ready"] is False and status["checks"]["sandbox_root_after"]["ok"] is False, status)
shutil.rmtree(tree_live / "run/user")
sh2.SKELETON_DIRS = (*sh2.SKELETON_DIRS, "run/user")  # the same entry, once listed, is ready
sh2.SKELETON_ENTRIES = {**sh2.SKELETON_ENTRIES, "run": (*sh2.SKELETON_ENTRIES["run"], "user"), "run/user": ()}
sh.SKELETON_DIRS, sh.SKELETON_ENTRIES = sh2.SKELETON_DIRS, sh2.SKELETON_ENTRIES
(tree_live / "run/user").mkdir()
status = selftest(Probing(add="run/user"))
must(status["ready"] is True, status["reason"])
(tree_live / "run/user").rmdir()  # a wrong skeleton: the probe is skipped with its own reason
shutil.rmtree(tree_live / "usr")
status = selftest(Probing())
must(status["checks"]["real_unit_shape"] == {"ok": False, "detail": "not run: the sandbox root folder is wrong"}, status["checks"])

# ---- the held Low, restored
line = (HERE / "legacy" / "version-1.18.11.py").read_text(encoding="utf-8").splitlines()[19]
must(line == 'assert "parents[2]" in legacy and "parents[1]" not in legacy', line)
legacy = (HERE / "legacy" / "version-1.18.10.py").read_text(encoding="utf-8")
must("parents[2]" in legacy and "parents[1]" not in legacy, "legacy 1.18.10 passes the restored assertion")

print("[TEST] PASS sandbox skeleton run 1.18.13")
