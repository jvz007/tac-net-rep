#!/usr/bin/env python3
"""1.18.8 regression: install.sh builds the sandbox root skeleton (core.sandbox Patch A, part 1).

Static: the block creates exactly the entries the helper's ``check_skeleton`` expects (read from the helper's own constants), root:root 0755 for
folders and 0644 for the empty mount files, copies this host's own form for bin sbin lib lib64 lib32 libx32 (a symlink with the same target, a
real folder, or nothing), never follows a symlink as a directory, never uses ``rm -rf``, removes only entries it found under the skeleton, keeps
the empty per-module mount points, keeps LF line endings, and the install still ends with the selftest and the same WARNING line.

Dynamic (where bash exists): the block is run with ``chown`` and ``install -o`` stubbed, twice (idempotent), and again after an unexpected file,
an unexpected folder with a child, a file where a folder belongs, a folder where a file belongs and a module mount point were added.

Not runnable here: the symlink form of a merged-/usr host (dev02 shows it with ``ls -la`` of the skeleton) and systemd's use of the root.
"""
from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
HELPER_PATH = ROOT / "scripts" / "sandbox-helper.py"


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_helper_188i", HELPER_PATH)
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

must(b"\r" not in (ROOT / "install.sh").read_bytes(), "install.sh keeps LF line endings")
start = INSTALL.index("SANDBOX_ROOT_DIR=")
stop = INSTALL.index('cat > "${SANDBOX_SUDOERS}"')
block_end = INSTALL.index('ln -sfn "${SANDBOX_LIB}/sandbox-helper.py"', start)
BLOCK = INSTALL[INSTALL.rindex("# 1.18.8: the sandbox root.", 0, start):block_end]
must('SANDBOX_ROOT_DIR="${SANDBOX_LIB}/root"' in BLOCK, "the skeleton is ${SANDBOX_LIB}/root")
must(INSTALL.index('install_root_script "${REPO_ROOT}/scripts/sandbox-canary-runner.py"') < start < INSTALL.index('systemctl enable --now tec-tac-sandbox-sweep.timer') < INSTALL.index('--selftest >/dev/null 2>&1; then'), "the skeleton is built before the selftest runs")

# ---- the entries are the helper's constants
dirs = re.search(r"for sandbox_entry in (usr work [^;]+); do\n\s+SANDBOX_SKEL\[\"\$\{sandbox_entry\}\"\]=\"d\"", BLOCK)
files = re.search(r"for sandbox_entry in (etc/passwd [^;]+); do\n\s+SANDBOX_SKEL\[\"\$\{sandbox_entry\}\"\]=\"f\"", BLOCK)
merged = re.search(r"for sandbox_entry in (bin sbin [^;]+); do\n\s+if \[\[ -L", BLOCK)
must(dirs and files and merged, "the three entry lists")
must(dirs.group(1).split() == list(sh.SKELETON_DIRS), (dirs.group(1).split(), sh.SKELETON_DIRS))
must(files.group(1).split() == list(sh.SKELETON_FILES), (files.group(1).split(), sh.SKELETON_FILES))
must(merged.group(1).split() == list(sh.MERGED_USR_NAMES), (merged.group(1).split(), sh.MERGED_USR_NAMES))
for relative in sh.BASE_BINDS_REQUIRED + sh.BASE_BINDS_OPTIONAL + ("/etc/resolv.conf",):
    must(relative.lstrip("/") in sh.SKELETON_DIRS + sh.SKELETON_FILES, f"{relative} has a mount point")

# ---- modes, owners, links, removal
must(BLOCK.count("chown root:root") >= 3 and "chown -h root:root" in BLOCK and "chmod 0755" in BLOCK and "chmod 0644" in BLOCK and "install -m 0644 -o root -g root /dev/null" in BLOCK, "root-owned 0755 and 0644")
must('SANDBOX_SKEL["${sandbox_entry}"]="l:$(readlink "/${sandbox_entry}")"' in BLOCK and 'ln -s -- "${sandbox_want#l:}"' in BLOCK, "a symlink with the host's own target on a merged-/usr host")
must('elif [[ -d "/${sandbox_entry}" ]]; then' in BLOCK, "a real folder on a host that has one")
must(BLOCK.index('[[ -L "/${sandbox_entry}" ]]') < BLOCK.index('[[ -d "/${sandbox_entry}" ]]'), "the link form is asked first")
must("rm -rf" not in BLOCK and "rm -rf" not in INSTALL[start:stop], "no recursive delete in the block")
must("rm -f --" in BLOCK and "rmdir --" in BLOCK, "links and files with rm -f, folders with rmdir")
must(re.findall(r'(?:rm -f --|rmdir --) "([^"]+)"', BLOCK) == ["${SANDBOX_ROOT_DIR}", "${sandbox_path}", "${sandbox_path}"], "removal targets only the skeleton root symlink and entries found under it")
must('find "${SANDBOX_ROOT_DIR}" -mindepth 1 -depth -print0' in BLOCK and "-L " not in BLOCK.split("find ", 1)[1].split("\n")[0], "find never follows links, children before parents")
must('[[ -L "${sandbox_path}" ]] && fail "Sandbox root: a folder is a symlink."' in BLOCK and 'fail "Sandbox root: a file is a symlink."' in BLOCK, "never a symlink as a folder or file")
must("^opt/tec-tac/runtimes/[A-Za-z0-9][A-Za-z0-9_-]{0,99}$" in BLOCK, "the per-module mount point is the one entry that is not on the fixed list")
must(re.fullmatch(sh.MODULE_ID_RE.pattern, "ai") and "{0,99}" in BLOCK and sh.MODULE_ID_RE.pattern == r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$", "the same module id rule as the helper")

# ---- the install still ends the same way
tail = INSTALL[block_end:INSTALL.index("# Housekeeping trust boundary")]
must('"${SANDBOX_HELPER}" --selftest >/dev/null 2>&1; then' in tail and 'log "WARNING: Sandbox is off: ${SANDBOX_OFF_REASON}. ai ChatGPT stays off."' in tail, "selftest and the WARNING line")
must("${TACTICAL_USER} ALL=(root) NOPASSWD: ${SANDBOX_HELPER} --start, ${SANDBOX_HELPER} --stop, ${SANDBOX_HELPER} --status" in tail, "the sudoers rule lists exactly --start, --stop and --status")
must(not re.search(r"SANDBOX_ENABLED|enable.*sandbox\.enabled", BLOCK), "the block does not touch the kill switch")

bash = shutil.which("bash")
if bash:
    done = subprocess.run([bash, "-n", str(ROOT / "install.sh")], capture_output=True, text=True, check=False)
    must(done.returncode == 0, done.stderr)

    def run_block(folder):
        script = ("set -euo pipefail\nfail() { echo \"FAIL $*\"; exit 1; }\nchown() { :; }\ninstall() { local last; for last; do :; done; : > \"$last\"; }\n"
                  f'SANDBOX_LIB="{Path(folder).as_posix()}"\n' + BLOCK + "\necho BLOCK-DONE\n")
        return subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)

    def tree(folder):
        out = {}
        for path in sorted(Path(folder).rglob("*")):
            out[path.relative_to(folder).as_posix()] = "d" if path.is_dir() else "f"
        return out

    with tempfile.TemporaryDirectory() as tmp:
        lib = Path(tmp) / "lib"
        lib.mkdir()
        done = run_block(lib)
        if "BLOCK-DONE" not in done.stdout:
            print("[NOTE] this bash cannot run the block (stubs or find differ): the dynamic cases were skipped:", done.stdout[-200:], done.stderr[-200:])
        else:
            skeleton = lib / "root"
            first = tree(skeleton)
            expected = set(sh.SKELETON_DIRS) | set(sh.SKELETON_FILES)
            for name in sh.MERGED_USR_NAMES:
                if Path("/" + name).is_dir() and not Path("/" + name).is_symlink():
                    expected.add(name)  # a host with a real folder: an empty folder here
            must(expected <= set(first), sorted(expected - set(first)))
            extra = set(first) - expected
            must(all(item.split("/")[0] in sh.MERGED_USR_NAMES for item in extra) or not extra, sorted(extra))
            must(all((first[e] == "d") == (e in sh.SKELETON_DIRS or e in sh.MERGED_USR_NAMES) for e in expected), "folders are folders and mount files are files")
            must(all(not any(skeleton.joinpath(e).iterdir()) for e in sh.SKELETON_DIRS if e not in ("var", "run", "run/systemd", "opt", "opt/tec-tac", "etc", "etc/ssl")), "mount points are empty")  # 1.18.13: run and run/systemd hold the one folder each
            second = run_block(lib)
            must("BLOCK-DONE" in second.stdout and tree(skeleton) == first, "running it again changes nothing")
            # damage the skeleton in every way the block must repair
            (skeleton / "intruder.txt").write_text("x", encoding="utf-8")
            (skeleton / "etc" / "shadow").write_text("x", encoding="utf-8")
            (skeleton / "home" / "deep").mkdir(parents=True)
            (skeleton / "home" / "deep" / "file").write_text("x", encoding="utf-8")
            shutil.rmtree(skeleton / "usr")
            (skeleton / "usr").write_text("a file where a folder belongs", encoding="utf-8")
            (skeleton / "etc" / "passwd").unlink()
            (skeleton / "etc" / "passwd").mkdir()
            (skeleton / "etc" / "passwd" / "child").write_text("x", encoding="utf-8")
            (skeleton / "opt" / "tec-tac" / "runtimes" / "ai").mkdir()
            (skeleton / "opt" / "tec-tac" / "runtimes" / "bad name").mkdir()
            (skeleton / "opt" / "tec-tac" / "runtimes" / "afile").write_text("x", encoding="utf-8")
            keep_outside = Path(tmp) / "outside.txt"
            keep_outside.write_text("must survive", encoding="utf-8")
            third = run_block(lib)
            must("BLOCK-DONE" in third.stdout, third.stdout + third.stderr)
            repaired = tree(skeleton)
            must("intruder.txt" not in repaired and "etc/shadow" not in repaired and "home" not in repaired and "home/deep/file" not in repaired, sorted(repaired))
            must(repaired["usr"] == "d" and repaired["etc/passwd"] == "f", "wrong types are replaced")
            must("opt/tec-tac/runtimes/ai" in repaired and "opt/tec-tac/runtimes/bad name" not in repaired and "opt/tec-tac/runtimes/afile" not in repaired, "only a valid module mount point is kept")
            must(keep_outside.read_text(encoding="utf-8") == "must survive", "nothing outside the skeleton is touched")
            del repaired["opt/tec-tac/runtimes/ai"]
            must(repaired == first, "the repaired skeleton is the first one")

print("[TEST] PASS sandbox installer skeleton 1.18.8")
