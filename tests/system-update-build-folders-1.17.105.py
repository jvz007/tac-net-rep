#!/usr/bin/env python3
"""1.17.105: the owner hand-over of a source checkout skips the UI's Git-ignored top-level build folders (found on dev02).

A UI update stopped on a root-owned file with two hard links in /opt/tec-tac-src/ui/node_modules/@esbuild/..., left by an old root
`npm install`. scripts/system-update-helper.py _normalise_owner_from_fd now:
1. does not walk the UI checkout's top-level node_modules and dist (nothing runs from them, stage_release_tree never copies them),
   and leaves them as they are: nothing is removed and their owner is not changed;
2. still walks a node_modules or dist deeper down, and still walks every folder of the Framework checkout;
3. still refuses a root-owned file with a second hard link anywhere else, and now names the top-level folder that holds it
   ("Remove it" for a file at the top level);
4. still refuses a path owned by a third account.

os.fwalk and dir_fd are POSIX only, so the walk runs against a small in-memory file system that stands in for the helper's `os`
(fwalk, stat, open, fstat, fchown, close). tests/system-update-linux-staging-1.17.98.py runs the real thing as root on Linux.
"""
from __future__ import annotations

import ast
import posixpath
import stat
import types
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "system-update-helper.py"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# The helper only imports on Linux as root (fcntl, pwd, a root-owned bash), so the walk and its constants are taken from its source.
WANTED = {"UNWALKED_BUILD_FOLDERS", "_hard_link_refusal", "_normalise_owner_from_fd", "_NOFOLLOW_READ", "_NOFOLLOW_DIR"}
TREE = ast.parse(HELPER.read_text(encoding="utf-8"))
picked = [n for n in TREE.body if (isinstance(n, ast.FunctionDef) and n.name in WANTED)
          or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in WANTED for t in n.targets))]
must(len(picked) == len(WANTED), [getattr(n, "name", None) for n in picked])
import os as _real_os  # only for the flag constants while the source is loaded

h = types.SimpleNamespace()
H: dict = {"os": _real_os, "stat": stat, "PurePosixPath": PurePosixPath, "_group_name": lambda gid: "tactical",
           "_owner_name": lambda uid: {0: "root", 4242: "uid 4242"}.get(uid, "tactical")}
exec(compile(ast.Module(body=picked, type_ignores=[]), str(HELPER), "exec"), H)  # noqa: S102 - test only
h.UNWALKED_BUILD_FOLDERS = H["UNWALKED_BUILD_FOLDERS"]

UID = GID = 999
CHECKOUT = "/opt/tec-tac-src/ui"


class FakeOS:
    """A checkout in memory: path -> stat-like node. Descriptors are paths. Records every fchown."""

    path = posixpath
    sep = "/"

    def __init__(self, entries):
        self.nodes = {}
        self.inode = 100
        self.fds = {}
        self.chowned = []
        self._add(CHECKOUT, True, UID, 1)
        for rel, (is_dir, uid, nlink) in entries.items():
            self._add(posixpath.join(CHECKOUT, rel), is_dir, uid, nlink)

    def _add(self, path, is_dir, uid, nlink):
        parts = path.strip("/").split("/")
        for i in range(1, len(parts)):  # parents default to a Tactical-owned folder
            parent = "/" + "/".join(parts[:i])
            if parent.startswith(CHECKOUT + "/") and parent not in self.nodes:
                self._add(parent, True, UID, 1)
        self.inode += 1
        mode = (stat.S_IFDIR | 0o755) if is_dir else (stat.S_IFREG | 0o644)
        self.nodes[path] = types.SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=uid, st_nlink=nlink,
                                                 st_dev=1, st_ino=self.inode)

    def _fd(self, path):
        fd = len(self.fds) + 10
        self.fds[fd] = path
        return fd

    def _children(self, path):
        prefix = path.rstrip("/") + "/"
        return sorted(p[len(prefix):] for p in self.nodes if p.startswith(prefix) and "/" not in p[len(prefix):])

    def fwalk(self, top, dir_fd=None, follow_symlinks=False):
        base = self.fds[dir_fd]

        def walk(rel, path):
            names = self._children(path)
            dirs = [n for n in names if stat.S_ISDIR(self.nodes[posixpath.join(path, n)].st_mode)]
            files = [n for n in names if n not in dirs]
            yield rel, dirs, files, self._fd(path)
            for name in dirs:  # topdown: a pruned name is not entered
                yield from walk(posixpath.join(rel, name), posixpath.join(path, name))

        yield from walk(top, base)

    def stat(self, name, dir_fd=None, follow_symlinks=False):
        return self.nodes[posixpath.join(self.fds[dir_fd], name)]

    def open(self, name, flags, dir_fd=None):
        return self._fd(posixpath.join(self.fds[dir_fd], name))

    def fstat(self, fd):
        return self.nodes[self.fds[fd]]

    def fchown(self, fd, uid, gid):
        path = self.fds[fd]
        self.chowned.append(path)
        self.nodes[path].st_uid, self.nodes[path].st_gid = uid, gid

    def close(self, fd):
        pass


def walk(entries, component="ui"):
    fake = FakeOS(entries)
    H["os"] = fake
    root_fd = fake._fd(CHECKOUT)
    try:
        return fake, H["_normalise_owner_from_fd"](root_fd, PurePosixPath(CHECKOUT), component, "tactical", UID, GID), None
    except RuntimeError as exc:
        return fake, None, str(exc)


ESBUILD = "node_modules/@esbuild/linux-x64/bin/esbuild"
BUILD = {
    ESBUILD: (False, 0, 2),                     # the dev02 file: root-owned, two hard links
    "node_modules/@esbuild/linux-x64/package.json": (False, 0, 1),
    "node_modules/third": (False, 4242, 1),     # even a third account's file there is never walked
    "dist/assets/index.js": (False, 0, 2),
    "src/App.vue": (False, 0, 1),               # a tracked file root left behind: still handed over
    "package.json": (False, UID, 1),
}

# --- 1. the UI's top-level node_modules and dist are not walked, not changed and not removed
fake, changed, error = walk(BUILD)
must(error is None, error)
must(changed == 1 and fake.chowned == [f"{CHECKOUT}/src/App.vue"], fake.chowned)
for rel in (ESBUILD, "node_modules/third", "dist/assets/index.js"):
    must(f"{CHECKOUT}/{rel}" in fake.nodes, f"{rel} was removed")
must(fake.nodes[f"{CHECKOUT}/{ESBUILD}"].st_uid == 0 and fake.nodes[f"{CHECKOUT}/node_modules"].st_uid == UID, "a build folder changed owner")
print("       1. UI: top-level node_modules and dist are skipped (a root-owned hard-linked esbuild no longer stops the update)")

# --- 2. deeper down, and in the Framework checkout, they are walked as before
fake, changed, error = walk({"src/node_modules/x.js": (False, 0, 2)})
must(error and "more than one hard link" in error and f"Remove the top-level folder {CHECKOUT}/src that holds it" in error, error)
fake, changed, error = walk({ESBUILD: (False, 0, 2)}, component="framework")
must(error and "more than one hard link" in error and f"{CHECKOUT}/node_modules that holds it" in error, error)
fake, changed, error = walk({"dist/a.js": (False, 0, 1)}, component="framework")
must(error is None and fake.chowned == [f"{CHECKOUT}/dist/a.js"], (error, fake.chowned))
print("       2. a node_modules deeper down, and the Framework checkout's folders, are still walked")

# --- 3. the hard-link refusal names the top-level folder; a top-level file says "Remove it"
fake, changed, error = walk({"public/fonts/inter.woff2": (False, 0, 3)})
must(error == f"ui source checkout {CHECKOUT}/public/fonts/inter.woff2 is a root-owned file with more than one hard link, so it is not handed "
              f"to tactical. Remove the top-level folder {CHECKOUT}/public that holds it (Git restores tracked files on the next update), "
              "then update again.", error)
must(fake.nodes[f"{CHECKOUT}/public/fonts/inter.woff2"].st_uid == 0, "a hard-linked root file was handed over")
fake, changed, error = walk({"index.html": (False, 0, 2)})
must(error and error.endswith("is a root-owned file with more than one hard link, so it is not handed to tactical. Remove it, then update again."), error)
must(f"{CHECKOUT}/index.html" not in fake.chowned, "a hard-linked root file was handed over")
print("       3. a root-owned hard-linked file elsewhere is still refused, and the message names the top-level folder to remove")

# --- 4. a third account elsewhere is still refused
fake, changed, error = walk({"src/evil.js": (False, 4242, 1)})
must(error and "must be owned by tactical" in error and "chown -R tactical:tactical" in error, error)
print("       4. a path owned by a third account is still refused")

# --- static: one list, UI only; documented; LF only
must(h.UNWALKED_BUILD_FOLDERS == {"ui": frozenset({"node_modules", "dist"})}, h.UNWALKED_BUILD_FOLDERS)
must(b"\r" not in HELPER.read_bytes(), "system-update-helper.py has CR")
doc = (ROOT / "docs" / "system-update-signed-releases.md").read_text(encoding="utf-8")
must("1.17.105" in doc and "`node_modules` and `dist` are not walked" in doc, "the update doc")
print("[TEST] PASS system update build folders 1.17.105")
