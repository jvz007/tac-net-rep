#!/usr/bin/env python3
"""1.18.8 regression: the canary's rootview group, the host listing plan and the marker handling (core.sandbox Patch A, part 0, canary-first).

* ``g_rootview`` (the in-unit program) runs against a fake file system: a visible name that the host has and the allowed list does not give
  ATTACK SUCCEEDED naming it (the first ten), an allowed-only view gives OK, a folder the unit cannot list is OK, a missing row is NOT RUN
  through ``group_table``, an empty directory in the runtimes folder is a mount point (OK) and a non-empty one is not;
* ``view_plan`` caps the names, cleans odd characters and reads an unreadable folder as empty; ``rootview_plan`` keeps the json under the budget;
* marker files are made with O_CREAT|O_EXCL|O_NOFOLLOW and an explicit mode on the descriptor, an existing name or a planted link is refused;
* ``remove_markers`` removes only the marker files it made and only a folder named exactly ``tectac-canary-<12 hex>`` directly under the
  stand-in parent, and only when it is empty (rmdir, never a recursive delete).

Not runnable here: the unit itself (dev02: tests/sandbox-canary-1.18.8.sh).
"""
from __future__ import annotations

import contextlib
import errno
import importlib.util
import io
import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_188r", HERE / "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
runner = load("sandbox_runner_188", HERE.parent / "scripts" / "sandbox-canary-runner.py")

HOST = {
    "/": ["bin", "boot", "etc", "home", "lib", "lib64", "opt", "proc", "rmmbackups", "backup", "snap", "run", "sbin", "srv", "sys", "tmp", "usr", "var", "rmm"],
    "/etc": ["passwd", "shadow", "ssl", "tec-tac", "group", "tactical"], "/var": ["lib", "log", "tmp"], "/opt": ["tec-tac", "other"],
    "/opt/tec-tac": ["runtimes", "etc"], "/opt/tec-tac/runtimes": ["ai", "wapm"], "/run": ["credentials", "tec-tac", "systemd"],
    "/usr/local": ["bin", "sbin", "lib"], "/usr/local/lib": ["tec-tac", "python3.12"], "/usr/local/lib/tec-tac": ["sandbox"],
    "/usr/local/lib/tec-tac/sandbox": ["registry", "runners", "canary", "sandbox-launcher.py", "sandbox-helper.py", "root"],
}
GOOD_UNIT = {
    "/": ["bin", "lib", "lib64", "sbin", "usr", "etc", "var", "opt", "run", "tmp", "proc", "sys", "dev", "work"], "/etc": ["passwd", "group", "ssl", "resolv.conf"],
    "/var": ["tmp"], "/opt": ["tec-tac"], "/opt/tec-tac": ["runtimes"], "/opt/tec-tac/runtimes": [], "/run": ["credentials", "systemd"], "/usr/local": ["lib"],
    "/usr/local/lib": ["tec-tac"], "/usr/local/lib/tec-tac": ["sandbox"], "/usr/local/lib/tec-tac/sandbox": ["canary", "sandbox-launcher.py"],
}


class Entry:
    def __init__(self, name):
        self.name = name


class Scan:
    def __init__(self, names):
        self.names = names

    def __enter__(self):
        return [Entry(n) for n in self.names]

    def __exit__(self, *a):
        return False


def host_scandir(tree):
    def scandir(path):
        if path not in tree or tree[path] is None:
            raise OSError(errno.EACCES, "denied")
        return Scan(tree[path])
    return scandir


def plan_for(tree=HOST):
    return sh.rootview_plan(host_scandir(tree))


def run_unit_view(plan, unit_tree, empty_dirs=()):
    """Run the in-unit g_rootview against a fake file system and return the parsed rows."""
    real = (os.listdir, os.path.isdir, os.path.islink)

    def fake_listdir(path):
        path = str(path).replace("\\", "/")
        if path in empty_dirs:
            return []
        if path not in unit_tree or unit_tree[path] is None:
            raise OSError(errno.ENOENT, "none")
        return list(unit_tree[path])

    def fake_isdir(path):
        return str(path).replace("\\", "/") in empty_dirs

    os.listdir, os.path.isdir, os.path.islink = fake_listdir, fake_isdir, lambda path: False
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            runner.g_rootview(plan)
    finally:
        os.listdir, os.path.isdir, os.path.islink = real
    return sh.parse_runner_rows(out.getvalue().encode("utf-8"))


def verdicts(rows):
    return {r["attack"]: sh.classify_tag(r["tag"]) for r in rows}


# ---- 1. an allowed-only view is OK in every row: twelve rows, one per folder and the / row
plan = plan_for()
rows = run_unit_view(plan, GOOD_UNIT)
v = verdicts(rows)
must(len(rows) == 12 and set(v.values()) == {"OK"}, rows)
must(sorted(v) == sorted(["view " + f for f in sh.CANARY_VIEW_FOLDERS] + ["/ lists only the allowed set"]), sorted(v))
must(sh.CANARY_REQUIRED["rootview"][0] == list(v) or sorted(sh.CANARY_REQUIRED["rootview"][0]) == sorted(v), "the helper requires exactly these rows")
table = sh.group_table("Files", "rootview", "only the allowed names are visible", rows)
must(all(entry["verdict"] == "OK" for entry in table) and len(table) == 12, table)

# ---- 2. what 1.18.7 shows: the host's own folders are visible
unit_1187 = dict(GOOD_UNIT)
unit_1187["/"] = GOOD_UNIT["/"] + ["boot", "rmmbackups", "backup", "snap", "srv", "mnt"]
unit_1187["/usr/local"] = ["lib", "bin", "sbin"]
rows = run_unit_view(plan, unit_1187)
v = verdicts(rows)
must(v["view /"] == "ATTACK SUCCEEDED" and v["view /usr/local"] == "ATTACK SUCCEEDED" and v["/ lists only the allowed set"] == "ATTACK SUCCEEDED", v)
text = {r["attack"]: r["actual"] for r in rows}
must("rmmbackups" in text["view /"] and "backup" in text["view /"] and "snap" in text["view /"] and "boot" in text["view /"], text["view /"])
must("bin" in text["view /usr/local"] and "sbin" in text["view /usr/local"], text["view /usr/local"])
must("mnt" in text["/ lists only the allowed set"], "a name the host does not have still fails the unit's own / row")
must(v["view /etc"] == "OK" and v["view /var"] == "OK", "folders that did not leak stay OK")
# only the first ten are named
many = dict(GOOD_UNIT)
many["/"] = GOOD_UNIT["/"] + [f"leak{n:02d}" for n in range(15)]
many_host = dict(HOST)
many_host["/"] = HOST["/"] + [f"leak{n:02d}" for n in range(15)]
rows = run_unit_view(plan_for(many_host), many)
actual = {r["attack"]: r["actual"] for r in rows}["view /"]
must(actual.count("leak") == 10 and "(+5 more)" in actual, actual)

# ---- 3. a folder the unit cannot list is OK; one that cannot list / is NOT RUN
unit_missing = dict(GOOD_UNIT)
unit_missing["/opt/tec-tac"] = None
v = verdicts(run_unit_view(plan, unit_missing))
must(v["view /opt/tec-tac"] == "OK" and set(v.values()) == {"OK"}, v)
unit_noroot = dict(GOOD_UNIT)
unit_noroot["/"] = None
v = verdicts(run_unit_view(plan, unit_noroot))
must(v["/ lists only the allowed set"] == "NOT RUN", v)
must(verdicts(run_unit_view({}, GOOD_UNIT)) == {"rootview plan": "NOT RUN"}, "an empty plan is NOT RUN, never OK")

# ---- 4. a row the program did not print is NOT RUN
rows = run_unit_view(plan, GOOD_UNIT)
short = [r for r in rows if r["attack"] != "view /etc"]
table = sh.group_table("Files", "rootview", "x", short)
must([e for e in table if e["verdict"] == "NOT RUN" and e["attack"] == "view /etc"], table)
table = sh.group_table("Files", "rootview", "x", [])
must(len([e for e in table if e["verdict"] == "NOT RUN"]) == 12, "nothing printed: every row is NOT RUN")

# ---- 5. the runtimes folder: an empty directory is a mount point, a non-empty one is not
unit_rt = dict(GOOD_UNIT)
unit_rt["/opt/tec-tac/runtimes"] = ["ai"]
v = verdicts(run_unit_view(plan, unit_rt, empty_dirs={"/opt/tec-tac/runtimes/ai"}))
must(v["view /opt/tec-tac/runtimes"] == "OK", v)
v = verdicts(run_unit_view(plan, unit_rt, empty_dirs=set()))
must(v["view /opt/tec-tac/runtimes"] == "ATTACK SUCCEEDED", v)
unit_rt["/opt/tec-tac/runtimes"] = ["other-runtime-the-host-does-not-have"]
must(verdicts(run_unit_view(plan, unit_rt))["view /opt/tec-tac/runtimes"] == "OK", "a name the host does not have is not a leak of the host")

# ---- 6. view_plan: names only, capped, cleaned, unreadable = empty
big = dict(HOST)
big["/"] = [f"n{n:04d}" for n in range(500)]
listing = sh.view_plan(host_scandir(big))
must(len(listing["/"]) == sh.CANARY_VIEW_NAMES_MAX == 200 and listing["/"] == sorted(listing["/"]), "capped at 200, sorted")
odd = dict(HOST)
odd["/etc"] = ["pass\nwd", "tést", "x" * 300, "ok"]
cleaned = sh.view_plan(host_scandir(odd))["/etc"]
must("pass?wd" in cleaned and "t?st" in cleaned and "ok" in cleaned and all(len(n) <= 100 and all(32 <= ord(c) < 127 for c in n) for n in cleaned), cleaned)
unreadable = dict(HOST)
unreadable["/var"] = None
must(sh.view_plan(host_scandir(unreadable))["/var"] == [] and set(sh.view_plan(host_scandir(unreadable))) == set(sh.CANARY_VIEW_FOLDERS), "unreadable folder = empty list")
must(set(plan["view"]) == set(sh.CANARY_VIEW_FOLDERS) and plan["view"]["/"]["allowed"] == list(sh.CANARY_VIEW_ALLOWED["/"]), "the plan carries host names and allowed names")
must(all(not (set(sh.CANARY_VIEW_ALLOWED[f]) - set(plan["view"][f]["allowed"])) for f in sh.CANARY_VIEW_FOLDERS), "allowed lists are the helper's constant")
must(sh.CANARY_VIEW_ALLOWED["/opt/tec-tac/runtimes"] == () and "credentials" in sh.CANARY_VIEW_ALLOWED["/run"], "the fixed allowed lists")
must(set(sh.CANARY_VIEW_ALLOWED["/"]) == {"usr", "bin", "sbin", "lib", "lib64", "lib32", "libx32", "etc", "var", "opt", "run", "tmp", "proc", "sys", "dev", "work", "root"}, "the / list")
must(set(sh.CANARY_VIEW_ALLOWED["/etc"]) == {"ssl", "ca-certificates", "passwd", "group", "ld.so.cache", "nsswitch.conf", "localtime", "resolv.conf"}, "the /etc list")
must(set(sh.CANARY_VIEW_ALLOWED["/usr/local/lib/tec-tac/sandbox"]) == {"runners", "canary", "sandbox-launcher.py"}, "the sandbox folder list")
# the json stays under the runner's stdin read even with huge listings
huge = {folder: [("x" * 90) + f"{n:04d}" for n in range(300)] for folder in sh.CANARY_VIEW_FOLDERS}
fitted = sh.rootview_plan(host_scandir(huge))
must(len(json.dumps(fitted)) <= sh.CANARY_VIEW_BUDGET < 65536, len(json.dumps(fitted)))

# ---- 7. markers: exclusive, no link followed, explicit mode on the descriptor
seen = {}
real_open = os.open


def spy_open(path, flags, mode=0o777, *a, **k):
    seen[str(path)] = (flags, mode)
    return real_open(path, flags, mode, *a, **k)


target = BASE / "marker-one"
os.open = spy_open
try:
    created = sh._create_marker(str(target), "abc")
finally:
    os.open = real_open
flags, mode = seen[str(target)]
must(created and flags & os.O_EXCL and flags & os.O_CREAT and flags & getattr(os, "O_NOFOLLOW", 0) == getattr(os, "O_NOFOLLOW", 0) and mode == 0o644, (flags, mode))
must(target.read_text(encoding="utf-8") == "abc", "content written")
must(sh._create_marker(str(target), "again") is False and target.read_text(encoding="utf-8") == "abc", "an existing name is refused, the content stays")
link = BASE / "planted-link"
try:
    os.symlink(str(BASE / "victim-file"), str(link))
except (OSError, NotImplementedError, AttributeError):
    print("[NOTE] this system cannot make a symlink without a privilege: the planted-link case was skipped (the O_EXCL case above covers the same refusal)")
else:
    must(sh._create_marker(str(link), "x") is False and not (BASE / "victim-file").exists(), "a planted symlink is not followed")

# ---- 8. _plant_markers and remove_markers
folders = [BASE / "m1", BASE / "m2"]
for folder in folders:
    folder.mkdir()
sh.CANARY_MARKER_DIRS = (str(folders[0]), str(folders[1]), str(BASE / "does-not-exist"))
sh.CANARY_REAL_FILES = ()
entries = sh._plant_markers()
paths = [e["path"] for e in entries]
standin = [p for p in paths if os.path.basename(os.path.dirname(p)).startswith("tectac-canary-")]
must(len(entries) == 3 and len(standin) == 1 and not any("does-not-exist" in p for p in paths), paths)
folder = Path(os.path.dirname(standin[0]))
must(sh.CANARY_STANDIN_NAME_RE.fullmatch(folder.name) and Path(os.path.dirname(str(folder))) == BASE and folder.is_dir(), folder)
must(H.CHMODS.get(H.norm(folder)) == 0o755, "the stand-in folder gets an explicit 0755")
record = json.loads(sh.CANARY_MARKERS_FILE.read_text(encoding="utf-8"))
must(record["folders"] == [str(folder)] and sorted(record["paths"]) == sorted(paths), record)
for e in entries:
    must(Path(e["path"]).read_text(encoding="utf-8") == e["content"] and len(e["content"]) == 32 and os.path.basename(e["path"]).startswith(".tectac-canary-"), e)
sh.remove_markers()
must(not folder.exists() and not any(Path(p).exists() for p in paths) and not sh.CANARY_MARKERS_FILE.exists(), "everything this run made is gone")

# a stand-in that holds something else is never emptied: rmdir, no rmtree
entries = sh._plant_markers()
folder = Path(os.path.dirname(next(e["path"] for e in entries if os.path.basename(os.path.dirname(e["path"])).startswith("tectac-canary-"))))
(folder / "keep-me.txt").write_text("not ours", encoding="utf-8")
sh.remove_markers()
must(folder.is_dir() and (folder / "keep-me.txt").read_text(encoding="utf-8") == "not ours", "a folder that is not empty after the markers are gone stays")
(folder / "keep-me.txt").unlink()
folder.rmdir()

# only the exact shape under the parent, whatever the markers file says
decoy_name = BASE / "decoy-folder"
decoy_name.mkdir()
too_long = BASE / ("tectac-canary-" + "a" * 13)
too_long.mkdir()
other_parent = BASE / "sub"
other_parent.mkdir()
nested = other_parent / ("tectac-canary-" + "b" * 12)
nested.mkdir()
shaped = BASE / ("tectac-canary-" + "c" * 12)
shaped.mkdir()
sh.CANARY_MARKERS_FILE.write_text(json.dumps({"paths": [], "folders": [str(decoy_name), str(too_long), str(nested), str(shaped), "/", 5, None]}), encoding="utf-8")
sh.remove_markers()
must(decoy_name.is_dir() and too_long.is_dir() and nested.is_dir() and not shaped.exists(), "only the folder with the exact name directly under the parent is removed")
for leftover in (decoy_name, too_long, nested, other_parent):
    leftover.rmdir()
sh.CANARY_MARKERS_FILE.write_text("not json", encoding="utf-8")
sh.remove_markers()
must(not sh.CANARY_MARKERS_FILE.exists(), "a broken markers file is removed without an error")

# ---- 9. the marker folder list names the new places, and the planting is only for folders that exist
helper_text = (HERE.parent / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
for name in ("/rmmbackups", "/backup", "/backups", "/snap", "/srv"):
    must(f'"{name}"' in helper_text.split("CANARY_MARKER_DIRS = (")[1].split(")")[0], name)
must(sh.CANARY_STANDIN_PARENT == str(BASE) and "CANARY_STANDIN_PARENT = \"/\"" in helper_text, "the real parent is /, the harness moved it")

print("[TEST] PASS sandbox canary rootview 1.18.8")
