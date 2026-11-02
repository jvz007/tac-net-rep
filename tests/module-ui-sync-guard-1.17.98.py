#!/usr/bin/env python3
"""1.17.98: module jobs run only the root-owned, published UI sync script, checked just before it runs.

Review of f72e984 (Medium): UI_SYNC_SCRIPT could name ${TEC_TAC_UI_SOURCE}/scripts/sync-modules.sh, a file in the Tactical-owned
UI checkout. Now:
  * install.sh writes only the published root path /usr/local/lib/tec-tac-ui-sync/scripts/sync-modules.sh;
  * module-job-helper.py, module-v2-job-helper.py and module-hotfix-job-helper.py share one guard (trusted_ui_sync_script):
    the script and the tec-tac-config.sh it sources are opened with O_NOFOLLOW, must be regular, root-owned and not group/world
    writable, and every parent folder must be root-owned and not group/world writable. A missing script means UI sync is off
    (a clear log line, no run); a script that fails the rule is refused. v1 checks again immediately before it runs.
The guard is read from each helper with ast (the helpers cannot be imported without a server) and run on temporary folders.
The ownership cases need root (Linux); elsewhere only the static checks run.
"""
from __future__ import annotations

import ast
import os
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ("scripts/module-job-helper.py", "scripts/module-v2-job-helper.py", "scripts/module-hotfix-job-helper.py")
NAMES = ("UI_SYNC_PUBLISHED", "UI_SYNC_OFF_MESSAGE", "_require_trusted_root_file", "trusted_ui_sync_script")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def guard_source(rel):
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
    picked = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in NAMES)
              or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in NAMES for t in n.targets))]
    must(len(picked) == len(NAMES), f"{rel}: guard incomplete")
    return picked


sources = {rel: ast.unparse(ast.Module(body=guard_source(rel), type_ignores=[])) for rel in HELPERS}
must(len(set(sources.values())) == 1, "the three module helpers must share the same UI sync guard")
for rel in HELPERS:
    text = (ROOT / rel).read_text(encoding="utf-8")
    must("/opt/tec-tac-src/ui/scripts/sync-modules.sh" not in text, f"{rel} still defaults to the UI checkout")
    must("trusted_ui_sync_script(config)" in text, f"{rel} does not use the guard")
v1 = (ROOT / "scripts/module-job-helper.py").read_text(encoding="utf-8")
must("trusted_ui_sync_script(config)  # checked again immediately before it runs" in v1, "v1 re-check before the run")
install = (ROOT / "install.sh").read_text(encoding="utf-8")
must('UI_SYNC_SCRIPT_PATH="/usr/local/lib/tec-tac-ui-sync/scripts/sync-modules.sh"' in install, "install.sh writes the published path")
must("${TEC_TAC_UI_SOURCE}/scripts/sync-modules.sh" not in install, "install.sh never writes the UI checkout path")
print("       static: one guard in all three helpers, no UI checkout default, install.sh writes only the published path")

if not sys.platform.startswith("linux") or os.geteuid() != 0:
    print("[TEST] PASS module UI sync guard 1.17.98 (static checks only; the ownership cases need root on Linux)")
    raise SystemExit(0)

ns = {"os": os, "stat": stat, "Path": Path}
exec(compile(ast.Module(body=guard_source(HELPERS[0]), type_ignores=[]), HELPERS[0], "exec"), ns)  # noqa: S102 - test only
guard = ns["trusted_ui_sync_script"]


def refused(path, expect):
    try:
        guard({"UI_SYNC_SCRIPT": str(path)})
    except RuntimeError as exc:
        must(expect in str(exc), (expect, str(exc)))
        return
    raise AssertionError(f"accepted: {path}")


base = Path(tempfile.mkdtemp(prefix="uisync-", dir="/root" if os.path.isdir("/root") else "/opt"))  # /tmp is world-writable
os.chmod(base, 0o755)
good = base / "lib" / "scripts"
good.mkdir(parents=True)
for d in (base / "lib", good):
    os.chmod(d, 0o755)
script = good / "sync-modules.sh"
script.write_text("#!/bin/bash\n", encoding="utf-8")
os.chmod(script, 0o755)
(good / "tec-tac-config.sh").write_text("TEC_TAC_ROOT=/opt/tec-tac\n", encoding="utf-8")
os.chmod(good / "tec-tac-config.sh", 0o644)
must(guard({"UI_SYNC_SCRIPT": str(script)}) == script, "the published root-owned script is accepted")
must(guard({"UI_SYNC_SCRIPT": str(base / "missing" / "sync-modules.sh")}) is None, "a missing script means UI sync is off")
must("UI module sync is off" in ns["UI_SYNC_OFF_MESSAGE"], "clear message")

link = base / "link-sync.sh"
link.symlink_to(script)
refused(link, "symbolic link")
os.chmod(script, 0o775)
refused(script, "non-root-owned or writable UI sync script")
os.chmod(script, 0o755)
os.chown(script, 1001, 1001)
refused(script, "non-root-owned or writable UI sync script")
os.chown(script, 0, 0)
os.chmod(good / "tec-tac-config.sh", 0o666)
refused(script, "UI sync config reader")
os.chmod(good / "tec-tac-config.sh", 0o644)
os.chown(good, 1001, 1001)
refused(script, "is not root-owned or is group/world writable")
os.chown(good, 0, 0)
os.chmod(base / "lib", 0o775)
refused(script, "is not root-owned or is group/world writable")
os.chmod(base / "lib", 0o755)
# The old value: a script inside a Tactical-owned UI checkout, itself root-owned.
checkout = base / "src" / "ui" / "scripts"
checkout.mkdir(parents=True)
os.chown(base / "src" / "ui", 1001, 1001)
(checkout / "sync-modules.sh").write_text("#!/bin/bash\n", encoding="utf-8")
os.chmod(checkout / "sync-modules.sh", 0o755)
refused(checkout / "sync-modules.sh", "is not root-owned or is group/world writable")
print("       guard: link, writable, foreign-owned, writable config reader, foreign or writable folder, and a script in the UI checkout are refused")
print("[TEST] PASS module UI sync guard 1.17.98")
