#!/usr/bin/env python3
"""1.17.98: a server-backup restore never runs install.sh straight from a restored, Tactical-owned source checkout.

Review fix note of 2 November 2026: run_post_restore_tec_tac used to run <framework source>/install.sh and the UI's
scripts/install.sh as root. Now it copies the installed system update helper into a root-only folder and runs
"--install-restored framework" (then "ui") with it. That helper stages each component, checks the staged copy against the signed
release manifest with the privileged verifier, and only then runs its installer from the copy
(tests/system-update-linux-staging-1.17.98.py proves a changed install.sh is refused there before any installer runs).
Here: the commands run_post_restore_tec_tac issues, that a framework failure stops before the UI, and the helper snapshot rules.
Linux only (the backup helper imports fcntl, pwd and cryptography); the snapshot ownership checks need root.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import types
from pathlib import Path

if not sys.platform.startswith("linux"):
    print("[TEST] SKIP server backup restore staged 1.17.98 (Linux only)")
    raise SystemExit(0)
try:
    import cryptography  # noqa: F401
except ImportError:
    print("[TEST] SKIP server backup restore staged 1.17.98 (needs cryptography)")
    raise SystemExit(0)

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("server_backup_helper", ROOT / "scripts/server-backup-helper.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


tmp = Path(tempfile.mkdtemp(prefix="sbh-restore-"))
fw, ui, ui_root = tmp / "src" / "framework", tmp / "src" / "ui", tmp / "ui-deploy"
for d in (fw, ui / "scripts", ui_root):
    d.mkdir(parents=True)
(fw / "install.sh").write_text("#!/bin/bash\ntouch /should-never-run\n", encoding="utf-8")
(ui / "scripts" / "install.sh").write_text("#!/bin/bash\n", encoding="utf-8")
(ui_root / "index.html").write_text("<html/>", encoding="utf-8")
config = {"TEC_TAC_FRAMEWORK_SOURCE": str(fw), "TEC_TAC_UI_SOURCE": str(ui), "TACTICAL_PYTHON": str(tmp / "none"),
          "TACTICAL_BACKEND_ROOT": str(tmp / "none"), "TEC_TAC_UI_DEPLOY_ROOT": str(ui_root), "TACTICAL_USER": "tactical"}

commands = []
fail_on = []


def run_logged(args, log, **kwargs):
    commands.append([str(a) for a in args])
    if fail_on and fail_on[0] in commands[-1]:
        raise RuntimeError("command failed with status 1: python3")
    return 0


h.run_logged = run_logged
h._clear_tec_tac_restore_roots = lambda cfg, log: None
h.safe_extract_payload_tar = lambda archive, config=None: None
h.verify_tactical_runtime = lambda cfg, log: None
h._verify_restored_core_version = lambda cfg, meta, log: "2.0.3"
snapshots = []


def snapshot(dest):
    snapshots.append(dest)
    copy = dest / "system-update-helper.py"
    copy.write_text("# helper copy\n", encoding="utf-8")
    return copy


h._snapshot_restore_installer_helper = snapshot
h.subprocess = types.SimpleNamespace(run=lambda *a, **k: None, DEVNULL=None)

must(h.run_post_restore_tec_tac(config, {}, tmp / "archive.tar.gz", log=None) == "2.0.3", "restore result")
installer_calls = [c for c in commands if "--install-restored" in c]
must([c[-1] for c in installer_calls] == ["framework", "ui"], installer_calls)
must(all(c[0] == sys.executable and c[1] == "-I" and c[2].endswith("system-update-helper.py") for c in installer_calls), installer_calls)
must(not any(arg.endswith("install.sh") for c in commands for arg in c), f"an install.sh was run directly: {commands}")
must(len(snapshots) == 1 and not snapshots[0].exists(), "one helper snapshot, removed afterwards")
print("       restore runs the staged, verified installer for framework then UI; no install.sh is run directly; the helper copy is removed")

# Round 6: the version each restored tree must be signed for comes from the backup's manifest, never from the restored checkout.
commands.clear()
h.run_post_restore_tec_tac(config, {"framework_version": "2.0.3", "ui_version": "0.5.2"}, tmp / "archive.tar.gz", log=None)
must([c[-2:] for c in commands if "--install-restored" in c] == [["framework", "2.0.3"], ["ui", "0.5.2"]], commands)
commands.clear()
h.run_post_restore_tec_tac(config, {"framework_version": "2.0.3; rm -rf /"}, tmp / "archive.tar.gz", log=None)
must([c[-1] for c in commands if "--install-restored" in c] == ["framework", "ui"], f"an invalid recorded version was passed on: {commands}")
src = (ROOT / "scripts/server-backup-helper.py").read_text(encoding="utf-8")
must('"framework_version": detect_version(paths["runtime_root"]),' in src and 'detect_version(paths["framework_source"])' not in src,
     "the backup records the runtime version, never the checkout's")
must('detect_version(Path(config["TEC_TAC_FRAMEWORK_SOURCE"]))' not in src, "no version decision from the framework checkout")
print("       round 6: restore passes the backup's recorded versions; the backup records runtime versions, never the checkout's")

commands.clear()
fail_on[:] = ["framework"]
try:
    h.run_post_restore_tec_tac(config, {}, tmp / "archive.tar.gz", log=None)
except RuntimeError:
    pass
else:
    raise AssertionError("a refused framework restore did not stop the restore")
must([c[-1] for c in commands if "--install-restored" in c] == ["framework"], f"the UI ran after a refused framework: {commands}")
print("       a refused framework restore (for example a changed install.sh) stops before the UI and before any check")

if os.geteuid() == 0:
    spec2 = importlib.util.spec_from_file_location("server_backup_helper_real", ROOT / "scripts/server-backup-helper.py")
    r = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(r)
    lib = tmp / "lib"
    lib.mkdir(mode=0o755)
    target = lib / "system-update-helper.py"
    target.write_text("print('helper')\n", encoding="utf-8")
    os.chmod(target, 0o755)
    link = tmp / "tec-tac-system-update"
    link.symlink_to(target)
    r.SYSTEM_UPDATE_HELPER = link
    dest = tmp / "snap"
    dest.mkdir()
    copy = r._snapshot_restore_installer_helper(dest)
    must(copy.read_text(encoding="utf-8") == "print('helper')\n" and (os.stat(copy).st_mode & 0o777) == 0o700, "helper copy")
    must((os.stat(dest).st_mode & 0o777) == 0o700, "the copy folder is root-only")
    os.chmod(target, 0o775)
    dest2 = tmp / "snap2"
    dest2.mkdir()
    try:
        r._snapshot_restore_installer_helper(dest2)
    except RuntimeError as exc:
        must("must be root-owned and not group/world writable" in str(exc), exc)
    else:
        raise AssertionError("a group-writable helper was copied and run")
    print("       helper snapshot: root-owned helper copied 0700; a group-writable helper is refused")
else:
    print("       helper snapshot ownership checks skipped (not root)")

# Review of f72e984 (High): root never follows a link in a source checkout, for its VERSION or when it backs the checkout up.
import tarfile  # noqa: E402

spec3 = importlib.util.spec_from_file_location("server_backup_helper_reads", ROOT / "scripts/server-backup-helper.py")
r3 = importlib.util.module_from_spec(spec3)
spec3.loader.exec_module(r3)
secret_text = "ROOT-ONLY-SECRET-backup"
secret = tmp / "secret.txt"
secret.write_text(secret_text + "\n", encoding="utf-8")
checkout = tmp / "checkout"
(checkout / "sub").mkdir(parents=True)
(checkout / "VERSION").symlink_to(secret)
(checkout / "plain.txt").write_text("plain\n", encoding="utf-8")
(checkout / "sub" / "leak").symlink_to(secret)
(checkout / "linked-dir").symlink_to(tmp / "src")
must(r3.detect_version(checkout) is None, "a VERSION link must not be read")
(tmp / "v").mkdir()
for text, expect in (("2.0.3\n", "2.0.3"), ("2.0.3; rm -rf /", None), ("x" * 65, None)):
    (tmp / "v" / "VERSION").write_text(text, encoding="utf-8")
    must(r3.detect_version(tmp / "v") == expect, (text, r3.detect_version(tmp / "v")))
archive = tmp / "payload.tar.gz"
r3.make_payload_tar(archive, [checkout], nofollow_roots=[checkout])
with tarfile.open(archive, "r:gz") as tf:
    names = tf.getnames()
    data = b"".join(tf.extractfile(m).read() for m in tf.getmembers() if m.isfile())
    must(not any(m.issym() or m.islnk() for m in tf.getmembers()), "links stored in the archive")
must(secret_text.encode() not in data, "the root-only secret was archived through a link")
must(any(n.endswith("checkout/plain.txt") for n in names) and not any(n.endswith("/VERSION") or n.endswith("/leak") for n in names), names)
must(not any("linked-dir" in n for n in names), "a linked folder was followed")
print("       source checkout reads: VERSION link refused, version text validated, backup archives no link and no file through a link")

print("[TEST] PASS server backup restore staged 1.17.98")
