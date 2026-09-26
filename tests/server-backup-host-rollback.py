#!/usr/bin/env python3
import importlib.util
import io
import os
import shutil
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "server-backup-helper.py"
spec = importlib.util.spec_from_file_location("tt_server_backup_host_rollback", HELPER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def must(condition, message):
    if not condition:
        raise AssertionError(message)


with tempfile.TemporaryDirectory(prefix="tectac-b1-host-") as td:
    base = Path(td)
    snap = base / "snapshot"
    snap.mkdir()
    os.chmod(snap, 0o700)

    live_file = base / "nginx.conf"
    live_file.write_text("original-nginx\n", encoding="utf-8")
    os.chmod(live_file, 0o640)

    live_dir = base / "letsencrypt"
    live_dir.mkdir()
    cert = live_dir / "cert.pem"
    cert.write_text("original-cert\n", encoding="utf-8")
    os.chmod(cert, 0o600)

    real = base / "sites-available.conf"
    real.write_text("original-site\n", encoding="utf-8")
    link = base / "sites-enabled.conf"
    link.symlink_to(real.name)

    absent_before = base / "created-by-failed-restore"

    records = mod._snapshot_host_paths(snap, [live_file, live_dir, link, absent_before])
    must(len(records) == 4, "all fixed rollback targets were not recorded")
    must(stat.S_IMODE((snap / "host-paths").stat().st_mode) == 0o700, "host snapshot root is not 0700")

    # Simulate writes performed by restore.sh and Tec-Tac post-restore.
    live_file.write_text("restored-nginx\n", encoding="utf-8")
    os.chmod(live_file, 0o666)
    shutil.rmtree(live_dir)
    live_dir.mkdir()
    (live_dir / "cert.pem").write_text("restored-cert\n", encoding="utf-8")
    link.unlink()
    link.write_text("replaced-symlink-with-file\n", encoding="utf-8")
    absent_before.mkdir()
    (absent_before / "junk").write_text("must disappear\n", encoding="utf-8")

    log = io.StringIO()
    snapshot = {"host_paths": records}
    old_run = mod.subprocess.run
    try:
        # The final daemon-reload is operational glue; avoid touching host systemd in this unit test.
        def run(argv, *args, **kwargs):
            if list(argv[:2]) == ["systemctl", "daemon-reload"]:
                class R: returncode = 0
                return R()
            return old_run(argv, *args, **kwargs)
        mod.subprocess.run = run
        mod._restore_host_paths(snapshot, log)
    finally:
        mod.subprocess.run = old_run

    must(live_file.read_text(encoding="utf-8") == "original-nginx\n", "file content was not rolled back")
    must(stat.S_IMODE(live_file.stat().st_mode) == 0o640, "file mode was not rolled back")
    must(cert.read_text(encoding="utf-8") == "original-cert\n", "directory content was not rolled back")
    must(stat.S_IMODE(cert.stat().st_mode) == 0o600, "nested file mode was not rolled back")
    must(link.is_symlink(), "symlink identity was not restored")
    must(os.readlink(link) == real.name, "symlink target was not restored")
    must(not absent_before.exists(), "path absent before restore was not removed during rollback")

    # Nested snapshot targets are collapsed so a child is not restored twice.
    collapsed = mod._canonical_snapshot_targets([live_dir, cert])
    must(collapsed == [live_dir], f"nested rollback targets were not canonicalized: {collapsed}")


# Exercise the rollback coordinator in Tec-Tac-only mode. It must restore host
# paths without moving /rmm or touching databases.
with tempfile.TemporaryDirectory(prefix="tectac-b1-coordinator-") as td:
    base = Path(td)
    snapshot_root = base / "snapshot"
    snapshot_root.mkdir()
    os.chmod(snapshot_root, 0o700)
    protected = base / "tec-tac.conf"
    protected.write_text("before\n", encoding="utf-8")
    records = mod._snapshot_host_paths(snapshot_root, [protected])
    protected.write_text("after\n", encoding="utf-8")
    snapshot = {"root": str(snapshot_root), "host_paths": records, "databases": []}
    old_stop = mod.service_stop_for_restore
    old_start = mod.service_start_after_restore
    old_verify = mod.verify_tactical_runtime
    old_run = mod.subprocess.run
    try:
        mod.service_stop_for_restore = lambda log: None
        mod.service_start_after_restore = lambda log: None
        mod.verify_tactical_runtime = lambda config, log: None
        def run(argv, *args, **kwargs):
            if list(argv[:2]) == ["systemctl", "daemon-reload"]:
                class R: returncode = 0
                return R()
            return old_run(argv, *args, **kwargs)
        mod.subprocess.run = run
        result = mod.rollback_failed_restore(
            {"TACTICAL_ROOT": str(base / "rmm")}, None, snapshot, io.StringIO(), restore_tactical_tree=False
        )
    finally:
        mod.service_stop_for_restore = old_stop
        mod.service_start_after_restore = old_start
        mod.verify_tactical_runtime = old_verify
        mod.subprocess.run = old_run
    must(result["rollback_performed"] is True, f"Tec-Tac-only rollback failed: {result}")
    must(result["rollback_host_paths_restored"] is True, "host rollback marker not set")
    must(protected.read_text(encoding="utf-8") == "before\n", "coordinator did not restore Tec-Tac host state")

# Symlinked intermediate directories are rejected: rollback must not follow a
# hostile parent path even though final nginx links are allowed.
with tempfile.TemporaryDirectory(prefix="tectac-b1-parent-link-") as td:
    base = Path(td)
    outside = base / "outside"
    outside.mkdir()
    parent = base / "parent"
    parent.symlink_to(outside, target_is_directory=True)
    victim = parent / "victim.conf"
    try:
        mod._snapshot_host_paths(base / "snapshot", [victim])
    except RuntimeError as exc:
        must("unsafe symlink" in str(exc), f"wrong parent-symlink error: {exc}")
    else:
        raise AssertionError("symlinked snapshot parent was accepted")

# Privileged installer rollback coverage: every Core-owned path that install.sh
# writes/removes under /usr/local/{lib,sbin} or /etc/sudoers.d must be covered
# by the fixed Tec-Tac rollback target set. Nested paths may be covered by a
# snapshotted parent directory such as /usr/local/lib/tec-tac.
installer_privileged_paths = {
    "/usr/local/sbin/tec-tac-module-job",
    "/usr/local/sbin/tec-tac-module-v2-job",
    "/usr/local/sbin/tec-tac-module-hotfix",
    "/usr/local/sbin/tec-tac-repair",
    "/usr/local/sbin/tec-tac-diagnostics",
    "/usr/local/lib/tec-tac/server-maintenance/actions",
    "/usr/local/lib/tec-tac-security",
    "/usr/local/sbin/tec-tac-trust-policy",
    "/usr/local/sbin/tec-tac-system-update",
    "/usr/local/lib/tec-tac-updater",
    "/etc/sudoers.d/tec-tac-system-update",
    "/usr/local/sbin/tec-tac-server-backup",
    "/usr/local/lib/tec-tac-backup",
    "/etc/sudoers.d/tec-tac-server-backup",
    "/usr/local/sbin/tec-tac-server-maintenance",
    "/usr/local/lib/tec-tac-server-maintenance",
    "/etc/sudoers.d/tec-tac-server-maintenance",
    "/usr/local/sbin/tec-tac-housekeeping",
    "/usr/local/lib/tec-tac-housekeeping",
    "/etc/sudoers.d/tec-tac-housekeeping",
    "/etc/sudoers.d/tec-tac-module-manager",
    "/etc/sudoers.d/tec-tac-module-manager-v2",
    "/etc/sudoers.d/tec-tac-module-hotfix",
}
rollback_roots = [Path(path) for path in mod.TEC_TAC_PRIVILEGED_INSTALL_PATHS]
for raw in sorted(installer_privileged_paths):
    path = Path(raw)
    must(
        any(path == root or root in path.parents for root in rollback_roots),
        f"installer privileged target is not covered by rollback snapshot: {path}",
    )

# The literal target inventory itself must remain present in install.sh. This
# makes an installer target rename/addition fail the regression until rollback
# coverage is reviewed and updated.
install_text = (ROOT / "install.sh").read_text(encoding="utf-8")
for raw in sorted(installer_privileged_paths):
    must(raw in install_text, f"expected privileged installer target disappeared/changed: {raw}")

# Restored Tec-Tac sudoers rules must force a full visudo validation before the
# rollback can be considered successful. Exercise both success and failure.
old_which = mod.shutil.which
old_run = mod.subprocess.run
try:
    mod.shutil.which = lambda name: "/usr/sbin/visudo" if name == "visudo" else old_which(name)
    calls = []
    class GoodResult:
        returncode = 0
        stdout = ""
        stderr = ""
    def good_run(argv, *args, **kwargs):
        calls.append(list(argv))
        return GoodResult()
    mod.subprocess.run = good_run
    mod._validate_restored_tec_tac_sudoers([{"path": "/etc/sudoers.d/tec-tac-server-backup"}])
    must(calls == [["/usr/sbin/visudo", "-c"]], f"unexpected visudo validation command: {calls}")

    class BadResult:
        returncode = 1
        stdout = ""
        stderr = "syntax error"
    mod.subprocess.run = lambda argv, *args, **kwargs: BadResult()
    try:
        mod._validate_restored_tec_tac_sudoers([{"path": "/etc/sudoers.d/tec-tac-system-update"}])
    except RuntimeError as exc:
        must("sudoers validation failed" in str(exc), f"wrong visudo failure: {exc}")
    else:
        raise AssertionError("invalid restored sudoers did not fail rollback validation")
finally:
    mod.shutil.which = old_which
    mod.subprocess.run = old_run

print("[TEST] PASS server backup host rollback transaction")
