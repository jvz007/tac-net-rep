#!/usr/bin/env python3
"""Regression: Core 1.18.7 keeps every recovery file private (0600) and /rmmbackups at 0700.

The static half runs anywhere. The behaviour half needs Linux (the helper imports
pwd, grp and fcntl) and the cryptography package, and is skipped with a notice
elsewhere. The pipeline validator and Johan's checklist cover it.
"""
import importlib.util
import io
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "server-backup-helper.py"
text = HELPER.read_text(encoding="utf-8")


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


def body(name):
    start = text.index(f"def {name}(")
    nxt = re.search(r"\n(?:def |class |@)", text[start + 5:])
    return text[start:start + 5 + nxt.start()] if nxt else text[start:]


# ---- static half ----
store = body("_store_local")
must(".write_text(" not in store and "os.chmod" not in store and ".chmod(" not in store, "_store_local writes or chmods a path in a folder another user can write")
must("_private_write_text(hash_tmp" in store, "hash temp file is not written through an fd")
must("O_NOFOLLOW" in body("_private_write_text") and "O_EXCL" in body("_private_write_text") and "fchmod" in body("_private_write_text"), "_private_write_text is not O_EXCL|O_NOFOLLOW|fchmod")
must("os.utime(target" not in body("_private_copy"), "_private_copy sets the mtime by path")
must("shutil.copy2" not in store, "store_local still uses shutil.copy2")
must("0o640" not in store and "0o640" not in body("write_sidecar"), "a 0o640 mode is left in the publish path")
must("_private_copy(archive,archive_tmp)" in store and "mode=0o600" in store and "0o600" in store, "store_local not private")
must("with _private_umask():" in body("store_local"), "store_local lacks the umask wrapper")
must("_private_umask()" in body("create_recovery_bundle"), "bundle tar is not written under a private umask")
must("shutil.copy2" not in body("download_local") and "_private_copy" in body("download_local"), "download_local copy not private")
must("shutil.copy2" not in body("validate_local_roundtrip"), "round-trip test object not private")
tactical = body("create_tactical_component")
must("_make_private(archive)" in tactical and "os.chmod(backup_root, 0o700)" in tactical, "native Tactical archive or folder not tightened")
must('"mode_private"' in store, "destination result lacks mode_private")
create = body("operation_create_backup")
must("repair_backup_permissions(config, log, destinations)" in create, "create_backup does not repair first")
main_src = text[text.index("def main("):]
must('argv[1] == "--repair-backup-permissions"' in main_src and "geteuid() != 0" in main_src, "main() flag missing or not root-only")
must("--repair-backup-permissions" in main_src.split("usage:")[1].split(")")[0], "usage string lacks the flag")
must(text.index('argv[1] == "--repair-backup-permissions"') > text.index("geteuid() != 0"), "flag is reachable before the root check")

install = (ROOT / "install.sh").read_text(encoding="utf-8")
helper_line = install.index('log "Installed privileged Core server-backup helper')
call = install.index('"${SERVER_BACKUP_HELPER}" --repair-backup-permissions')
must(call > helper_line, "install.sh does not repair after installing the helper")
must('ln -sfn "${SERVER_BACKUP_LIB}/server-backup-helper.py" "${SERVER_BACKUP_HELPER}"' in install, "helper link changed")
must('SERVER_BACKUP_HELPER="/usr/local/sbin/tec-tac-server-backup"' in install, "helper path changed")
for line in install.splitlines():
    if "NOPASSWD" in line and "SERVER_BACKUP_HELPER" in line:
        must("repair" not in line, "sudoers line allows repair")
must("--dispatch *" in install and "--tactical-privileged *" in install, "sudoers lines changed")
docs = (ROOT / "docs" / "server-backup-capability.md").read_text(encoding="utf-8")
must("File permissions (1.18.7)" in docs and "0700" in docs, "docs section missing")
for rel in ("scripts/server-backup-helper.py", "install.sh", "docs/server-backup-capability.md", "VERSION"):
    data = (ROOT / rel).read_bytes()
    must(b"\r\n" not in data, f"{rel}: CRLF in an LF file")
print("[TEST] PASS static 1.18.7 backup modes")

# ---- behaviour half (Linux) ----
if not sys.platform.startswith("linux"):
    print("[TEST] SKIP behaviour half: needs Linux (pwd, grp, fcntl)")
    sys.exit(0)
try:
    spec = importlib.util.spec_from_file_location("server_backup_helper_1187", HELPER)
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
except ImportError as exc:
    print(f"[TEST] SKIP behaviour half: {exc}")
    sys.exit(0)


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    src = tmp / "tec-tac-backup-2026_11_18__10_00_00_000001.tgz"
    src.write_bytes(b"bundle-bytes" * 100)
    os.chmod(src, 0o644)
    os.utime(src, (1_700_000_000, 1_700_000_000))
    sha = h.sha256_file(src)
    meta = {"sha256": sha, "size_bytes": src.stat().st_size, "backup_class": "manual", "components": {}, "recovery_modes": []}
    dest = tmp / "dest"
    log = io.StringIO()
    result = h.store_local({"id": "local", "type": "local", "name": "local", "path": str(dest)}, src, meta, log)
    pub = dest / src.name
    must(result["ok"] and result["mode_private"] is True, result)
    for item in (pub, dest / (src.name + ".tectac.json"), dest / (src.name + ".sha256")):
        must(mode(item) == 0o600, f"{item.name} is {oct(mode(item))}")
    must(mode(dest) == 0o700, f"new folder is {oct(mode(dest))}")
    must(not list(dest.glob("*.partial")), "partial files left")
    must(int(pub.stat().st_mtime) == 1_700_000_000, "mtime not kept")
    must(h.sha256_file(pub) == sha, "hash changed")
    rows = h.list_local({"id": "local", "type": "local", "name": "local", "path": str(dest)})
    must(len(rows) == 1 and rows[0].get("sidecar_status") == "ok", rows)
    # immutable names: a second store refuses
    try:
        h.store_local({"id": "local", "type": "local", "name": "local", "path": str(dest)}, src, meta, log)
    except RuntimeError as exc:
        must("immutable" in str(exc), exc)
    else:
        raise AssertionError("second store was not refused")
    must(not list(dest.glob("*.partial")), "partial files left after refusal")
    # download copy is private
    h.load_config = dict
    out = tmp / "downloaded.tgz"
    h.download_local({"path": str(dest)}, src.name, out)
    must(mode(out) == 0o600, "download copy not private")
    # a bundle written under the private umask
    old = os.umask(0o022)
    try:
        with h._private_umask():
            probe = tmp / "probe"
            probe.write_text("x")
        must(mode(probe) == 0o600, "umask wrapper not private")
        must(os.umask(old) == 0o022, "umask not restored")
    finally:
        os.umask(old)
    # a filesystem that keeps no modes: backup succeeds, mode_private false, one WARNING
    src2 = tmp / "tec-tac-backup-2026_11_18__10_00_01_000002.tgz"
    src2.write_bytes(b"other" * 50)
    meta2 = dict(meta, sha256=h.sha256_file(src2), size_bytes=src2.stat().st_size)
    orig_make = h._make_private
    h._make_private = lambda p: False  # what a CIFS/vfat mount does: the mode will not stick
    try:
        log2 = io.StringIO()
        r2 = h.store_local({"id": "local", "type": "local", "name": "local", "path": str(dest)}, src2, meta2, log2)
    finally:
        h._make_private = orig_make
    must(r2["ok"] and r2["mode_private"] is False, r2)
    must(log2.getvalue().count("WARNING") == 1, log2.getvalue())

    # a link planted at the hash temp name must not be followed by root
    src3 = tmp / "tec-tac-backup-2026_11_18__10_00_02_000003.tgz"
    src3.write_bytes(b"third" * 50)
    meta3 = dict(meta, sha256=h.sha256_file(src3), size_bytes=src3.stat().st_size)
    sentinel = tmp / "sentinel.txt"
    sentinel.write_text("keep me")
    os.chmod(sentinel, 0o644)
    dest3 = tmp / "dest3"
    dest3.mkdir(mode=0o700)
    os.symlink(sentinel, dest3 / (src3.name + ".sha256.partial"))
    try:
        h.store_local({"id": "local", "type": "local", "name": "local", "path": str(dest3)}, src3, meta3, io.StringIO())
    except OSError:
        pass
    else:
        raise AssertionError("store followed or ignored a planted hash temp link")
    must(sentinel.read_text() == "keep me" and mode(sentinel) == 0o644, "planted link target was written or chmodded")
    must(not (dest3 / src3.name).exists(), "bundle published despite the refused hash file")

    # repair
    fake = tmp / "rmmbackups"
    (fake / "daily").mkdir(parents=True)
    os.chmod(fake, 0o755)
    names = [
        "tec-tac-backup-2026_01_01__00_00_00_000001.tgz",
        "tec-tac-backup-2026_01_01__00_00_00_000001.tgz.tectac.json",
        "tec-tac-backup-2026_01_01__00_00_00_000001.tgz.sha256",
        "tec-tac-backup-2026_01_01__00_00_00_000009.tgz.partial",
    ]
    for n in names:
        (fake / n).write_text("x")
        os.chmod(fake / n, 0o644)
    (fake / "daily" / "rmm-backup-2026_01_01.tar").write_text("x")
    os.chmod(fake / "daily" / "rmm-backup-2026_01_01.tar", 0o644)
    unrelated = fake / "notes.txt"
    unrelated.write_text("x"); os.chmod(unrelated, 0o644)
    target = tmp / "outside.tgz"
    target.write_text("x"); os.chmod(target, 0o644)
    os.symlink(target, fake / "tec-tac-backup-2026_01_01__00_00_00_000002.tgz")
    h.DEFAULT_LOCAL_RECOVERY_ROOT = fake
    h.tactical_identity = lambda config: (os.getuid(), os.getgid(), "tactical", str(tmp))
    other = tmp / "backups-other"
    other.mkdir(); os.chmod(other, 0o755)
    (other / "tec-tac-backup-2026_02_02__00_00_00_000001.tgz").write_text("x")
    os.chmod(other / "tec-tac-backup-2026_02_02__00_00_00_000001.tgz", 0o644)
    cfg = {"TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": f"{fake},{other}"}
    log3 = io.StringIO()
    res = h.repair_backup_permissions(cfg, log3, [{"type": "local", "path": str(other)}])
    for n in names:
        must(mode(fake / n) == 0o600, n)
    must(mode(fake / "daily" / "rmm-backup-2026_01_01.tar") == 0o600, "daily tar")
    must(mode(fake) == 0o700 and mode(fake / "daily") == 0o755, "folder modes")
    must(mode(unrelated) == 0o644 and mode(target) == 0o644, "unrelated or symlink target touched")
    must(mode(other) == 0o755, "foreign folder mode changed")
    must(mode(other / "tec-tac-backup-2026_02_02__00_00_00_000001.tgz") == 0o600, "foreign file")
    must(res["set"] == 6 and res["already_private"] == 0, res)
    must(log3.getvalue().count("backup permissions:") == 1 and "NOTICE" in log3.getvalue(), log3.getvalue())
    log4 = io.StringIO()
    res2 = h.repair_backup_permissions(cfg, log4, [])
    must(res2["set"] == 0 and res2["already_private"] == 6, res2)
    must(len([x for x in log4.getvalue().splitlines() if x.strip()]) == 2, log4.getvalue())  # summary + the NOTICE for the foreign folder
    log5 = io.StringIO()
    h.repair_backup_permissions({"TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": str(fake)}, log5, [])
    must(len(log5.getvalue().splitlines()) == 1, log5.getvalue())

    # root only: another user cannot open a private file
    if os.geteuid() == 0:
        pid = os.fork()
        if pid == 0:
            try:
                os.setuid(65534)
                with open(pub, "rb"):
                    pass
            except PermissionError:
                os._exit(0)
            os._exit(1)
        _, status = os.waitpid(pid, 0)
        must(os.WEXITSTATUS(status) == 0, "another user could read a private bundle")
print("[TEST] PASS behaviour 1.18.7 backup modes")
