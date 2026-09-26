#!/usr/bin/env python3
"""R3: module artifacts are snapshotted into new root-private inodes before verification."""
from __future__ import annotations

import importlib.util
import os
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def assert_private(path: Path):
    st = path.stat()
    assert stat.S_ISREG(st.st_mode), st
    assert stat.S_IMODE(st.st_mode) == 0o600, oct(stat.S_IMODE(st.st_mode))
    if os.geteuid() == 0:
        assert st.st_uid == 0 and st.st_gid == 0, (st.st_uid, st.st_gid)


def exercise_v1():
    mod = load("tt_module_v1_r3", ROOT / "scripts/module-job-helper.py")
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        staged = base / "staged"
        private = base / "private"
        staged.mkdir(mode=0o770)
        private.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(private, 0, 0)
        os.chmod(private, 0o700)
        mod.STAGED_ROOT = staged

        source = staged / "package.zip"
        source.write_bytes(b"SIGNED-BYTES")
        original_inode = source.stat().st_ino
        fd = os.open(source, os.O_RDWR)
        try:
            target = private / "package.zip"
            claimed = mod._private_artifact_copy(source, target, "module package")
            assert claimed == target
            assert not source.exists(), "staged pathname must be removed after snapshot"
            assert target.stat().st_ino != original_inode, "claim must create a new inode"
            assert_private(target)
            before = target.read_bytes()
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b"ATTACKED!!!!")
            os.fsync(fd)
            assert target.read_bytes() == before == b"SIGNED-BYTES", "old writable fd changed privileged snapshot"
        finally:
            os.close(fd)

        victim = staged / "victim.zip"
        victim.write_bytes(b"victim")
        link = staged / "link.zip"
        link.symlink_to(victim.name)
        try:
            mod._private_artifact_copy(link, private / "link-copy.zip", "module package")
        except SystemExit:
            pass
        else:
            raise AssertionError("v1 claim followed a staged symlink")

        # A Tactical-controlled intermediate directory symlink must not let the
        # root helper reach or unlink an arbitrary host file.
        outside = base / "outside"
        outside.mkdir()
        outside_victim = outside / "shadow"
        outside_victim.write_bytes(b"do-not-delete")
        (staged / "sub").symlink_to(outside, target_is_directory=True)
        try:
            mod._private_artifact_copy(staged / "sub" / outside_victim.name, private / "victim-copy", "module package")
        except SystemExit:
            pass
        else:
            raise AssertionError("v1 claim accepted a symlinked staging subdirectory")
        assert outside_victim.read_bytes() == b"do-not-delete", "v1 claim deleted or changed external victim"


def exercise_v2():
    mod = load("tt_module_v2_r3", ROOT / "scripts/module-v2-job-helper.py")
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        staged = base / "staged"
        private = base / "private"
        staged.mkdir(mode=0o770)
        private.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(private, 0, 0)
        os.chmod(private, 0o700)
        mod.STAGED_ROOT = staged
        mod.BUNDLES_ROOT = staged / "bundles"
        mod.BUNDLES_ROOT.mkdir(mode=0o770)

        source = staged / "bundle.zip"
        source.write_bytes(b"SIGNED-BUNDLE")
        original_inode = source.stat().st_ino
        fd = os.open(source, os.O_RDWR)
        try:
            target = Path(mod._claim_artifact(source, private, "bundle"))
            assert not source.exists(), "staged pathname must be removed after snapshot"
            assert target.stat().st_ino != original_inode, "v2 claim must create a new inode"
            assert_private(target)
            before = target.read_bytes()
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b"ATTACKED-BUNDLE")
            os.fsync(fd)
            assert target.read_bytes() == before == b"SIGNED-BUNDLE", "old writable fd changed v2 snapshot"
        finally:
            os.close(fd)

        victim = staged / "victim.zip"
        victim.write_bytes(b"victim")
        link = staged / "link.zip"
        link.symlink_to(victim.name)
        try:
            mod._claim_artifact(link, private, "bundle")
        except SystemExit:
            pass
        else:
            raise AssertionError("v2 claim followed a staged symlink")

        outside = base / "outside"
        outside.mkdir()
        outside_victim = outside / "shadow"
        outside_victim.write_bytes(b"do-not-delete")
        (staged / "sub").symlink_to(outside, target_is_directory=True)
        try:
            mod._claim_artifact(staged / "sub" / outside_victim.name, private, "bundle")
        except SystemExit:
            pass
        else:
            raise AssertionError("v2 claim accepted a symlinked staging subdirectory")
        assert outside_victim.read_bytes() == b"do-not-delete", "v2 claim deleted or changed external victim"

        # Legitimate signed bundle artifacts are direct children of bundles/.
        bundle_source = mod.BUNDLES_ROOT / "12345678-1234-1234-1234-123456789abc.zip"
        bundle_source.write_bytes(b"SIGNED-BUNDLE-ROOT")
        bundle_target = Path(mod._claim_artifact(bundle_source, private, "bundle-root"))
        assert bundle_target.read_bytes() == b"SIGNED-BUNDLE-ROOT"
        assert not bundle_source.exists()
        assert_private(bundle_target)


def static_guards():
    v1 = (ROOT / "scripts/module-job-helper.py").read_text(encoding="utf-8")
    v2 = (ROOT / "scripts/module-v2-job-helper.py").read_text(encoding="utf-8")
    assert "O_NOFOLLOW" in v1 and "os.fsync(dst_fd)" in v1
    assert "dir_fd=root_fd" in v1 and "follow_symlinks=False" in v1
    assert "_private_artifact_copy(package_path, package_target" in v1
    assert "os.replace(package_path, package_target)" not in v1
    assert "O_NOFOLLOW" in v2 and "os.fsync(dst_fd)" in v2
    assert "dir_fd=root_fd" in v2 and "follow_symlinks=False" in v2
    start = v2.index("def _claim_artifact")
    end = v2.index("\ndef claim_job", start)
    assert "os.replace(" not in v2[start:end]


if __name__ == "__main__":
    static_guards()
    exercise_v1()
    exercise_v2()
    print("[TEST] PASS R3 immutable root-private module artifact claims")
