#!/usr/bin/env python3
"""Regression coverage for the privileged System Update staged-artifact claim."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "system-update-helper.py"
spec = importlib.util.spec_from_file_location("tt_system_update_claim", HELPER_PATH)
helper = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(helper)


def expect_system_exit(fn, label: str) -> None:
    try:
        fn()
    except SystemExit:
        return
    raise AssertionError(f"{label}: expected SystemExit")


def write_meta(staged: Path, upload_id: str, component: str = "framework") -> Path:
    path = staged / f"{upload_id}.json"
    path.write_text(json.dumps({
        "upload_id": upload_id,
        "filename": "framework.zip",
        "package_path": "/attacker/controlled/path/is/not/authority.zip",
        "preview": {"component": component},
    }), encoding="utf-8")
    return path


with tempfile.TemporaryDirectory(prefix="tt-system-update-claim-") as tmp:
    base = Path(tmp)
    staged = base / "staged"
    running = base / "running"
    staged.mkdir(mode=0o750)
    running.mkdir(mode=0o700)
    helper.STAGED_ROOT = staged
    helper.RUNNING_ROOT = running

    upload_id = "11111111-1111-1111-1111-111111111111"
    write_meta(staged, upload_id)
    package = staged / f"{upload_id}.zip"
    package.write_bytes(b"trusted-package")

    # The root helper derives the package identity from upload_id, not from the
    # Tactical-writable metadata package_path value.
    root_fd = helper._open_staged_root_fd()
    try:
        meta, _meta_info = helper._read_staged_metadata(root_fd, upload_id)
        assert meta["package_path"].startswith("/attacker/")
        name, info = helper._select_staged_package(root_fd, upload_id)
        assert name == f"{upload_id}.zip"

        # Keep a writable descriptor to the original inode open across claim.
        held = os.open(package, os.O_RDWR)
        try:
            target = running / "claimed.zip"
            helper._copy_staged_package(root_fd, name, info, target)
            assert target.read_bytes() == b"trusted-package"
            assert not package.exists(), "claimed staging name should be consumed"
            os.lseek(held, 0, os.SEEK_SET)
            os.write(held, b"MUTATED")
            os.fsync(held)
            assert target.read_bytes() == b"trusted-package", "old writable fd changed root-private snapshot"
        finally:
            os.close(held)
    finally:
        os.close(root_fd)

    # Final-component package symlink must never be followed to an outside file.
    upload_link = "22222222-2222-2222-2222-222222222222"
    write_meta(staged, upload_link)
    victim = base / "victim.zip"
    victim.write_bytes(b"do-not-touch")
    (staged / f"{upload_link}.zip").symlink_to(victim)
    root_fd = helper._open_staged_root_fd()
    try:
        expect_system_exit(lambda: helper._select_staged_package(root_fd, upload_link), "package symlink")
    finally:
        os.close(root_fd)
    assert victim.read_bytes() == b"do-not-touch"

    # Metadata is also Tactical-writable and must not be allowed to redirect root.
    upload_meta = "33333333-3333-3333-3333-333333333333"
    outside_meta = base / "outside.json"
    outside_meta.write_text('{"preview":{"component":"framework"}}', encoding="utf-8")
    (staged / f"{upload_meta}.json").symlink_to(outside_meta)
    (staged / f"{upload_meta}.zip").write_bytes(b"package")
    root_fd = helper._open_staged_root_fd()
    try:
        expect_system_exit(lambda: helper._read_staged_metadata(root_fd, upload_meta), "metadata symlink")
    finally:
        os.close(root_fd)
    assert outside_meta.is_file()

    # More than one direct package for the same upload id is ambiguous/fail-closed.
    upload_amb = "44444444-4444-4444-4444-444444444444"
    write_meta(staged, upload_amb)
    (staged / f"{upload_amb}.zip").write_bytes(b"one")
    (staged / f"{upload_amb}.tgz").write_bytes(b"two")
    root_fd = helper._open_staged_root_fd()
    try:
        expect_system_exit(lambda: helper._select_staged_package(root_fd, upload_amb), "ambiguous package")
    finally:
        os.close(root_fd)

    # The managed staging root itself must not be a symlink.
    real_staged = base / "real-staged"
    real_staged.mkdir()
    linked_staged = base / "linked-staged"
    linked_staged.symlink_to(real_staged, target_is_directory=True)
    helper.STAGED_ROOT = linked_staged
    expect_system_exit(helper._open_staged_root_fd, "staging-root symlink")

print("[TEST] PASS system update staged-artifact claim security")
