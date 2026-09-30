#!/usr/bin/env python3
"""AD-3 regression: SFTP/WebDAV/S3 hash companions use rclone, never SCP."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "server_backup_helper_d3_rclone_hash",
    ROOT / "scripts" / "server-backup-helper.py",
)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

archive_name = "tec-tac-recovery-20260930T070000Z.tgz"
archive_bytes = b"d3-rclone-hash-regression"
digest = hashlib.sha256(archive_bytes).hexdigest()

destinations = {
    "sftp": {
        "id": "sftp-test",
        "type": "sftp",
        "name": "SFTP",
        "host": "backup.example.test",
        "username": "backup",
        "port": 22,
        "remote_path": "/tectac",
        "host_key_policy": "insecure",
    },
    "webdav": {
        "id": "webdav-test",
        "type": "webdav",
        "name": "WebDAV",
        "url": "https://backup.example.test/webdav",
        "remote_path": "/tectac",
    },
    "s3": {
        "id": "s3-test",
        "type": "s3",
        "name": "S3",
        "provider": "Other",
        "bucket": "tectac-test",
        "prefix": "backups",
        "remote_path": "backups",
    },
}

original_make = h.make_rclone_config
original_exists = h.rclone_path_exists
original_run = h.subprocess.run
original_scp_args = h.scp_args
original_run_logged = h.run_logged

calls = []
exists_state = {"value": False}

try:
    def fake_make_rclone_config(config, destination, temp, log):
        calls.append(("config", destination["type"]))
        cfg = pathlib.Path(temp) / "rclone.conf"
        cfg.write_text("[tectac]\ntype = test\n", encoding="utf-8")
        return cfg

    def fake_rclone_path_exists(remote, cfg):
        calls.append(("exists", remote))
        return exists_state["value"]

    def fake_subprocess_run(argv, **kwargs):
        if argv and argv[0] in {"ssh", "scp"}:
            raise AssertionError(f"unexpected SSH/SCP invocation for rclone destination: {argv}")
        if argv[:2] == ["rclone", "cat"]:
            calls.append(("cat", argv[2]))
            return subprocess.CompletedProcess(argv, 0, stdout=f"{digest}  {archive_name}\n", stderr="")
        raise AssertionError(f"unexpected subprocess invocation: {argv}")

    def fail_scp_args(*args, **kwargs):
        raise AssertionError("scp_args must not be used for SFTP/WebDAV/S3 hash companions")

    def fail_run_logged(*args, **kwargs):
        raise AssertionError("run_logged SCP path must not be used for SFTP/WebDAV/S3 hash companions")

    h.make_rclone_config = fake_make_rclone_config
    h.rclone_path_exists = fake_rclone_path_exists
    h.subprocess.run = fake_subprocess_run
    h.scp_args = fail_scp_args
    h.run_logged = fail_run_logged

    with tempfile.TemporaryDirectory() as td_raw:
        archive = pathlib.Path(td_raw) / archive_name
        archive.write_bytes(archive_bytes)
        for dtype, destination in destinations.items():
            config = {"TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": td_raw}
            calls.clear()
            exists_state["value"] = False
            missing = h.verify_archive_hash_companion(config, destination, archive_name, archive, io.StringIO())
            assert missing["status"] == "not_verified", (dtype, missing)
            assert any(item[0] == "config" and item[1] == dtype for item in calls), (dtype, calls)
            assert not any(item[0] == "cat" for item in calls), (dtype, calls)

            calls.clear()
            exists_state["value"] = True
            present = h.verify_archive_hash_companion(config, destination, archive_name, archive, io.StringIO())
            assert present == {"status": "verified", "sha256": digest}, (dtype, present)
            assert any(item[0] == "config" and item[1] == dtype for item in calls), (dtype, calls)
            assert any(item[0] == "cat" for item in calls), (dtype, calls)
finally:
    h.make_rclone_config = original_make
    h.rclone_path_exists = original_exists
    h.subprocess.run = original_run
    h.scp_args = original_scp_args
    h.run_logged = original_run_logged

print("[TEST] PASS D3 SFTP/WebDAV/S3 hash companions use rclone and never SSH/SCP")
