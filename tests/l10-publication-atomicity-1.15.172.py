#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def must(value, message):
    if not value:
        raise AssertionError(message)


class Log:
    def write(self, *_args):
        pass


# ---------------------------------------------------------------------------
# L10: every backup transport must make the sidecar visible before the final
# archive and remove the sidecar again if final archive publication fails.
# ---------------------------------------------------------------------------
h = load("backup161", "scripts/server-backup-helper.py")

with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    archive = base / "local.tgz"
    archive.write_bytes(b"abc")
    metadata = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    dest = base / "dest"
    real_replace = h.os.replace
    events = []

    def failing_replace(src, dst):
        events.append(Path(dst).name)
        if Path(dst).name == archive.name:
            raise RuntimeError("simulated final archive publication failure")
        return real_replace(src, dst)

    h.os.replace = failing_replace
    try:
        try:
            h.store_local({"id": "local", "type": "local", "path": str(dest)}, archive, metadata)
        except RuntimeError:
            pass
        else:
            raise AssertionError("local final archive failure was not surfaced")
    finally:
        h.os.replace = real_replace

    must(events.index("local.tgz.tectac.json") < events.index("local.tgz"), "local archive was published before sidecar")
    must(not (dest / "local.tgz").exists(), "local archive remained visible after failed publish")


class FakeFTP:
    def __init__(self):
        self.objects = {}
        self.cwd_path = "/"

    def storbinary(self, command, fh, blocksize=0):
        name = command.split(" ", 1)[1]
        self.objects[name] = fh.read()

    def size(self, name):
        if name not in self.objects:
            raise h.ftplib.error_perm("550 not found")
        return len(self.objects[name])

    def retrbinary(self, command, callback, blocksize=0):
        callback(self.objects[command.split(" ", 1)[1]])

    def delete(self, name):
        self.objects.pop(name, None)

    def rename(self, src, dst):
        if dst == "ftp.tgz":
            raise RuntimeError("simulated archive rename failure")
        self.objects[dst] = self.objects.pop(src)

    def quit(self):
        pass

    def close(self):
        pass


with tempfile.TemporaryDirectory() as td:
    archive = Path(td) / "ftp.tgz"
    archive.write_bytes(b"abc")
    metadata = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    ftp = FakeFTP()
    old_connect, old_prepare = h.ftp_connect, h.ftp_prepare_path
    h.ftp_connect = lambda *_a, **_k: ftp
    h.ftp_prepare_path = lambda *_a, **_k: None
    try:
        try:
            h.ftp_store({}, {"id": "ftp", "type": "ftp", "host": "h", "port": 21, "username": "u", "remote_path": "/"}, archive, metadata, Log())
        except RuntimeError:
            pass
        else:
            raise AssertionError("FTP final archive failure was not surfaced")
    finally:
        h.ftp_connect, h.ftp_prepare_path = old_connect, old_prepare
    must("ftp.tgz.tectac.json" not in ftp.objects, "FTP left published sidecar after archive failure")
    must("ftp.tgz" not in ftp.objects, "FTP exposed final archive after failed publish")


with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    archive = base / "rclone.tgz"
    archive.write_bytes(b"abc")
    metadata = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    remote = {}
    old_cfg, old_run, old_subrun = h.make_rclone_config, h.run_logged, h.subprocess.run
    h.make_rclone_config = lambda *_a, **_k: base / "rclone.conf"

    def fake_run_logged(argv, _log, timeout=None):
        op = argv[1]
        if op == "copyto":
            source, target = argv[2], argv[3]
            remote[target] = Path(source).read_bytes()
            return None
        if op == "moveto":
            src, dst = argv[2], argv[3]
            if dst.endswith("/rclone.tgz"):
                raise RuntimeError("simulated archive moveto failure")
            remote[dst] = remote.pop(src)
            return None
        raise AssertionError(argv)

    def fake_subrun(argv, **kwargs):
        if argv[1] == "lsjson" and "--stat" in argv:
            return SimpleNamespace(returncode=1, stdout="", stderr="object not found")
        if argv[1] == "lsjson":
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"Size": 3}]), stderr="")
        if argv[1] == "hash":
            return SimpleNamespace(returncode=0, stdout=metadata["sha256"] + "  rclone.tgz.partial\n", stderr="")
        if argv[1] == "deletefile":
            remote.pop(argv[2], None)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(argv)

    h.run_logged = fake_run_logged
    h.subprocess.run = fake_subrun
    try:
        try:
            h.store_rclone({}, {"id": "r", "type": "s3", "bucket": "bucket", "remote_path": "."}, archive, metadata, Log())
        except RuntimeError:
            pass
        else:
            raise AssertionError("rclone final archive failure was not surfaced")
    finally:
        h.make_rclone_config, h.run_logged, h.subprocess.run = old_cfg, old_run, old_subrun
    must(not any(key.endswith("rclone.tgz.tectac.json") for key in remote), "rclone left published sidecar after archive failure")
    must(not any(key.endswith("/rclone.tgz") for key in remote), "rclone exposed final archive after failed publish")


with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    staging = base / "staging"
    staging.mkdir()
    remote_dir = base / "remote"
    remote_dir.mkdir()
    archive = base / "scp.tgz"
    archive.write_bytes(b"abc")
    metadata = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    # Force the second mv in the real publish shell to fail.
    (remote_dir / "scp.tgz").mkdir()
    old_roots, old_args, old_run = h.roots, h.scp_args, h.run_logged
    h.roots = lambda _config=None: {"staging": staging}
    h.scp_args = lambda *_a, **_k: ([], [])

    def fake_scp_run(argv, _log, timeout=None):
        if argv[0] == "ssh" and argv[-3:-1] == ["mkdir", "-p"]:
            return None
        if argv[0] == "scp":
            src, dst = argv[-2], argv[-1]
            if ":" in dst:
                target = Path(dst.split(":", 1)[1])
                target.write_bytes(Path(src).read_bytes())
            elif ":" in src:
                source = Path(src.split(":", 1)[1])
                Path(dst).write_bytes(source.read_bytes())
            else:
                raise AssertionError(argv)
            return None
        if argv[0] == "ssh":
            proc = subprocess.run(["bash", "-c", argv[-1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode:
                raise RuntimeError(proc.stderr.strip() or "remote publish failed")
            return None
        raise AssertionError(argv)

    h.run_logged = fake_scp_run
    try:
        try:
            h.store_scp({}, {"id": "s", "type": "scp", "host": "host", "port": 22, "username": "u", "remote_path": str(remote_dir)}, archive, metadata, Log())
        except RuntimeError:
            pass
        else:
            raise AssertionError("SCP final archive failure was not surfaced")
    finally:
        h.roots, h.scp_args, h.run_logged = old_roots, old_args, old_run
    must(not (remote_dir / "scp.tgz.tectac.json").exists(), "SCP left published sidecar after archive failure")
    must((remote_dir / "scp.tgz").is_dir(), "SCP test did not preserve the forced failing final target")

print('[TEST] PASS L10 final sidecar-first publication and rollback across local/FTP/rclone/SCP')
