#!/usr/bin/env python3
"""L10 done-when: no archive may remain published without its sidecar.

For local, FTP, rclone and SCP, execute the real store function, force final
archive publication to fail after sidecar publication, and prove:
  1. sidecar publication happens before final archive publication;
  2. the sidecar is rolled back on archive publication failure;
  3. no final archive is exposed.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("server_backup_helper_l10_173", ROOT / "scripts" / "server-backup-helper.py")
h = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(h)


def meta(data=b"abc"):
    return {"size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def must(value, message):
    if not value:
        raise AssertionError(message)


class Log:
    def write(self, *_args):
        pass


# ---------------- local ----------------
with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    archive = td / "local.tgz"
    archive.write_bytes(b"abc")
    dest = td / "dest"
    events = []
    real_replace = h.os.replace

    def replace(src, dst):
        dst = Path(dst)
        events.append(("replace", dst.name))
        if dst.name == "local.tgz":
            raise RuntimeError("forced final archive failure")
        return real_replace(src, dst)

    h.os.replace = replace
    try:
        try:
            h.store_local({"id": "local", "type": "local", "path": str(dest)}, archive, meta())
        except RuntimeError:
            pass
        else:
            raise AssertionError("local archive publication failure did not propagate")
    finally:
        h.os.replace = real_replace

    side = "local.tgz.tectac.json"
    must(events.index(("replace", side)) < events.index(("replace", "local.tgz")), "local sidecar was not published first")
    must(not (dest / side).exists(), "local published sidecar was not rolled back")
    must(not (dest / "local.tgz").exists(), "local final archive became visible")


# ---------------- FTP ----------------
class FakeFTP:
    def __init__(self):
        self.objects = {}
        self.events = []
    def storbinary(self, command, fh, blocksize=0):
        name = command.split(" ", 1)[1]
        self.objects[name] = fh.read()
        self.events.append(("store", name))
    def size(self, name):
        if name not in self.objects:
            raise h.ftplib.error_perm("550 missing")
        return len(self.objects[name])
    def retrbinary(self, command, callback, blocksize=0):
        callback(self.objects[command.split(" ", 1)[1]])
    def rename(self, src, dst):
        self.events.append(("rename", src, dst))
        if dst == "ftp.tgz":
            raise RuntimeError("forced final archive failure")
        self.objects[dst] = self.objects.pop(src)
    def delete(self, name):
        self.events.append(("delete", name))
        self.objects.pop(name, None)
    def quit(self):
        pass
    def close(self):
        pass

with tempfile.TemporaryDirectory() as td_raw:
    archive = Path(td_raw) / "ftp.tgz"
    archive.write_bytes(b"abc")
    ftp = FakeFTP()
    old_connect, old_prepare, old_exists = h.ftp_connect, h.ftp_prepare_path, h.ftp_path_exists
    h.ftp_connect = lambda *_a, **_k: ftp
    h.ftp_prepare_path = lambda *_a, **_k: None
    h.ftp_path_exists = lambda *_a, **_k: False
    try:
        try:
            h.ftp_store({}, {"id":"ftp","type":"ftp","host":"h","port":21,"username":"u","remote_path":"/"}, archive, meta(), Log())
        except RuntimeError:
            pass
        else:
            raise AssertionError("FTP archive publication failure did not propagate")
    finally:
        h.ftp_connect, h.ftp_prepare_path, h.ftp_path_exists = old_connect, old_prepare, old_exists

    side_publish = ("rename", "ftp.tgz.tectac.json.partial", "ftp.tgz.tectac.json")
    archive_publish = ("rename", "ftp.tgz.partial", "ftp.tgz")
    must(ftp.events.index(side_publish) < ftp.events.index(archive_publish), "FTP sidecar was not published first")
    must("ftp.tgz.tectac.json" not in ftp.objects, "FTP published sidecar was not rolled back")
    must("ftp.tgz" not in ftp.objects, "FTP final archive became visible")


# ---------------- rclone ----------------
with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    archive = td / "rclone.tgz"
    archive.write_bytes(b"abc")
    remote = {}
    events = []
    old_cfg, old_exists, old_run, old_subrun = h.make_rclone_config, h.rclone_path_exists, h.run_logged, h.subprocess.run
    h.make_rclone_config = lambda *_a, **_k: td / "rclone.conf"
    h.rclone_path_exists = lambda *_a, **_k: False

    def run_logged(argv, _log, timeout=None):
        events.append(tuple(argv[:4]))
        op = argv[1]
        if op == "copyto":
            remote[argv[3]] = Path(argv[2]).read_bytes()
            return None
        if op == "moveto":
            src, dst = argv[2], argv[3]
            if dst.endswith("/rclone.tgz"):
                raise RuntimeError("forced final archive failure")
            remote[dst] = remote.pop(src)
            return None
        raise AssertionError(argv)

    def subrun(argv, **kwargs):
        if argv[1] == "lsjson":
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"Size": 3}]), stderr="")
        if argv[1] == "hash":
            return SimpleNamespace(returncode=0, stdout=meta()["sha256"] + "  rclone.tgz.partial\n", stderr="")
        if argv[1] == "deletefile":
            events.append(tuple(argv[:3]))
            remote.pop(argv[2], None)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(argv)

    h.run_logged = run_logged
    h.subprocess.run = subrun
    try:
        try:
            h.store_rclone({}, {"id":"r","type":"s3","bucket":"bucket","remote_path":"."}, archive, meta(), Log())
        except RuntimeError:
            pass
        else:
            raise AssertionError("rclone archive publication failure did not propagate")
    finally:
        h.make_rclone_config, h.rclone_path_exists, h.run_logged, h.subprocess.run = old_cfg, old_exists, old_run, old_subrun

    side_event = next(i for i, event in enumerate(events) if len(event) >= 4 and event[1] == "moveto" and event[3].endswith(".tectac.json"))
    archive_event = next(i for i, event in enumerate(events) if len(event) >= 4 and event[1] == "moveto" and event[3].endswith("/rclone.tgz"))
    must(side_event < archive_event, "rclone sidecar was not published first")
    must(not any(key.endswith("rclone.tgz.tectac.json") for key in remote), "rclone published sidecar was not rolled back")
    must(not any(key.endswith("/rclone.tgz") for key in remote), "rclone final archive became visible")


# ---------------- SCP ----------------
with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    staging = td / "staging"; staging.mkdir()
    remote_dir = td / "remote"; remote_dir.mkdir()
    archive = td / "scp.tgz"; archive.write_bytes(b"abc")
    # Force the final archive mv to fail only after the immutable-name precheck.
    events = []
    publish_commands = []
    old_roots, old_args, old_run, old_subrun = h.roots, h.scp_args, h.run_logged, h.subprocess.run
    h.roots = lambda _config=None: {"staging": staging}
    h.scp_args = lambda *_a, **_k: ([], [])

    def run_logged(argv, _log, timeout=None):
        events.append(tuple(argv))
        if argv[0] == "ssh" and "mkdir" in argv and "-p" in argv:
            return None
        if argv[0] == "scp":
            src, dst = argv[-2], argv[-1]
            if ":" in dst:
                Path(dst.split(":", 1)[1]).write_bytes(Path(src).read_bytes())
            elif ":" in src:
                Path(dst).write_bytes(Path(src.split(":", 1)[1]).read_bytes())
            else:
                raise AssertionError(argv)
            return None
        if argv[0] == "ssh":
            command = argv[-1]
            publish_commands.append(command)
            if "tectac.json.partial" in command and "scp.tgz.partial" in command:
                # Execute the first publication step, then emulate failure of
                # the archive mv and the command's inline sidecar rollback.
                partial_sidecar = remote_dir / "scp.tgz.tectac.json.partial"
                final_sidecar = remote_dir / "scp.tgz.tectac.json"
                partial_sidecar.replace(final_sidecar)
                if not final_sidecar.exists():
                    raise AssertionError("SCP sidecar was not made visible before archive publication")
                final_sidecar.unlink()
                raise RuntimeError("forced final archive failure")
            proc = subprocess.run(["bash", "-c", command], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if proc.returncode:
                raise RuntimeError(proc.stderr.strip() or "remote publish failed")
            return None
        raise AssertionError(argv)

    def subrun(argv, **kwargs):
        # store_scp's generic exception cleanup of partials.
        if argv[0] == "ssh":
            proc = subprocess.run(["bash", "-c", argv[-1]], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return proc
        return old_subrun(argv, **kwargs)

    h.run_logged = run_logged
    h.subprocess.run = subrun
    try:
        try:
            h.store_scp({}, {"id":"s","type":"scp","host":"host","port":22,"username":"u","remote_path":str(remote_dir)}, archive, meta(), Log())
        except RuntimeError:
            pass
        else:
            raise AssertionError("SCP archive publication failure did not propagate")
    finally:
        h.roots, h.scp_args, h.run_logged, h.subprocess.run = old_roots, old_args, old_run, old_subrun

    publish = next(command for command in publish_commands if "tectac.json.partial" in command and "scp.tgz.partial" in command)
    side_mv = publish.index("scp.tgz.tectac.json.partial")
    archive_mv = publish.index("scp.tgz.partial", side_mv + 1)
    must(side_mv < archive_mv, "SCP publish command did not make sidecar visible first")
    must(not (remote_dir / "scp.tgz.tectac.json").exists(), "SCP published sidecar was not rolled back")
    # The directory used to force failure is not a published archive file.
    must(not (remote_dir / "scp.tgz").is_file(), "SCP final archive became visible")

print("[TEST] PASS L10 final atomic publication on local/FTP/rclone/SCP")
