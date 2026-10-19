#!/usr/bin/env python3
"""1.17.54 (Backups R5): validate_destination also says which step failed.

The helper imports fcntl, pwd and grp, so this runs on Linux or WSL, not plain Windows.
"""
from __future__ import annotations

import ftplib
import importlib.util
import json
import pathlib
import socket
import ssl
import sys
import tempfile
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
MARKER = "MARKER-SECRET-5d1e"
OLD_KEYS = {"ok", "destination_id", "type", "validated_at", "checks", "reason"}
CHECKS = ("configuration", "connection", "authentication", "path_access", "write", "read", "integrity", "delete")
CONFIG = {"TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": "/tmp"}
FTP = {"id": "f", "type": "ftp", "host": "ftp.example.com", "port": 2121, "username": "u", "remote_path": "/x", "tls_mode": "explicit"}
SCP = {"id": "s", "type": "scp", "host": "ssh.example.com", "port": 22, "username": "u", "remote_path": "/r"}
SFTP = {"id": "r", "type": "sftp", "host": "sftp.example.com", "port": 22, "username": "u", "remote_path": "/r"}


def load_helper():
    spec = importlib.util.spec_from_file_location("server_backup_helper_stage_" + uuid.uuid4().hex[:6], ROOT / "scripts/server-backup-helper.py")
    helper = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(helper)
    helper.load_secret = lambda config, destination: {"password": MARKER} if destination.get("type") == "ftp" else {}
    helper.register_destination = lambda config, destination: None
    return helper


class Log:
    def __init__(self):
        self.lines = []

    def write(self, text):
        self.lines.append(text)


def validate(helper, destination, config=CONFIG):
    log = Log()
    job = {"id": str(uuid.uuid4()), "request": {"destination": destination}}
    try:
        result = helper.operation_validate_destination(config, job, log)
        failed = False
    except helper.OperationFailed as exc:
        result, failed = exc.result, True
        assert str(exc) == result["reason"]
    blob = json.dumps(result) + "".join(log.lines)
    assert MARKER not in blob, "a secret reached the result or the log"
    return result, failed


def ftp_connect_failing(step, exc):
    def connect(config, destination, *, timeout=60, progress=None):
        if progress is not None:
            progress["step"] = step
        raise exc
    return connect


def check_failed(result, stage, code, *, failed_check, reason):
    assert OLD_KEYS <= set(result), set(result)
    assert result["ok"] is False and result["reason"] == reason, result["reason"]
    assert result["checks"][failed_check] == "failed"
    assert set(result["checks"]) == set(CHECKS)
    assert (result["stage"], result["reason_code"]) == (stage, code), (result["stage"], result["reason_code"])
    assert result["protocol"] == result["type"]


def cert_error(code, text):
    exc = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {text} password={MARKER}")
    exc.verify_code = code
    exc.verify_message = text
    return exc


def test_ftp_connect_stages() -> None:
    helper = load_helper()
    cases = [
        ("connect", socket.gaierror(-2, f"Name or service not known {MARKER}"), "name_resolution", "name_not_resolved", "connection", "connection failed"),
        ("connect", TimeoutError("timed out"), "tcp_connect", "timeout", "connection", "connection failed"),
        ("connect", ConnectionRefusedError(111, "Connection refused"), "tcp_connect", "refused", "connection", "connection failed"),
        ("connect", ftplib.error_reply(f"220 weird banner {MARKER}"), "tcp_connect", "banner_mismatch", "connection", "connection failed"),
        ("tls", cert_error(10, "certificate has expired"), "certificate", "certificate_expired", "connection", "connection failed"),
        ("tls", cert_error(62, "Hostname mismatch, certificate is not valid for the host."), "certificate", "certificate_name_mismatch", "connection", "connection failed"),
        ("tls", cert_error(20, "unable to get local issuer certificate"), "certificate", "certificate_untrusted", "connection", "connection failed"),
        ("tls", ssl.SSLError(1, f"handshake failure {MARKER}"), "tls_handshake", "tls_handshake_failed", "connection", "connection failed"),
        ("login", ftplib.error_perm(f"530 Login incorrect {MARKER}"), "login", "login_refused", "authentication", "authentication failed"),
        ("login", TimeoutError("timed out"), "login", "timeout", "connection", "connection failed"),
        ("login", RuntimeError("backup credential is bound to a different destination endpoint"), "configuration", "configuration_invalid", "connection", "connection failed"),
    ]
    for step, exc, stage, code, failed_check, reason in cases:
        helper.ftp_connect = ftp_connect_failing(step, exc)
        result, failed = validate(helper, FTP)
        assert failed
        check_failed(result, stage, code, failed_check=failed_check, reason=reason)
        assert (result["host"], result["port"]) == ("ftp.example.com", 2121)
        assert result["detail"] and len(result["detail"]) <= 500
    # Authentication keeps its 1.17.53 check shape: connection passed, authentication failed.
    helper.ftp_connect = ftp_connect_failing("login", ftplib.error_perm("530 no"))
    result, _ = validate(helper, FTP)
    assert result["checks"]["connection"] == "passed" and result["checks"]["authentication"] == "failed"


class FakeFtp:
    def __init__(self, store_exc=None, retr_exc=None):
        self.store_exc, self.retr_exc, self.data = store_exc, retr_exc, b""

    def storbinary(self, cmd, fh, blocksize=0):
        if self.store_exc:
            raise self.store_exc
        self.data = fh.read()

    def retrbinary(self, cmd, callback, blocksize=0):
        if self.retr_exc:
            raise self.retr_exc
        callback(self.data)

    def delete(self, name):
        pass

    def nlst(self):
        return []

    def quit(self):
        pass

    def close(self):
        pass


def test_ftp_data_connection_and_success() -> None:
    helper = load_helper()
    helper.ftp_prepare_path = lambda ftp, path, create=False: None
    for exc, key, expected in (
        (OSError(113, f"No route to host {MARKER}"), "store_exc", ("data_connection", "passive_port_unreachable", "write", "write failed")),
        (TimeoutError("timed out"), "retr_exc", ("data_connection", "passive_port_unreachable", "read", "read failed")),
    ):
        fake = FakeFtp(**{key: exc})
        helper.ftp_connect = lambda config, destination, *, timeout=60, progress=None, fake=fake: fake
        result, failed = validate(helper, FTP)
        assert failed
        check_failed(result, expected[0], expected[1], failed_check=expected[2], reason=expected[3])
    # A 5xx answer during STOR is a refused write, not a data connection problem.
    fake = FakeFtp(store_exc=ftplib.error_perm("553 not allowed"))
    helper.ftp_connect = lambda config, destination, *, timeout=60, progress=None: fake
    result, _ = validate(helper, FTP)
    assert (result["stage"], result["reason_code"]) == ("write", "write_failed")
    # Success.
    fake = FakeFtp()
    helper.ftp_connect = lambda config, destination, *, timeout=60, progress=None: fake
    result, failed = validate(helper, FTP)
    assert not failed and result["ok"] is True
    assert (result["stage"], result["reason_code"]) == ("complete", "ok")
    assert result["protocol"] == "ftp" and result["host"] == "ftp.example.com" and result["port"] == 2121 and result["detail"] is None
    assert all(result["checks"][name] == "passed" for name in CHECKS)
    assert "reason" not in result


def test_ftp_connect_progress_argument() -> None:
    helper = load_helper()
    events = []

    class FakeTls:
        def __init__(self, timeout=None, context=None):
            pass

        def connect(self, *a, **k):
            events.append("connect")

        def auth(self):
            events.append("auth")

        def login(self, *a):
            events.append("login")

        def prot_p(self):
            events.append("prot_p")

        def set_pasv(self, flag):
            events.append("pasv")

        def close(self):
            pass

    saved = helper.ftplib.FTP_TLS
    helper.ftplib.FTP_TLS = FakeTls
    helper.ftp_tls_context = lambda: None
    try:
        progress = {}
        helper.ftp_connect(CONFIG, FTP, progress=progress)
        assert events == ["connect", "auth", "login", "prot_p", "pasv"] and progress["step"] == "prot_p", (events, progress)
        events.clear()
        helper.ftp_connect(CONFIG, FTP)  # the backup upload path: no progress, behaves as before
        assert events == ["connect", "login", "prot_p", "pasv"], events
    finally:
        helper.ftplib.FTP_TLS = saved


def scripted(helper, outputs):
    calls = []

    def capture(args, *, timeout=120):
        calls.append(list(args))
        return outputs[min(len(calls), len(outputs)) - 1]

    helper._capture_command = capture
    return calls


def test_scp_and_rclone_best_effort() -> None:
    helper = load_helper()
    helper.scp_args = lambda config, destination, temp, log: (["-o", "x"], ["-o", "x"])
    helper.make_rclone_config = lambda config, destination, temp, log: temp / "rclone.conf"
    table = [
        ("ssh: Could not resolve hostname ssh.example.com: Name or service not known", "name_resolution", "name_not_resolved", "connection"),
        ("ssh: connect to host ssh.example.com port 22: Connection timed out", "tcp_connect", "timeout", "connection"),
        ("ssh: connect to host ssh.example.com port 22: Connection refused", "tcp_connect", "refused", "connection"),
        ("u@ssh.example.com: Permission denied (publickey).", "login", "login_refused", "authentication"),
        ("Host key verification failed.", "certificate", "host_key_mismatch", "connection"),
        ("something nobody has seen before", "unknown", "unknown", "connection"),
    ]
    for dest in (SCP, SFTP):
        for text, stage, code, failed_check in table:
            scripted(helper, [(255, "", text + f" password={MARKER}")])
            result, failed = validate(helper, dest)
            assert failed
            assert (result["stage"], result["reason_code"]) == (stage, code), (dest["type"], text, result["stage"], result["reason_code"])
            assert result["checks"][failed_check] == "failed"
            assert result["reason"] == ("authentication failed" if failed_check == "authentication" else "connection failed")
            assert result["protocol"] == dest["type"] and result["host"] == dest["host"]
        # timeout from the helper's own wrapper
        scripted(helper, [(124, "", "timeout")])
        result, _ = validate(helper, dest)
        assert (result["stage"], result["reason_code"]) == ("tcp_connect", "timeout")
        # A later step keeps the short reason and names its own stage.
        scripted(helper, [(0, "", ""), (0, "", ""), (1, "", f"scp: write denied token={MARKER}")])
        result, _ = validate(helper, dest)
        check_failed(result, "write", "write_failed", failed_check="write", reason="write failed")
        assert "<redacted>" in result["detail"]


def test_scrub_detail() -> None:
    helper = load_helper()
    text = f"Bearer abc.def password={MARKER}\nline two https://u:{MARKER}2@host/x {MARKER}3 " + "z" * 900
    out = helper._scrub_detail(text, [MARKER + "3", ""])
    assert MARKER not in out and "\n" not in out and len(out) <= 500, out
    assert "abc.def" not in out
    assert helper._scrub_detail("-----BEGIN OPENSSH PRIVATE KEY----- x") == "[redacted private key material]"
    assert helper._scrub_detail(None) == ""


def test_local_and_configuration_failures_keep_shape() -> None:
    helper = load_helper()
    result, failed = validate(helper, {"id": "e", "type": "local", "path": "/etc/ssh"})
    assert failed and (result["stage"], result["reason_code"]) == ("configuration", "configuration_invalid")
    assert result["protocol"] == "local" and result["host"] is None and result["port"] is None and result["detail"] is None
    assert result["checks"]["configuration"] == "failed"
    result, failed = validate(helper, {"id": "bad id!", "type": "carrier-pigeon", "host": MARKER})
    assert failed and result["stage"] == "configuration" and result["host"] is None
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="sb-stage-local-"))
    config = {"TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": str(tmp)}
    result, failed = validate(helper, {"id": "l", "type": "local", "path": str(tmp / "d")}, config)
    assert not failed and result["ok"] and (result["stage"], result["reason_code"]) == ("complete", "ok")
    assert result["host"] is None and result["port"] is None


def test_core_masks_detail() -> None:
    import tec_tac.server_backup as sb
    masked = sb._sanitize_log_line(f"login failed password={MARKER}")
    assert MARKER not in masked and "<redacted>" in masked


if __name__ == "__main__":
    test_ftp_connect_stages()
    test_ftp_data_connection_and_success()
    test_ftp_connect_progress_argument()
    test_scp_and_rclone_best_effort()
    test_scrub_detail()
    test_local_and_configuration_failures_keep_shape()
    test_core_masks_detail()
    print("[TEST] PASS validate_destination stage, reason_code and detail")
