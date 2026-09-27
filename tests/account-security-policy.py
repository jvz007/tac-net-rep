#!/usr/bin/env python3
"""Behavioural D1 account-security policy regression coverage.

This suite intentionally runs without root. Root-only filesystem primitives are
stubbed at the narrow write boundary so the policy mutation/audit behaviour can
be exercised in the normal test runner.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


helper_path = ROOT / "scripts" / "system-update-helper.py"
spec = importlib.util.spec_from_file_location("tec_tac_system_update_helper_test", helper_path)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

# L85/L86: exercise the real privileged mutation flow without requiring root.
# The test proves a durable root-audit intent is required before the policy write
# and that the actual sudo identity is independent of the application actor label.
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    target = td / "policy" / "account-security-policy.json"
    audit_target = td / "log" / "account-security-policy-audit.jsonl"
    helper.ACCOUNT_SECURITY_POLICY = target
    helper.ACCOUNT_SECURITY_AUDIT = audit_target

    events = []
    writes = []
    original_append = helper._append_root_account_security_audit
    original_atomic = helper.atomic_json
    original_chown = helper.os.chown
    original_chmod = helper.os.chmod
    original_env = dict(os.environ)

    def fake_append(payload):
        events.append(payload)

    def fake_atomic(path, payload, mode=0o640, *, uid=None, gid=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        writes.append((path, payload, mode, uid, gid))

    helper._append_root_account_security_audit = fake_append
    helper.atomic_json = fake_atomic
    helper.os.chown = lambda *args, **kwargs: None
    helper.os.chmod = lambda *args, **kwargs: None
    os.environ["SUDO_USER"] = "tactical"
    os.environ["SUDO_UID"] = "1001"
    try:
        payload = helper.set_root_account_security_policy("true", "spoofable-app-label")
        require(payload["protect_superuser_accounts"] is True, "policy did not enable")
        require(len(events) == 1, "root audit intent was not written exactly once")
        event = events[0]
        require(event["sudo_user"] == "tactical", "root audit did not record actual sudo user")
        require(event["sudo_uid"] == "1001", "root audit did not record actual sudo uid")
        require(event["actor_label"] == "spoofable-app-label", "application actor label not retained")
        require(event["requested"]["protect_superuser_accounts"] is True, "requested state missing from root audit")
        require(len(writes) == 1, "policy write did not occur")
        require(writes[0][3:] == (0, 0), "policy write is not requested as root-owned")

        # If the root audit boundary fails, the policy write must not occur.
        writes.clear()
        def fail_audit(payload):
            raise RuntimeError("audit unavailable")
        helper._append_root_account_security_audit = fail_audit
        try:
            helper.set_root_account_security_policy("false", "root-admin")
        except RuntimeError as exc:
            require("audit unavailable" in str(exc), "unexpected root-audit failure")
        else:
            raise AssertionError("policy mutation continued after root-audit failure")
        require(not writes, "policy was written after root-audit failure")
    finally:
        helper._append_root_account_security_audit = original_append
        helper.atomic_json = original_atomic
        helper.os.chown = original_chown
        helper.os.chmod = original_chmod
        os.environ.clear()
        os.environ.update(original_env)

# Exercise the root-audit writer itself without requiring uid 0: only the
# ownership-changing syscalls/fstat uid are shimmed, while the real O_NOFOLLOW,
# append, flock, JSON serialization and fsync path executes against a tempfile.
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    helper.ACCOUNT_SECURITY_AUDIT = td / "audit" / "account-security-policy-audit.jsonl"
    original_fstat = helper.os.fstat
    original_fchown = helper.os.fchown
    original_chown = helper.os.chown
    original_chmod = helper.os.chmod
    class RootStat:
        def __init__(self, base):
            self.st_mode = base.st_mode
            self.st_uid = 0
            self.st_gid = 0
            self.st_size = base.st_size
    helper.os.fstat = lambda fd: RootStat(original_fstat(fd))
    helper.os.fchown = lambda *args, **kwargs: None
    helper.os.chown = lambda *args, **kwargs: None
    helper.os.chmod = lambda *args, **kwargs: None
    try:
        helper._append_root_account_security_audit({"event": "test", "sudo_user": "tactical"})
    finally:
        helper.os.fstat = original_fstat
        helper.os.fchown = original_fchown
        helper.os.chown = original_chown
        helper.os.chmod = original_chmod
    lines = helper.ACCOUNT_SECURITY_AUDIT.read_text(encoding="utf-8").splitlines()
    require(len(lines) == 1, "root audit writer did not append one record")
    require(json.loads(lines[0])["sudo_user"] == "tactical", "root audit writer corrupted record")

# Keep the existing low-cleanup boundaries visible in the same normal runner.
uninstall_source = (ROOT / "uninstall.sh").read_text()
require('source "${TEC_TAC_CONFIG_FILE}"' not in uninstall_source, "uninstaller still sources config data")
require('scripts/tec-tac-config.sh' in uninstall_source, "uninstaller does not use safe config parser")

print("account-security-policy: PASS")
