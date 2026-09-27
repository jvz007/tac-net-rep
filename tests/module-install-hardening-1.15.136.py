#!/usr/bin/env python3
"""Behavioral regressions for Core 1.15.136 module/install hardening."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


worker = load("tt_module_v2_115136", ROOT / "scripts" / "module-v2-job-helper.py")
update = load("tt_system_update_115136", ROOT / "scripts" / "system-update-helper.py")
trust = load("tt_privileged_trust_115136", ROOT / "scripts" / "privileged-trust.py")

# L55: aliases such as ./x.zip must never overwrite the authenticated x.zip.
with tempfile.TemporaryDirectory(prefix="tt-115136-alias-") as td:
    base = Path(td)
    bundle = base / "bundle.zip"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.writestr("packages/x.zip", b"verified-child")
        zf.writestr("./packages/x.zip", b"attacker-alias")
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    try:
        worker._extract_verified_bundle(bundle, base / "out", digest, "alias-test")
    except RuntimeError as exc:
        assert "aliased" in str(exc) or "unsafe" in str(exc), exc
    else:
        raise AssertionError("aliased ZIP member was accepted")

# L56: snapshot/trust failure must not leave the claimed bridge/request behind.
with tempfile.TemporaryDirectory(prefix="tt-115136-claim-") as td:
    base = Path(td)
    worker.RUNNING_ROOT = base / "running-v2"
    worker.RUNNING_REQUEST_ROOT = worker.RUNNING_ROOT / "requests"
    worker.LOGS_ROOT = base / "logs"
    worker.BACKUP_ROOT = base / "backups"
    worker.LIFECYCLE_LOCK_PATH = base / "lifecycle.lock"
    job_id = "11111111-1111-1111-1111-111111111111"
    status_path = base / "status.json"
    request_path = worker.RUNNING_REQUEST_ROOT / f"{job_id}.json"
    request_path.parent.mkdir(parents=True)
    request_path.write_text("{}", encoding="utf-8")
    claim_dir = worker.RUNNING_ROOT / f"{job_id}.claimed"
    claim_dir.mkdir(parents=True)
    (claim_dir / "artifact.zip").write_bytes(b"claimed")
    worker.load_job = lambda _job_id: (status_path, {"status": "dispatched", "stage": "dispatched", "created_at": "now"})
    worker.load_running_request = lambda _job_id: (request_path, {"id": job_id, "action": "bundle_install", "bundle_path": str(claim_dir / "artifact.zip")})
    worker.acquire_lifecycle_lock = lambda: None
    worker.load_config = lambda: {}
    worker._snapshot_v2_job_artifacts = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("snapshot failed"))
    try:
        worker.run_job(job_id)
    except RuntimeError as exc:
        assert "snapshot failed" in str(exc)
    else:
        raise AssertionError("forced snapshot failure did not propagate")
    assert not request_path.exists(), "root-private running request survived snapshot failure"
    assert not claim_dir.exists(), "root-private claim directory survived snapshot failure"

# L57: reject component mismatch before _copy_staged_package consumes the package.
with tempfile.TemporaryDirectory(prefix="tt-115136-component-") as td:
    base = Path(td)
    update.STAGED_ROOT = base / "staged"
    update.RUNNING_ROOT = base / "running"
    update.RUNNING_REQUEST_ROOT = update.RUNNING_ROOT / "requests"
    update.LOGS_ROOT = base / "logs"
    update.BACKUPS_ROOT = base / "backups"
    update.HISTORY_ROOT = base / "history"
    update.STAGED_ROOT.mkdir(parents=True)
    job_id = "22222222-2222-2222-2222-222222222222"
    upload_id = "33333333-3333-3333-3333-333333333333"
    status_path = base / "status.json"
    request = {"status": "queued", "component": "ui", "upload_id": upload_id, "allow_downgrade": False}
    (update.STAGED_ROOT / f"{upload_id}.json").write_text(json.dumps({"upload_id": upload_id, "filename": "framework.zip", "preview": {"component": "framework"}}), encoding="utf-8")
    package = update.STAGED_ROOT / f"{upload_id}.zip"
    package.write_bytes(b"framework-bytes")
    update.load_job = lambda _job_id: (status_path, dict(request))
    update.load_config = lambda: {}
    update.tactical_gid = lambda _cfg=None: os.getgid()
    original_chown = update.os.chown
    update.os.chown = lambda *_args, **_kwargs: None
    try:
        try:
            update.claim_job(job_id)
        except SystemExit as exc:
            assert "component" in str(exc), exc
        else:
            raise AssertionError("component mismatch was accepted")
    finally:
        update.os.chown = original_chown
    assert package.exists(), "component mismatch consumed staged package before validation"
    assert package.read_bytes() == b"framework-bytes"

# L58: ownership checks follow TEC_TAC_FRAMEWORK_ROOT instead of /opt/tec-tac.
with tempfile.TemporaryDirectory(prefix="tt-115136-custom-root-") as td:
    base = Path(td)
    runtime = base / "custom" / "framework"
    package = runtime / "tec_tac"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "trusted_publishers.py").write_text(
        "class PublisherTrustError(RuntimeError): pass\n"
        "def verify_release_files(*a, **k): return {}\n"
        "def verify_release_tree(*a, **k): return {}\n",
        encoding="utf-8",
    )
    config = base / "tec-tac.conf"
    config.write_text(f"TEC_TAC_FRAMEWORK_ROOT={runtime}\n", encoding="utf-8")
    trust.CONFIG = config
    trust.FRAMEWORK_ROOT = base / "must-not-be-used"
    checked = []
    original_check = trust._require_root_owned_nonwritable
    trust._require_root_owned_nonwritable = lambda path, label: checked.append(Path(path).resolve())
    old_path = list(sys.path)
    old_pkg = sys.modules.pop("tec_tac", None)
    old_pub = sys.modules.pop("tec_tac.trusted_publishers", None)
    try:
        trust._imports()
    finally:
        trust._require_root_owned_nonwritable = original_check
        sys.path[:] = old_path
        sys.modules.pop("tec_tac", None)
        sys.modules.pop("tec_tac.trusted_publishers", None)
        if old_pkg is not None: sys.modules["tec_tac"] = old_pkg
        if old_pub is not None: sys.modules["tec_tac.trusted_publishers"] = old_pub
    resolved_runtime = runtime.resolve()
    assert resolved_runtime in checked, checked
    assert package.resolve() in checked, checked
    assert Path("/opt/tec-tac").resolve() not in checked, checked

print("[TEST] PASS Core 1.15.136 module/install hardening L55-L58")
