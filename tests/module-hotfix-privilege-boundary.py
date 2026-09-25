import importlib.util
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hotfix_helper_boundary", ROOT / "scripts/module-hotfix-job-helper.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def test_claim_is_root_private_and_public_job_is_not_authoritative():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        helper.HOTFIX_ROOT = base / "hotfixes"
        helper.STAGED_ROOT = helper.HOTFIX_ROOT / "staged"
        helper.JOBS_ROOT = helper.HOTFIX_ROOT / "jobs"
        helper.RUNNING_ROOT = helper.HOTFIX_ROOT / "running"
        helper.LOGS_ROOT = helper.HOTFIX_ROOT / "logs"
        helper.BACKUPS_ROOT = helper.HOTFIX_ROOT / "backups"
        helper.APPLIED_ROOT = helper.HOTFIX_ROOT / "applied"
        helper.HISTORY_ROOT = helper.HOTFIX_ROOT / "history"
        for path in (helper.STAGED_ROOT, helper.JOBS_ROOT):
            path.mkdir(parents=True, exist_ok=True)
        helper.load_config = lambda: {"TACTICAL_USER": "root"}
        job_id = "00000000-0000-0000-0000-000000000111"
        original = {"id": job_id, "action": "apply", "status": "queued", "module_id": "safe", "upload_id": "00000000-0000-0000-0000-000000000222"}
        helper.atomic_json(helper.JOBS_ROOT / f"{job_id}.json", original)
        claimed_path, claimed = helper.claim_job(job_id)
        assert claimed_path.parent == helper.RUNNING_ROOT
        assert claimed_path.stat().st_uid == 0
        assert (claimed_path.stat().st_mode & 0o077) == 0
        public = dict(claimed)
        public["module_id"] = "attacker-replaced"
        helper.atomic_json(helper.JOBS_ROOT / f"{job_id}.json", public)
        _, authority = helper.load_job(job_id, claimed=True)
        assert authority["module_id"] == "safe"


def test_root_verifier_is_mandatory_before_apply_source():
    source = (ROOT / "scripts/module-hotfix-job-helper.py").read_text(encoding="utf-8")
    apply_pos = source.index("def apply_job(")
    verify_pos = source.index("privileged_verify_hotfix(package", apply_pos)
    mutate_pos = source.index('job["stage"] = "apply-files"', apply_pos)
    assert verify_pos < mutate_pos
    assert 'PRIVILEGED_TRUST = Path("/usr/local/lib/tec-tac-security/privileged-trust.py")' in source
    assert 'CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")' in source


def test_privileged_verifier_exposes_hotfix_command():
    source = (ROOT / "scripts/privileged-trust.py").read_text(encoding="utf-8")
    assert "def verify_hotfix(" in source
    assert "sub.add_parser('verify-hotfix')" in source
    assert 'required_permissions=("module.install",)' in source



def test_root_hotfix_verifier_checks_exact_signed_bytes():
    import base64
    import hashlib
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tec_tac.trusted_publishers import PublisherTrustError, verify_release_files

    spec2 = importlib.util.spec_from_file_location("privileged_trust_hotfix", ROOT / "scripts/privileged-trust.py")
    trust_helper = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(trust_helper)
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        trust_root = base / "trust"
        pubdir = trust_root / "tech-flow"
        pubdir.mkdir(parents=True)
        package = base / "module-HF001.zip"
        package.write_bytes(b"signed hotfix bytes")
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (pubdir / "public.key").write_text("ed25519:" + base64.b64encode(public).decode() + "\n")
        (pubdir / "publisher.json").write_text(json.dumps({
            "schema": 1, "publisher_id": "tech-flow", "status": "trusted", "environment": "development",
            "permissions": ["module.install"],
            "keys": [{"key_id": "dev", "status": "active", "algorithm": "Ed25519", "public_key_file": "public.key"}],
        }))
        signature = base / "module-HF001.zip.sig"
        signature.write_text("ed25519:" + base64.b64encode(key.sign(package.read_bytes())).decode() + "\n")
        metadata = base / "module-HF001.release.json"
        metadata.write_text(json.dumps({
            "schema": 1, "publisher_id": "tech-flow", "key_id": "dev", "filename": package.name,
            "sha256": hashlib.sha256(package.read_bytes()).hexdigest(), "signature": signature.name,
            "algorithm": "Ed25519", "environment": "development",
        }))
        trust_helper.TRUST_ROOT = trust_root
        trust_helper._imports = lambda: (PublisherTrustError, verify_release_files, None)
        trust_helper._config = lambda: {"TEC_TAC_ENVIRONMENT": "development"}
        trust_helper.enforce_policy = lambda trust, kind: {**trust, "root_policy": {"accepted": True}}
        ok = trust_helper.verify_hotfix(package, signature, metadata)
        assert ok["verified"] and ok["trusted"] and ok["publisher_id"] == "tech-flow"
        package.write_bytes(package.read_bytes() + b"tampered")
        try:
            trust_helper.verify_hotfix(package, signature, metadata)
        except PublisherTrustError as exc:
            assert exc.code == "sha256_mismatch"
        else:
            raise AssertionError("tampered hotfix bytes were accepted")



def _write_hotfix_zip(path: Path, *, module_id: str, hotfix_id: str, before: bytes, after: bytes):
    import hashlib
    import zipfile
    manifest = {
        "type": "tec-tac-hotfix",
        "schema": 1,
        "id": hotfix_id,
        "module_id": module_id,
        "base_version": "1.0.0",
        "reload": "none",
        "ui_sync": False,
        "validation": {"python_compile": False, "django_check": False},
        "targets": [{
            "component": "extension",
            "path": "payload.txt",
            "sha256_before": hashlib.sha256(before).hexdigest(),
            "sha256_after": hashlib.sha256(after).hexdigest(),
        }],
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("tec_tac_hotfix.json", json.dumps(manifest))
        zf.writestr("payload/extension/payload.txt", after)


def test_verified_private_copy_survives_staged_swap():
    import hashlib
    import io
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        helper.HOTFIX_ROOT = base / "hotfixes"
        helper.STAGED_ROOT = helper.HOTFIX_ROOT / "staged"
        helper.JOBS_ROOT = helper.HOTFIX_ROOT / "jobs"
        helper.RUNNING_ROOT = helper.HOTFIX_ROOT / "running"
        helper.LOGS_ROOT = helper.HOTFIX_ROOT / "logs"
        helper.BACKUPS_ROOT = helper.HOTFIX_ROOT / "backups"
        helper.APPLIED_ROOT = helper.HOTFIX_ROOT / "applied"
        helper.HISTORY_ROOT = helper.HOTFIX_ROOT / "history"
        helper.STAGED_ROOT.mkdir(parents=True)
        helper.JOBS_ROOT.mkdir(parents=True)
        helper.RUNNING_ROOT.mkdir(parents=True, mode=0o700)
        os.chmod(helper.RUNNING_ROOT, 0o700)
        for p in (helper.BACKUPS_ROOT, helper.APPLIED_ROOT, helper.HISTORY_ROOT, helper.LOGS_ROOT):
            p.mkdir(parents=True)

        module_id = "safe"
        original = b"original module bytes"
        approved = b"approved signed hotfix"
        swapped = b"attacker swapped payload"
        ext = base / "extensions" / module_id
        rep = base / "reportsets" / module_id
        ext.mkdir(parents=True); rep.mkdir(parents=True)
        (ext / "tec_tac.json").write_text(json.dumps({"id": module_id, "version": "1.0.0"}))
        (rep / "tec_tac.json").write_text(json.dumps({"id": module_id, "version": "1.0.0"}))
        target = ext / "payload.txt"; target.write_bytes(original)

        upload_id = "00000000-0000-0000-0000-000000000222"
        job_id = "00000000-0000-0000-0000-000000000111"
        staged = helper.STAGED_ROOT / f"{upload_id}.zip"
        replacement = base / "replacement.zip"
        _write_hotfix_zip(staged, module_id=module_id, hotfix_id="HF001", before=original, after=approved)
        _write_hotfix_zip(replacement, module_id=module_id, hotfix_id="HF001", before=original, after=swapped)
        expected_sha = hashlib.sha256(staged.read_bytes()).hexdigest()
        claimed = helper.RUNNING_ROOT / f"{job_id}.json"
        job = {
            "id": job_id, "action": "apply", "status": "running", "stage": "preflight",
            "module_id": module_id, "hotfix_id": "HF001", "base_version": "1.0.0",
            "upload_id": upload_id, "package_path": str(staged), "package_sha256": expected_sha,
            "requested_by": "test",
        }
        helper.atomic_json(claimed, job, mode=0o600, uid=0, gid=0)
        config = {"TEC_TAC_EXTENSIONS_ROOT": str(base / "extensions"), "TEC_TAC_REPORTSETS_ROOT": str(base / "reportsets"), "TACTICAL_USER": "root"}
        helper.write_claimed_job = lambda *args, **kwargs: None
        def swap_after_private_copy(package, signature, metadata):
            os.replace(replacement, staged)
            return {"root_policy": {"accepted": True}, "signed": True, "trusted": True}
        helper.privileged_verify_hotfix = swap_after_private_copy
        helper.apply_job(claimed, job, config, io.StringIO())
        assert target.read_bytes() == approved, "root used swapped Tactical-writable bytes after verification"


def test_symlinked_staged_zip_is_rejected():
    import hashlib
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        helper.STAGED_ROOT = base / "staged"; helper.STAGED_ROOT.mkdir()
        helper.RUNNING_ROOT = base / "running"; helper.RUNNING_ROOT.mkdir(mode=0o700)
        upload_id = "00000000-0000-0000-0000-000000000222"
        job_id = "00000000-0000-0000-0000-000000000111"
        real = base / "real.zip"; real.write_bytes(b"not important")
        staged = helper.STAGED_ROOT / f"{upload_id}.zip"; staged.symlink_to(real)
        job = {"id": job_id, "upload_id": upload_id, "package_path": str(staged), "package_sha256": hashlib.sha256(real.read_bytes()).hexdigest()}
        try:
            helper.claim_staged_artifacts(job)
        except RuntimeError as exc:
            assert "unsafe" in str(exc) or "unreadable" in str(exc)
        else:
            raise AssertionError("symlinked staged hotfix ZIP was accepted")


def test_job_mirror_temp_symlink_cannot_clobber_canary():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        helper.JOBS_ROOT = base / "jobs"; helper.JOBS_ROOT.mkdir()
        job_id = "00000000-0000-0000-0000-000000000111"
        canary = base / "canary"; canary.write_text("root-owned-canary")
        os.chmod(canary, 0o600)
        before = canary.stat()
        legacy_tmp = helper.JOBS_ROOT / f"{job_id}.json.tmp"
        legacy_tmp.symlink_to(canary)
        helper.mirror_job(job_id, {"id": job_id, "status": "running"}, os.getgid())
        after = canary.stat()
        assert canary.read_text() == "root-owned-canary"
        assert (after.st_mode & 0o777) == (before.st_mode & 0o777)
        assert after.st_uid == before.st_uid and after.st_gid == before.st_gid
        mirror = helper.JOBS_ROOT / f"{job_id}.json"
        assert mirror.is_file() and not mirror.is_symlink()


if __name__ == "__main__":
    test_claim_is_root_private_and_public_job_is_not_authoritative()
    test_root_verifier_is_mandatory_before_apply_source()
    test_privileged_verifier_exposes_hotfix_command()
    test_root_hotfix_verifier_checks_exact_signed_bytes()
    test_verified_private_copy_survives_staged_swap()
    test_symlinked_staged_zip_is_rejected()
    test_job_mirror_temp_symlink_cannot_clobber_canary()
    print("[TEST] PASS module hotfix privileged boundary")
