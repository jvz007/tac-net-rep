#!/usr/bin/env python3
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tarfile
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("server_backup_helper_n1", ROOT / "scripts" / "server-backup-helper.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def make_identity(base: pathlib.Path, key_id: str, *, trust=True):
    signing = base / f"sign-{key_id}"
    trust_root = base / f"trust-{key_id}"
    signing.mkdir(); trust_root.mkdir()
    os.chmod(signing, 0o700); os.chmod(trust_root, 0o755)
    private = signing / "private.pem"
    key = Ed25519PrivateKey.generate()
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(private, 0o600)
    if trust:
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        trusted = trust_root / f"{key_id}.pub"
        trusted.write_bytes(public)
        os.chmod(trusted, 0o644)
    return key, private, trust_root


def config(private: pathlib.Path, trust_root: pathlib.Path, key_id="source-a"):
    return {
        "TEC_TAC_INSTALLATION_ID": key_id,
        "TEC_TAC_RECOVERY_SIGNING_KEY": str(private),
        "TEC_TAC_RECOVERY_TRUST_ROOT": str(trust_root),
        "TEC_TAC_ROOT": "/opt/tec-tac",
        "TEC_TAC_FRAMEWORK_SOURCE": "/opt/tec-tac-src/framework",
        "TEC_TAC_UI_SOURCE": "/opt/tec-tac-src/ui",
        "TEC_TAC_STATE_ROOT": "/var/lib/tec-tac",
    }


def make_tec_component(path: pathlib.Path, extra=None):
    files = {
        "opt/tec-tac/VERSION": b"1.15.80\n",
        "etc/tec-tac/tec-tac.conf": b"x=1\n",
    }
    files.update(extra or {})
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name); ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))


def make_bundle(base: pathlib.Path, cfg: dict, *, component_extra=None, tamper_manifest=False):
    tec = base / "tec.tar.gz"
    make_tec_component(tec, component_extra)
    tec_hash = h.sha256_file(tec)
    cmeta = {
        "included": True,
        "archive": "tec-tac/tec-tac-backup.tar.gz",
        "archive_name": "tec-tac-backup.tar.gz",
        "sha256": tec_hash,
        "size_bytes": tec.stat().st_size,
        "framework_version": "1.15.80",
        "ui_version": "0.12.33",
        # These are deliberately attacker-controlled descriptive values. Root
        # restore code must never use them to select executable paths.
        "paths": {"framework_source": "/etc/cron.d", "ui_source": "/root/.ssh"},
        "state_policy": {"state_root": "/var/lib/tec-tac"},
    }
    manifest = {
        "format_version": 2,
        "artifact_type": "tec-tac-recovery-bundle",
        "created_at": h.now(),
        "installation_id": cfg["TEC_TAC_INSTALLATION_ID"],
        "backup_class": "manual",
        "components": {"tactical": {"included": False}, "tec_tac": cmeta},
        "recovery_modes": ["tec_tac"],
    }
    manifest_path = base / "manifest.json"
    checksums = base / "checksums.sha256"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksums.write_text(f"{tec_hash}  tec-tac/tec-tac-backup.tar.gz\n", encoding="utf-8")
    envelope = h.create_recovery_signature(cfg, manifest_path.read_bytes(), checksums.read_bytes())
    sig = base / h.RECOVERY_SIGNATURE_MEMBER
    sig.write_text(json.dumps(envelope, sort_keys=True) + "\n", encoding="utf-8")
    if tamper_manifest:
        manifest["backup_class"] = "monthly"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    bundle = base / "tec-tac-backup-n1.tgz"
    with tarfile.open(bundle, "w:gz") as tf:
        tf.add(manifest_path, arcname="manifest.json")
        tf.add(checksums, arcname="checksums.sha256")
        tf.add(sig, arcname=h.RECOVERY_SIGNATURE_MEMBER)
        tf.add(tec, arcname="tec-tac/tec-tac-backup.tar.gz")
    return bundle


with tempfile.TemporaryDirectory() as td:
    td = pathlib.Path(td)
    _key, private, trust_root = make_identity(td, "source-a", trust=True)
    cfg = config(private, trust_root)

    good_dir = td / "good"; good_dir.mkdir()
    good = make_bundle(good_dir, cfg)
    stage = td / "stage-good"; stage.mkdir()
    manifest, parts = h.validate_recovery_bundle(good, "tec_tac", stage, config=cfg)
    assert manifest["recovery_trust"]["verified"] is True
    assert manifest["recovery_trust"]["key_id"] == "source-a"
    assert hashlib.sha256(parts["tec_tac"].read_bytes()).hexdigest() == manifest["components"]["tec_tac"]["sha256"]

    tamper_dir = td / "tamper"; tamper_dir.mkdir()
    tampered = make_bundle(tamper_dir, cfg, tamper_manifest=True)
    stage = td / "stage-tamper"; stage.mkdir()
    try:
        h.validate_recovery_bundle(tampered, "tec_tac", stage, config=cfg)
    except RuntimeError as exc:
        assert "signed manifest hash" in str(exc) or "signature verification" in str(exc)
    else:
        raise AssertionError("tampered recovery manifest was accepted")

    untrusted_dir = td / "untrusted"; untrusted_dir.mkdir()
    _k2, p2, empty_trust = make_identity(untrusted_dir, "source-b", trust=False)
    cfg_b = config(p2, empty_trust, "source-b")
    bdir = untrusted_dir / "bundle"; bdir.mkdir()
    untrusted = make_bundle(bdir, cfg_b)
    # Target has not imported source-b public key.
    target_cfg = dict(cfg_b); target_cfg["TEC_TAC_RECOVERY_TRUST_ROOT"] = str(trust_root)
    stage = td / "stage-untrusted"; stage.mkdir()
    try:
        h.validate_recovery_bundle(untrusted, "tec_tac", stage, config=target_cfg)
    except RuntimeError as exc:
        assert "not trusted" in str(exc)
    else:
        raise AssertionError("untrusted recovery signer was accepted")

    malicious_dir = td / "malicious"; malicious_dir.mkdir()
    malicious = make_bundle(malicious_dir, cfg, component_extra={"etc/cron.d/tectac-root": b"* * * * * root id\n"})
    stage = td / "stage-malicious"; stage.mkdir()
    try:
        h.validate_recovery_bundle(malicious, "tec_tac", stage, config=cfg)
    except RuntimeError as exc:
        assert "not allow-listed" in str(exc)
    else:
        raise AssertionError("signed recovery payload escaped the fixed destination allow-list")

    trust_replace_dir = td / "trust-replace"; trust_replace_dir.mkdir()
    trust_replace = make_bundle(trust_replace_dir, cfg, component_extra={"etc/tec-tac/recovery-trust/evil.pub": b"evil"})
    stage = td / "stage-trust-replace"; stage.mkdir()
    try:
        h.validate_recovery_bundle(trust_replace, "tec_tac", stage, config=cfg)
    except RuntimeError as exc:
        assert "may not replace target recovery trust" in str(exc)
    else:
        raise AssertionError("recovery payload was allowed to replace target recovery trust")

source = (ROOT / "scripts" / "server-backup-helper.py").read_text(encoding="utf-8")
post = source[source.index("def run_post_restore_tec_tac"):source.index("VALIDATE_RESTORE_STATUSES")]
assert 'Path(config["TEC_TAC_FRAMEWORK_SOURCE"])' in post
assert 'Path(config["TEC_TAC_UI_SOURCE"])' in post
assert 'paths.get("framework_source")' not in post and 'paths.get("ui_source")' not in post
assert 'exclude_paths=(' in source and '"recovery-signing"' in source and '"recovery-trust"' in source

print("[TEST] PASS N1 signed recovery trust and fixed restore destinations")
