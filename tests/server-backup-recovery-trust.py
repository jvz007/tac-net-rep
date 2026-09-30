#!/usr/bin/env python3
"""Portable AD-3 regression retained under the historical filename.

The old test covered recovery-signer trust. AD-3 removed that trust model. This
regression now proves unsigned new bundles, legacy signed-bundle compatibility,
and fixed Tec-Tac restore destinations without requiring root-owned trust state.
"""
import base64
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("server_backup_helper_ad3", ROOT / "scripts" / "server-backup-helper.py")
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)


def make_tec_component(path: pathlib.Path, extra=None):
    files = {
        "opt/tec-tac/VERSION": b"1.15.188\n",
        "etc/tec-tac/tec-tac.conf": b"x=1\n",
    }
    files.update(extra or {})
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name); ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))


def build_bundle(base: pathlib.Path, *, signed=False, tamper_manifest=False, extra=None):
    tec = base / "tec.tar.gz"; make_tec_component(tec, extra)
    tec_hash = h.sha256_file(tec)
    cmeta = {
        "included": True,
        "archive": "tec-tac/tec-tac-backup.tar.gz",
        "archive_name": "tec-tac-backup.tar.gz",
        "sha256": tec_hash,
        "size_bytes": tec.stat().st_size,
        "framework_version": "1.15.188",
        "ui_version": "0.12.80",
        "paths": {"framework_source": "/etc/cron.d", "ui_source": "/root/.ssh"},
        "state_policy": {"state_root": "/var/lib/tec-tac"},
    }
    manifest = {
        "format_version": 2,
        "artifact_type": "tec-tac-recovery-bundle",
        "created_at": h.now(),
        "installation_id": "source-a",
        "server_name": "source-rmm",
        "backup_class": "manual",
        "components": {"tactical": {"included": False}, "tec_tac": cmeta},
        "recovery_modes": ["tec_tac"],
    }
    m = base / "manifest.json"; c = base / "checksums.sha256"
    m.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    c.write_text(f"{tec_hash}  tec-tac/tec-tac-backup.tar.gz\n")
    sig = None
    if signed:
        key = Ed25519PrivateKey.generate()
        mb, cb = m.read_bytes(), c.read_bytes()
        pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        env = {
            "schema": 1, "algorithm": "ed25519", "key_id": "legacy-source",
            "public_key_sha256": hashlib.sha256(raw).hexdigest(), "public_key_pem": pem.decode(),
            "manifest_sha256": hashlib.sha256(mb).hexdigest(), "checksums_sha256": hashlib.sha256(cb).hexdigest(),
            "signature": base64.b64encode(key.sign(h._recovery_signing_message(mb, cb))).decode(),
        }
        sig = base / h.RECOVERY_SIGNATURE_MEMBER; sig.write_text(json.dumps(env) + "\n")
    if tamper_manifest:
        manifest["backup_class"] = "monthly"
        m.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    bundle = base / ("tec-tac-backup-signed.tgz" if signed else "tec-tac-backup-unsigned.tgz")
    with tarfile.open(bundle, "w:gz") as tf:
        tf.add(m, arcname="manifest.json"); tf.add(c, arcname="checksums.sha256")
        if sig: tf.add(sig, arcname=h.RECOVERY_SIGNATURE_MEMBER)
        tf.add(tec, arcname="tec-tac/tec-tac-backup.tar.gz")
    return bundle


cfg = {
    "TEC_TAC_INSTALLATION_ID": "target-a",
    "TEC_TAC_ROOT": "/opt/tec-tac",
    "TEC_TAC_FRAMEWORK_SOURCE": "/opt/tec-tac-src/framework",
    "TEC_TAC_UI_SOURCE": "/opt/tec-tac-src/ui",
    "TEC_TAC_STATE_ROOT": "/var/lib/tec-tac",
}

with tempfile.TemporaryDirectory() as td:
    td = pathlib.Path(td)
    good_dir = td / "good"; good_dir.mkdir()
    good = build_bundle(good_dir, signed=False)
    stage = td / "stage-good"; stage.mkdir()
    manifest, parts = h.validate_recovery_bundle(good, "tec_tac", stage, config=cfg)
    assert manifest["legacy_signature"] is None
    assert hashlib.sha256(parts["tec_tac"].read_bytes()).hexdigest() == manifest["components"]["tec_tac"]["sha256"]

    signed_dir = td / "signed"; signed_dir.mkdir()
    legacy = build_bundle(signed_dir, signed=True)
    stage = td / "stage-signed"; stage.mkdir()
    manifest, _ = h.validate_recovery_bundle(legacy, "tec_tac", stage, config=cfg)
    assert manifest["legacy_signature"]["verified"] is True
    assert manifest["legacy_signature"]["trust_required"] is False

    tamper_dir = td / "tamper"; tamper_dir.mkdir()
    tampered = build_bundle(tamper_dir, signed=True, tamper_manifest=True)
    stage = td / "stage-tamper"; stage.mkdir()
    try:
        h.validate_recovery_bundle(tampered, "tec_tac", stage, config=cfg)
    except RuntimeError as exc:
        assert "signed manifest hash" in str(exc) or "signature verification" in str(exc)
    else:
        raise AssertionError("tampered legacy signed recovery manifest was accepted")

    malicious_dir = td / "malicious"; malicious_dir.mkdir()
    malicious = build_bundle(malicious_dir, extra={"etc/cron.d/tectac-root": b"* * * * * root id\n"})
    stage = td / "stage-malicious"; stage.mkdir()
    try:
        h.validate_recovery_bundle(malicious, "tec_tac", stage, config=cfg)
    except RuntimeError as exc:
        assert "not allow-listed" in str(exc)
    else:
        raise AssertionError("recovery payload escaped the fixed destination allow-list")

source = (ROOT / "scripts" / "server-backup-helper.py").read_text()
post = source[source.index("def run_post_restore_tec_tac"):source.index("VALIDATE_RESTORE_STATUSES")]
assert 'Path(config["TEC_TAC_FRAMEWORK_SOURCE"])' in post
assert 'Path(config["TEC_TAC_UI_SOURCE"])' in post
assert 'paths.get("framework_source")' not in post and 'paths.get("ui_source")' not in post
assert 'create_recovery_signature' not in source
assert 'operation_trust_recovery_signer' not in source
assert 'archive_hash_companion' not in source or '.sha256' in source

print("[TEST] PASS AD-3 unsigned recovery, legacy signature compatibility and fixed restore destinations")
