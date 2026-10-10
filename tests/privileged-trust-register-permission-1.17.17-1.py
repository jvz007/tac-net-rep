"""1.17.17: the root trust gate (privileged-trust verify-package) refuses an unsigned package that declares
server_maintenance.register (signature_required), and a signed package whose publisher lacks it (publisher_permission_denied).
Both job helpers verify before they install and register, so no registry file reaches actions.d in either case."""
import base64
import hashlib
import importlib.util
import json
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from tec_tac.trusted_publishers import (
    PublisherTrustError,
    verify_release_files,
)

spec = importlib.util.spec_from_file_location("privileged_trust_register_perm", ROOT / "scripts/privileged-trust.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def make_package(path, permissions):
    manifest = {"id": "smprobe", "type": "extension", "version": "1.0.0", "publisher_permissions": permissions}
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("extensions/smprobe/tec_tac.json", json.dumps(manifest))


def check(permissions, publisher_permissions, signed, expect_code):
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        trust_root = base / "trust"
        pubdir = trust_root / "tech-flow"
        pubdir.mkdir(parents=True)
        package = base / "smprobe-1.0.0.zip"
        make_package(package, permissions)
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (pubdir / "public.key").write_text("ed25519:" + base64.b64encode(public).decode() + "\n")
        (pubdir / "publisher.json").write_text(json.dumps({
            "schema": 1, "publisher_id": "tech-flow", "status": "trusted", "environment": "development",
            "permissions": publisher_permissions,
            "keys": [{"key_id": "dev", "status": "active", "algorithm": "Ed25519", "public_key_file": "public.key"}],
        }))
        signature = metadata = None
        if signed:
            signature = base / "smprobe-1.0.0.zip.sig"
            signature.write_text("ed25519:" + base64.b64encode(key.sign(package.read_bytes())).decode() + "\n")
            metadata = base / "smprobe-1.0.0.release.json"
            metadata.write_text(json.dumps({
                "schema": 1, "publisher_id": "tech-flow", "key_id": "dev", "filename": package.name,
                "sha256": hashlib.sha256(package.read_bytes()).hexdigest(), "signature": signature.name,
                "algorithm": "Ed25519", "environment": "development",
            }))
        gate.TRUST_ROOT = trust_root
        gate._imports = lambda: (PublisherTrustError, verify_release_files, None)
        gate._config = lambda: {"TEC_TAC_ENVIRONMENT": "development"}
        gate._require_root_owned_nonwritable = lambda *a, **k: None
        # The policy floor is 'unsigned' (the weakest): the gate must still refuse.
        gate.enforce_policy = lambda trust, kind: {**trust, "root_policy": {"accepted": True, "level": "unsigned"}}
        try:
            result = gate.verify_package(package, signature, metadata)
        except PublisherTrustError as exc:
            assert expect_code and exc.code == expect_code, (exc.code, expect_code)
            return None
        assert expect_code is None, f"expected {expect_code}, package was accepted"
        return result


def test_unsigned_package_declaring_register_is_refused():
    check(["server_maintenance.register"], ["module.install", "server_maintenance.register"], False, "signature_required")


def test_signed_package_without_publisher_permission_is_refused():
    check(["server_maintenance.register"], ["module.install"], True, "publisher_permission_denied")


def test_signed_package_with_permission_and_plain_unsigned_package_still_work():
    ok = check(["server_maintenance.register"], ["module.install", "server_maintenance.register"], True, None)
    assert ok["signed"] and "server_maintenance.register" in ok["required_permissions"]
    plain = check(["module.install"], ["module.install"], False, None)
    assert plain["signed"] is False


def test_job_helpers_verify_before_they_register():
    for name, verify in (("module-v2-job-helper.py", "_verify_v2_job_trust"), ("module-job-helper.py", "_privileged_verify_package")):
        source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        body = source[source.index("def run_job("):]
        first_verify = body.index(verify + "(")
        first_sync = body.index("sync_server_maintenance_actions(")
        assert first_verify < first_sync, name


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print("ok")
