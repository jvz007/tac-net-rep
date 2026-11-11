"""1.17.116: the root trust gate treats the new publisher permission sandbox.register like server_maintenance.register.

* privileged-trust verify-package: an unsigned package that declares sandbox.register is refused (signature_required); a signed package
  whose publisher lacks it is refused (publisher_permission_denied); a signed package whose publisher holds it passes.
* An unknown permission is still refused: in the package path as a permission the publisher does not hold (there is one permission
  check there, not a separate allowed set), and in the installed-target set of a hotfix (``allowed``), which now has three members.
* install.sh does not grant sandbox.register to any publisher (the local trust policy stays the authority).
* Both job helpers verify before they register runners.

The plan named two ``allowed`` sets in privileged-trust.py; the code has one (the hotfix target check). The package path has no set.
"""
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tec_tac.trusted_publishers import PublisherTrustError, verify_release_files

spec = importlib.util.spec_from_file_location("privileged_trust_sandbox_perm", ROOT / "scripts/privileged-trust.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def make_package(path, permissions):
    manifest = {"id": "sbprobe", "type": "extension", "version": "1.0.0", "publisher_permissions": permissions}
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("extensions/sbprobe/tec_tac.json", json.dumps(manifest))


def check(permissions, publisher_permissions, signed, expect_code):
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        trust_root = base / "trust"
        pubdir = trust_root / "tech-flow"
        pubdir.mkdir(parents=True)
        package = base / "sbprobe-1.0.0.zip"
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
            signature = base / "sbprobe-1.0.0.zip.sig"
            signature.write_text("ed25519:" + base64.b64encode(key.sign(package.read_bytes())).decode() + "\n")
            metadata = base / "sbprobe-1.0.0.release.json"
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


def test_unsigned_package_declaring_sandbox_register_is_refused():
    check(["sandbox.register"], ["module.install", "sandbox.register"], False, "signature_required")


def test_signed_package_without_publisher_permission_is_refused():
    check(["sandbox.register"], ["module.install"], True, "publisher_permission_denied")
    # holding the other register permission is not enough
    check(["sandbox.register"], ["module.install", "server_maintenance.register"], True, "publisher_permission_denied")


def test_signed_package_with_the_permission_passes():
    ok = check(["sandbox.register"], ["module.install", "sandbox.register"], True, None)
    assert ok["signed"] and "sandbox.register" in ok["required_permissions"]


def test_unknown_permission_is_still_refused_in_the_package_path():
    check(["sandbox.root"], ["module.install"], True, "publisher_permission_denied")
    check(["sandbox.root"], ["module.install", "sandbox.register"], False, "signature_required")


def test_hotfix_target_set_accepts_sandbox_register_and_refuses_unknown():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        extensions = base / "extensions"
        gate._require_root_owned_nonwritable = lambda *a, **k: None

        def target(permissions):
            folder = extensions / "sbprobe"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "tec_tac.json").write_text(json.dumps({"id": "sbprobe", "type": "extension", "publisher_permissions": permissions}))
            package = base / "hotfix.zip"
            with zipfile.ZipFile(package, "w") as zf:
                zf.writestr("tec_tac_hotfix.json", json.dumps({"type": "tec-tac-hotfix", "schema": 1, "module_id": "sbprobe"}))
            return gate._hotfix_target_permissions(package, {"TEC_TAC_EXTENSIONS_ROOT": str(extensions)})

        assert target(["sandbox.register"]) == {"module.install", "sandbox.register"}
        assert target(["server_maintenance.register", "sandbox.register"]) == {"module.install", "server_maintenance.register", "sandbox.register"}
        try:
            target(["sandbox.root"])
        except RuntimeError as exc:
            assert "unsupported publisher permission" in str(exc)
        else:
            raise AssertionError("an unknown permission was accepted")


def test_registry_allows_exactly_the_three_permissions():
    source = (ROOT / "framwork" / "tec_tac" / "registry.py").read_text(encoding="utf-8")
    assert 'allowed = {"module.install", "server_maintenance.register", SANDBOX_REGISTER_PERMISSION}' in source
    assert 'SANDBOX_REGISTER_PERMISSION = "sandbox.register"' in source


def test_install_sh_never_grants_sandbox_register():
    source = (ROOT / "install.sh").read_text(encoding="utf-8")
    for line in source.splitlines():
        if "sandbox.register" in line:
            assert line.lstrip().startswith("#"), "only a comment may name it: " + line


def test_job_helpers_verify_before_they_register_runners():
    for name, verify in (("module-v2-job-helper.py", "_verify_v2_job_trust"), ("module-job-helper.py", "_privileged_verify_package")):
        source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        body = source[source.index("def run_job("):]
        assert body.index(verify + "(") < body.index("sync_sandbox_runners("), name


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print("ok")
