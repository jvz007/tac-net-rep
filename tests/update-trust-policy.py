#!/usr/bin/env python3
import json
import os
import tempfile
import zipfile
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tacticalrmm.settings")

from tec_tac import trust_policy
from tec_tac.module_manager import ModuleManagerError, _verify_stage_trust
from tec_tac.system_update import SystemUpdateError, inspect_archive


def write_framework_zip(path: Path, version: str = "1.15.36") -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        root = f"tac-net-rep-{version}"
        zf.writestr(f"{root}/VERSION", version + "\n")
        zf.writestr(f"{root}/install.sh", "#!/usr/bin/env bash\nexit 0\n")
        zf.writestr(f"{root}/framwork/tec_tac/__init__.py", "")
        zf.writestr(f"{root}/tec_tac_package.json", '{"type":"tec-tac-framework","version":"%s"}' % version)


def write_policy(root: Path, level: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / trust_policy.POLICY_FILENAME).write_text(json.dumps({
        "schema": 1,
        "minimum_level": level,
        "updated_at": None,
        "updated_by": "test-root",
    }), encoding="utf-8")


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    policy_root = root / "policy"
    config = root / "tec-tac.conf"
    config.write_text("TEC_TAC_ENVIRONMENT=production\n", encoding="utf-8")
    trust_policy.DEFAULT_POLICY_ROOT = policy_root
    trust_policy.CONFIG_FILE = config

    # Fresh production installs are signed-by-default and the policy is read
    # from the root-owned policy location (the test substitutes a temp root).
    policy = trust_policy.get_policy()
    assert policy["minimum_level"] == "signed_production"
    assert policy["root_owned"] is True
    assert policy["applies_to"] == ["system_updates", "modules"]

    guidance = trust_policy.console_guidance("signed_development")
    assert guidance["status"] == "console_required"
    assert guidance["requested_level"] == "signed_development"
    assert "sudo tec-tac-trust-policy set signed_development" in guidance["command"]
    assert guidance["command"].endswith('--hours 8')
    assert guidance["help_article"] == "core.trust-policy"
    assert trust_policy.get_policy()["ui_lowering_allowed"] is False

    unsigned = {"signed": False, "trusted": False, "state": "unsigned"}
    dev = {"signed": True, "trusted": True, "publisher_environment": "development", "assurance": "standard"}
    prod = {"signed": True, "trusted": True, "publisher_environment": "production", "assurance": "standard"}
    secure = {"signed": True, "trusted": True, "publisher_environment": "production", "assurance": "secure"}

    assert trust_policy.classify_trust(unsigned) == "unsigned"
    assert trust_policy.classify_trust(dev) == "signed_development"
    assert trust_policy.classify_trust(prod) == "signed_production"
    assert trust_policy.classify_trust(secure) == "secure_signed"

    write_policy(policy_root, "signed_development")
    assert trust_policy.acceptance(unsigned)["accepted"] is False
    assert trust_policy.acceptance(dev)["accepted"] is True
    assert trust_policy.acceptance(prod)["accepted"] is True

    write_policy(policy_root, "signed_production")
    assert trust_policy.acceptance(dev)["accepted"] is False
    assert trust_policy.acceptance(prod)["accepted"] is True
    assert trust_policy.acceptance(secure)["accepted"] is True

    write_policy(policy_root, "secure_signed")
    assert trust_policy.acceptance(prod)["accepted"] is False
    assert trust_policy.acceptance(secure)["accepted"] is True

    # The shared web-tier floor blocks unsigned content before root dispatch as
    # defence in depth. Root helpers independently repeat signature/policy checks.
    module_zip = Path(__file__).resolve().parents[1] / "docs/tutorial-packages/packagetest/packagetest-0.1.0.zip"
    meta = {"package_path": str(module_zip), "filename": module_zip.name}
    write_policy(policy_root, "signed_development")
    try:
        _verify_stage_trust(meta, require_signed=False, required_permissions=("module.install",))
    except ModuleManagerError as exc:
        assert "Update trust policy rejected module package" in str(exc), exc
    else:
        raise AssertionError("unsigned module was not blocked by signed policy")

    system_zip = root / "framework-1.15.36.zip"
    write_framework_zip(system_zip)
    try:
        inspect_archive(system_zip, source={"type": "offline"})
    except SystemUpdateError as exc:
        assert "Update trust policy rejected framework package" in str(exc), exc
    else:
        raise AssertionError("unsigned framework update was not blocked by signed policy")

    # Development defaults to Signed Development, not Unsigned.
    config.write_text("TEC_TAC_ENVIRONMENT=development\n", encoding="utf-8")
    (policy_root / trust_policy.POLICY_FILENAME).unlink(missing_ok=True)
    assert trust_policy.get_policy()["minimum_level"] == "signed_development"

print("[TEST] PASS root-owned shared update/module trust policy")

# Built-in Help article contract: Core must not emit a server-supplied URL.
assert "help_url" not in trust_policy.console_guidance("signed_development")
