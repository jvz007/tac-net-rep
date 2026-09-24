#!/usr/bin/env python3
import io
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


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    os.environ["TEC_TAC_POLICY_ROOT"] = str(root / "policy")

    policy = trust_policy.get_policy()
    assert policy["minimum_level"] == "unsigned"
    assert policy["applies_to"] == ["system_updates", "modules"]

    unsigned = {"signed": False, "trusted": False, "state": "unsigned"}
    dev = {"signed": True, "trusted": True, "publisher_environment": "development", "assurance": "standard"}
    prod = {"signed": True, "trusted": True, "publisher_environment": "production", "assurance": "standard"}
    secure = {"signed": True, "trusted": True, "publisher_environment": "production", "assurance": "secure"}

    assert trust_policy.classify_trust(unsigned) == "unsigned"
    assert trust_policy.classify_trust(dev) == "signed_development"
    assert trust_policy.classify_trust(prod) == "signed_production"
    assert trust_policy.classify_trust(secure) == "secure_signed"

    trust_policy.set_policy("signed_development", updated_by="test")
    assert trust_policy.acceptance(unsigned)["accepted"] is False
    assert trust_policy.acceptance(dev)["accepted"] is True
    assert trust_policy.acceptance(prod)["accepted"] is True
    assert trust_policy.acceptance(secure)["accepted"] is True

    trust_policy.set_policy("signed_production", updated_by="test")
    assert trust_policy.acceptance(dev)["accepted"] is False
    assert trust_policy.acceptance(prod)["accepted"] is True
    assert trust_policy.acceptance(secure)["accepted"] is True

    trust_policy.set_policy("secure_signed", updated_by="test")
    assert trust_policy.acceptance(prod)["accepted"] is False
    assert trust_policy.acceptance(secure)["accepted"] is True

    # Module Manager v1/v2 share _verify_stage_trust. Prove the global floor
    # blocks a normal unsigned module even when no privileged permission itself
    # requires a signature.
    module_zip = Path(__file__).resolve().parents[1] / "docs/tutorial-packages/packagetest/packagetest-0.1.0.zip"
    meta = {"package_path": str(module_zip), "filename": module_zip.name}
    trust_policy.set_policy("signed_development", updated_by="test")
    try:
        _verify_stage_trust(meta, require_signed=False, required_permissions=("module.install",))
    except ModuleManagerError as exc:
        assert "Update trust policy rejected module package" in str(exc), exc
    else:
        raise AssertionError("unsigned module was not blocked by signed_development policy")

    # System Updates enforce the same floor during archive inspection.
    system_zip = root / "framework-1.15.36.zip"
    write_framework_zip(system_zip)
    try:
        inspect_archive(system_zip, source={"type": "offline"})
    except SystemUpdateError as exc:
        assert "Update trust policy rejected framework package" in str(exc), exc
    else:
        raise AssertionError("unsigned framework update was not blocked by signed_development policy")

    trust_policy.set_policy("unsigned", updated_by="test")
    preview = inspect_archive(system_zip, source={"type": "offline"})
    assert preview["release_trust"]["acceptance_policy"]["accepted"] is True
    assert preview["release_trust"]["acceptance_policy"]["actual_level"] == "unsigned"

print("[TEST] PASS shared update/module trust policy")
