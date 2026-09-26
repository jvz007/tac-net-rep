#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "trust-policy-migration.py"
INSTALL = ROOT / "install.sh"
spec = importlib.util.spec_from_file_location("trust_policy_migration", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(mod)


def write(path: Path, level: str, by: str = "admin") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema": 1,
        "minimum_level": level,
        "updated_at": "2026-09-01T00:00:00Z",
        "updated_by": by,
    }) + "\n", encoding="utf-8")


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


with tempfile.TemporaryDirectory() as td:
    base = Path(td)

    # Fresh production remains signed-production by default.
    current = base / "fresh/etc/update-trust-policy.json"
    legacy = base / "fresh/var/update-trust-policy.json"
    result = mod.migrate(current, legacy, "production")
    assert result["minimum_level"] == "signed_production"
    assert read(current)["minimum_level"] == "signed_production"

    # The tracker regression: a legacy secure-signed administrator policy must
    # survive relocation to the new root-owned policy path.
    current = base / "legacy-secure/etc/update-trust-policy.json"
    legacy = base / "legacy-secure/var/update-trust-policy.json"
    write(legacy, "secure_signed", "security-admin")
    result = mod.migrate(current, legacy, "production")
    assert result["minimum_level"] == "secure_signed"
    saved = read(current)
    assert saved["minimum_level"] == "secure_signed"
    assert str(saved["updated_by"]).startswith("installer-legacy-policy-migration")

    # A stronger legacy floor wins over an existing weaker current floor.
    current = base / "merge/etc/update-trust-policy.json"
    legacy = base / "merge/var/update-trust-policy.json"
    write(current, "signed_production", "current-admin")
    write(legacy, "secure_signed", "legacy-admin")
    assert mod.migrate(current, legacy, "production")["minimum_level"] == "secure_signed"

    # A weaker legacy value can never lower an existing stronger current one,
    # and administrator metadata remains untouched when current already wins.
    current = base / "no-lower/etc/update-trust-policy.json"
    legacy = base / "no-lower/var/update-trust-policy.json"
    write(current, "secure_signed", "current-security-admin")
    before = current.read_bytes()
    write(legacy, "signed_development", "old-admin")
    assert mod.migrate(current, legacy, "production")["minimum_level"] == "secure_signed"
    assert current.read_bytes() == before

    # The environment baseline is also monotonic: an old unsigned/development
    # policy cannot weaken a production upgrade.
    current = base / "baseline/etc/update-trust-policy.json"
    legacy = base / "baseline/var/update-trust-policy.json"
    write(current, "unsigned", "old-install")
    write(legacy, "signed_development", "old-admin")
    assert mod.migrate(current, legacy, "production")["minimum_level"] == "signed_production"

    # Policy files are read without following final-component symlinks.
    victim = base / "victim.json"
    write(victim, "secure_signed", "victim")
    current = base / "link/etc/update-trust-policy.json"
    legacy = base / "link/var/update-trust-policy.json"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.symlink_to(victim)
    try:
        mod.migrate(current, legacy, "production")
    except mod.PolicyMigrationError:
        pass
    else:
        raise AssertionError("legacy policy symlink was accepted")
    assert victim.exists()
    assert not current.exists()

install = INSTALL.read_text(encoding="utf-8")
assert 'LEGACY_POLICY_FILE="/var/lib/tec-tac/policy/update-trust-policy.json"' in install
assert '/usr/bin/python3 -I "${SOURCE_ROOT}/scripts/trust-policy-migration.py"' in install
assert '"${SOURCE_ROOT}/scripts/trust-policy-migration.py"' in install
assert "installer-security-migration" not in install  # old embedded migration removed

print("[TEST] PASS monotonic trust-policy upgrade migration")
