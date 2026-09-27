#!/usr/bin/env python3
"""D1 + low-cleanup regression coverage."""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def require(condition, message):
    if not condition:
        raise AssertionError(message)

# Root helper policy write uses a root-owned atomic destination and defaults are
# represented explicitly in the payload.
helper_path = ROOT / "scripts" / "system-update-helper.py"
spec = importlib.util.spec_from_file_location("tec_tac_system_update_helper_test", helper_path)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
with tempfile.TemporaryDirectory() as td:
    target = Path(td) / "policy" / "account-security-policy.json"
    helper.ACCOUNT_SECURITY_POLICY = target
    payload = helper.set_root_account_security_policy("true", "root-admin")
    require(payload["protect_superuser_accounts"] is True, "policy did not enable")
    require(target.is_file() and not target.is_symlink(), "policy is not a regular file")
    require(stat.S_IMODE(target.stat().st_mode) == 0o644, "policy mode is not 0644")
    require(target.stat().st_uid == 0, "policy is not root-owned")
    saved = json.loads(target.read_text())
    require(saved["updated_by"] == "root-admin", "policy actor not retained")
    payload = helper.set_root_account_security_policy("false", "root-admin")
    require(payload["protect_superuser_accounts"] is False, "policy did not disable")

policy_source = (ROOT / "framwork" / "tec_tac" / "account_security_policy.py").read_text()
views_source = (ROOT / "framwork" / "tec_tac" / "account_security_views.py").read_text()
guard_source = (ROOT / "framwork" / "tec_tac" / "tactical_account_guard.py").read_text()
urls_source = (ROOT / "framwork" / "tec_tac" / "urls.py").read_text()
install_source = (ROOT / "install.sh").read_text()
uninstall_source = (ROOT / "uninstall.sh").read_text()

require('"protect_superuser_accounts": enabled' in policy_source, "default policy contract missing")
require('if not is_effective_superuser(request.user)' in views_source, "policy PUT is not superuser-only")
require('strict=True' in views_source, "policy change audit is not strict")
require('"superuser_account_protection"' in guard_source, "protected-account guard missing")
for token in ("reset_password", "reset_totp", "create_api_key", "update_api_key", "delete_api_key", "setup_totp"):
    require(token in guard_source, f"D1 guard coverage missing {token}")
require('access/security-policy/' in urls_source, "account security API route missing")
require('--set-account-security-policy *' in install_source, "privileged policy helper sudo rule missing")

# Low C18: config is parsed as data, not executed.
require('source "${TEC_TAC_CONFIG_FILE}"' not in uninstall_source, "uninstaller still sources config data")
require('scripts/tec-tac-config.sh' in uninstall_source, "uninstaller does not use safe config parser")

# Low privileged Python path cleanup.
for rel in [
    "install.sh",
    "scripts/recovery/tec-tac-diagnostics.sh",
    "scripts/recovery/tec-tac-repair-permissions.sh",
    "scripts/recovery/tec-tac-repair-modules.sh",
]:
    text = (ROOT / rel).read_text()
    # The cited privileged invocations must use an absolute isolated interpreter.
    require('/usr/bin/python3 -I' in text, f"{rel} does not use isolated /usr/bin/python3")

print("account-security-policy: PASS")
