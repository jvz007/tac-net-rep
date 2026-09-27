#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import inspect
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# L26: signed-in trust-policy writes use dedicated authenticated throttles.
views = (ROOT / "framwork/tec_tac/views.py").read_text(encoding="utf-8")
throttles = (ROOT / "framwork/tec_tac/throttles.py").read_text(encoding="utf-8")
start = views.index("class SystemUpdateTrustPolicyView")
end = views.index("\n\n@extend_schema_view", start)
view_block = views[start:end]
assert "TrustPolicyMinThrottle" in view_block and "TrustPolicyDayThrottle" in view_block
assert "LoginMinThrottle" not in view_block and "LoginDayThrottle" not in view_block
assert 'scope = "tec_tac_trust_policy_min"' in throttles
assert 'scope = "tec_tac_trust_policy_day"' in throttles

# L27: the install-time immediate check is non-fatal; the timer is durable.
install = (ROOT / "install.sh").read_text(encoding="utf-8")
assert 'if ! TRUST_POLICY_CHECK_OUTPUT="$(${TRUST_POLICY_CLI} check-revert 2>&1)"; then' in install
assert "the persistent timer will retry" in install

# M9/L28: all mutation/recovery entry points serialize on policy_lock.
spec = importlib.util.spec_from_file_location("trust_policy_cli_115133", ROOT / "scripts/trust-policy-cli.py")
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(mod)
assert "with policy_lock()" in inspect.getsource(mod.set_level)
assert "with policy_lock()" in inspect.getsource(mod.check_revert_due)
assert "with policy_lock()" in inspect.getsource(mod.revert_due)

with tempfile.TemporaryDirectory(prefix="trust-policy-115133-") as raw:
    td = Path(raw)
    mod.CONFIG_FILE = td / "tec-tac.conf"
    mod.POLICY_ROOT = td / "policy"
    mod.POLICY_FILE = mod.POLICY_ROOT / "update-trust-policy.json"
    mod.PENDING_FILE = mod.POLICY_ROOT / "pending-trust-policy-revert.json"
    mod.AUDIT_DIR = td / "audit"
    mod.AUDIT_FILE = mod.AUDIT_DIR / "trust-policy-audit.jsonl"
    mod.CONFIG_FILE.write_text("TEC_TAC_ENVIRONMENT=production\n", encoding="utf-8")
    mod.POLICY_ROOT.mkdir(parents=True)
    mod.POLICY_FILE.write_text(json.dumps({"schema": 1, "minimum_level": "unsigned"}) + "\n")
    mod.PENDING_FILE.write_text("{broken", encoding="utf-8")
    mod.os.chown = lambda *args, **kwargs: None
    mod.os.fchown = lambda *args, **kwargs: None
    result = mod.check_revert_due()
    assert result["status"] == "corrupt_pending_recovered"
    assert result["minimum_level"] == "secure_signed"
    assert not mod.PENDING_FILE.exists()
    assert (mod.POLICY_ROOT / ".trust-policy.lock").is_file()

# L30: keep both help surfaces for old and new clients.
spec = importlib.util.spec_from_file_location("trust_policy_115133", ROOT / "framwork/tec_tac/trust_policy.py")
# Importing this module does not require Django.
tp = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(tp)
with tempfile.TemporaryDirectory(prefix="trust-help-115133-") as raw:
    td = Path(raw)
    tp.CONFIG_FILE = td / "tec-tac.conf"
    tp.DEFAULT_POLICY_ROOT = td / "policy"
    tp.CONFIG_FILE.write_text("TEC_TAC_HELP_TRUST_POLICY_URL=/custom/trust-help\n", encoding="utf-8")
    guidance = tp.console_guidance("signed_development")
    assert guidance["help_article"] == "core.trust-policy"
    assert guidance["help_url"] == "/custom/trust-help"
    policy = tp.get_policy()
    assert policy["help_article"] == "core.trust-policy"
    assert policy["help_url"] == "/custom/trust-help"

print("trust-policy batch 1.15.133: PASS")
