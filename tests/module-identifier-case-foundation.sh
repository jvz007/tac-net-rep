#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

PYTHONPATH="${ROOT}/framwork" python3 - <<'PY'
import json
import tempfile
from pathlib import Path

from tec_tac.registry import discover_plugins
import tec_tac.capabilities as cap
import tec_tac.module_state as state

MODULE = "securityWAF"
CAP = "securityWAF.waf"
PERMS = ["securityWAF.read", "securityWAF.manage"]

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    ext = root / "extensions"
    rep = root / "reportsets"
    (ext / MODULE).mkdir(parents=True)
    (rep / MODULE).mkdir(parents=True)
    (ext / MODULE / "tec_tac.json").write_text(json.dumps({
        "id": MODULE,
        "type": "extension",
        "version": "0.1.0",
        "python_paths": ["."],
        "django_apps": [],
        "permission_groups": {"WAF": PERMS},
    }), encoding="utf-8")
    (rep / MODULE / "tec_tac.json").write_text(json.dumps({
        "id": MODULE,
        "type": "reportset",
        "version": "0.1.0",
        "python_paths": ["."],
        "django_apps": [],
    }), encoding="utf-8")
    plugins = discover_plugins(ext, rep)
    assert [p.plugin_id for p in plugins] == [MODULE, MODULE]
    extension = plugins[0]
    assert extension.permission_group_map()["WAF"] == tuple(PERMS)

cap._clear_capabilities_for_tests()
provider = object()
cap.get_plugin = lambda module_id, plugin_type="extension": type("P", (), {
    "plugin_id": module_id, "plugin_type": plugin_type, "version": "0.1.0"
})()
cap.is_enabled = lambda module_id: module_id == MODULE
reg = cap.register_capability(id=CAP, module_id=MODULE, version="1.0.0", provider=provider)
assert reg.id == CAP
assert reg.module_id == MODULE
assert cap.get_capability(CAP) is provider
assert cap.capability_status(CAP)["module_id"] == MODULE

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    state.STATE_ROOT = root
    state.STATE_FILE = root / "module-state.json"
    state.set_enabled(MODULE, False)
    saved = state.load_state()
    assert MODULE in saved["modules"]
    assert "securitywaf" not in saved["modules"]
    assert state.is_enabled(MODULE, saved) is False

print("mixed-case module identity contract: PASS")
PY

# Repository/catalogue and licensing validators intentionally admit uppercase ASCII.
grep -Fq 're.fullmatch(r"[A-Za-z0-9_-]+", module_id)' "${ROOT}/framwork/tec_tac/module_repository.py" || fail "repository module-id validator changed"
grep -Fq 'allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")' "${ROOT}/framwork/tec_tac/capabilities.py" || fail "capability identifier validator no longer admits uppercase"
grep -Fq 'allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "licensing capability validator no longer admits uppercase"

# No legacy securityWAF predecessor alias is built into Core.
if grep -RIn --exclude='module-identifier-case-foundation.sh' --exclude='module-identifiers.md' \
  -E '(["'"''])security(["'"'']|\.|/)|security\.waf|/api/tfd/security/|/extensions/security|extensions/security/|reportsets/security/' \
  "${ROOT}/framwork" "${ROOT}/scripts" "${ROOT}/install.sh" >/dev/null; then
  fail "legacy security module identifier/reference found in Core"
fi

grep -Fq 'case-sensitive and case-preserving' "${ROOT}/docs/module-identifiers.md" || fail "module identity documentation missing"
grep -Fq 'securityWAF.waf' "${ROOT}/docs/module-identifiers.md" || fail "securityWAF canonical capability not documented"
grep -Fq '/api/tfd/securityWAF/' "${ROOT}/docs/module-identifiers.md" || fail "securityWAF API root not documented"

echo '[TEST] PASS module identifier case contract'
