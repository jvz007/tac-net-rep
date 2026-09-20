#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

VERSION="$(tr -d '\r\n' < "${ROOT}/VERSION")"
PACKAGE_VERSION="$(python3 - "${ROOT}/tec_tac_package.json" <<'PY_VERSION'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['version'])
PY_VERSION
)"
[[ "${PACKAGE_VERSION}" == "${VERSION}" ]] || fail "VERSION (${VERSION}) does not match tec_tac_package.json (${PACKAGE_VERSION})"
[[ -f "${ROOT}/framwork/tec_tac/capabilities.py" ]] || fail "capabilities.py missing"
[[ -f "${ROOT}/framwork/tec_tac/capability_views.py" ]] || fail "capability_views.py missing"
grep -q 'capabilities/' "${ROOT}/framwork/tec_tac/urls.py" || fail "capability routes missing"
grep -q 'tec_tac.capability_probe' "${ROOT}/framwork/tec_tac/tasks.py" || fail "Celery capability probe missing"
grep -q 'TEC_TAC_DEFER_WORKER_REFRESH' "${ROOT}/scripts/install-extension.sh" || fail "extension worker refresh/defer support missing"
grep -q 'systemctl restart celery' "${ROOT}/scripts/remove-extension.sh" || fail "removal worker refresh missing"
grep -q 'refresh_workers=True' "${ROOT}/scripts/module-v2-job-helper.py" || fail "v2 enable/install worker refresh missing"

PYTHONPATH="${ROOT}/framwork" python3 - <<'PY'
from types import SimpleNamespace
import tec_tac.capabilities as cap

provider = object()
cap._clear_capabilities_for_tests()
cap.get_plugin = lambda module_id, plugin_type="extension": SimpleNamespace(plugin_id=module_id, plugin_type=plugin_type, version="0.4.0")
cap.is_enabled = lambda module_id: True

reg = cap.register_capability(
    id="communicator.messaging",
    module_id="communicator",
    version="1.0.0",
    provider=provider,
    description="Messaging",
    operations=("send", "presence"),
    metadata={"reference": True},
)
assert reg.id == "communicator.messaging"
assert cap.get_capability("communicator.messaging") is provider
assert cap.get_capability("communicator.messaging", version=">=1.0.0,<2.0.0") is provider
assert cap.has_capability("communicator.messaging", version=">=1,<2") is True
status = cap.capability_status("communicator.messaging")
assert status["available"] is True and status["state"] == "available"
assert status["installed_version"] == "0.4.0"
assert status["capability_version"] == "1.0.0"
assert status["operations"] == ["send", "presence"]
assert cap.list_capabilities()[0]["id"] == "communicator.messaging"

try:
    cap.get_capability("communicator.messaging", version=">=2,<3")
except cap.CapabilityVersionMismatch as exc:
    assert exc.status["state"] == "version-incompatible"
else:
    raise AssertionError("version mismatch did not raise")
assert cap.get_capability("communicator.messaging", version=">=2,<3", required=False) is None

cap.is_enabled = lambda module_id: False
try:
    cap.get_capability("communicator.messaging")
except cap.CapabilityDisabled as exc:
    assert exc.status["state"] == "disabled"
else:
    raise AssertionError("disabled capability did not raise")

cap.is_enabled = lambda module_id: True
cap.get_plugin = lambda *args, **kwargs: (_ for _ in ()).throw(cap.RegistryError("missing"))
status = cap.capability_status("communicator.messaging")
assert status["state"] == "missing" and status["available"] is False

cap._clear_capabilities_for_tests()
cap.get_plugin = lambda module_id, plugin_type="extension": SimpleNamespace(plugin_id=module_id, plugin_type=plugin_type, version="2.3.0")
cap.is_enabled = lambda module_id: True
cap.register_capability(
    id="communicator.messaging",
    module_id="communicator",
    version="1.1.0",
    provider=provider,
    health=lambda: {"healthy": False, "reason": "provider offline", "queue": "down"},
)
status = cap.capability_status("communicator.messaging")
assert status["state"] == "unhealthy" and status["health"]["queue"] == "down"
try:
    cap.get_capability("communicator.messaging")
except cap.CapabilityUnhealthy:
    pass
else:
    raise AssertionError("unhealthy capability did not raise")

cap._clear_capabilities_for_tests()
status = cap.capability_status("communicator.messaging")
assert status["state"] == "capability-unavailable"

context = cap.build_operation_context(
    source_module="patching",
    source_action="patching.install-approved",
    source_run_id="run-123",
    requested_by="system",
    profile_id="prod",
)
assert context["source_module"] == "patching"
assert context["profile_id"] == "prod"

print("capability registry unit contract: PASS")
PY

python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/capabilities.py" \
  "${ROOT}/framwork/tec_tac/capability_views.py" \
  "${ROOT}/framwork/tec_tac/tasks.py"

bash -n "${ROOT}/scripts/install-extension.sh"
bash -n "${ROOT}/scripts/remove-extension.sh"
python3 -m py_compile "${ROOT}/scripts/module-v2-job-helper.py"

echo "[TEST] PASS capability foundation"
