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
for f in \
  framwork/tec_tac/module_manager.py \
  framwork/tec_tac/module_manager_v2.py \
  framwork/tec_tac/module_state.py \
  framwork/tec_tac/module_v2_views.py \
  framwork/tec_tac/module_repository.py \
  framwork/tec_tac/module_repository_views.py \
  framwork/tec_tac/system_update.py \
  framwork/tec_tac/capabilities.py \
  framwork/tec_tac/capability_views.py \
  scripts/module-job-helper.py \
  scripts/module-v2-job-helper.py \
  scripts/system-update-helper.py \
  scripts/reload-rmm-uwsgi.sh \
  framwork/tec_tac/views.py \
  framwork/tec_tac/urls.py; do
  [[ -f "${ROOT}/${f}" ]] || fail "missing ${f}"
done


grep -q 'system/updates/' "${ROOT}/framwork/tec_tac/urls.py" || fail "system update routes missing"
grep -q '/usr/local/sbin/tec-tac-system-update' "${ROOT}/install.sh" || fail "system update helper installer missing"
grep -q 'systemd-run' "${ROOT}/scripts/system-update-helper.py" || fail "independent system update worker missing"
grep -q 'update.lock' "${ROOT}/scripts/system-update-helper.py" || fail "global system update lock missing"
grep -q 'restoring previous component backup' "${ROOT}/scripts/system-update-helper.py" || fail "automatic rollback missing"
grep -q 'modules/packages/inspect/' "${ROOT}/framwork/tec_tac/urls.py" || fail "package inspect route missing"
grep -q 'modules/packages/<uuid:upload_id>/' "${ROOT}/framwork/tec_tac/urls.py" || fail "staged package route missing"
grep -q 'modules/packages/<uuid:upload_id>/install/' "${ROOT}/framwork/tec_tac/urls.py" || fail "package install route missing"
grep -q 'modules/<str:plugin_id>/remove/' "${ROOT}/framwork/tec_tac/urls.py" || fail "module removal route missing"
grep -q 'modules/jobs/<uuid:job_id>/' "${ROOT}/framwork/tec_tac/urls.py" || fail "module job route missing"
grep -q '"manage_modules": allowed("can_do_server_maint")' "${ROOT}/framwork/tec_tac/views.py" || fail "module capability mapping missing"
grep -q 'UI_ROOT=${TEC_TAC_UI_ROOT}' "${ROOT}/install.sh" || fail "persistent UI root config missing"
grep -q 'TEC_TAC_UI_ROOT' "${ROOT}/scripts/module-job-helper.py" || fail "module sync UI root environment missing"
grep -q '/usr/local/sbin/tec-tac-module-job' "${ROOT}/install.sh" || fail "privileged helper installer missing"
grep -q '/usr/local/sbin/tec-tac-module-v2-job' "${ROOT}/install.sh" || fail "v2 privileged helper installer missing"
grep -q 'chmod 0644 "${MODULE_STATE_FILE}"' "${ROOT}/install.sh" || fail "module state runtime read mode missing"
grep -q 'atomic_json(MODULE_STATE, state, 0o644)' "${ROOT}/scripts/module-v2-job-helper.py" || fail "v2 helper state mode is not 0644"
grep -q '/etc/sudoers.d/tec-tac-module-manager' "${ROOT}/install.sh" || fail "sudoers installer missing"
grep -q 'PROTECTED_PLUGIN_IDS' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "protected module policy missing"
grep -q 'MAX_PACKAGE_BYTES' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "package size guard missing"
grep -q 'MAX_EXTRACTED_BYTES' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "archive expansion guard missing"
grep -q 'refusing to execute non-root-owned or writable lifecycle script' "${ROOT}/scripts/module-job-helper.py" || fail "root helper ownership guard missing"
grep -q 'tags=\["Tec-Tac Framework"\]' "${ROOT}/framwork/tec_tac/views.py" || fail "framework Swagger tag missing"
grep -q 'auth/totp/qr/' "${ROOT}/framwork/tec_tac/urls.py" || fail "TOTP QR route missing"
grep -q 'SvgPathImage' "${ROOT}/framwork/tec_tac/views.py" || fail "local SVG QR generation missing"
grep -q 'Module package inspection failed.' "${ROOT}/framwork/tec_tac/views.py" || fail "structured upload diagnostics missing"
grep -q 'error_type' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "structured job error type missing"
grep -q 'Fresh-process verification OK' "${ROOT}/scripts/install-extension.sh" || fail "fresh-process lifecycle verification missing"
grep -q 'UI verification OK' "${ROOT}/scripts/module-job-helper.py" || fail "UI deployment verification missing"
grep -q 'SupplementaryGroups=${TACTICAL_GROUP}' "${ROOT}/install.sh" || fail "rmm supplementary-group drop-in missing"
grep -q 'kill -HUP' "${ROOT}/scripts/reload-rmm-uwsgi.sh" || fail "uWSGI graceful reload signal missing"
! grep -q 'systemctl restart rmm daphne celery celerybeat' "${ROOT}/scripts/install-extension.sh" || fail "extension install still performs full Tactical restart"
! grep -q 'systemctl restart rmm daphne celery celerybeat' "${ROOT}/scripts/remove-extension.sh" || fail "extension removal still performs full Tactical restart"

python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/module_manager.py" \
  "${ROOT}/framwork/tec_tac/module_manager_v2.py" \
  "${ROOT}/framwork/tec_tac/module_state.py" \
  "${ROOT}/framwork/tec_tac/module_v2_views.py" \
  "${ROOT}/framwork/tec_tac/module_repository.py" \
  "${ROOT}/framwork/tec_tac/module_repository_views.py" \
  "${ROOT}/framwork/tec_tac/system_update.py" \
  "${ROOT}/framwork/tec_tac/views.py" \
  "${ROOT}/scripts/module-job-helper.py" \
  "${ROOT}/scripts/system-update-helper.py"

PYTHONPATH="${ROOT}/framwork" python3 - "${ROOT}" <<'PY'
import sys
from pathlib import Path
from tec_tac.module_manager import inspect_archive
root=Path(sys.argv[1])
package=root/'docs/tutorial-packages/packagetest/packagetest-0.1.0.zip'
result=inspect_archive(package)
assert result['id']=='packagetest'
assert result['versions_match'] is True
assert result['installable'] is True
assert result['permission_count']==2
ui_package=root/'docs/tutorial-packages/uitest/uitest-0.1.1.zip'
ui_result=inspect_archive(ui_package)
assert ui_result['id']=='uitest'
assert ui_result['ui_enabled'] is True
assert ui_result['ui']['entry']=='ui/index.js'
assert ui_result['ui']['permissions']==['uitest.read']
assert ui_result['authenticated_ui_enabled'] is True
assert ui_result['public_ui_enabled'] is True
assert ui_result['ui']['public']['entry']=='ui/public.js'
assert ui_result['ui']['public']['base_path']=='/public/uitest'
print('[TEST] package inspection OK')
PY

bash -n "${ROOT}/install.sh"
bash -n "${ROOT}/uninstall.sh"
bash -n "${ROOT}/scripts/install-extension.sh"
bash -n "${ROOT}/scripts/remove-extension.sh"
bash -n "${ROOT}/scripts/reload-rmm-uwsgi.sh"
echo "[TEST] PASS module management foundation"

grep -q '_plan_with_requested_order' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "dependency-safe requested install ordering missing"
grep -q 'discard_v2_stage' "${ROOT}/framwork/tec_tac/module_v2_views.py" || fail "v2 staged artifact discard route missing"

grep -q 'def is_visible' "${ROOT}/framwork/tec_tac/module_state.py" || fail "module visibility state helper missing"
grep -q 'queue_set_visibility' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "module visibility queue missing"
grep -q 'modules/v2/<str:plugin_id>/visibility/' "${ROOT}/framwork/tec_tac/urls.py" || fail "module visibility route missing"
grep -q '"visibility"' "${ROOT}/scripts/module-v2-job-helper.py" || fail "visibility worker action missing"

# 1.7.0 repository/catalog foundation
grep -q 'modules/repositories/' "${ROOT}/framwork/tec_tac/urls.py" || fail "module repository routes missing"
grep -q 'modules/catalog/online/' "${ROOT}/framwork/tec_tac/urls.py" || fail "online module catalog route missing"
grep -q 'stage_repository_package' "${ROOT}/framwork/tec_tac/module_repository.py" || fail "online package staging missing"
grep -q 'package_sha256' "${ROOT}/framwork/tec_tac/module_repository.py" || fail "online package provenance hash missing"
grep -q 'repositories/cache' "${ROOT}/scripts/recovery/lib.sh" || fail "repository cache runtime directory missing"
grep -q 'source_provenance' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "online source provenance handoff missing"


# 1.9.0 capability registry foundation
grep -q 'def register_capability' "${ROOT}/framwork/tec_tac/capabilities.py" || fail "capability registration missing"
grep -q 'def get_capability' "${ROOT}/framwork/tec_tac/capabilities.py" || fail "capability lookup missing"
grep -q 'def capability_status' "${ROOT}/framwork/tec_tac/capabilities.py" || fail "capability status missing"
grep -q 'capabilities/' "${ROOT}/framwork/tec_tac/urls.py" || fail "capability API routes missing"
grep -q 'tec_tac.capability_probe' "${ROOT}/framwork/tec_tac/tasks.py" || fail "capability Celery probe missing"
grep -q 'systemctl restart celery' "${ROOT}/scripts/install-extension.sh" || fail "install lifecycle worker refresh missing"
grep -q 'systemctl restart celery' "${ROOT}/scripts/remove-extension.sh" || fail "remove lifecycle worker refresh missing"

# Current registry schema must accept v2 dependency/runtime metadata even in a
# fresh process that imports tec_tac.registry directly (the install-extension
# lifecycle path does exactly this).
PYTHONPATH="${ROOT}/framwork" python3 - <<'PY_REGISTRY_V2'
import json
import tempfile
from pathlib import Path
from tec_tac.registry import discover_plugins

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    for kind, ptype in (("extensions", "extension"), ("reportsets", "reportset")):
        plugin = root / kind / "schema-test"
        plugin.mkdir(parents=True)
        manifest = {
            "id": "schema-test",
            "type": ptype,
            "version": "1.0.0",
            "python_paths": ["."],
            "django_apps": [],
        }
        if ptype == "extension":
            manifest.update({
                "dependencies": {},
                "optional_dependencies": {},
                "requires": {"framework": ">=1.7.0,<2.0.0", "ui": ">=0.7.0,<1.0.0"},
                "licensing": {
                    "required": True,
                    "product": "schema-test",
                    "capability": "licensing.entitlements",
                    "capability_version": ">=1.0.0,<2.0.0",
                },
            })
        (plugin / "tec_tac.json").write_text(json.dumps(manifest), encoding="utf-8")
    plugins = discover_plugins(root / "extensions", root / "reportsets")
    assert len(plugins) == 2
print("[TEST] v2 registry schema accepted in fresh process")
PY_REGISTRY_V2


# 1.8.0 scheduler foundation
grep -q 'class TecTacSchedule' "${ROOT}/framwork/tec_tac/models.py" || fail "scheduler model missing"
grep -q 'register_scheduled_action' "${ROOT}/framwork/tec_tac/scheduler.py" || fail "scheduled action registry missing"
grep -q 'tec_tac.execute_schedule_run' "${ROOT}/framwork/tec_tac/tasks.py" || fail "scheduler Celery task missing"
grep -q 'scheduler/schedules/' "${ROOT}/framwork/tec_tac/urls.py" || fail "scheduler routes missing"
grep -q 'tec-tac-scheduler.timer' "${ROOT}/install.sh" || fail "scheduler timer installation missing"

grep -q 'f"{filename}: {exc}"' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "filename-scoped multi-package errors missing"

# 1.13.6 artifact classification must be structural, not filename-based.
! grep -q '"bundle" not in name.lower()' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "module artifact classification still depends on filename"
grep -q 'Classification is structural, never filename-based' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "structural package/bundle classification guard missing"
echo "[TEST] PASS structural module artifact classification"

# 1.14.1 manifest-declared licensing enforcement
[[ -f "${ROOT}/docs/module-licensing.md" ]] || fail "module licensing contract missing"
grep -q '"licensing"' "${ROOT}/framwork/tec_tac/registry.py" || fail "registry does not accept licensing manifest metadata"
grep -q 'class LicensingRequirementError' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "structured licensing error missing"
grep -q 'check_licensing_requirement' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "licensing entitlement check missing"
grep -q '_enforce_candidate_licensing(preview)' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "inspection licensing enforcement missing"
grep -q '_enforce_candidate_licensing(candidate)' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "batch install licensing re-check missing"
grep -q 'fresh_preview = _inspect_bundle' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "bundle install does not re-inspect/re-check licensing"
grep -q 'licensing_requirement_failed' "${ROOT}/framwork/tec_tac/module_manager_v2.py" || fail "structured licensing failure code missing"
grep -q 'except LicensingRequirementError' "${ROOT}/framwork/tec_tac/module_v2_views.py" || fail "licensing HTTP failure mapping missing"

PYTHONPATH="${ROOT}/framwork" python3 - <<'PY_LICENSING'
from types import SimpleNamespace
import tec_tac.module_manager_v2 as mm

manifest = {
    "licensing": {
        "required": True,
        "product": "reportmanager",
        "capability": "licensing.entitlements",
        "capability_version": ">=1.0.0,<2.0.0",
    }
}
meta = mm._licensing_metadata(manifest)
assert meta["required"] is True
assert meta["product"] == "reportmanager"
assert meta["capability"] == "licensing.entitlements"

candidate = {
    "id": "reportmanager",
    "extension_version": "1.2.3",
    "licensing": meta,
}

class Provider:
    def __init__(self, result): self.result = result
    def check_entitlement(self, **kwargs):
        assert kwargs == {
            "product": "reportmanager",
            "module_id": "reportmanager",
            "module_version": "1.2.3",
        }
        return self.result

available = {
    "id": "licensing.entitlements",
    "module_id": "licensing",
    "available": True,
    "state": "available",
    "capability_version": "1.0.4",
}
mm.capability_status = lambda *args, **kwargs: dict(available)
mm.get_capability = lambda *args, **kwargs: Provider({"licensed": True, "edition": "pro"})
result = mm.check_licensing_requirement(dict(candidate))
assert result["licensed"] is True and result["state"] == "licensed"
assert result["details"]["edition"] == "pro"

mm.get_capability = lambda *args, **kwargs: Provider({"licensed": False, "reason": "subscription expired"})
try:
    mm.check_licensing_requirement(dict(candidate))
except mm.LicensingRequirementError as exc:
    payload = exc.as_payload()
    assert payload["code"] == "licensing_requirement_failed"
    assert payload["licensing"]["state"] == "unlicensed"
    assert payload["licensing"]["reason"] == "subscription expired"
else:
    raise AssertionError("unlicensed product did not fail closed")

for state in ("missing", "disabled", "unhealthy", "version-incompatible", "capability-unavailable"):
    mm.capability_status = lambda *args, _state=state, **kwargs: {
        "id": "licensing.entitlements",
        "module_id": "licensing",
        "available": False,
        "state": _state,
        "capability_version": None,
        "reason": f"{_state} test",
    }
    try:
        mm.check_licensing_requirement(dict(candidate))
    except mm.LicensingRequirementError as exc:
        assert exc.result["state"] == state
        assert exc.result["licensed"] is False
    else:
        raise AssertionError(f"{state} licensing provider state did not fail closed")

mm.capability_status = lambda *args, **kwargs: dict(available)
mm.get_capability = lambda *args, **kwargs: object()
try:
    mm.check_licensing_requirement(dict(candidate))
except mm.LicensingRequirementError as exc:
    assert exc.result["state"] == "provider-contract-invalid"
else:
    raise AssertionError("invalid provider contract did not fail closed")

not_required = mm.check_licensing_requirement({"id": "free", "version": "1.0.0", "licensing": {"required": False}})
assert not_required["licensed"] is True and not_required["state"] == "not-required"

print("[TEST] licensing entitlement contract OK")
PY_LICENSING


# Licensing must not be bypassable through compatibility or online staging paths.
grep -q 'stage = "licensing-check"' "${ROOT}/framwork/tec_tac/views.py" || fail "legacy v1 inspect endpoint bypasses licensing"
grep -A18 'class ModulePackageInstallView' "${ROOT}/framwork/tec_tac/views.py" | grep -q '_enforce_candidate_licensing' || fail "legacy v1 install endpoint bypasses licensing"
grep -q 'except LicensingRequirementError' "${ROOT}/framwork/tec_tac/module_repository_views.py" || fail "online repository stage does not preserve structured licensing failure"
grep -q 'except (ModuleRepositoryError, LicensingRequirementError)' "${ROOT}/framwork/tec_tac/module_repository.py" || fail "online repository staging wraps licensing failures"

echo "[TEST] PASS manifest licensing enforcement"
