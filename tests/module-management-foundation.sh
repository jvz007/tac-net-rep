#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ "$(tr -d '\r\n' < "${ROOT}/VERSION")" == "1.6.1" ]] || fail "VERSION is not 1.6.1"
for f in \
  framwork/tec_tac/module_manager.py \
  framwork/tec_tac/module_manager_v2.py \
  framwork/tec_tac/module_state.py \
  framwork/tec_tac/module_v2_views.py \
  framwork/tec_tac/system_update.py \
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
