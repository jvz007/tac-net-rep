#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ "$(tr -d '\r\n' < "${ROOT}/VERSION")" == "1.2.3" ]] || fail "VERSION is not 1.2.3"
for f in \
  framwork/tec_tac/module_manager.py \
  scripts/module-job-helper.py \
  framwork/tec_tac/views.py \
  framwork/tec_tac/urls.py; do
  [[ -f "${ROOT}/${f}" ]] || fail "missing ${f}"
done

grep -q 'modules/packages/inspect/' "${ROOT}/framwork/tec_tac/urls.py" || fail "package inspect route missing"
grep -q 'modules/packages/<uuid:upload_id>/' "${ROOT}/framwork/tec_tac/urls.py" || fail "staged package route missing"
grep -q 'modules/packages/<uuid:upload_id>/install/' "${ROOT}/framwork/tec_tac/urls.py" || fail "package install route missing"
grep -q 'modules/<str:plugin_id>/remove/' "${ROOT}/framwork/tec_tac/urls.py" || fail "module removal route missing"
grep -q 'modules/jobs/<uuid:job_id>/' "${ROOT}/framwork/tec_tac/urls.py" || fail "module job route missing"
grep -q '"manage_modules": allowed("can_do_server_maint")' "${ROOT}/framwork/tec_tac/views.py" || fail "module capability mapping missing"
grep -q 'UI_ROOT=${TEC_TAC_UI_ROOT}' "${ROOT}/install.sh" || fail "persistent UI root config missing"
grep -q 'TEC_TAC_UI_ROOT' "${ROOT}/scripts/module-job-helper.py" || fail "module sync UI root environment missing"
grep -q '/usr/local/sbin/tec-tac-module-job' "${ROOT}/install.sh" || fail "privileged helper installer missing"
grep -q '/etc/sudoers.d/tec-tac-module-manager' "${ROOT}/install.sh" || fail "sudoers installer missing"
grep -q 'PROTECTED_PLUGIN_IDS' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "protected module policy missing"
grep -q 'MAX_PACKAGE_BYTES' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "package size guard missing"
grep -q 'MAX_EXTRACTED_BYTES' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "archive expansion guard missing"
grep -q 'refusing to execute non-root-owned or writable lifecycle script' "${ROOT}/scripts/module-job-helper.py" || fail "root helper ownership guard missing"
grep -q 'tags=\["Tec-Tac Framework"\]' "${ROOT}/framwork/tec_tac/views.py" || fail "framework Swagger tag missing"
grep -q 'Module package inspection failed.' "${ROOT}/framwork/tec_tac/views.py" || fail "structured upload diagnostics missing"
grep -q 'error_type' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "structured job error type missing"
grep -q 'Fresh-process verification OK' "${ROOT}/scripts/install-extension.sh" || fail "fresh-process lifecycle verification missing"
grep -q 'UI verification OK' "${ROOT}/scripts/module-job-helper.py" || fail "UI deployment verification missing"

python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/module_manager.py" \
  "${ROOT}/framwork/tec_tac/views.py" \
  "${ROOT}/scripts/module-job-helper.py"

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
echo "[TEST] PASS module management foundation"
