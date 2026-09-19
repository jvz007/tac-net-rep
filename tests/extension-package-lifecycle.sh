#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE="${REPO_ROOT}/docs/tutorial-packages/packagetest/packagetest-0.1.0.zip"
USERNAME="${TEC_TAC_PACKAGE_TEST_USERNAME:-}"
[[ ${EUID} -eq 0 ]] || { echo '[TEST] FAIL run as root' >&2; exit 1; }
[[ -f "${PACKAGE}" ]] || { echo '[TEST] FAIL tutorial package missing' >&2; exit 1; }
[[ ! -e "${REPO_ROOT}/extensions/packagetest" ]] || { echo '[TEST] FAIL packagetest already installed' >&2; exit 1; }
cleanup(){ if [[ -e "${REPO_ROOT}/extensions/packagetest" || -e "${REPO_ROOT}/reportsets/packagetest" ]]; then bash "${REPO_ROOT}/scripts/remove-extension.sh" packagetest --yes || true; fi; }
trap cleanup EXIT
if [[ -n "${USERNAME}" ]]; then TEC_TAC_EXTENSION_USERNAME="${USERNAME}" TEC_TAC_EXTENSION_PERMISSION_GROUP="manage" bash "${REPO_ROOT}/scripts/install-extension.sh" "${PACKAGE}"; else bash "${REPO_ROOT}/scripts/install-extension.sh" "${PACKAGE}" </dev/null; fi
PYTHONPATH="${REPO_ROOT}/framwork:${REPO_ROOT}/extensions/packagetest:${REPO_ROOT}/reportsets/packagetest" /rmm/api/env/bin/python - <<'PY_TEST'
from tec_tac.registry import get_plugin
from tec_tac_packagetest.sample import sample_device
from tec_tac_packagetest_reportset.sample import map_device
ext=get_plugin('packagetest','extension'); rep=get_plugin('packagetest','reportset')
assert 'manage' in ext.permission_group_map()
print('package_pair=',ext.plugin_id,rep.plugin_id,map_device(sample_device()))
PY_TEST
bash "${REPO_ROOT}/scripts/remove-extension.sh" packagetest --yes
[[ ! -e "${REPO_ROOT}/extensions/packagetest" && ! -e "${REPO_ROOT}/reportsets/packagetest" ]] || { echo '[TEST] FAIL package remains' >&2; exit 1; }
trap - EXIT
echo '[TEST] PASS extension package lifecycle'
