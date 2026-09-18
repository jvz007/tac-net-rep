#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
[[ "$(tr -d '\r\n' < "${ROOT}/VERSION")" == "1.3.0" ]] || fail "VERSION is not 1.3.0"
for f in framwork/tec_tac/system_update.py scripts/system-update-helper.py tec_tac_package.json; do
  [[ -f "${ROOT}/${f}" ]] || fail "missing ${f}"
done
grep -q 'system/updates/online/stage/' "${ROOT}/framwork/tec_tac/urls.py" || fail "online stage route missing"
grep -q 'systemd-run' "${ROOT}/scripts/system-update-helper.py" || fail "transient worker missing"
grep -q 'flock' "${ROOT}/scripts/system-update-helper.py" || fail "global update lock missing"
grep -q 'backup_root' "${ROOT}/scripts/system-update-helper.py" || fail "backup lifecycle missing"
grep -q 'restore_backup' "${ROOT}/scripts/system-update-helper.py" || fail "rollback lifecycle missing"
grep -q 'FRAMEWORK_REPOSITORY' "${ROOT}/install.sh" || fail "framework repository config missing"
grep -q 'UI_REPOSITORY' "${ROOT}/install.sh" || fail "UI repository config missing"
python3 -m py_compile "${ROOT}/framwork/tec_tac/system_update.py" "${ROOT}/scripts/system-update-helper.py"
bash -n "${ROOT}/install.sh"
bash -n "${ROOT}/uninstall.sh"
echo "[TEST] PASS system update foundation"
