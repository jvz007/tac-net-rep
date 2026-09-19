#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
LOCAL_SETTINGS="${BACKEND_DIR}/tacticalrmm/local_settings.py"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
TEC_TAC_CONFIG_FILE="${TEC_TAC_CONFIG_FILE:-/opt/tec-tac/etc/tec-tac.conf}"
[[ -f "${TEC_TAC_CONFIG_FILE}" ]] && source "${TEC_TAC_CONFIG_FILE}"
REPO_ROOT="${TEC_TAC_ROOT:-/opt/tec-tac}"
STATE_DIR="${TEC_TAC_STATE_DIR:-/var/lib/tec-tac/tests}"
STATE_FILE="${STATE_DIR}/tactical-update-survival.state"
MODE="${1:-check}"

[[ ${EUID} -eq 0 ]] || { echo '[TEST] FAIL run as root' >&2; exit 1; }
TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || { echo '[TEST] FAIL could not determine Tactical service user' >&2; exit 1; }

verify_now() {
    runuser -u "${TACTICAL_USER}" -- git -C "${TACTICAL_ROOT}" check-ignore -q "api/tacticalrmm/tacticalrmm/local_settings.py" || { echo '[TEST] FAIL local_settings.py is not ignored' >&2; exit 1; }
    grep -Fq '# BEGIN TEC-TAC EXTENSION FRAMEWORK' "${LOCAL_SETTINGS}" || { echo '[TEST] FAIL bootstrap marker missing' >&2; exit 1; }
    CODE="import tfdreporting; assert tfdreporting.__file__.startswith('${REPO_ROOT}/extensions/reporting/'); print(tfdreporting.__file__)"
    runuser -u "${TACTICAL_USER}" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${CODE}\""
    if [[ -f "${TEC_TAC_CONFIG_FILE}" ]]; then
        grep -Fq 'TEC_TAC_UI_DEPLOY_ROOT=/var/lib/tec-tac/ui/tec-tac' "${TEC_TAC_CONFIG_FILE}" || { echo '[TEST] FAIL persistent UI root is not configured' >&2; exit 1; }
    fi
}

case "${MODE}" in
    before)
        mkdir -p "${STATE_DIR}"
        verify_now
        printf 'repo=%s\nbootstrap_sha=%s\n' "${REPO_ROOT}" "$(sha256sum "${LOCAL_SETTINGS}" | awk '{print $1}')" > "${STATE_FILE}"
        echo '[TEST] Baseline captured. Run the normal Tactical RMM updater, then run this script with after.'
        ;;
    after)
        [[ -f "${STATE_FILE}" ]] || { echo '[TEST] FAIL no baseline; run with before first' >&2; exit 1; }
        verify_now
        echo '[TEST] PASS Tec-Tac survived Tactical update verification.'
        ;;
    check)
        verify_now
        echo '[TEST] PASS current upgrade-safety checks.'
        ;;
    *)
        echo 'Usage: sudo bash tests/tactical-update-survival.sh [check|before|after]' >&2
        exit 2
        ;;
esac
