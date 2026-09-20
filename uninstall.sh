#!/usr/bin/env bash
set -euo pipefail

APP_NAME="tfdreporting"
TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
LOCAL_SETTINGS="${BACKEND_DIR}/tacticalrmm/local_settings.py"

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEC_TAC_CONFIG_FILE="${TEC_TAC_CONFIG_FILE:-/opt/tec-tac/etc/tec-tac.conf}"
if [[ -f "${TEC_TAC_CONFIG_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${TEC_TAC_CONFIG_FILE}"
fi
REPO_ROOT="${TEC_TAC_ROOT:-/opt/tec-tac}"
FRAMEWORK_DIR="${TEC_TAC_FRAMEWORK_ROOT:-${REPO_ROOT}/framework}"
EXTENSIONS_DIR="${TEC_TAC_EXTENSIONS_ROOT:-${REPO_ROOT}/extensions}"
REPORTSETS_DIR="${TEC_TAC_REPORTSETS_ROOT:-${REPO_ROOT}/reportsets}"
LEGACY_REPORTING_DIR="${EXTENSIONS_DIR}/reporting"
APP_DIR="${LEGACY_REPORTING_DIR}/${APP_NAME}"

BEGIN_MARKER="# BEGIN TEC-TAC EXTENSION FRAMEWORK"
END_MARKER="# END TEC-TAC EXTENSION FRAMEWORK"
OLD_BEGIN_MARKER="# BEGIN TFD REPORTING EXTENSION"
OLD_END_MARKER="# END TFD REPORTING EXTENSION"
LEGACY_DEST_APP="${BACKEND_DIR}/${APP_NAME}"
EXCLUDE_FILE="${TACTICAL_ROOT}/.git/info/exclude"
PURGE_DATA=false

if [[ "${1:-}" == "--purge-data" ]]; then
    PURGE_DATA=true
fi

log() { printf '[TEC-TAC] %s\n' "$*"; }
fail() { printf '[TEC-TAC] ERROR: %s\n' "$*" >&2; exit 1; }

if [[ ${EUID} -ne 0 ]]; then
    fail "Run this uninstaller as root."
fi

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
if [[ -z "${TACTICAL_USER}" ]]; then
    TACTICAL_USER="$(awk -F= '$1 == "User" {print $2; exit}' /etc/systemd/system/rmm.service 2>/dev/null || true)"
fi
[[ -n "${TACTICAL_USER}" ]] || fail "Could not determine Tactical service user."
TACTICAL_GROUP="$(id -gn "${TACTICAL_USER}")"

run_as_tactical() {
    runuser -u "${TACTICAL_USER}" -- "$@"
}

log "Detected Tec-Tac runtime root: ${REPO_ROOT}"

if ${PURGE_DATA}; then
    [[ -f "${APP_DIR}/apps.py" || -d "${LEGACY_DEST_APP}" ]] || fail "${APP_NAME} code is missing; cannot safely run migration rollback."
    log "Purging ${APP_NAME} database objects via Django migrations."
    run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' migrate '${APP_NAME}' zero --noinput"
else
    log "Database data will be preserved. Use --purge-data to remove extension tables and data."
fi

if [[ -f "${LOCAL_SETTINGS}" ]]; then
    BACKUP_DIR="${TEC_TAC_BACKUP_DIR:-/var/lib/tec-tac/backups}"
    mkdir -p "${BACKUP_DIR}"
    BACKUP_FILE="${BACKUP_DIR}/local_settings.py.$(date +%Y%m%dT%H%M%S).uninstall.bak"
    cp -a "${LOCAL_SETTINGS}" "${BACKUP_FILE}"

    TMP_SETTINGS="$(mktemp)"
    trap 'rm -f "${TMP_SETTINGS}"' EXIT
    awk \
        -v begin1="${BEGIN_MARKER}" -v end1="${END_MARKER}" \
        -v begin2="${OLD_BEGIN_MARKER}" -v end2="${OLD_END_MARKER}" '
        $0 == begin1 {skip=1; next}
        $0 == end1 {skip=0; next}
        $0 == begin2 {skip=1; next}
        $0 == end2 {skip=0; next}
        !skip {print}
    ' "${LOCAL_SETTINGS}" > "${TMP_SETTINGS}"

    cat "${TMP_SETTINGS}" > "${LOCAL_SETTINGS}"
    chown "${TACTICAL_USER}:${TACTICAL_GROUP}" "${LOCAL_SETTINGS}"
    log "Removed Tec-Tac bootstrap block from local_settings.py."
fi

MODULE_HELPER="/usr/local/sbin/tec-tac-module-job"
MODULE_SUDOERS="/etc/sudoers.d/tec-tac-module-manager"
MODULE_CONFIG="${TEC_TAC_CONFIG_FILE}"
RMM_DROPIN="/etc/systemd/system/rmm.service.d/tec-tac.conf"
SYSTEM_UPDATE_HELPER="/usr/local/sbin/tec-tac-system-update"
SYSTEM_UPDATE_LIB="/usr/local/lib/tec-tac-updater"
SYSTEM_UPDATE_SUDOERS="/etc/sudoers.d/tec-tac-system-update"
SYSTEM_UPDATE_CONFIG="${TEC_TAC_CONFIG_FILE}"
SERVER_BACKUP_HELPER="/usr/local/sbin/tec-tac-server-backup"
SERVER_BACKUP_LIB="/usr/local/lib/tec-tac-backup"
SERVER_BACKUP_SUDOERS="/etc/sudoers.d/tec-tac-server-backup"
rm -f "${MODULE_SUDOERS}" "${MODULE_HELPER}" "${MODULE_CONFIG}" "${RMM_DROPIN}" "${SYSTEM_UPDATE_SUDOERS}" "${SYSTEM_UPDATE_HELPER}" "${SYSTEM_UPDATE_CONFIG}" "${SERVER_BACKUP_SUDOERS}" "${SERVER_BACKUP_HELPER}" /usr/local/sbin/tec-tac-repair /usr/local/sbin/tec-tac-diagnostics
rm -rf "${SYSTEM_UPDATE_LIB}" "${SERVER_BACKUP_LIB}"
systemctl daemon-reload
log "Removed Tec-Tac privileged lifecycle/update/backup helpers, sudoers rules, and rmm.service drop-in."

# Runtime code and installed modules are intentionally not deleted.
# Uninstall disconnects Tec-Tac from Tactical; source checkouts under /opt/tec-tac-src remain separate.
if [[ -d "${LEGACY_DEST_APP}" ]]; then
    rm -rf "${LEGACY_DEST_APP}"
    log "Removed legacy in-tree ${LEGACY_DEST_APP}."
fi

if [[ -f "${EXCLUDE_FILE}" ]]; then
    TMP_EXCLUDE="$(mktemp)"
    grep -Fxv "/api/tacticalrmm/${APP_NAME}/" "${EXCLUDE_FILE}" > "${TMP_EXCLUDE}" || true
    cat "${TMP_EXCLUDE}" > "${EXCLUDE_FILE}"
    rm -f "${TMP_EXCLUDE}"
    chown "${TACTICAL_USER}:${TACTICAL_GROUP}" "${EXCLUDE_FILE}"
fi

systemctl restart rmm daphne celery celerybeat

for svc in rmm daphne celery celerybeat; do
    if ! systemctl is-active --quiet "${svc}"; then
        systemctl --no-pager --full status "${svc}" || true
        fail "${svc} did not return to active state."
    fi
    log "${svc}: active"
done

log "Uninstall complete."
log "Bootstrap removed from Tactical local_settings.py."
if ${PURGE_DATA}; then
    log "Database migrations rolled back; extension tables and data were removed."
else
    log "Database tables and data were preserved."
fi
log "Runtime preserved: ${REPO_ROOT}"
log "Persistent backups: ${TEC_TAC_BACKUP_DIR:-/var/lib/tec-tac/backups}"
