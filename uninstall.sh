#!/usr/bin/env bash
set -euo pipefail

APP_NAME="tfdreporting"
TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
LOCAL_SETTINGS="${BACKEND_DIR}/tacticalrmm/local_settings.py"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRAMEWORK_DIR="${REPO_ROOT}/framwork"
REPORTING_DIR="${REPO_ROOT}/extensions/reporting"
APP_DIR="${REPORTING_DIR}/${APP_NAME}"

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

log "Detected Tec-Tac repository root: ${REPO_ROOT}"

if ${PURGE_DATA}; then
    [[ -f "${APP_DIR}/apps.py" || -d "${LEGACY_DEST_APP}" ]] || fail "${APP_NAME} code is missing; cannot safely run migration rollback."
    log "Purging ${APP_NAME} database objects via Django migrations."
    run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' migrate '${APP_NAME}' zero --noinput"
else
    log "Database data will be preserved. Use --purge-data to remove extension tables and data."
fi

if [[ -f "${LOCAL_SETTINGS}" ]]; then
    BACKUP_DIR="${TEC_TAC_BACKUP_DIR:-${REPO_ROOT}/backups}"
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

# Repository-owned framework/extension files are intentionally not deleted.
# Uninstall only disconnects Tec-Tac from Tactical. Delete the Git checkout
# separately if the repository itself is no longer wanted.
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
if ${PURGE_DATA}; then
    log "Extension tables and data were removed."
else
    log "Extension database tables and data were preserved."
fi
log "Repository files were left intact at ${REPO_ROOT}."
