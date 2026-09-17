#!/usr/bin/env bash
set -euo pipefail

APP_NAME="tfdreporting"
TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
LOCAL_SETTINGS="${BACKEND_DIR}/tacticalrmm/local_settings.py"
DEST_APP="${BACKEND_DIR}/${APP_NAME}"
EXCLUDE_FILE="${TACTICAL_ROOT}/.git/info/exclude"
BEGIN_MARKER="# BEGIN TFD REPORTING EXTENSION"
END_MARKER="# END TFD REPORTING EXTENSION"
PURGE_DATA=false

if [[ "${1:-}" == "--purge-data" ]]; then
    PURGE_DATA=true
fi

log() { printf '[TFD] %s\n' "$*"; }
fail() { printf '[TFD] ERROR: %s\n' "$*" >&2; exit 1; }

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

if ${PURGE_DATA}; then
    [[ -d "${DEST_APP}" ]] || fail "${DEST_APP} is missing; cannot safely run migration rollback."
    log "Purging ${APP_NAME} database objects via Django migrations."
    run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' migrate '${APP_NAME}' zero --noinput"
else
    log "Database data will be preserved. Use --purge-data to remove it."
fi

if [[ -f "${LOCAL_SETTINGS}" ]]; then
    BACKUP_DIR="${TFD_STATE_DIR:-/opt/tfd-tactical}/backups"
    mkdir -p "${BACKUP_DIR}"
    BACKUP_FILE="${BACKUP_DIR}/local_settings.py.$(date +%Y%m%dT%H%M%S).uninstall.bak"
    cp -a "${LOCAL_SETTINGS}" "${BACKUP_FILE}"

    TMP_SETTINGS="$(mktemp)"
    trap 'rm -f "${TMP_SETTINGS}"' EXIT
    awk -v begin="${BEGIN_MARKER}" -v end="${END_MARKER}" '
        $0 == begin {skip=1; next}
        $0 == end {skip=0; next}
        !skip {print}
    ' "${LOCAL_SETTINGS}" > "${TMP_SETTINGS}"
    cat "${TMP_SETTINGS}" > "${LOCAL_SETTINGS}"
    chown "${TACTICAL_USER}:${TACTICAL_GROUP}" "${LOCAL_SETTINGS}"
    log "Removed TFD loader block from local_settings.py."
fi

rm -rf "${DEST_APP}"
log "Removed ${DEST_APP}."

if [[ -f "${EXCLUDE_FILE}" ]]; then
    TMP_EXCLUDE="$(mktemp)"
    grep -Fxv "/api/tacticalrmm/${APP_NAME}/" "${EXCLUDE_FILE}" > "${TMP_EXCLUDE}" || true
    cat "${TMP_EXCLUDE}" > "${EXCLUDE_FILE}"
    rm -f "${TMP_EXCLUDE}"
    chown "${TACTICAL_USER}:${TACTICAL_GROUP}" "${EXCLUDE_FILE}"
    log "Removed Git exclude rule."
fi

systemctl restart rmm daphne celery celerybeat
log "Uninstall complete."
