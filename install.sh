#!/usr/bin/env bash
set -euo pipefail

APP_NAME="tfdreporting"
APP_CONFIG="tfdreporting.apps.TfdreportingConfig"
MODEL_NAME="NetworkAvailability"
TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
LOCAL_SETTINGS="${BACKEND_DIR}/tacticalrmm/local_settings.py"
DEST_APP="${BACKEND_DIR}/${APP_NAME}"
EXCLUDE_FILE="${TACTICAL_ROOT}/.git/info/exclude"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_APP="${SCRIPT_DIR}/${APP_NAME}"
BEGIN_MARKER="# BEGIN TFD REPORTING EXTENSION"
END_MARKER="# END TFD REPORTING EXTENSION"

log() { printf '[TFD] %s\n' "$*"; }
fail() { printf '[TFD] ERROR: %s\n' "$*" >&2; exit 1; }

if [[ ${EUID} -ne 0 ]]; then
    fail "Run this installer as root (for example: sudo ./install.sh)."
fi

[[ -d "${TACTICAL_ROOT}/.git" ]] || fail "${TACTICAL_ROOT} is not a Tactical RMM Git checkout."
[[ -f "${MANAGE_PY}" ]] || fail "Tactical manage.py was not found at ${MANAGE_PY}."
[[ -x "${VENV_PYTHON}" ]] || fail "Tactical Python was not found at ${VENV_PYTHON}."
[[ -d "${SOURCE_APP}" ]] || fail "Installer payload is missing ${SOURCE_APP}. Clone/download the full repository before running install.sh."
[[ -f "${LOCAL_SETTINGS}" ]] || fail "Tactical local_settings.py was not found at ${LOCAL_SETTINGS}."
[[ -f "${BACKEND_DIR}/ee/reporting/constants.py" ]] || fail "Tactical Report Manager (ee.reporting) was not found."

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
if [[ -z "${TACTICAL_USER}" ]]; then
    TACTICAL_USER="$(awk -F= '$1 == "User" {print $2; exit}' /etc/systemd/system/rmm.service 2>/dev/null || true)"
fi
[[ -n "${TACTICAL_USER}" ]] || fail "Could not determine the Tactical service user from rmm.service."
id "${TACTICAL_USER}" >/dev/null 2>&1 || fail "Detected Tactical user '${TACTICAL_USER}' does not exist."
TACTICAL_GROUP="$(id -gn "${TACTICAL_USER}")"

run_as_tactical() {
    runuser -u "${TACTICAL_USER}" -- "$@"
}

log "Detected Tactical root: ${TACTICAL_ROOT}"
log "Detected Tactical service user: ${TACTICAL_USER}"

# local_settings.py is our only Tactical-provided persistence hook. Refuse to
# install if a future Tactical release starts tracking/cleaning it.
if ! run_as_tactical git -C "${TACTICAL_ROOT}" check-ignore -q "api/tacticalrmm/tacticalrmm/local_settings.py"; then
    fail "Tactical no longer treats local_settings.py as ignored. Refusing to install because the extension would not be upgrade-safe."
fi
log "Confirmed local_settings.py is ignored by Tactical Git."

mkdir -p "$(dirname "${EXCLUDE_FILE}")"
touch "${EXCLUDE_FILE}"
chown "${TACTICAL_USER}:${TACTICAL_GROUP}" "${EXCLUDE_FILE}"

EXCLUDE_RULE="/api/tacticalrmm/${APP_NAME}/"
if ! grep -Fxq "${EXCLUDE_RULE}" "${EXCLUDE_FILE}"; then
    printf '%s\n' "${EXCLUDE_RULE}" >> "${EXCLUDE_FILE}"
    log "Added ${APP_NAME} to .git/info/exclude."
else
    log "Git exclude rule already present."
fi

if ! run_as_tactical git -C "${TACTICAL_ROOT}" check-ignore -q "api/tacticalrmm/${APP_NAME}/models.py" 2>/dev/null; then
    # models.py might not exist yet on a first install, so validate the directory rule instead.
    if ! run_as_tactical git -C "${TACTICAL_ROOT}" check-ignore -q "api/tacticalrmm/${APP_NAME}/"; then
        fail "Git exclude rule for ${APP_NAME} is not effective."
    fi
fi
log "Confirmed ${APP_NAME} is protected from git clean -df."

BACKUP_DIR="${TFD_STATE_DIR:-/opt/tfd-tactical}/backups"
mkdir -p "${BACKUP_DIR}"
BACKUP_FILE="${BACKUP_DIR}/local_settings.py.$(date +%Y%m%dT%H%M%S).bak"
cp -a "${LOCAL_SETTINGS}" "${BACKUP_FILE}"
log "Backed up local_settings.py to ${BACKUP_FILE}."

# Validate the loader state before modifying local_settings.py. Older POC builds
# used an unmarked _tfd_populate hook. Stacking another hook on top of that can
# recurse indefinitely, so fail safely and require the legacy hook to be removed.
BEGIN_COUNT="$(grep -Fxc "${BEGIN_MARKER}" "${LOCAL_SETTINGS}" || true)"
END_COUNT="$(grep -Fxc "${END_MARKER}" "${LOCAL_SETTINGS}" || true)"

if [[ "${BEGIN_COUNT}" -ne "${END_COUNT}" ]] || [[ "${BEGIN_COUNT}" -gt 1 ]]; then
    fail "Malformed TFD loader markers in ${LOCAL_SETTINGS}. Expected zero or one matching marker pair. Restore the backup and inspect the file before retrying."
fi

TMP_SETTINGS="$(mktemp)"
trap 'rm -f "${TMP_SETTINGS}"' EXIT

awk -v begin="${BEGIN_MARKER}" -v end="${END_MARKER}" '
    $0 == begin {skip=1; next}
    $0 == end {skip=0; next}
    !skip {print}
' "${LOCAL_SETTINGS}" > "${TMP_SETTINGS}"

if grep -Eq '(^|[^[:alnum:]_])_tfd_populate([^[:alnum:]_]|$)|Apps\.populate[[:space:]]*=[[:space:]]*_tfd_populate' "${TMP_SETTINGS}"; then
    fail "Legacy unmarked TFD loader detected in ${LOCAL_SETTINGS}. Remove the old _tfd_populate/Apps.populate hook before rerunning this installer. Backup: ${BACKUP_FILE}"
fi

cat >> "${TMP_SETTINGS}" <<'PYEOF'

# BEGIN TFD REPORTING EXTENSION
# Loads TFD Django apps into the primary registry without modifying Tactical's
# tracked settings.py. Temporary migration StateApps registries are left alone.
from django.apps import apps as django_apps
from django.apps.registry import Apps

_tfd_original_populate = Apps.populate


def _tfd_populate(self, installed_apps=None):
    if self is django_apps and installed_apps is not None:
        installed_apps = list(installed_apps)
        tfd_app = "tfdreporting.apps.TfdreportingConfig"

        if tfd_app not in installed_apps:
            installed_apps.append(tfd_app)

    return _tfd_original_populate(self, installed_apps)


Apps.populate = _tfd_populate
# END TFD REPORTING EXTENSION
PYEOF

cat "${TMP_SETTINGS}" > "${LOCAL_SETTINGS}"
chown "${TACTICAL_USER}:${TACTICAL_GROUP}" "${LOCAL_SETTINGS}"

POST_BEGIN_COUNT="$(grep -Fxc "${BEGIN_MARKER}" "${LOCAL_SETTINGS}" || true)"
POST_END_COUNT="$(grep -Fxc "${END_MARKER}" "${LOCAL_SETTINGS}" || true)"
if [[ "${POST_BEGIN_COUNT}" -ne 1 ]] || [[ "${POST_END_COUNT}" -ne 1 ]]; then
    cp -a "${BACKUP_FILE}" "${LOCAL_SETTINGS}"
    chown "${TACTICAL_USER}:${TACTICAL_GROUP}" "${LOCAL_SETTINGS}"
    fail "TFD loader verification failed after writing local_settings.py. The previous file was restored."
fi
log "Installed/updated the TFD loader in local_settings.py."

STAGE_DIR="$(mktemp -d)"
trap 'rm -f "${TMP_SETTINGS}"; rm -rf "${STAGE_DIR}"' EXIT
cp -a "${SOURCE_APP}/." "${STAGE_DIR}/"
rm -rf "${DEST_APP}"
mkdir -p "${DEST_APP}"
cp -a "${STAGE_DIR}/." "${DEST_APP}/"
chown -R "${TACTICAL_USER}:${TACTICAL_GROUP}" "${DEST_APP}"
log "Installed ${APP_NAME} into ${DEST_APP}."

log "Running Django system checks."
run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' check"

log "Applying ${APP_NAME} migrations."
run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' migrate '${APP_NAME}' --noinput"

log "Verifying Django model and Tactical Report Manager registration."
VERIFY_CODE="from django.apps import apps; m=apps.get_model('${APP_NAME}','${MODEL_NAME}'); p=apps.get_model('${APP_NAME}','ExtensionRolePermission'); from ee.reporting.utils import resolve_model; r=resolve_model(data_source={'model':'${MODEL_NAME}'}); assert r['model'] is m; from tfdreporting.rbac import REGISTERED_PERMISSIONS; assert len(REGISTERED_PERMISSIONS) >= 2; c=m.objects.count(); print('TFD verification OK:', m._meta.label, p._meta.label, sorted(REGISTERED_PERMISSIONS), 'network_rows=', c)"
run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${VERIFY_CODE}\""

log "Restarting Tactical Django/reporting services."
systemctl restart rmm daphne celery celerybeat

for svc in rmm daphne celery celerybeat; do
    if ! systemctl is-active --quiet "${svc}"; then
        systemctl --no-pager --full status "${svc}" || true
        fail "${svc} did not return to active state."
    fi
    log "${svc}: active"
done

log "Installation complete."
