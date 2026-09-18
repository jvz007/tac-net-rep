#!/usr/bin/env bash
set -euo pipefail

APP_NAME="tfdreporting"
MODEL_NAME="NetworkAvailability"
TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
LOCAL_SETTINGS="${BACKEND_DIR}/tacticalrmm/local_settings.py"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRAMEWORK_DIR="${REPO_ROOT}/framwork"
EXTENSIONS_DIR="${REPO_ROOT}/extensions"
REPORTSETS_DIR="${REPO_ROOT}/reportsets"
LEGACY_REPORTING_DIR="${EXTENSIONS_DIR}/reporting"
APP_DIR="${LEGACY_REPORTING_DIR}/${APP_NAME}"
VERSION_FILE="${REPO_ROOT}/VERSION"

BEGIN_MARKER="# BEGIN TEC-TAC EXTENSION FRAMEWORK"
END_MARKER="# END TEC-TAC EXTENSION FRAMEWORK"
OLD_BEGIN_MARKER="# BEGIN TFD REPORTING EXTENSION"
OLD_END_MARKER="# END TFD REPORTING EXTENSION"
LEGACY_DEST_APP="${BACKEND_DIR}/${APP_NAME}"
EXCLUDE_FILE="${TACTICAL_ROOT}/.git/info/exclude"

log() { printf '[TEC-TAC] %s\n' "$*"; }
fail() { printf '[TEC-TAC] ERROR: %s\n' "$*" >&2; exit 1; }

if [[ ${EUID} -ne 0 ]]; then
    fail "Run this installer as root (for example: sudo bash install.sh)."
fi

PACKAGE_VERSION="unknown"
if [[ -f "${VERSION_FILE}" ]]; then
    PACKAGE_VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}")"
fi
log "Installing Tec-Tac framework ${PACKAGE_VERSION}."
log "Detected Tec-Tac repository root: ${REPO_ROOT}"

[[ -d "${TACTICAL_ROOT}/.git" ]] || fail "${TACTICAL_ROOT} is not a Tactical RMM Git checkout."
[[ -f "${MANAGE_PY}" ]] || fail "Tactical manage.py was not found at ${MANAGE_PY}."
[[ -x "${VENV_PYTHON}" ]] || fail "Tactical Python was not found at ${VENV_PYTHON}."
REQUIRED_FILES=(
    "${FRAMEWORK_DIR}/tec_tac/__init__.py"
    "${FRAMEWORK_DIR}/tec_tac/bootstrap.py"
    "${FRAMEWORK_DIR}/tec_tac/registry.py"
    "${FRAMEWORK_DIR}/tec_tac/rbac.py"
    "${FRAMEWORK_DIR}/tec_tac/apps.py"
    "${FRAMEWORK_DIR}/tec_tac/urls.py"
    "${FRAMEWORK_DIR}/tec_tac/views.py"
    "${FRAMEWORK_DIR}/tec_tac/module_manager.py"
    "${APP_DIR}/__init__.py"
    "${APP_DIR}/apps.py"
    "${APP_DIR}/models.py"
    "${APP_DIR}/rbac.py"
    "${APP_DIR}/serializers.py"
    "${APP_DIR}/views.py"
    "${APP_DIR}/urls.py"
    "${APP_DIR}/migrations/0001_initial.py"
    "${APP_DIR}/migrations/0002_extensionrolepermission.py"
    "${APP_DIR}/migrations/0003_networkavailability_ingest_hardening.py"
    "${REPO_ROOT}/scripts/reporting-permission.sh"
    "${REPO_ROOT}/scripts/framework-info.sh"
    "${REPO_ROOT}/scripts/plugin-info.sh"
    "${REPO_ROOT}/scripts/scaffold-plugin.sh"
    "${REPO_ROOT}/scripts/install-extension.sh"
    "${REPO_ROOT}/scripts/remove-extension.sh"
    "${REPO_ROOT}/scripts/module-job-helper.py"
    "${REPO_ROOT}/scripts/reload-rmm-uwsgi.sh"
    "${REPO_ROOT}/tests/framework-foundation.sh"
    "${REPO_ROOT}/tests/access-api-foundation.sh"
    "${REPO_ROOT}/tests/module-management-foundation.sh"
    "${REPO_ROOT}/tests/registry-validation.sh"
    "${REPO_ROOT}/tests/tactical-update-survival.sh"
    "${REPO_ROOT}/tests/example-plugin.sh"
    "${REPO_ROOT}/extensions/example/tec_tac.json"
    "${REPO_ROOT}/extensions/example/tec_tac_example_extension/__init__.py"
    "${REPO_ROOT}/extensions/example/tec_tac_example_extension/apps.py"
    "${REPO_ROOT}/extensions/example/tec_tac_example_extension/sample.py"
    "${REPO_ROOT}/reportsets/example/tec_tac.json"
    "${REPO_ROOT}/reportsets/example/tec_tac_example_reportset/__init__.py"
    "${REPO_ROOT}/reportsets/example/tec_tac_example_reportset/apps.py"
    "${REPO_ROOT}/reportsets/example/tec_tac_example_reportset/sample.py"
    "${REPO_ROOT}/templates/plugin/extension/tec_tac.json"
    "${REPO_ROOT}/templates/plugin/reportset/tec_tac.json"
)
for required_file in "${REQUIRED_FILES[@]}"; do
    [[ -f "${required_file}" ]] || fail "Installer payload is missing ${required_file}."
done
log "Preflight repository layout: OK"
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
log "Tec-Tac framework: ${FRAMEWORK_DIR}"

log "Extensions root: ${EXTENSIONS_DIR}"
log "Reportsets root: ${REPORTSETS_DIR}"
log "Legacy reporting POC: ${LEGACY_REPORTING_DIR}"

if ! run_as_tactical git -C "${TACTICAL_ROOT}" check-ignore -q "api/tacticalrmm/tacticalrmm/local_settings.py"; then
    fail "Tactical no longer treats local_settings.py as ignored. Refusing to install because the bootstrap would not be upgrade-safe."
fi
log "Confirmed local_settings.py is ignored by Tactical Git."

# Ensure Tactical can traverse/read the checkout without changing repository
# ownership. This is intentionally limited to read/execute permissions.
chmod -R a+rX "${FRAMEWORK_DIR}" "${EXTENSIONS_DIR}" "${REPORTSETS_DIR}"

BACKUP_DIR="${TEC_TAC_BACKUP_DIR:-/var/lib/tec-tac/backups}"
mkdir -p "${BACKUP_DIR}"
BACKUP_FILE="${BACKUP_DIR}/local_settings.py.$(date +%Y%m%dT%H%M%S).bak"
cp -a "${LOCAL_SETTINGS}" "${BACKUP_FILE}"
log "Backed up local_settings.py to ${BACKUP_FILE}."

BEGIN_COUNT="$(grep -Fxc "${BEGIN_MARKER}" "${LOCAL_SETTINGS}" || true)"
END_COUNT="$(grep -Fxc "${END_MARKER}" "${LOCAL_SETTINGS}" || true)"
if [[ "${BEGIN_COUNT}" -ne "${END_COUNT}" ]] || [[ "${BEGIN_COUNT}" -gt 1 ]]; then
    fail "Malformed Tec-Tac loader markers in ${LOCAL_SETTINGS}. Backup: ${BACKUP_FILE}"
fi

TMP_SETTINGS="$(mktemp)"
trap 'rm -f "${TMP_SETTINGS}"' EXIT

# Replace either the previous TFD loader or an existing Tec-Tac loader.
awk \
    -v begin1="${BEGIN_MARKER}" -v end1="${END_MARKER}" \
    -v begin2="${OLD_BEGIN_MARKER}" -v end2="${OLD_END_MARKER}" '
    $0 == begin1 {skip=1; next}
    $0 == end1 {skip=0; next}
    $0 == begin2 {skip=1; next}
    $0 == end2 {skip=0; next}
    !skip {print}
' "${LOCAL_SETTINGS}" > "${TMP_SETTINGS}"

if grep -Eq '(^|[^[:alnum:]_])_tfd_populate([^[:alnum:]_]|$)|Apps\.populate[[:space:]]*=[[:space:]]*_tfd_populate' "${TMP_SETTINGS}"; then
    fail "Legacy unmarked TFD loader detected in ${LOCAL_SETTINGS}. Backup: ${BACKUP_FILE}"
fi

cat >> "${TMP_SETTINGS}" <<PYEOF

${BEGIN_MARKER}
# Minimal bootstrap only. Path generated from the Tec-Tac repository location.
import sys

_TEC_TAC_FRAMEWORK = "${FRAMEWORK_DIR}"
if _TEC_TAC_FRAMEWORK not in sys.path:
    sys.path.insert(0, _TEC_TAC_FRAMEWORK)

from tec_tac.bootstrap import load_extensions
load_extensions()
${END_MARKER}
PYEOF

cat "${TMP_SETTINGS}" > "${LOCAL_SETTINGS}"
chown "${TACTICAL_USER}:${TACTICAL_GROUP}" "${LOCAL_SETTINGS}"

POST_BEGIN_COUNT="$(grep -Fxc "${BEGIN_MARKER}" "${LOCAL_SETTINGS}" || true)"
POST_END_COUNT="$(grep -Fxc "${END_MARKER}" "${LOCAL_SETTINGS}" || true)"
if [[ "${POST_BEGIN_COUNT}" -ne 1 ]] || [[ "${POST_END_COUNT}" -ne 1 ]]; then
    cp -a "${BACKUP_FILE}" "${LOCAL_SETTINGS}"
    chown "${TACTICAL_USER}:${TACTICAL_GROUP}" "${LOCAL_SETTINGS}"
    fail "Tec-Tac bootstrap verification failed. Previous local_settings.py restored."
fi
log "Installed minimal Tec-Tac bootstrap in local_settings.py."

log "Running Django system checks."
run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' check"

log "Applying ${APP_NAME} migrations."
run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' migrate '${APP_NAME}' --noinput"

log "Verifying framework API, repository-loaded app, RBAC, Report Manager, and API routes."
VERIFY_CODE="import tfdreporting; from django.apps import apps; from django.urls import resolve; expected='${LEGACY_REPORTING_DIR}/'; assert tfdreporting.__file__.startswith(expected), tfdreporting.__file__; assert apps.is_installed('tec_tac'); m=apps.get_model('${APP_NAME}','${MODEL_NAME}'); p=apps.get_model('${APP_NAME}','ExtensionRolePermission'); from ee.reporting.utils import resolve_model; r=resolve_model(data_source={'model':'${MODEL_NAME}'}); assert r['model'] is m; from tec_tac.rbac import registered_permissions, permission_catalog; from tfdreporting.rbac import REGISTERED_PERMISSIONS; assert len(REGISTERED_PERMISSIONS) >= 2; match=resolve('/api/tfd/reporting/network-availability/'); assert match.url_name == 'network-availability'; ctx=resolve('/api/tfd/ui/context/'); assert ctx.url_name == 'tec-tac-ui-context'; access=resolve('/api/tfd/access/extensions/'); assert access.url_name == 'tec-tac-extension-permissions'; modules=resolve('/api/tfd/modules/'); assert modules.url_name == 'tec-tac-module-catalog'; updates=resolve('/api/tfd/system/updates/'); assert updates.url_name == 'tec-tac-system-update-status'; fields={f.name for f in m._meta.fields}; assert {'idempotency_key','ingested_by','received_at'} <= fields; c=m.objects.count(); print('TEC-TAC verification OK:', 'module=', tfdreporting.__file__, m._meta.label, p._meta.label, 'context=', ctx.route, 'access=', access.route, 'modules=', modules.route, 'updates=', updates.route, 'network_rows=', c)"
run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${VERIFY_CODE}\""

MODULE_STATE_ROOT="/var/lib/tec-tac/module-manager"
MODULE_HELPER="/usr/local/sbin/tec-tac-module-job"
MODULE_CONFIG_DIR="/etc/tec-tac"
MODULE_CONFIG="${MODULE_CONFIG_DIR}/module-manager.conf"
MODULE_SUDOERS="/etc/sudoers.d/tec-tac-module-manager"
RMM_DROPIN_DIR="/etc/systemd/system/rmm.service.d"
RMM_DROPIN="${RMM_DROPIN_DIR}/tec-tac.conf"
TEC_TAC_UI_REPO="${TEC_TAC_UI_REPO:-/opt/tec-tac-ui}"
TEC_TAC_UI_ROOT="${TEC_TAC_UI_ROOT:-/var/lib/tec-tac/ui/tec-tac}"

mkdir -p "${RMM_DROPIN_DIR}"
cat > "${RMM_DROPIN}" <<EOF
[Service]
SupplementaryGroups=${TACTICAL_GROUP}
EOF
chown root:root "${RMM_DROPIN}"
chmod 0644 "${RMM_DROPIN}"
systemctl daemon-reload
log "Installed rmm.service supplementary-group drop-in for Tec-Tac runtime access: ${TACTICAL_GROUP}"

mkdir -p "${MODULE_STATE_ROOT}/staged" "${MODULE_STATE_ROOT}/jobs" "${MODULE_STATE_ROOT}/running" "${MODULE_STATE_ROOT}/logs"
chown -R root:"${TACTICAL_GROUP}" "${MODULE_STATE_ROOT}"
chmod 2750 "${MODULE_STATE_ROOT}" "${MODULE_STATE_ROOT}/running" "${MODULE_STATE_ROOT}/logs"
chmod 2770 "${MODULE_STATE_ROOT}/staged" "${MODULE_STATE_ROOT}/jobs"

install -o root -g root -m 0755 "${REPO_ROOT}/scripts/module-job-helper.py" "${MODULE_HELPER}"
mkdir -p "${MODULE_CONFIG_DIR}"
cat > "${MODULE_CONFIG}" <<EOF
REPO_ROOT=${REPO_ROOT}
UI_SYNC_SCRIPT=${TEC_TAC_UI_REPO}/scripts/sync-modules.sh
UI_ROOT=${TEC_TAC_UI_ROOT}
TACTICAL_USER=${TACTICAL_USER}
EOF
chown root:root "${MODULE_CONFIG}"
chmod 0644 "${MODULE_CONFIG}"

cat > "${MODULE_SUDOERS}" <<EOF
${TACTICAL_USER} ALL=(root) NOPASSWD: ${MODULE_HELPER} --dispatch *
EOF
chown root:root "${MODULE_SUDOERS}"
chmod 0440 "${MODULE_SUDOERS}"
if command -v visudo >/dev/null 2>&1; then
    visudo -cf "${MODULE_SUDOERS}" >/dev/null || fail "Module manager sudoers validation failed."
fi
log "Installed privileged module lifecycle helper: ${MODULE_HELPER}"


SYSTEM_UPDATE_ROOT="/var/lib/tec-tac/system-updates"
SYSTEM_UPDATE_HELPER="/usr/local/sbin/tec-tac-system-update"
SYSTEM_UPDATE_LIB="/usr/local/lib/tec-tac-updater"
SYSTEM_UPDATE_CONFIG="/etc/tec-tac/system-update.conf"
SYSTEM_UPDATE_SUDOERS="/etc/sudoers.d/tec-tac-system-update"
FRAMEWORK_REPOSITORY="${TEC_TAC_FRAMEWORK_REPOSITORY:-jvz007/tac-net-rep}"
UI_REPOSITORY="${TEC_TAC_UI_REPOSITORY:-jvz007/tec-tac-ui}"

mkdir -p "${SYSTEM_UPDATE_ROOT}/staged" "${SYSTEM_UPDATE_ROOT}/jobs" "${SYSTEM_UPDATE_ROOT}/running" "${SYSTEM_UPDATE_ROOT}/logs" "${SYSTEM_UPDATE_ROOT}/backups" "${SYSTEM_UPDATE_ROOT}/history"
chown -R root:"${TACTICAL_GROUP}" "${SYSTEM_UPDATE_ROOT}"
chmod 2750 "${SYSTEM_UPDATE_ROOT}" "${SYSTEM_UPDATE_ROOT}/running" "${SYSTEM_UPDATE_ROOT}/logs" "${SYSTEM_UPDATE_ROOT}/backups" "${SYSTEM_UPDATE_ROOT}/history"
chmod 2770 "${SYSTEM_UPDATE_ROOT}/staged" "${SYSTEM_UPDATE_ROOT}/jobs"

mkdir -p "${SYSTEM_UPDATE_LIB}"
install -o root -g root -m 0755 "${REPO_ROOT}/scripts/system-update-helper.py" "${SYSTEM_UPDATE_LIB}/system-update-helper.py"
ln -sfn "${SYSTEM_UPDATE_LIB}/system-update-helper.py" "${SYSTEM_UPDATE_HELPER}"
chown -h root:root "${SYSTEM_UPDATE_HELPER}"

cat > "${SYSTEM_UPDATE_CONFIG}" <<EOF
FRAMEWORK_ROOT=${REPO_ROOT}
UI_REPO_ROOT=${TEC_TAC_UI_REPO}
TACTICAL_USER=${TACTICAL_USER}
FRAMEWORK_REPOSITORY=${FRAMEWORK_REPOSITORY}
UI_REPOSITORY=${UI_REPOSITORY}
GITHUB_TOKEN_FILE=/etc/tec-tac/github-token
EOF
chown root:root "${SYSTEM_UPDATE_CONFIG}"
chmod 0644 "${SYSTEM_UPDATE_CONFIG}"

cat > "${SYSTEM_UPDATE_SUDOERS}" <<EOF
${TACTICAL_USER} ALL=(root) NOPASSWD: ${SYSTEM_UPDATE_HELPER} --dispatch *
EOF
chown root:root "${SYSTEM_UPDATE_SUDOERS}"
chmod 0440 "${SYSTEM_UPDATE_SUDOERS}"
if command -v visudo >/dev/null 2>&1; then
    visudo -cf "${SYSTEM_UPDATE_SUDOERS}" >/dev/null || fail "System update sudoers validation failed."
fi
log "Installed independent Tec-Tac system update worker: ${SYSTEM_UPDATE_HELPER}"


# Optional reporting permission assignment. Permissions are stored against the
# Tactical role used by the named user, not against the user directly. Existing
# granted manage permissions are kept by default on repeat installs.
REPORTING_USERNAME="${TEC_TAC_REPORTING_USERNAME:-}"
EXISTING_PERMISSION_CODE=$(cat <<'PYEOF'
from django.contrib.auth import get_user_model
from tfdreporting.models import ExtensionRolePermission
from tfdreporting.rbac import PERMISSION_NETWORK_AVAILABILITY_MANAGE

rows = list(
    ExtensionRolePermission.objects.filter(
        codename=PERMISSION_NETWORK_AVAILABILITY_MANAGE,
        granted=True,
    ).order_by("role_id")
)

users_by_role = {}
role_names = {}
for user in get_user_model().objects.all().order_by("username"):
    try:
        role = user.get_and_set_role_cache()
    except Exception:
        continue
    if not role:
        continue
    role_id = int(role.id)
    role_names[role_id] = str(role.name)
    users_by_role.setdefault(role_id, []).append(str(user.username))

for row in rows:
    role_id = int(row.role_id)
    role_name = role_names.get(role_id, "unknown")
    usernames = ",".join(users_by_role.get(role_id, ())) or "none"
    print(f"FOUND|{role_id}|{role_name}|{usernames}")
PYEOF
)

EXISTING_PERMISSIONS="$(run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell" <<< "${EXISTING_PERMISSION_CODE}")"

if [[ -n "${REPORTING_USERNAME}" ]]; then
    log "Granting reporting ingest permission using Tactical user '${REPORTING_USERNAME}'."
    bash "${REPO_ROOT}/scripts/reporting-permission.sh" "${REPORTING_USERNAME}" manage
elif [[ -n "${EXISTING_PERMISSIONS}" ]]; then
    log "Existing reporting ingest permission assignment(s) found:"
    while IFS='|' read -r marker role_id role_name usernames; do
        [[ "${marker}" == "FOUND" ]] || continue
        log "Role: ${role_name} (id=${role_id}); users: ${usernames}"
    done <<< "${EXISTING_PERMISSIONS}"

    CHANGE_PERMISSION="n"
    if [[ -t 0 ]]; then
        printf '[TEC-TAC] Change/add reporting ingest permission assignment? [y/N]: '
        read -r CHANGE_PERMISSION
    fi

    case "${CHANGE_PERMISSION}" in
        y|Y|yes|YES|Yes)
            printf '[TEC-TAC] Tactical username whose role should receive reporting ingest permission: '
            read -r REPORTING_USERNAME
            if [[ -n "${REPORTING_USERNAME}" ]]; then
                log "Granting reporting ingest permission using Tactical user '${REPORTING_USERNAME}'."
                bash "${REPO_ROOT}/scripts/reporting-permission.sh" "${REPORTING_USERNAME}" manage
            else
                log "No username entered; existing reporting permission assignment(s) kept unchanged."
            fi
            ;;
        *)
            log "Keeping existing reporting permission assignment(s) unchanged."
            ;;
    esac
elif [[ -t 0 ]]; then
    printf '[TEC-TAC] Tactical username to grant reporting ingest permission (leave blank to skip): '
    read -r REPORTING_USERNAME
    if [[ -n "${REPORTING_USERNAME}" ]]; then
        log "Granting reporting ingest permission using Tactical user '${REPORTING_USERNAME}'."
        bash "${REPO_ROOT}/scripts/reporting-permission.sh" "${REPORTING_USERNAME}" manage
    else
        log "Reporting permission assignment skipped."
    fi
else
    log "No existing reporting ingest permission found and no unattended username supplied; permission assignment skipped."
fi

# Remove any old in-tree extension copy only after the repository-loaded copy
# has been verified successfully.
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
    log "Removed obsolete ${APP_NAME} Git exclude rule if present."
fi

log "Restarting Tactical services."
systemctl restart rmm daphne celery celerybeat

for svc in rmm daphne celery celerybeat; do
    if ! systemctl is-active --quiet "${svc}"; then
        systemctl --no-pager --full status "${svc}" || true
        fail "${svc} did not return to active state."
    fi
    log "${svc}: active"
done

RMM_SUPPLEMENTARY="$(systemctl show rmm.service -p SupplementaryGroups --value)"
case " ${RMM_SUPPLEMENTARY} " in
    *" ${TACTICAL_GROUP} "*) ;;
    *) fail "rmm.service did not load required supplementary group '${TACTICAL_GROUP}'." ;;
esac
RMM_PID="$(systemctl show rmm.service -p MainPID --value)"
TACTICAL_GID="$(id -g "${TACTICAL_USER}")"
if [[ ! "${RMM_PID}" =~ ^[0-9]+$ || "${RMM_PID}" -le 1 || ! -r "/proc/${RMM_PID}/status" ]]; then
    fail "Could not inspect live rmm process after restart."
fi
LIVE_GROUPS="$(awk '/^Groups:/ {$1=""; sub(/^ /, ""); print}' "/proc/${RMM_PID}/status")"
case " ${LIVE_GROUPS} " in
    *" ${TACTICAL_GID} "*) log "Verified live rmm process has Tec-Tac runtime group ${TACTICAL_GROUP} (gid ${TACTICAL_GID})." ;;
    *) fail "Live rmm process is missing Tec-Tac runtime group ${TACTICAL_GROUP} (gid ${TACTICAL_GID})." ;;
esac

log "Installation complete."
log "Framework: ${FRAMEWORK_DIR}"
log "Extensions: ${EXTENSIONS_DIR}"
log "Reportsets: ${REPORTSETS_DIR}"
log "Swagger endpoint: /api/tfd/reporting/network-availability/"
