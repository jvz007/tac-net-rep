#!/usr/bin/env bash
set -euo pipefail

APP_NAME="tfdreporting"
MODEL_NAME="NetworkAvailability"
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
TEC_TAC_ROOT="${TEC_TAC_ROOT:-/opt/tec-tac}"
TEC_TAC_SOURCE_ROOT="${TEC_TAC_SOURCE_ROOT:-/opt/tec-tac-src}"
TEC_TAC_FRAMEWORK_SOURCE="${TEC_TAC_FRAMEWORK_SOURCE:-${SOURCE_ROOT}}"
TEC_TAC_UI_SOURCE="${TEC_TAC_UI_SOURCE:-${TEC_TAC_SOURCE_ROOT}/ui}"
FRAMEWORK_DIR="${TEC_TAC_FRAMEWORK_ROOT:-${TEC_TAC_ROOT}/framework}"
EXTENSIONS_DIR="${TEC_TAC_EXTENSIONS_ROOT:-${TEC_TAC_ROOT}/extensions}"
REPORTSETS_DIR="${TEC_TAC_REPORTSETS_ROOT:-${TEC_TAC_ROOT}/reportsets}"
RUNTIME_SCRIPTS_DIR="${TEC_TAC_SCRIPTS_ROOT:-${TEC_TAC_ROOT}/scripts}"
SOURCE_FRAMEWORK_DIR="${SOURCE_ROOT}/framwork"
SOURCE_EXTENSIONS_DIR="${SOURCE_ROOT}/extensions"
SOURCE_REPORTSETS_DIR="${SOURCE_ROOT}/reportsets"
SOURCE_SCRIPTS_DIR="${SOURCE_ROOT}/scripts"
SOURCE_TEMPLATES_DIR="${SOURCE_ROOT}/templates"
LEGACY_REPORTING_DIR="${EXTENSIONS_DIR}/reporting"
APP_DIR="${LEGACY_REPORTING_DIR}/${APP_NAME}"
VERSION_FILE="${SOURCE_ROOT}/VERSION"
REPO_ROOT="${TEC_TAC_ROOT}"

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
log "Tec-Tac source: ${SOURCE_ROOT}"
log "Tec-Tac runtime: ${TEC_TAC_ROOT}"

[[ -d "${TACTICAL_ROOT}/.git" ]] || fail "${TACTICAL_ROOT} is not a Tactical RMM Git checkout."
[[ -f "${MANAGE_PY}" ]] || fail "Tactical manage.py was not found at ${MANAGE_PY}."
[[ -x "${VENV_PYTHON}" ]] || fail "Tactical Python was not found at ${VENV_PYTHON}."
REQUIRED_FILES=(
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/__init__.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/bootstrap.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/registry.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/rbac.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/apps.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/urls.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/views.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/contracts.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/contract_views.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/module_manager.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/module_manager_v2.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/module_state.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/module_v2_views.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/module_repository.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/module_repository_views.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/__init__.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/apps.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/models.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/rbac.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/serializers.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/views.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/urls.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/migrations/0001_initial.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/migrations/0002_extensionrolepermission.py"
    "${SOURCE_EXTENSIONS_DIR}/reporting/${APP_NAME}/migrations/0003_networkavailability_ingest_hardening.py"
    "${SOURCE_ROOT}/scripts/reporting-permission.sh"
    "${SOURCE_ROOT}/scripts/framework-info.sh"
    "${SOURCE_ROOT}/scripts/plugin-info.sh"
    "${SOURCE_ROOT}/scripts/scaffold-plugin.sh"
    "${SOURCE_ROOT}/scripts/install-extension.sh"
    "${SOURCE_ROOT}/scripts/remove-extension.sh"
    "${SOURCE_ROOT}/scripts/module-job-helper.py"
    "${SOURCE_ROOT}/scripts/module-v2-job-helper.py"
    "${SOURCE_ROOT}/scripts/server-backup-helper.py"
    "${SOURCE_ROOT}/scripts/reload-rmm-uwsgi.sh"
    "${SOURCE_ROOT}/scripts/tec-tac-config.sh"
    "${SOURCE_ROOT}/framwork/tec_tac/config.py"
    "${SOURCE_ROOT}/tests/framework-foundation.sh"
    "${SOURCE_ROOT}/tests/access-api-foundation.sh"
    "${SOURCE_ROOT}/tests/module-management-foundation.sh"
    "${SOURCE_ROOT}/tests/scheduler-foundation.sh"
    "${SOURCE_ROOT}/tests/contracts-foundation.sh"
    "${SOURCE_ROOT}/tests/recovery-foundation.sh"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/server_backup.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/scheduler.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/scheduler_views.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/tasks.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/models.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/migrations/0001_scheduler.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/migrations/0002_scheduler_hardening.py"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/migrations/0003_scheduler_model_options.py"
    "${SOURCE_ROOT}/scripts/recovery/lib.sh"
    "${SOURCE_ROOT}/scripts/recovery/tec-tac-repair.sh"
    "${SOURCE_ROOT}/scripts/recovery/tec-tac-diagnostics.sh"
    "${SOURCE_ROOT}/scripts/recovery/tec-tac-repair-permissions.sh"
    "${SOURCE_ROOT}/scripts/recovery/tec-tac-repair-modules.sh"
    "${SOURCE_ROOT}/scripts/recovery/tec-tac-recover-modules-from-backup.sh"
    "${SOURCE_ROOT}/scripts/recovery/tec-tac-repair-runtime.sh"
    "${SOURCE_ROOT}/scripts/recovery/tec-tac-repair-scheduler.sh"
    "${SOURCE_FRAMEWORK_DIR}/tec_tac/management/commands/tec_tac_scheduler_tick.py"
    "${SOURCE_ROOT}/tests/registry-validation.sh"
    "${SOURCE_ROOT}/tests/tactical-update-survival.sh"
    "${SOURCE_ROOT}/tests/example-plugin.sh"
    "${SOURCE_ROOT}/extensions/example/tec_tac.json"
    "${SOURCE_ROOT}/extensions/example/tec_tac_example_extension/__init__.py"
    "${SOURCE_ROOT}/extensions/example/tec_tac_example_extension/apps.py"
    "${SOURCE_ROOT}/extensions/example/tec_tac_example_extension/sample.py"
    "${SOURCE_ROOT}/reportsets/example/tec_tac.json"
    "${SOURCE_ROOT}/reportsets/example/tec_tac_example_reportset/__init__.py"
    "${SOURCE_ROOT}/reportsets/example/tec_tac_example_reportset/apps.py"
    "${SOURCE_ROOT}/reportsets/example/tec_tac_example_reportset/sample.py"
    "${SOURCE_ROOT}/templates/plugin/extension/tec_tac.json"
    "${SOURCE_ROOT}/templates/plugin/reportset/tec_tac.json"
)
for required_file in "${REQUIRED_FILES[@]}"; do
    [[ -f "${required_file}" ]] || fail "Installer payload is missing ${required_file}."
done
log "Preflight source repository layout: OK"

# Deploy framework-owned code into a Git-independent runtime tree. Dynamic
# extensions/reportsets are deliberately preserved and never copied back into
# the source checkout.
mkdir -p "${TEC_TAC_ROOT}" "${EXTENSIONS_DIR}" "${REPORTSETS_DIR}" "${TEC_TAC_ROOT}/etc"
rm -rf "${FRAMEWORK_DIR}" "${RUNTIME_SCRIPTS_DIR}" "${TEC_TAC_ROOT}/templates"
cp -a "${SOURCE_FRAMEWORK_DIR}" "${FRAMEWORK_DIR}"
cp -a "${SOURCE_SCRIPTS_DIR}" "${RUNTIME_SCRIPTS_DIR}"
cp -a "${SOURCE_TEMPLATES_DIR}" "${TEC_TAC_ROOT}/templates"
for rel in extensions/example extensions/reporting reportsets/example; do
    source_path="${SOURCE_ROOT}/${rel}"
    target_path="${TEC_TAC_ROOT}/${rel}"
    if [[ -e "${source_path}" ]]; then
        rm -rf "${target_path}"
        mkdir -p "$(dirname "${target_path}")"
        cp -a "${source_path}" "${target_path}"
    fi
done
cp -a "${SOURCE_ROOT}/VERSION" "${TEC_TAC_ROOT}/VERSION"
cp -a "${SOURCE_ROOT}/tec_tac_package.json" "${TEC_TAC_ROOT}/tec_tac_package.json"
chmod -R a+rX "${FRAMEWORK_DIR}" "${EXTENSIONS_DIR}" "${REPORTSETS_DIR}" "${RUNTIME_SCRIPTS_DIR}"
log "Deployed framework-owned runtime code without altering dynamic modules."

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

log "Applying Tec-Tac framework migrations."
run_as_tactical bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' migrate tec_tac --noinput"

log "Verifying framework models, RBAC, and Report Manager integration."
VERIFY_MODEL_CODE="import tfdreporting; from django.apps import apps; expected='${LEGACY_REPORTING_DIR}/'; assert tfdreporting.__file__.startswith(expected), tfdreporting.__file__; assert apps.is_installed('tec_tac'); m=apps.get_model('${APP_NAME}','${MODEL_NAME}'); p=apps.get_model('${APP_NAME}','ExtensionRolePermission'); from ee.reporting.utils import resolve_model; r=resolve_model(data_source={'model':'${MODEL_NAME}'}); assert r['model'] is m; from tfdreporting.rbac import REGISTERED_PERMISSIONS; assert len(REGISTERED_PERMISSIONS) >= 2; fields={f.name for f in m._meta.fields}; assert {'idempotency_key','ingested_by','received_at'} <= fields; sm=apps.get_model('tec_tac','TecTacSchedule'); sr=apps.get_model('tec_tac','TecTacScheduleRun'); print('TEC-TAC model/RBAC verification OK:', tfdreporting.__file__, m._meta.label, p._meta.label, sm._meta.label, sr._meta.label)"
if ! run_as_tactical timeout 45s bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${VERIFY_MODEL_CODE}\""; then
    fail "Framework model/RBAC verification failed or timed out."
fi

log "Verifying Tec-Tac API routes."
VERIFY_ROUTE_CODE="from django.urls import resolve; checks=[('/api/tfd/reporting/network-availability/','network-availability'),('/api/tfd/ui/context/','tec-tac-ui-context'),('/api/tfd/access/extensions/','tec-tac-extension-permissions'),('/api/tfd/modules/','tec-tac-module-catalog'),('/api/tfd/system/updates/','tec-tac-system-update-status'),('/api/tfd/capabilities/','tec-tac-capabilities'),('/api/tfd/contracts/','tec-tac-contracts'),('/api/tfd/contracts/export/','tec-tac-contract-export'),('/api/tfd/scheduler/actions/','tec-tac-scheduler-actions'),('/api/tfd/scheduler/schedules/','tec-tac-scheduler-schedules'),('/api/tfd/scheduler/runs/','tec-tac-scheduler-runs'),('/api/tfd/modules/repositories/','tec-tac-module-repositories'),('/api/tfd/modules/catalog/online/','tec-tac-module-online-catalog')]; resolved=[(path, resolve(path).url_name) for path,_ in checks]; assert all(actual == expected for (path,actual),(_,expected) in zip(resolved,checks)), resolved; print('TEC-TAC route verification OK:', resolved)"
if ! run_as_tactical timeout 45s bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${VERIFY_ROUTE_CODE}\""; then
    fail "Framework API route verification failed or timed out."
fi

log "Verifying Tec-Tac developer contract catalog."
VERIFY_CONTRACT_CODE="from tec_tac.contracts import build_contract_catalog,render_markdown,render_text; c=build_contract_catalog(); expected='${PACKAGE_VERSION}'; assert c['framework_version']==expected, {'expected': expected, 'actual': c['framework_version']}; assert any(x['name']=='get_capability' for x in c['core']); assert any(x['route']=='/api/tfd/contracts/' for x in c['http']); assert '# Tec-Tac Public Contracts' in render_markdown(c); assert 'TEC-TAC PUBLIC CONTRACTS' in render_text(c); print('TEC-TAC developer contract catalog OK:', c['counts'], 'version='+expected)"
if ! run_as_tactical timeout 45s bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${VERIFY_CONTRACT_CODE}\""; then
    fail "Tec-Tac developer contract catalog verification failed or timed out."
fi

log "Verifying Tec-Tac scheduler/capability Celery task registration."
VERIFY_SCHEDULER_CODE="from tacticalrmm.celery import app; app.autodiscover_tasks(force=True); assert 'tec_tac.execute_schedule_run' in app.tasks and 'tec_tac.capability_probe' in app.tasks, sorted(k for k in app.tasks if k.startswith('tec_tac')); print('TEC-TAC scheduler/capability Celery tasks OK')"
if ! run_as_tactical timeout 45s bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${VERIFY_SCHEDULER_CODE}\""; then
    fail "Tec-Tac scheduler/capability Celery task registration failed or timed out."
fi

log "Verifying Tec-Tac capability registry."
VERIFY_CAPABILITY_CODE="from tec_tac.capabilities import register_capability,get_capability,capability_status; provider=object(); register_capability(id='tec-tac.install-probe',module_id='tec-tac',version='1.0.0',provider=provider); assert get_capability('tec-tac.install-probe',version='>=1,<2') is provider; status=capability_status('tec-tac.install-probe'); assert status['available'] and status['state']=='available', status; print('TEC-TAC capability registry OK:', status['id'], status['capability_version'])"
if ! run_as_tactical timeout 45s bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${VERIFY_CAPABILITY_CODE}\""; then
    fail "Tec-Tac capability registry verification failed or timed out."
fi

MODULE_STATE_ROOT="${TEC_TAC_MODULE_STATE_ROOT:-/var/lib/tec-tac/module-manager}"
MODULE_HELPER="/usr/local/sbin/tec-tac-module-job"
MODULE_V2_HELPER="/usr/local/sbin/tec-tac-module-v2-job"
MODULE_CONFIG_DIR="${TEC_TAC_ROOT}/etc"
MODULE_CONFIG="${TEC_TAC_CONFIG_FILE}"
MODULE_SUDOERS="/etc/sudoers.d/tec-tac-module-manager"
MODULE_V2_SUDOERS="/etc/sudoers.d/tec-tac-module-manager-v2"
MODULE_STATE_FILE="${MODULE_STATE_ROOT}/module-state.json"
RMM_DROPIN_DIR="/etc/systemd/system/rmm.service.d"
RMM_DROPIN="${RMM_DROPIN_DIR}/tec-tac.conf"
TEC_TAC_UI_REPO="${TEC_TAC_UI_SOURCE}"
TEC_TAC_UI_ROOT="${TEC_TAC_UI_DEPLOY_ROOT:-/var/lib/tec-tac/ui/tec-tac}"

mkdir -p "${RMM_DROPIN_DIR}"
cat > "${RMM_DROPIN}" <<EOF
[Service]
SupplementaryGroups=${TACTICAL_GROUP}
EOF
chown root:root "${RMM_DROPIN}"
chmod 0644 "${RMM_DROPIN}"
systemctl daemon-reload
log "Installed rmm.service supplementary-group drop-in for Tec-Tac runtime access: ${TACTICAL_GROUP}"

# ZIP extraction does not reliably preserve executable bits. Repair the
# Recovery Toolkit scripts before sourcing/calling them so offline framework
# updates remain self-healing. Keep the toolkit local to the framework tree.
find "${REPO_ROOT}/scripts/recovery" -maxdepth 1 -type f -name '*.sh' -exec chmod 0755 {} +
for recovery_script in "${REPO_ROOT}"/scripts/recovery/*.sh; do
    [[ -x "${recovery_script}" ]] || fail "Recovery Toolkit script is not executable: ${recovery_script}"
done
log "Verified Tec-Tac Recovery Toolkit scripts are executable."

# Use the same permission repair contract as the console recovery toolkit so
# installer and recovery behavior cannot drift. This also repairs existing
# directories whose modes were created incorrectly by earlier releases.
# shellcheck source=/dev/null
source "${REPO_ROOT}/scripts/recovery/lib.sh"
repair_module_permissions
chmod 0755 "$(dirname "${MODULE_STATE_ROOT}")"
for writable_path in \
    "${MODULE_STATE_ROOT}/staged" \
    "${MODULE_STATE_ROOT}/staged/bundles" \
    "${MODULE_STATE_ROOT}/staged/batches" \
    "${MODULE_STATE_ROOT}/jobs"; do
    run_as_tactical test -w "${writable_path}" || fail "Tactical service user cannot write ${writable_path} after permission repair."
done
log "Verified Module Manager staging paths are writable by ${TACTICAL_USER}."
REPOSITORY_CONFIG="${MODULE_STATE_ROOT}/repositories/repositories.json"
if [[ ! -f "${REPOSITORY_CONFIG}" ]]; then
    printf '%s\n' '{"schema":1,"repositories":[]}' > "${REPOSITORY_CONFIG}"
fi
chown root:"${TACTICAL_GROUP}" "${REPOSITORY_CONFIG}"
chmod 0660 "${REPOSITORY_CONFIG}"
if [[ ! -f "${MODULE_STATE_FILE}" ]]; then
    printf '%s\n' '{"schema":1,"modules":{}}' > "${MODULE_STATE_FILE}"
fi
chown root:root "${MODULE_STATE_FILE}"
chmod 0644 "${MODULE_STATE_FILE}"

install -o root -g root -m 0755 "${REPO_ROOT}/scripts/module-job-helper.py" "${MODULE_HELPER}"
install -o root -g root -m 0755 "${REPO_ROOT}/scripts/module-v2-job-helper.py" "${MODULE_V2_HELPER}"

# Recovery scripts intentionally remain under /opt/tec-tac/scripts/recovery.
# Remove convenience links created by 1.12.0 when they still point at this
# framework's recovery scripts; do not remove unrelated administrator files.
for recovery_link in /usr/local/sbin/tec-tac-repair /usr/local/sbin/tec-tac-diagnostics; do
    if [[ -L "${recovery_link}" ]]; then
        recovery_target="$(readlink -f "${recovery_link}" 2>/dev/null || true)"
        case "${recovery_target}" in
            "${REPO_ROOT}/scripts/recovery/"*) rm -f "${recovery_link}" ;;
        esac
    fi
done
log "Tec-Tac Recovery Toolkit retained under ${REPO_ROOT}/scripts/recovery."
mkdir -p "${MODULE_CONFIG_DIR}"
cat > "${MODULE_CONFIG}" <<EOF
# Tec-Tac installation layout. Managed by install.sh.
TEC_TAC_ROOT=${TEC_TAC_ROOT}
TEC_TAC_CONFIG_FILE=${TEC_TAC_CONFIG_FILE}
TEC_TAC_SOURCE_ROOT=${TEC_TAC_SOURCE_ROOT}
TEC_TAC_FRAMEWORK_SOURCE=${SOURCE_ROOT}
TEC_TAC_UI_SOURCE=${TEC_TAC_UI_SOURCE}
TEC_TAC_FRAMEWORK_ROOT=${FRAMEWORK_DIR}
TEC_TAC_EXTENSIONS_ROOT=${EXTENSIONS_DIR}
TEC_TAC_REPORTSETS_ROOT=${REPORTSETS_DIR}
TEC_TAC_SCRIPTS_ROOT=${RUNTIME_SCRIPTS_DIR}
TEC_TAC_STATE_ROOT=/var/lib/tec-tac
TEC_TAC_MODULE_STATE_ROOT=${MODULE_STATE_ROOT}
TEC_TAC_SYSTEM_UPDATE_ROOT=/var/lib/tec-tac/system-updates
TEC_TAC_SERVER_BACKUP_ROOT=/var/lib/tec-tac/server-backup
TEC_TAC_HOUSEKEEPING_ROOT=/var/lib/tec-tac/housekeeping
TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS=${TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS:-/rmmbackups,/mnt,/media,/srv,/backup,/backups}
TEC_TAC_UI_DEPLOY_ROOT=${TEC_TAC_UI_ROOT}
REPO_ROOT=${TEC_TAC_ROOT}
UI_SYNC_SCRIPT=${TEC_TAC_UI_SOURCE}/scripts/sync-modules.sh
UI_ROOT=${TEC_TAC_UI_ROOT}
GITHUB_TOKEN_FILE=${TEC_TAC_ROOT}/etc/github-token
TACTICAL_ROOT=${TACTICAL_ROOT}
TACTICAL_BACKEND_ROOT=${BACKEND_DIR}
TACTICAL_PYTHON=${VENV_PYTHON}
TACTICAL_USER=${TACTICAL_USER}
FRAMEWORK_REPOSITORY=${TEC_TAC_FRAMEWORK_REPOSITORY:-jvz007/tac-net-rep}
UI_REPOSITORY=${TEC_TAC_UI_REPOSITORY:-jvz007/tec-tac-ui}
EOF
chown root:root "${MODULE_CONFIG}"
chmod 0644 "${MODULE_CONFIG}"
log "Wrote Tec-Tac installation config: ${MODULE_CONFIG}"

cat > "${MODULE_SUDOERS}" <<EOF
${TACTICAL_USER} ALL=(root) NOPASSWD: ${MODULE_HELPER} --dispatch *
EOF
cat > "${MODULE_V2_SUDOERS}" <<EOF
${TACTICAL_USER} ALL=(root) NOPASSWD: ${MODULE_V2_HELPER} --dispatch *
EOF
chown root:root "${MODULE_SUDOERS}" "${MODULE_V2_SUDOERS}"
chmod 0440 "${MODULE_SUDOERS}" "${MODULE_V2_SUDOERS}"
if command -v visudo >/dev/null 2>&1; then
    visudo -cf "${MODULE_SUDOERS}" >/dev/null || fail "Module manager sudoers validation failed."
    visudo -cf "${MODULE_V2_SUDOERS}" >/dev/null || fail "Module manager v2 sudoers validation failed."
fi
log "Installed privileged module lifecycle helper: ${MODULE_HELPER}"
log "Installed privileged Module Management v2 helper: ${MODULE_V2_HELPER}"


SYSTEM_UPDATE_ROOT="${TEC_TAC_SYSTEM_UPDATE_ROOT:-/var/lib/tec-tac/system-updates}"
SYSTEM_UPDATE_HELPER="/usr/local/sbin/tec-tac-system-update"
SYSTEM_UPDATE_LIB="/usr/local/lib/tec-tac-updater"
SYSTEM_UPDATE_CONFIG="${TEC_TAC_CONFIG_FILE}"
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

# System Update and Module Manager share the authoritative Tec-Tac config.
# Keep repository identifiers current without relocating the config into /etc.
if ! grep -q '^FRAMEWORK_REPOSITORY=' "${SYSTEM_UPDATE_CONFIG}"; then
    printf 'FRAMEWORK_REPOSITORY=%s\n' "${FRAMEWORK_REPOSITORY}" >> "${SYSTEM_UPDATE_CONFIG}"
fi
if ! grep -q '^UI_REPOSITORY=' "${SYSTEM_UPDATE_CONFIG}"; then
    printf 'UI_REPOSITORY=%s\n' "${UI_REPOSITORY}" >> "${SYSTEM_UPDATE_CONFIG}"
fi
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


SERVER_BACKUP_ROOT="${TEC_TAC_SERVER_BACKUP_ROOT:-/var/lib/tec-tac/server-backup}"
SERVER_BACKUP_HELPER="/usr/local/sbin/tec-tac-server-backup"
SERVER_BACKUP_LIB="/usr/local/lib/tec-tac-backup"
SERVER_BACKUP_SUDOERS="/etc/sudoers.d/tec-tac-server-backup"
HOUSEKEEPING_ROOT="${TEC_TAC_HOUSEKEEPING_ROOT:-/var/lib/tec-tac/housekeeping}"
HOUSEKEEPING_HELPER="/usr/local/sbin/tec-tac-housekeeping"
HOUSEKEEPING_LIB="/usr/local/lib/tec-tac-housekeeping"
HOUSEKEEPING_SUDOERS="/etc/sudoers.d/tec-tac-housekeeping"

mkdir -p "${SERVER_BACKUP_ROOT}/jobs" "${SERVER_BACKUP_ROOT}/logs" "${SERVER_BACKUP_ROOT}/staging" "${SERVER_BACKUP_ROOT}/pre-restore" "${SERVER_BACKUP_ROOT}/restore-overrides" "${SERVER_BACKUP_ROOT}/secrets"
chown root:"${TACTICAL_GROUP}" "${SERVER_BACKUP_ROOT}" "${SERVER_BACKUP_ROOT}/jobs" "${SERVER_BACKUP_ROOT}/logs" "${SERVER_BACKUP_ROOT}/staging" "${SERVER_BACKUP_ROOT}/pre-restore" "${SERVER_BACKUP_ROOT}/restore-overrides"
chmod 2750 "${SERVER_BACKUP_ROOT}" "${SERVER_BACKUP_ROOT}/logs" "${SERVER_BACKUP_ROOT}/staging" "${SERVER_BACKUP_ROOT}/pre-restore" "${SERVER_BACKUP_ROOT}/restore-overrides"
chmod 2770 "${SERVER_BACKUP_ROOT}/jobs"
chown root:root "${SERVER_BACKUP_ROOT}/secrets"
chmod 0700 "${SERVER_BACKUP_ROOT}/secrets"
run_as_tactical test -w "${SERVER_BACKUP_ROOT}/jobs" || fail "Tactical service user cannot write ${SERVER_BACKUP_ROOT}/jobs."

mkdir -p "${SERVER_BACKUP_LIB}"
install -o root -g root -m 0755 "${REPO_ROOT}/scripts/server-backup-helper.py" "${SERVER_BACKUP_LIB}/server-backup-helper.py"
install -o root -g root -m 0755 "${REPO_ROOT}/scripts/tactical-backup-sudo.py" "${SERVER_BACKUP_LIB}/sudo"
ln -sfn "${SERVER_BACKUP_LIB}/server-backup-helper.py" "${SERVER_BACKUP_HELPER}"
chown -h root:root "${SERVER_BACKUP_HELPER}"
cat > "${SERVER_BACKUP_SUDOERS}" <<EOF
${TACTICAL_USER} ALL=(root) NOPASSWD: ${SERVER_BACKUP_HELPER} --dispatch *
${TACTICAL_USER} ALL=(root) NOPASSWD: ${SERVER_BACKUP_HELPER} --tactical-privileged *
EOF
chown root:root "${SERVER_BACKUP_SUDOERS}"
chmod 0440 "${SERVER_BACKUP_SUDOERS}"
if command -v visudo >/dev/null 2>&1; then
    visudo -cf "${SERVER_BACKUP_SUDOERS}" >/dev/null || fail "Server backup sudoers validation failed."
fi
log "Installed privileged Core server-backup helper: ${SERVER_BACKUP_HELPER}"

mkdir -p "${HOUSEKEEPING_ROOT}/requests" "${HOUSEKEEPING_ROOT}/results" "${HOUSEKEEPING_LIB}"
chown -R root:"${TACTICAL_GROUP}" "${HOUSEKEEPING_ROOT}"
chmod 2770 "${HOUSEKEEPING_ROOT}"
chmod 2750 "${HOUSEKEEPING_ROOT}/results"
chmod 2770 "${HOUSEKEEPING_ROOT}/requests"
install -o root -g root -m 0755 "${REPO_ROOT}/scripts/housekeeping-helper.py" "${HOUSEKEEPING_LIB}/housekeeping-helper.py"
ln -sfn "${HOUSEKEEPING_LIB}/housekeeping-helper.py" "${HOUSEKEEPING_HELPER}"
chown -h root:root "${HOUSEKEEPING_HELPER}"
cat > "${HOUSEKEEPING_SUDOERS}" <<EOF
${TACTICAL_USER} ALL=(root) NOPASSWD: ${HOUSEKEEPING_HELPER} --scan *, ${HOUSEKEEPING_HELPER} --purge *
EOF
chown root:root "${HOUSEKEEPING_SUDOERS}"
chmod 0440 "${HOUSEKEEPING_SUDOERS}"
if command -v visudo >/dev/null 2>&1; then
    visudo -cf "${HOUSEKEEPING_SUDOERS}" >/dev/null || fail "Housekeeping sudoers validation failed."
fi
log "Installed Core housekeeping helper: ${HOUSEKEEPING_HELPER}"

log "Verifying Core server-backup capability registration."
VERIFY_SERVER_BACKUP_CODE="from tec_tac.capabilities import capability_status,get_capability; s=capability_status('core.server_backup',version='>=1,<2'); assert s['available'], s; p=get_capability('core.server_backup',version='>=1,<2'); assert all(hasattr(p,n) for n in ('create_backup','list_backups','restore_backup','validate_restore','apply_retention','store_secret','delete_secret')); print('TEC-TAC core.server_backup OK:', s['capability_version'], s['operations'])"
if ! run_as_tactical timeout 45s bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${VERIFY_SERVER_BACKUP_CODE}\""; then
    fail "Core server-backup capability verification failed or timed out."
fi


SCHEDULER_SERVICE="/etc/systemd/system/tec-tac-scheduler.service"
SCHEDULER_TIMER="/etc/systemd/system/tec-tac-scheduler.timer"
cat > "${SCHEDULER_SERVICE}" <<EOF
[Unit]
Description=Tec-Tac Scheduler Tick
After=network.target redis-server.service

[Service]
Type=oneshot
User=${TACTICAL_USER}
Group=${TACTICAL_GROUP}
WorkingDirectory=${BACKEND_DIR}
ExecStart=${VENV_PYTHON} ${MANAGE_PY} tec_tac_scheduler_tick
EOF
cat > "${SCHEDULER_TIMER}" <<EOF
[Unit]
Description=Run Tec-Tac Scheduler every minute

[Timer]
OnCalendar=*-*-* *:*:00
Persistent=true
AccuracySec=1s
Unit=tec-tac-scheduler.service

[Install]
WantedBy=timers.target
EOF
chown root:root "${SCHEDULER_SERVICE}" "${SCHEDULER_TIMER}"
chmod 0644 "${SCHEDULER_SERVICE}" "${SCHEDULER_TIMER}"
systemctl daemon-reload
systemctl enable --now tec-tac-scheduler.timer >/dev/null
log "Installed Tec-Tac scheduler timer: tec-tac-scheduler.timer"


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
    log "Keeping existing reporting permission assignment(s) unchanged."
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
    ACTIVE=0
    for _attempt in $(seq 1 30); do
        if systemctl is-active --quiet "${svc}"; then
            ACTIVE=1
            break
        fi
        sleep 1
    done
    if [[ "${ACTIVE}" -ne 1 ]]; then
        systemctl --no-pager --full status "${svc}" || true
        fail "${svc} did not return to active state."
    fi
    log "${svc}: active"

    SERVICE_USER="$(systemctl show "${svc}.service" -p User --value 2>/dev/null || true)"
    [[ -n "${SERVICE_USER}" ]] || SERVICE_USER="root"
    if ! runuser -u "${SERVICE_USER}" -- test -r "${MODULE_STATE_FILE}"; then
        fail "${svc} service user '${SERVICE_USER}' cannot read ${MODULE_STATE_FILE}."
    fi
    log "${svc}: module state readable by ${SERVICE_USER}"
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
log "Framework source: ${SOURCE_ROOT}"
log "Framework runtime: ${FRAMEWORK_DIR}"
log "Extensions: ${EXTENSIONS_DIR}"
log "Reportsets: ${REPORTSETS_DIR}"
log "Swagger endpoint: /api/tfd/reporting/network-availability/"
