#!/usr/bin/env bash
set -euo pipefail

# Tec-Tac source/runtime layout migration
#
# Migrates:
#   /opt/tec-tac      (legacy Git checkout + runtime)
#   /opt/tec-tac-ui   (legacy UI Git checkout)
#
# To:
#   /opt/tec-tac-src/framework   Git source checkout
#   /opt/tec-tac-src/ui          Git source checkout
#   /opt/tec-tac/framework       live framework runtime
#   /opt/tec-tac/extensions      live extensions (preserved)
#   /opt/tec-tac/reportsets      live reportsets (preserved)
#   /opt/tec-tac/scripts         live runtime/admin scripts
#   /opt/tec-tac/etc/tec-tac.conf
#   /var/lib/tec-tac/ui/tec-tac  compiled UI (unchanged)
#
# Run after pulling the layout-aware framework release into /opt/tec-tac.

OLD_FRAMEWORK_REPO="${OLD_FRAMEWORK_REPO:-/opt/tec-tac}"
OLD_UI_REPO="${OLD_UI_REPO:-/opt/tec-tac-ui}"
SOURCE_ROOT="${TEC_TAC_SOURCE_ROOT:-/opt/tec-tac-src}"
FRAMEWORK_SOURCE="${TEC_TAC_FRAMEWORK_SOURCE:-${SOURCE_ROOT}/framework}"
UI_SOURCE="${TEC_TAC_UI_SOURCE:-${SOURCE_ROOT}/ui}"
RUNTIME_ROOT="${TEC_TAC_ROOT:-/opt/tec-tac}"
CONFIG_DIR="${TEC_TAC_CONFIG_DIR:-${RUNTIME_ROOT}/etc}"
CONFIG_FILE="${TEC_TAC_CONFIG_FILE:-${CONFIG_DIR}/tec-tac.conf}"
STATE_ROOT="${TEC_TAC_STATE_ROOT:-/var/lib/tec-tac}"
UI_DEPLOY_ROOT="${TEC_TAC_UI_DEPLOY_ROOT:-${STATE_ROOT}/ui/tec-tac}"
BACKUP_ROOT="${TEC_TAC_LAYOUT_BACKUP_ROOT:-${STATE_ROOT}/layout-migration-backups}"
TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_ROOT="${TACTICAL_BACKEND_ROOT:-${TACTICAL_ROOT}/api/tacticalrmm}"
TACTICAL_PYTHON="${TACTICAL_PYTHON:-${TACTICAL_ROOT}/api/env/bin/python}"
MANAGE_PY="${BACKEND_ROOT}/manage.py"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${BACKUP_ROOT}/${STAMP}"

log(){ printf '[TEC-TAC-LAYOUT] %s\n' "$*"; }
fail(){ printf '[TEC-TAC-LAYOUT] ERROR: %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || fail "Run as root: sudo bash $0"
command -v git >/dev/null 2>&1 || fail "git is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
[[ -d "${OLD_FRAMEWORK_REPO}/.git" ]] || fail "Legacy framework Git checkout not found at ${OLD_FRAMEWORK_REPO}"
[[ -d "${OLD_UI_REPO}/.git" ]] || fail "Legacy UI Git checkout not found at ${OLD_UI_REPO}"
[[ -x "${TACTICAL_PYTHON}" ]] || fail "Tactical Python not found: ${TACTICAL_PYTHON}"
[[ -f "${MANAGE_PY}" ]] || fail "Tactical manage.py not found: ${MANAGE_PY}"

mkdir -p "${BACKUP_DIR}"
chmod 0700 "${BACKUP_DIR}"

# Refuse to silently discard tracked local source edits. Untracked installed
# modules in the legacy mixed framework tree are expected and are preserved.
git -C "${OLD_FRAMEWORK_REPO}" diff --quiet || fail "Legacy framework checkout has uncommitted tracked changes; commit/stash them first."
git -C "${OLD_FRAMEWORK_REPO}" diff --cached --quiet || fail "Legacy framework checkout has staged changes; commit/stash them first."
git -C "${OLD_UI_REPO}" diff --quiet || fail "Legacy UI checkout has uncommitted tracked changes; commit/stash them first."
git -C "${OLD_UI_REPO}" diff --cached --quiet || fail "Legacy UI checkout has staged changes; commit/stash them first."

if [[ "${TEC_TAC_LAYOUT_SKIP_PULL:-0}" != "1" ]]; then
  log "Updating legacy source checkouts from GitHub before migration."
  git -C "${OLD_FRAMEWORK_REPO}" pull --ff-only
  git -C "${OLD_UI_REPO}" pull --ff-only
fi

python3 - "${OLD_FRAMEWORK_REPO}/VERSION" "${OLD_UI_REPO}/VERSION" <<'PY_VERSION'
import sys
from pathlib import Path

def parse(path):
    value=Path(path).read_text(encoding='utf-8').strip()
    return value, tuple(int(x) for x in value.split('.'))
fw, fwv=parse(sys.argv[1]); ui, uiv=parse(sys.argv[2])
if fwv < (1,13,0): raise SystemExit(f"Framework {fw} is too old for layout migration; require >=1.13.0")
if uiv < (0,10,3): raise SystemExit(f"UI {ui} is too old for layout migration; require >=0.10.3")
print(f"layout-aware source versions OK: framework={fw} ui={ui}")
PY_VERSION

MIGRATION_COMPLETE=0
rollback_layout(){
  local rc=$?
  if [[ "${MIGRATION_COMPLETE}" -eq 1 || "${rc}" -eq 0 ]]; then return; fi
  log "Migration failed; restoring pre-migration bootstrap/runtime selection."
  if [[ -f "${BACKUP_DIR}/local_settings.py" ]]; then
    cp -a "${BACKUP_DIR}/local_settings.py" "${BACKEND_ROOT}/tacticalrmm/local_settings.py" || true
  fi
  rm -rf "${RUNTIME_ROOT}/framework" "${RUNTIME_ROOT}/etc/tec-tac.conf" || true
  systemctl restart rmm daphne celery celerybeat >/dev/null 2>&1 || true
  log "Safety backups remain at ${BACKUP_DIR}."
}
trap rollback_layout EXIT

log "Creating safety backups before changing layout."
tar -C "$(dirname "${OLD_FRAMEWORK_REPO}")" -czf "${BACKUP_DIR}/legacy-framework-root.tar.gz" "$(basename "${OLD_FRAMEWORK_REPO}")"
tar -C "$(dirname "${OLD_UI_REPO}")" -czf "${BACKUP_DIR}/legacy-ui-source.tar.gz" "$(basename "${OLD_UI_REPO}")"
if [[ -d "${UI_DEPLOY_ROOT}" ]]; then
  tar -C "$(dirname "${UI_DEPLOY_ROOT}")" -czf "${BACKUP_DIR}/deployed-ui.tar.gz" "$(basename "${UI_DEPLOY_ROOT}")"
fi
if [[ -f "${BACKEND_ROOT}/tacticalrmm/local_settings.py" ]]; then
  cp -a "${BACKEND_ROOT}/tacticalrmm/local_settings.py" "${BACKUP_DIR}/local_settings.py"
fi

log "Validating currently installed module/reportset pairs and persistent module state before migration."
python3 - "${OLD_FRAMEWORK_REPO}/extensions" "${OLD_FRAMEWORK_REPO}/reportsets" "${STATE_ROOT}/module-manager/module-state.json" <<'PY'
import json, sys
from pathlib import Path

ext, rep, state_file = map(Path, sys.argv[1:])

def manifests(root):
    out = {}
    if not root.is_dir():
        return out
    for d in root.iterdir():
        p = d / "tec_tac.json"
        if d.is_dir() and p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            out[d.name] = data
    return out

def state_modules(path):
    if not path.is_file():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"module state is unreadable: {path}: {exc}")
    modules = payload.get("modules", {}) if isinstance(payload, dict) else None
    if not isinstance(modules, dict):
        raise SystemExit(f"module state has invalid structure: {path}")
    return {str(module_id) for module_id in modules if str(module_id).strip()}

e, r = manifests(ext), manifests(rep)
ignore = {"reporting"}
missing_r = sorted((set(e) - ignore) - set(r))
missing_e = sorted(set(r) - set(e))
if missing_r or missing_e:
    raise SystemExit(
        f"module pairing is not clean; missing reportsets={missing_r}, missing extensions={missing_e}"
    )

state_ids = state_modules(state_file)
missing_state_extensions = sorted(state_ids - set(e))
missing_state_reportsets = sorted(state_ids - set(r))
if missing_state_extensions or missing_state_reportsets:
    raise SystemExit(
        "persistent module state references module files that are absent; "
        f"missing extensions={missing_state_extensions}, missing reportsets={missing_state_reportsets}. "
        "Recover the missing module trees before running the layout migration."
    )

print(f"module pairing OK: {len(set(e) & set(r))} pair(s)")
print(f"module state/filesystem consistency OK: {len(state_ids)} state record(s)")
PY

mkdir -p "${SOURCE_ROOT}"

clone_local_repo(){
  local src="$1" dst="$2" label="$3"
  if [[ -d "${dst}/.git" ]]; then
    log "${label} source checkout already exists at ${dst}; verifying origin."
    git -C "${dst}" status --short >/dev/null
    return
  fi
  [[ ! -e "${dst}" ]] || fail "Target source path exists but is not a Git checkout: ${dst}"
  log "Creating ${label} source checkout at ${dst} from local repository."
  git clone --no-hardlinks "${src}" "${dst}"
}

clone_local_repo "${OLD_FRAMEWORK_REPO}" "${FRAMEWORK_SOURCE}" "framework"
clone_local_repo "${OLD_UI_REPO}" "${UI_SOURCE}" "UI"

FRAMEWORK_REMOTE="$(git -C "${OLD_FRAMEWORK_REPO}" remote get-url origin 2>/dev/null || true)"
UI_REMOTE="$(git -C "${OLD_UI_REPO}" remote get-url origin 2>/dev/null || true)"
[[ -n "${FRAMEWORK_REMOTE}" ]] && git -C "${FRAMEWORK_SOURCE}" remote set-url origin "${FRAMEWORK_REMOTE}"
[[ -n "${UI_REMOTE}" ]] && git -C "${UI_SOURCE}" remote set-url origin "${UI_REMOTE}"

mkdir -p "${CONFIG_DIR}"
cat > "${CONFIG_FILE}" <<EOF_CONFIG
# Tec-Tac installation layout. Managed by the Tec-Tac framework installer.
TEC_TAC_ROOT=${RUNTIME_ROOT}
TEC_TAC_CONFIG_FILE=${CONFIG_FILE}
TEC_TAC_SOURCE_ROOT=${SOURCE_ROOT}
TEC_TAC_FRAMEWORK_SOURCE=${FRAMEWORK_SOURCE}
TEC_TAC_UI_SOURCE=${UI_SOURCE}
TEC_TAC_FRAMEWORK_ROOT=${RUNTIME_ROOT}/framework
TEC_TAC_EXTENSIONS_ROOT=${RUNTIME_ROOT}/extensions
TEC_TAC_REPORTSETS_ROOT=${RUNTIME_ROOT}/reportsets
TEC_TAC_SCRIPTS_ROOT=${RUNTIME_ROOT}/scripts
TEC_TAC_STATE_ROOT=${STATE_ROOT}
TEC_TAC_MODULE_STATE_ROOT=${STATE_ROOT}/module-manager
TEC_TAC_SYSTEM_UPDATE_ROOT=${STATE_ROOT}/system-updates
TEC_TAC_UI_DEPLOY_ROOT=${UI_DEPLOY_ROOT}
TACTICAL_ROOT=${TACTICAL_ROOT}
TACTICAL_BACKEND_ROOT=${BACKEND_ROOT}
TACTICAL_PYTHON=${TACTICAL_PYTHON}
TACTICAL_USER=tactical
FRAMEWORK_REPOSITORY=jvz007/tac-net-rep
UI_REPOSITORY=jvz007/tec-tac-ui
EOF_CONFIG
chown root:root "${CONFIG_FILE}"
chmod 0644 "${CONFIG_FILE}"
log "Wrote authoritative layout config: ${CONFIG_FILE}"

# The layout-aware installer deploys source-owned code into the runtime tree,
# preserves dynamic modules/reportsets, updates bootstrap paths and helpers,
# and restarts/verifies Tactical services.
log "Deploying framework runtime from the new source checkout."
TEC_TAC_CONFIG_FILE="${CONFIG_FILE}" bash "${FRAMEWORK_SOURCE}/install.sh"

log "Building/deploying UI from the new source checkout."
TEC_TAC_CONFIG_FILE="${CONFIG_FILE}" bash "${UI_SOURCE}/scripts/install.sh"

log "Verifying Django against the new runtime path."
cd "${BACKEND_ROOT}"
"${TACTICAL_PYTHON}" "${MANAGE_PY}" check
"${TACTICAL_PYTHON}" "${MANAGE_PY}" shell -c "import tec_tac; p=tec_tac.__file__; assert p.startswith('${RUNTIME_ROOT}/framework/'), p; print('Tec-Tac runtime import OK:', p)"

if [[ -x "${RUNTIME_ROOT}/scripts/recovery/tec-tac-repair-modules.sh" ]]; then
  "${RUNTIME_ROOT}/scripts/recovery/tec-tac-repair-modules.sh" --check
fi

for svc in rmm daphne celery celerybeat; do
  systemctl is-active --quiet "${svc}" || fail "${svc} is not active after migration"
done
systemctl is-active --quiet tec-tac-scheduler.timer || fail "tec-tac-scheduler.timer is not active after migration"

log "Verifying source and runtime are independent."
[[ "$(readlink -f "${FRAMEWORK_SOURCE}")" != "$(readlink -f "${RUNTIME_ROOT}")" ]] || fail "framework source and runtime resolve to the same path"
[[ -d "${FRAMEWORK_SOURCE}/.git" ]] || fail "new framework source checkout has no .git"
[[ -d "${UI_SOURCE}/.git" ]] || fail "new UI source checkout has no .git"
[[ -d "${RUNTIME_ROOT}/framework/tec_tac" ]] || fail "runtime framework missing"
[[ -d "${RUNTIME_ROOT}/extensions" ]] || fail "runtime extensions missing"
[[ -d "${RUNTIME_ROOT}/reportsets" ]] || fail "runtime reportsets missing"

# Final cutover cleanup. Runtime must never be a Git checkout.
log "Removing legacy Git/source material from the runtime root only after validation succeeded."
rm -rf "${RUNTIME_ROOT}/.git" "${RUNTIME_ROOT}/framwork"
rm -rf "${RUNTIME_ROOT}/docs" "${RUNTIME_ROOT}/tests" "${RUNTIME_ROOT}/examples"
rm -f "${RUNTIME_ROOT}/install.sh" "${RUNTIME_ROOT}/uninstall.sh" "${RUNTIME_ROOT}/README.md" "${RUNTIME_ROOT}/.gitignore" "${RUNTIME_ROOT}/LICENSE"
find "${RUNTIME_ROOT}" -maxdepth 1 -type f -name 'RELEASE_NOTES_*.md' -delete

# Old UI source is no longer used after /opt/tec-tac-src/ui has been validated.
if [[ "$(readlink -f "${OLD_UI_REPO}")" != "$(readlink -f "${UI_SOURCE}")" ]]; then
  rm -rf "${OLD_UI_REPO}"
fi

cat > "${BACKUP_DIR}/MIGRATION_COMPLETE" <<EOF_DONE
completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
framework_source=${FRAMEWORK_SOURCE}
ui_source=${UI_SOURCE}
runtime_root=${RUNTIME_ROOT}
config=${CONFIG_FILE}
ui_deploy=${UI_DEPLOY_ROOT}
EOF_DONE

MIGRATION_COMPLETE=1
trap - EXIT
log "Migration completed successfully."
log "Framework source: ${FRAMEWORK_SOURCE}"
log "UI source: ${UI_SOURCE}"
log "Runtime: ${RUNTIME_ROOT}"
log "Config: ${CONFIG_FILE}"
log "UI deployment: ${UI_DEPLOY_ROOT}"
log "Safety backup: ${BACKUP_DIR}"
