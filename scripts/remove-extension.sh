#!/usr/bin/env bash
set -euo pipefail

# Tec-Tac extension remover
#
# Removes one paired:
#   extensions/<extension-id>/
#   reportsets/<extension-id>/
#
# By default, code is removed but database migrations/data are preserved.
#
# Usage:
#   sudo bash scripts/remove-extension.sh networkprobe
#   sudo bash scripts/remove-extension.sh networkprobe --purge-data
#
# Optional:
#   --yes      skip confirmation prompt

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${HERE}/tec-tac-config.sh"
REPO_ROOT="${TEC_TAC_ROOT}"
FRAMEWORK_DIR="${TEC_TAC_FRAMEWORK_ROOT}"
EXTENSIONS_ROOT="${TEC_TAC_EXTENSIONS_ROOT}"
REPORTSETS_ROOT="${TEC_TAC_REPORTSETS_ROOT}"

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"

BACKUP_ROOT="${TEC_TAC_BACKUP_DIR:-/var/lib/tec-tac/backups}/plugins"

PLUGIN_ID="${1:-}"
MODE="${2:-}"
ASSUME_YES="${3:-}"

log()  { printf '[TEC-TAC] %s\n' "$*"; }
fail() { printf '[TEC-TAC] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat >&2 <<'EOF'
Usage:
  sudo bash scripts/remove-extension.sh <extension-id> [--purge-data] [--yes]

Examples:
  sudo bash scripts/remove-extension.sh networkprobe
  sudo bash scripts/remove-extension.sh networkprobe --purge-data
  sudo bash scripts/remove-extension.sh networkprobe --purge-data --yes
EOF
    exit 2
}

[[ ${EUID} -eq 0 ]] || fail "Run this remover as root."
[[ -n "${PLUGIN_ID}" ]] || usage
[[ "${PLUGIN_ID}" =~ ^[A-Za-z0-9_-]+$ ]] || fail "Invalid extension ID."

case "${MODE}" in
    ""|--purge-data) ;;
    *) usage ;;
esac

if [[ -n "${ASSUME_YES}" && "${ASSUME_YES}" != "--yes" ]]; then
    usage
fi

EXT_DIR="${EXTENSIONS_ROOT}/${PLUGIN_ID}"
REP_DIR="${REPORTSETS_ROOT}/${PLUGIN_ID}"

[[ -d "${EXT_DIR}" ]] || fail "Extension not found: ${EXT_DIR}"
[[ -d "${REP_DIR}" ]] || fail "Matching reportset not found: ${REP_DIR}"
[[ -f "${EXT_DIR}/tec_tac.json" ]] || fail "Missing extension manifest."
[[ -f "${REP_DIR}/tec_tac.json" ]] || fail "Missing reportset manifest."
[[ -x "${VENV_PYTHON}" ]] || fail "Tactical Python not found."
[[ -f "${MANAGE_PY}" ]] || fail "Tactical manage.py not found."

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || fail "Could not determine Tactical service user."

# Verify that the live pair resolves and matches the requested ID.
PYTHONPATH="${FRAMEWORK_DIR}" \
"${VENV_PYTHON}" - "${PLUGIN_ID}" <<'PY'
import sys
from tec_tac.registry import get_plugin

plugin_id = sys.argv[1]
ext = get_plugin(plugin_id, "extension")
rep = get_plugin(plugin_id, "reportset")

assert ext.plugin_id == plugin_id
assert rep.plugin_id == plugin_id

print(f"[TEC-TAC] Found extension: {ext.plugin_id} {ext.version}")
print(f"[TEC-TAC] Found reportset: {rep.plugin_id} {rep.version}")
PY

if [[ "${PLUGIN_ID}" == "example" ]]; then
    log "WARNING: '${PLUGIN_ID}' is the Tec-Tac reference implementation."
fi

if [[ "${PLUGIN_ID}" == "legacy-reporting-poc" || "${PLUGIN_ID}" == "reporting" ]]; then
    fail "This script is for convention-based extension/reportset pairs, not the legacy reporting POC."
fi

if [[ "${MODE}" == "--purge-data" ]]; then
    log "WARNING: --purge-data will attempt to reverse migrations for Django apps declared by this extension/reportset."
    log "This may permanently delete plugin-owned database tables/data."
else
    log "Database objects will be preserved."
fi

if [[ "${ASSUME_YES}" != "--yes" && -t 0 ]]; then
    printf "[TEC-TAC] Remove extension/reportset '%s'? [y/N]: " "${PLUGIN_ID}"
    read -r answer
    case "${answer}" in
        y|Y|yes|YES) ;;
        *) log "Removal cancelled."; exit 0 ;;
    esac
fi

STAMP="$(date +%Y%m%dT%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${PLUGIN_ID}/removed-${STAMP}"
mkdir -p "${BACKUP_DIR}/extensions" "${BACKUP_DIR}/reportsets"
cp -a "${EXT_DIR}" "${BACKUP_DIR}/extensions/${PLUGIN_ID}"
cp -a "${REP_DIR}" "${BACKUP_DIR}/reportsets/${PLUGIN_ID}"
log "Backed up plugin code to ${BACKUP_DIR}"

if [[ "${MODE}" == "--purge-data" ]]; then
    # Reverse migrations for declared Django apps before removing code.
    MANIFESTS="${EXT_DIR}/tec_tac.json:${REP_DIR}/tec_tac.json"

    runuser -u "${TACTICAL_USER}" -- env \
        TEC_TAC_PLUGIN_MANIFESTS="${MANIFESTS}" \
        "${VENV_PYTHON}" "${MANAGE_PY}" shell -c '
import json
import os
from pathlib import Path
from django.apps import apps
from django.core.management import call_command
from django.utils.module_loading import import_string

manifest_paths = os.environ["TEC_TAC_PLUGIN_MANIFESTS"].split(":")
declared = []

for manifest_path in manifest_paths:
    payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    declared.extend(payload.get("django_apps", []))

# Reverse reportset first, then extension, in case reportset migrations depend
# on extension-owned models.
for config_path in reversed(declared):
    config_cls = import_string(config_path)
    matches = [cfg for cfg in apps.get_app_configs() if isinstance(cfg, config_cls)]
    if len(matches) != 1:
        raise RuntimeError(
            f"Could not resolve exactly one registered AppConfig for {config_path!r}"
        )

    cfg = matches[0]
    migrations_dir = Path(cfg.path) / "migrations"
    migration_files = (
        list(migrations_dir.glob("[0-9][0-9][0-9][0-9]_*.py"))
        if migrations_dir.is_dir()
        else []
    )

    if migration_files:
        print(f"[TEC-TAC] Reversing migrations for {cfg.label}")
        call_command("migrate", cfg.label, "zero", interactive=False, verbosity=1)
    else:
        print(f"[TEC-TAC] No conventional migrations found for {cfg.label}; skipping")
'
fi


# Disable active role grants declared by this extension before removing code.
runuser -u "${TACTICAL_USER}" -- env TEC_TAC_REMOVE_PERMISSION_MANIFEST="${EXT_DIR}/tec_tac.json" "${VENV_PYTHON}" "${MANAGE_PY}" shell -c '
import json, os
from pathlib import Path
from tfdreporting.models import ExtensionRolePermission
payload=json.loads(Path(os.environ["TEC_TAC_REMOVE_PERMISSION_MANIFEST"]).read_text(encoding="utf-8"))
codenames=sorted({p for values in payload.get("permission_groups", {}).values() for p in values})
if codenames:
    updated=ExtensionRolePermission.objects.filter(codename__in=codenames, granted=True).update(granted=False)
    print(f"[TEC-TAC] Revoked {updated} active extension permission grant(s).")
else:
    print("[TEC-TAC] Extension declares no permission groups; no grants to revoke.")
'

rm -rf "${EXT_DIR}" "${REP_DIR}"
log "Removed extension code: ${EXT_DIR}"
log "Removed reportset code: ${REP_DIR}"

# Validate remaining convention-based plugins after removal.
PYTHONPATH="${FRAMEWORK_DIR}" \
"${VENV_PYTHON}" - <<'PY'
from tec_tac.registry import get_plugins
plugins = get_plugins()
print("[TEC-TAC] Remaining plugin registry:")
for p in plugins:
    print(f"[TEC-TAC]   {p.plugin_type}:{p.plugin_id}:{p.version}")
PY

runuser -u "${TACTICAL_USER}" -- bash -lc \
    "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' check"

log "Reloading Tactical Django application without restarting the rmm service."
bash "${REPO_ROOT}/scripts/reload-rmm-uwsgi.sh"
systemctl is-active --quiet rmm || fail "rmm is not active after graceful uWSGI reload."
log "rmm: active (graceful uWSGI reload complete)"

# Remove stale in-memory capability/action registrations from the worker.
if [[ "${TEC_TAC_DEFER_WORKER_REFRESH:-0}" != "1" ]]; then
    log "Restarting Tactical Celery worker to remove stale module capabilities/actions."
    systemctl restart celery
    systemctl is-active --quiet celery || fail "celery is not active after module runtime refresh."
    log "celery: active (module runtime refreshed)"
else
    log "Celery worker refresh deferred to parent module lifecycle job."
fi

log "Extension/reportset '${PLUGIN_ID}' removed successfully."
log "Backup retained at: ${BACKUP_DIR}"

if [[ "${MODE}" == "--purge-data" ]]; then
    log "Plugin migrations were reversed before code removal."
else
    log "Plugin database objects were preserved."
fi
