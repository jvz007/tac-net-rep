#!/usr/bin/env bash
set -euo pipefail

# Tec-Tac extension package installer
#
# Installs one paired:
#   extensions/<extension-id>/
#   reportsets/<extension-id>/
#
# from a .zip, .tar.gz, or .tgz package.
#
# The archive may contain the extensions/ and reportsets/ directories at its
# root or beneath one wrapper directory.
#
# Usage:
#   sudo bash scripts/install-extension.sh ./networkprobe-0.1.0.zip
#   sudo bash scripts/install-extension.sh ./networkprobe-0.1.0.tar.gz
#   sudo bash scripts/install-extension.sh ./networkprobe-0.2.0.zip --replace

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

PACKAGE="${1:-}"
MODE="${2:-}"

log()  { printf '[TEC-TAC] %s\n' "$*"; }
fail() { printf '[TEC-TAC] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat >&2 <<'EOF'
Usage:
  sudo bash scripts/install-extension.sh <package.zip|package.tar.gz|package.tgz> [--replace]

Examples:
  sudo bash scripts/install-extension.sh ./networkprobe-0.1.0.zip
  sudo bash scripts/install-extension.sh ./networkprobe-0.1.0.tar.gz
  sudo bash scripts/install-extension.sh ./networkprobe-0.2.0.zip --replace
EOF
    exit 2
}

[[ ${EUID} -eq 0 ]] || fail "Run this installer as root."
[[ -n "${PACKAGE}" ]] || usage
[[ -f "${PACKAGE}" ]] || fail "Package not found: ${PACKAGE}"
[[ -z "${MODE}" || "${MODE}" == "--replace" ]] || usage

[[ -f "${FRAMEWORK_DIR}/tec_tac/registry.py" ]] || fail "Tec-Tac framework not found under ${REPO_ROOT}."
[[ -d "${EXTENSIONS_ROOT}" ]] || fail "Extensions root not found: ${EXTENSIONS_ROOT}"
[[ -d "${REPORTSETS_ROOT}" ]] || fail "Reportsets root not found: ${REPORTSETS_ROOT}"
[[ -x "${VENV_PYTHON}" ]] || fail "Tactical Python not found: ${VENV_PYTHON}"
[[ -f "${MANAGE_PY}" ]] || fail "Tactical manage.py not found: ${MANAGE_PY}"

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || fail "Could not determine Tactical service user."

TMP_ROOT="$(mktemp -d)"
PAYLOAD_ROOT="${TMP_ROOT}/payload"
mkdir -p "${PAYLOAD_ROOT}"

cleanup() {
    rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

# Use Python's archive readers so member names can be validated before
# extraction. Symlinks and hardlinks are rejected.
"${VENV_PYTHON}" - "${PACKAGE}" "${PAYLOAD_ROOT}" <<'PY'
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

archive = Path(sys.argv[1]).resolve()
dest = Path(sys.argv[2]).resolve()

def safe_name(name: str) -> Path:
    name = name.replace("\\", "/")
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts:
        raise SystemExit(f"[TEC-TAC] ERROR: unsafe archive path: {name!r}")
    return Path(*p.parts)

lower = archive.name.lower()

MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10000

if lower.endswith(".zip"):
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise SystemExit("[TEC-TAC] ERROR: archive contains too many members")
        if sum(info.file_size for info in infos) > MAX_EXTRACTED_BYTES:
            raise SystemExit("[TEC-TAC] ERROR: archive expands beyond the allowed size limit")
        for info in infos:
            rel = safe_name(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise SystemExit(
                    f"[TEC-TAC] ERROR: archive contains a symbolic link: {info.filename!r}"
                )
            target = (dest / rel).resolve()
            try:
                target.relative_to(dest)
            except ValueError:
                raise SystemExit(
                    f"[TEC-TAC] ERROR: archive path escapes extraction root: {info.filename!r}"
                )
        zf.extractall(dest)

elif lower.endswith(".tar.gz") or lower.endswith(".tgz"):
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise SystemExit("[TEC-TAC] ERROR: archive contains too many members")
        if sum(member.size for member in members if member.isfile()) > MAX_EXTRACTED_BYTES:
            raise SystemExit("[TEC-TAC] ERROR: archive expands beyond the allowed size limit")
        for member in members:
            safe_name(member.name)
            if member.issym() or member.islnk():
                raise SystemExit(
                    f"[TEC-TAC] ERROR: archive contains a link: {member.name!r}"
                )
            if not (member.isdir() or member.isfile()):
                raise SystemExit(
                    f"[TEC-TAC] ERROR: archive contains an unsupported special file: {member.name!r}"
                )
            target = (dest / Path(*PurePosixPath(member.name).parts)).resolve()
            try:
                target.relative_to(dest)
            except ValueError:
                raise SystemExit(
                    f"[TEC-TAC] ERROR: archive path escapes extraction root: {member.name!r}"
                )
        tf.extractall(dest)

else:
    raise SystemExit(
        "[TEC-TAC] ERROR: package must end in .zip, .tar.gz, or .tgz"
    )
PY

# Discover exactly one extension manifest and one reportset manifest and verify
# that the pair uses the same extension ID.
DISCOVERY="$("${VENV_PYTHON}" - "${PAYLOAD_ROOT}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()

def candidates(kind):
    found = []
    for manifest in root.rglob("tec_tac.json"):
        parent = manifest.parent
        if parent.parent.name != kind:
            continue
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SystemExit(
                f"[TEC-TAC] ERROR: unable to read {manifest}: {exc}"
            )
        if payload.get("type") == ("extension" if kind == "extensions" else "reportset"):
            found.append((manifest, payload))
    return found

ext = candidates("extensions")
rep = candidates("reportsets")

if len(ext) != 1:
    raise SystemExit(
        f"[TEC-TAC] ERROR: package must contain exactly one extension manifest; found {len(ext)}"
    )
if len(rep) != 1:
    raise SystemExit(
        f"[TEC-TAC] ERROR: package must contain exactly one reportset manifest; found {len(rep)}"
    )

ext_manifest, ext_payload = ext[0]
rep_manifest, rep_payload = rep[0]

ext_id = str(ext_payload.get("id", "")).strip()
rep_id = str(rep_payload.get("id", "")).strip()

if not ext_id or ext_id != rep_id:
    raise SystemExit(
        f"[TEC-TAC] ERROR: extension/reportset IDs do not match: {ext_id!r} vs {rep_id!r}"
    )
if ext_manifest.parent.name != ext_id or rep_manifest.parent.name != ext_id:
    raise SystemExit(
        "[TEC-TAC] ERROR: manifest ID must match its extension/reportset directory name"
    )

print(ext_id)
print(ext_manifest.parent)
print(rep_manifest.parent)
print(str(ext_payload.get("version", "0.0.0")).strip())
print(str(rep_payload.get("version", "0.0.0")).strip())
PY
)"

mapfile -t DISCOVERY_LINES <<< "${DISCOVERY}"
PLUGIN_ID="${DISCOVERY_LINES[0]}"
SOURCE_EXTENSION="${DISCOVERY_LINES[1]}"
SOURCE_REPORTSET="${DISCOVERY_LINES[2]}"
EXT_VERSION="${DISCOVERY_LINES[3]}"
REP_VERSION="${DISCOVERY_LINES[4]}"

DEST_EXTENSION="${EXTENSIONS_ROOT}/${PLUGIN_ID}"
DEST_REPORTSET="${REPORTSETS_ROOT}/${PLUGIN_ID}"

log "Package extension ID: ${PLUGIN_ID}"
log "Extension version: ${EXT_VERSION}"
log "Reportset version: ${REP_VERSION}"

if [[ -e "${DEST_EXTENSION}" || -e "${DEST_REPORTSET}" ]]; then
    [[ "${MODE}" == "--replace" ]] || fail \
        "Extension '${PLUGIN_ID}' is already installed. Re-run with --replace to upgrade/replace it."
fi

# Validate the package pair in isolation with the Tec-Tac registry before
# touching the live plugin directories.
STAGE_ROOT="${TMP_ROOT}/stage"
mkdir -p "${STAGE_ROOT}/extensions" "${STAGE_ROOT}/reportsets"
cp -a "${SOURCE_EXTENSION}" "${STAGE_ROOT}/extensions/${PLUGIN_ID}"
cp -a "${SOURCE_REPORTSET}" "${STAGE_ROOT}/reportsets/${PLUGIN_ID}"

PYTHONPATH="${FRAMEWORK_DIR}" \
"${VENV_PYTHON}" - "${STAGE_ROOT}" <<'PY'
import sys
from pathlib import Path
from tec_tac.registry import discover_plugins

root = Path(sys.argv[1])
plugins = discover_plugins(root / "extensions", root / "reportsets")
pairs = {(p.plugin_type, p.plugin_id) for p in plugins}
plugin_id = next(p.plugin_id for p in plugins if p.plugin_type == "extension")

assert ("extension", plugin_id) in pairs
assert ("reportset", plugin_id) in pairs
print(f"[TEC-TAC] Package registry validation OK: {plugin_id}")
PY

BACKUP_DIR=""
if [[ -e "${DEST_EXTENSION}" || -e "${DEST_REPORTSET}" ]]; then
    STAMP="$(date +%Y%m%dT%H%M%S)"
    BACKUP_DIR="${BACKUP_ROOT}/${PLUGIN_ID}/${STAMP}"
    mkdir -p "${BACKUP_DIR}/extensions" "${BACKUP_DIR}/reportsets"

    if [[ -e "${DEST_EXTENSION}" ]]; then
        cp -a "${DEST_EXTENSION}" "${BACKUP_DIR}/extensions/${PLUGIN_ID}"
    fi
    if [[ -e "${DEST_REPORTSET}" ]]; then
        cp -a "${DEST_REPORTSET}" "${BACKUP_DIR}/reportsets/${PLUGIN_ID}"
    fi

    log "Backed up installed plugin to ${BACKUP_DIR}"
fi

rollback() {
    log "Installation failed. Rolling back '${PLUGIN_ID}'."

    rm -rf "${DEST_EXTENSION}" "${DEST_REPORTSET}"

    if [[ -n "${BACKUP_DIR}" ]]; then
        if [[ -d "${BACKUP_DIR}/extensions/${PLUGIN_ID}" ]]; then
            cp -a "${BACKUP_DIR}/extensions/${PLUGIN_ID}" "${DEST_EXTENSION}"
        fi
        if [[ -d "${BACKUP_DIR}/reportsets/${PLUGIN_ID}" ]]; then
            cp -a "${BACKUP_DIR}/reportsets/${PLUGIN_ID}" "${DEST_REPORTSET}"
        fi
    fi
}
trap 'status=$?; if [[ $status -ne 0 ]]; then rollback; fi; cleanup; exit $status' EXIT

rm -rf "${DEST_EXTENSION}" "${DEST_REPORTSET}"
cp -a "${STAGE_ROOT}/extensions/${PLUGIN_ID}" "${DEST_EXTENSION}"
cp -a "${STAGE_ROOT}/reportsets/${PLUGIN_ID}" "${DEST_REPORTSET}"
chmod -R a+rX "${DEST_EXTENSION}" "${DEST_REPORTSET}"

# Validate the complete live registry, including conflicts with already
# installed plugins.
PYTHONPATH="${FRAMEWORK_DIR}" \
"${VENV_PYTHON}" - <<'PY'
from tec_tac.registry import get_plugins
plugins = get_plugins()
print("[TEC-TAC] Live registry validation OK:")
for p in plugins:
    print(f"[TEC-TAC]   {p.plugin_type}:{p.plugin_id}:{p.version}")
PY

# Verify that Tactical/Django can load the newly installed code.
runuser -u "${TACTICAL_USER}" -- bash -lc \
    "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' check"

# Apply migrations only for Django apps declared by this package and only when
# the app has a conventional migrations package containing migration files.
MIGRATION_MANIFESTS="${DEST_EXTENSION}/tec_tac.json:${DEST_REPORTSET}/tec_tac.json"

runuser -u "${TACTICAL_USER}" -- env \
    TEC_TAC_PLUGIN_MANIFESTS="${MIGRATION_MANIFESTS}" \
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

for config_path in declared:
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
        print(f"[TEC-TAC] Applying migrations for {cfg.label}")
        call_command("migrate", cfg.label, interactive=False, verbosity=1)
    else:
        print(f"[TEC-TAC] No conventional migrations found for {cfg.label}; skipping")
'

# Verify declared AppConfigs, model registry, and migration state before restart.
runuser -u "${TACTICAL_USER}" -- env \
    TEC_TAC_PLUGIN_MANIFESTS="${MIGRATION_MANIFESTS}" \
    "${VENV_PYTHON}" "${MANAGE_PY}" shell -c '
import json
import os
from pathlib import Path
from django.apps import apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils.module_loading import import_string

manifest_paths = os.environ["TEC_TAC_PLUGIN_MANIFESTS"].split(":")
declared = []
for manifest_path in manifest_paths:
    payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    declared.extend(payload.get("django_apps", []))

executor = MigrationExecutor(connection)
for config_path in declared:
    config_cls = import_string(config_path)
    matches = [cfg for cfg in apps.get_app_configs() if isinstance(cfg, config_cls)]
    if len(matches) != 1:
        raise RuntimeError(f"Declared AppConfig is not registered exactly once: {config_path}")
    cfg = matches[0]
    models = list(cfg.get_models())
    print(f"[TEC-TAC] AppConfig verification OK: {cfg.label}; models={len(models)}")
    leaves = executor.loader.graph.leaf_nodes(cfg.label)
    if leaves:
        pending = executor.migration_plan(leaves)
        if pending:
            names = ", ".join(f"{m.app_label}.{m.name}" for m, backwards in pending if not backwards)
            raise RuntimeError(f"Unapplied migrations remain for {cfg.label}: {names}")
        print(f"[TEC-TAC] Migration verification OK: {cfg.label}")
'

# Re-run checks after migrations.
runuser -u "${TACTICAL_USER}" -- bash -lc \
    "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' check"


# Extension-declared role permissions.
PERMISSION_MANIFEST="${DEST_EXTENSION}/tec_tac.json"
PERMISSION_GROUPS="$("${VENV_PYTHON}" - "${PERMISSION_MANIFEST}" <<'PY_PERM_GROUPS'
import json, sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for name in payload.get("permission_groups", {}):
    print(name)
PY_PERM_GROUPS
)"

if [[ -n "${PERMISSION_GROUPS}" ]]; then
    log "Extension '${PLUGIN_ID}' declares role permission group(s):"
    while IFS= read -r group; do [[ -n "${group}" ]] && log "  ${group}"; done <<< "${PERMISSION_GROUPS}"

    EXISTING_PERMISSION_CODE=$(cat <<'PY_EXISTING_PERMS'
import json, os
from pathlib import Path
from django.contrib.auth import get_user_model
from tfdreporting.models import ExtensionRolePermission
payload = json.loads(Path(os.environ["TEC_TAC_PERMISSION_MANIFEST"]).read_text(encoding="utf-8"))
codenames = sorted({p for values in payload.get("permission_groups", {}).values() for p in values})
rows = ExtensionRolePermission.objects.filter(codename__in=codenames, granted=True).order_by("role_id", "codename")
by_role = {}
for row in rows: by_role.setdefault(row.role_id, []).append(row.codename)
User = get_user_model(); users_by_role = {}; role_names = {}
for user in User.objects.all():
    try: role = user.get_and_set_role_cache()
    except Exception: continue
    if not role: continue
    role_names[role.id] = role.name
    users_by_role.setdefault(role.id, []).append(user.username)
for role_id, permissions in by_role.items():
    print("FOUND|{}|{}|{}|{}".format(role_id, role_names.get(role_id, "unknown"), ",".join(sorted(users_by_role.get(role_id, []))) or "none", ",".join(permissions)))
PY_EXISTING_PERMS
)
    EXISTING_PERMISSIONS="$(runuser -u "${TACTICAL_USER}" -- env TEC_TAC_PERMISSION_MANIFEST="${PERMISSION_MANIFEST}" bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell" <<< "${EXISTING_PERMISSION_CODE}")"
    EXISTING_FOUND="$(printf '%s\n' "${EXISTING_PERMISSIONS}" | grep '^FOUND|' || true)"
    PERMISSION_USERNAME="${TEC_TAC_EXTENSION_USERNAME:-}"
    PERMISSION_GROUP="${TEC_TAC_EXTENSION_PERMISSION_GROUP:-}"
    SHOULD_ASSIGN=0

    if [[ -n "${PERMISSION_USERNAME}" ]]; then
        SHOULD_ASSIGN=1
    elif [[ -n "${EXISTING_FOUND}" ]]; then
        log "Existing permission assignment(s) for '${PLUGIN_ID}' found:"
        while IFS='|' read -r marker role_id role_name users permissions; do
            [[ "${marker}" == "FOUND" ]] || continue
            log "Role: ${role_name} (id=${role_id}); users: ${users}; permissions: ${permissions}"
        done <<< "${EXISTING_FOUND}"
        if [[ -t 0 ]]; then
            printf "[TEC-TAC] Change/add '%s' extension permission assignment? [y/N]: " "${PLUGIN_ID}"
            read -r answer
            case "${answer}" in y|Y|yes|YES) SHOULD_ASSIGN=1 ;; *) log "Keeping existing extension permission assignment(s) unchanged." ;; esac
        else
            log "Keeping existing extension permission assignment(s) unchanged."
        fi
    elif [[ -t 0 ]]; then
        printf "[TEC-TAC] Tactical username to receive '%s' extension permissions (blank to skip): " "${PLUGIN_ID}"
        read -r PERMISSION_USERNAME
        [[ -n "${PERMISSION_USERNAME}" ]] && SHOULD_ASSIGN=1
    else
        log "No existing extension permission assignment found; non-interactive install is skipping assignment."
    fi

    if [[ ${SHOULD_ASSIGN} -eq 1 ]]; then
        if [[ -z "${PERMISSION_USERNAME}" ]]; then printf "[TEC-TAC] Tactical username: "; read -r PERMISSION_USERNAME; fi
        [[ -n "${PERMISSION_USERNAME}" ]] || fail "A Tactical username is required to assign extension permissions."
        if [[ -z "${PERMISSION_GROUP}" ]]; then
            DEFAULT_GROUP="$(printf '%s\n' "${PERMISSION_GROUPS}" | grep -x 'manage' | head -n1 || true)"
            [[ -n "${DEFAULT_GROUP}" ]] || DEFAULT_GROUP="$(printf '%s\n' "${PERMISSION_GROUPS}" | head -n1)"
            if [[ -t 0 ]]; then
                log "Available permission groups:"
                while IFS= read -r group; do [[ -n "${group}" ]] && log "  ${group}"; done <<< "${PERMISSION_GROUPS}"
                printf "[TEC-TAC] Permission group [%s]: " "${DEFAULT_GROUP}"
                read -r PERMISSION_GROUP
                PERMISSION_GROUP="${PERMISSION_GROUP:-${DEFAULT_GROUP}}"
            else
                PERMISSION_GROUP="${DEFAULT_GROUP}"
            fi
        fi
        printf '%s\n' "${PERMISSION_GROUPS}" | grep -Fxq "${PERMISSION_GROUP}" || fail "Unknown permission group '${PERMISSION_GROUP}' for extension '${PLUGIN_ID}'."
        runuser -u "${TACTICAL_USER}" -- env TEC_TAC_PERMISSION_USERNAME="${PERMISSION_USERNAME}" TEC_TAC_PERMISSION_PLUGIN="${PLUGIN_ID}" TEC_TAC_PERMISSION_GROUP="${PERMISSION_GROUP}" "${VENV_PYTHON}" "${MANAGE_PY}" shell -c '
from django.contrib.auth import get_user_model
import os
from tec_tac.rbac import grant_permission_group, get_role_permissions
username=os.environ["TEC_TAC_PERMISSION_USERNAME"]; plugin_id=os.environ["TEC_TAC_PERMISSION_PLUGIN"]; group_name=os.environ["TEC_TAC_PERMISSION_GROUP"]
User=get_user_model(); user=User.objects.get(username=username); role=user.get_and_set_role_cache()
if not role: raise RuntimeError(f"Tactical user {username!r} has no role assigned")
grant_permission_group(role, plugin_id, group_name)
print(f"[TEC-TAC] User: {user.username}"); print(f"[TEC-TAC] Tactical role: {role.name} (id={role.id})"); print(f"[TEC-TAC] Granted permission group: {group_name}")
for codename, granted in get_role_permissions(role, plugin_id).items(): print(f"[TEC-TAC] {codename}={granted}")
print("[TEC-TAC] NOTE: Tec-Tac permissions are role-based; all users sharing this role inherit the grants.")
'
    fi
fi

log "Reloading Tactical Django application without restarting the rmm service."
bash "${REPO_ROOT}/scripts/reload-rmm-uwsgi.sh"
systemctl is-active --quiet rmm || fail "rmm is not active after graceful uWSGI reload."
log "rmm: active (graceful uWSGI reload complete)"

# Start a fresh Django process after the graceful uWSGI reload. This catches bootstrap,
# AppConfig, import, model-registry, and migration-state problems that only show
# up after process recreation.
runuser -u "${TACTICAL_USER}" -- env \
    TEC_TAC_PLUGIN_MANIFESTS="${MIGRATION_MANIFESTS}" \
    "${VENV_PYTHON}" "${MANAGE_PY}" shell -c '
import json
import os
from pathlib import Path
from django.apps import apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils.module_loading import import_string

manifest_paths = os.environ["TEC_TAC_PLUGIN_MANIFESTS"].split(":")
declared = []
for manifest_path in manifest_paths:
    payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    declared.extend(payload.get("django_apps", []))
executor = MigrationExecutor(connection)
for config_path in declared:
    config_cls = import_string(config_path)
    matches = [cfg for cfg in apps.get_app_configs() if isinstance(cfg, config_cls)]
    if len(matches) != 1:
        raise RuntimeError(f"Fresh-process AppConfig verification failed: {config_path}")
    cfg = matches[0]
    list(cfg.get_models())
    leaves = executor.loader.graph.leaf_nodes(cfg.label)
    pending = executor.migration_plan(leaves) if leaves else []
    if pending:
        names = ", ".join(f"{m.app_label}.{m.name}" for m, backwards in pending if not backwards)
        raise RuntimeError(f"Fresh-process migration verification failed for {cfg.label}: {names}")
    print(f"[TEC-TAC] Fresh-process verification OK: {cfg.label}")
'

# Capability and scheduled-action registrations live in Django/Celery process
# memory. Refresh the worker after extension install/upgrade so unattended
# execution sees the same module contracts as the web runtime. Bundle installs
# may defer this and refresh once after the complete dependency plan.
if [[ "${TEC_TAC_DEFER_WORKER_REFRESH:-0}" != "1" ]]; then
    log "Restarting Tactical Celery worker to refresh module capabilities/actions."
    systemctl restart celery
    systemctl is-active --quiet celery || fail "celery is not active after module runtime refresh."
    log "celery: active (module runtime refreshed)"
else
    log "Celery worker refresh deferred to parent module lifecycle job."
fi

log "Installed extension/reportset '${PLUGIN_ID}' successfully."
log "Extension: ${DEST_EXTENSION}"
log "Reportset: ${DEST_REPORTSET}"
[[ -n "${BACKUP_DIR}" ]] && log "Previous version backup: ${BACKUP_DIR}"

# Success: replace the rollback trap with normal cleanup.
trap cleanup EXIT
