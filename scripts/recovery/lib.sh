#!/usr/bin/env bash
set -o pipefail

CONFIG_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tec-tac-config.sh"
# shellcheck source=/dev/null
source "${CONFIG_HELPER}"
BACKEND_DIR="${TACTICAL_BACKEND_ROOT}"
VENV_PYTHON="${TACTICAL_PYTHON}"
MANAGE_PY="${BACKEND_DIR}/manage.py"
MODULE_ROOT="${MODULE_ROOT:-${TEC_TAC_MODULE_STATE_ROOT}}"
SYSTEM_UPDATE_ROOT="${SYSTEM_UPDATE_ROOT:-${TEC_TAC_SYSTEM_UPDATE_ROOT}}"
LOCAL_SETTINGS="${BACKEND_DIR}/tacticalrmm/local_settings.py"

recovery_log(){ printf '[TEC-TAC-RECOVERY] %s\n' "$*"; }
recovery_err(){ printf '[TEC-TAC-RECOVERY] ERROR: %s\n' "$*" >&2; }

require_root(){
  if [[ ${EUID} -ne 0 ]]; then
    recovery_err "Run as root (for example: sudo $0 $*)."
    exit 1
  fi
}

detect_tactical_user(){
  local user
  user="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
  if [[ -z "$user" ]]; then
    user="$(awk -F= '$1 == "User" {print $2; exit}' /etc/systemd/system/rmm.service 2>/dev/null || true)"
  fi
  [[ -n "$user" ]] || user="tactical"
  printf '%s\n' "$user"
}

detect_tactical_group(){
  local user="${1:-$(detect_tactical_user)}"
  id -gn "$user" 2>/dev/null || printf '%s\n' tactical
}

mode_of(){ stat -c '%a' "$1" 2>/dev/null || true; }
owner_of(){ stat -c '%U:%G' "$1" 2>/dev/null || true; }

module_permission_specs(){
  local group="$1"
  cat <<SPECS
${MODULE_ROOT}|root:${group}|2755
${MODULE_ROOT}/staged|root:${group}|2770
${MODULE_ROOT}/staged/bundles|root:${group}|2770
${MODULE_ROOT}/staged/batches|root:${group}|2770
${MODULE_ROOT}/jobs|root:${group}|2770
${MODULE_ROOT}/running|root:${group}|2750
${MODULE_ROOT}/running-v2|root:${group}|2750
${MODULE_ROOT}/logs|root:${group}|2750
${MODULE_ROOT}/bundle-backups|root:${group}|2750
${MODULE_ROOT}/repositories|root:${group}|2770
${MODULE_ROOT}/repositories/cache|root:${group}|2770
SPECS
}

ensure_path_spec(){
  local path="$1" owner="$2" mode="$3"
  install -d -o "${owner%%:*}" -g "${owner##*:}" -m "$mode" "$path"
}

check_module_permissions(){
  local user group failures=0 path owner expected_mode actual_owner actual_mode
  user="$(detect_tactical_user)"
  group="$(detect_tactical_group "$user")"
  while IFS='|' read -r path owner expected_mode; do
    [[ -n "$path" ]] || continue
    if [[ ! -d "$path" ]]; then
      printf 'FAIL|missing|%s|%s|%s\n' "$path" "$owner" "$expected_mode"
      failures=$((failures+1)); continue
    fi
    actual_owner="$(owner_of "$path")"; actual_mode="$(mode_of "$path")"
    if [[ "$actual_owner" != "$owner" || "$actual_mode" != "$expected_mode" ]]; then
      printf 'FAIL|mismatch|%s|%s/%s|%s/%s\n' "$path" "$actual_owner" "$owner" "$actual_mode" "$expected_mode"
      failures=$((failures+1))
    else
      printf 'OK|permissions|%s|%s|%s\n' "$path" "$actual_owner" "$actual_mode"
    fi
  done < <(module_permission_specs "$group")

  if [[ -f "${MODULE_ROOT}/module-state.json" ]]; then
    actual_owner="$(owner_of "${MODULE_ROOT}/module-state.json")"; actual_mode="$(mode_of "${MODULE_ROOT}/module-state.json")"
    if [[ "$actual_owner" != "root:root" || "$actual_mode" != "644" ]]; then
      printf 'FAIL|state-file|%s|%s/root:root|%s/644\n' "${MODULE_ROOT}/module-state.json" "$actual_owner" "$actual_mode"
      failures=$((failures+1))
    else
      printf 'OK|state-file|%s|root:root|644\n' "${MODULE_ROOT}/module-state.json"
    fi
  fi

  for writable in "${MODULE_ROOT}/staged" "${MODULE_ROOT}/staged/bundles" "${MODULE_ROOT}/staged/batches" "${MODULE_ROOT}/jobs"; do
    if ! runuser -u "$user" -- test -w "$writable" 2>/dev/null; then
      printf 'FAIL|runtime-write|%s|user=%s|not-writable\n' "$writable" "$user"
      failures=$((failures+1))
    else
      printf 'OK|runtime-write|%s|user=%s|writable\n' "$writable" "$user"
    fi
  done
  return "$failures"
}

repair_module_permissions(){
  local user group path owner mode
  user="$(detect_tactical_user)"
  group="$(detect_tactical_group "$user")"
  while IFS='|' read -r path owner mode; do
    [[ -n "$path" ]] || continue
    ensure_path_spec "$path" "$owner" "$mode"
  done < <(module_permission_specs "$group")
  if [[ ! -f "${MODULE_ROOT}/module-state.json" ]]; then
    printf '%s\n' '{"schema":1,"modules":{}}' > "${MODULE_ROOT}/module-state.json"
  fi
  chown root:root "${MODULE_ROOT}/module-state.json"
  chmod 0644 "${MODULE_ROOT}/module-state.json"
}

run_manage(){
  local user
  user="$(detect_tactical_user)"
  runuser -u "$user" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' $*"
}
