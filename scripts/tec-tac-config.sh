#!/usr/bin/env bash
# Shared Tec-Tac installation-layout loader. The config is parsed as data and is
# never sourced as shell code.
TEC_TAC_CONFIG_FILE="${TEC_TAC_CONFIG_FILE:-/opt/tec-tac/etc/tec-tac.conf}"
_tec_tac_load_config() {
  local file="$1" line key value
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || { printf 'Malformed Tec-Tac config line in %s\n' "$file" >&2; return 1; }
    key="${line%%=*}"; value="${line#*=}"
    [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || { printf 'Invalid Tec-Tac config key: %s\n' "$key" >&2; return 1; }
    case "$key" in
      TEC_TAC_*|TACTICAL_*|FRAMEWORK_REPOSITORY|UI_REPOSITORY|REPO_ROOT|UI_SYNC_SCRIPT|UI_ROOT|GITHUB_TOKEN_FILE) ;;
      *) printf 'Unsupported Tec-Tac config key: %s\n' "$key" >&2; return 1 ;;
    esac
    printf -v "$key" '%s' "$value"
  done < "$file"
}
if ! _tec_tac_load_config "${TEC_TAC_CONFIG_FILE}"; then
  unset -f _tec_tac_load_config
  return 1 2>/dev/null || exit 1
fi
unset -f _tec_tac_load_config
TEC_TAC_ROOT="${TEC_TAC_ROOT:-/opt/tec-tac}"
TEC_TAC_SOURCE_ROOT="${TEC_TAC_SOURCE_ROOT:-/opt/tec-tac-src}"
TEC_TAC_FRAMEWORK_SOURCE="${TEC_TAC_FRAMEWORK_SOURCE:-${TEC_TAC_SOURCE_ROOT}/framework}"
TEC_TAC_UI_SOURCE="${TEC_TAC_UI_SOURCE:-${TEC_TAC_SOURCE_ROOT}/ui}"
TEC_TAC_FRAMEWORK_ROOT="${TEC_TAC_FRAMEWORK_ROOT:-${TEC_TAC_ROOT}/framework}"
TEC_TAC_EXTENSIONS_ROOT="${TEC_TAC_EXTENSIONS_ROOT:-${TEC_TAC_ROOT}/extensions}"
TEC_TAC_REPORTSETS_ROOT="${TEC_TAC_REPORTSETS_ROOT:-${TEC_TAC_ROOT}/reportsets}"
TEC_TAC_SCRIPTS_ROOT="${TEC_TAC_SCRIPTS_ROOT:-${TEC_TAC_ROOT}/scripts}"
TEC_TAC_STATE_ROOT="${TEC_TAC_STATE_ROOT:-/var/lib/tec-tac}"
TEC_TAC_MODULE_STATE_ROOT="${TEC_TAC_MODULE_STATE_ROOT:-${TEC_TAC_STATE_ROOT}/module-manager}"
TEC_TAC_SYSTEM_UPDATE_ROOT="${TEC_TAC_SYSTEM_UPDATE_ROOT:-${TEC_TAC_STATE_ROOT}/system-updates}"
TEC_TAC_UI_DEPLOY_ROOT="${TEC_TAC_UI_DEPLOY_ROOT:-${TEC_TAC_STATE_ROOT}/ui/tec-tac}"
TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
TACTICAL_BACKEND_ROOT="${TACTICAL_BACKEND_ROOT:-${TACTICAL_ROOT}/api/tacticalrmm}"
TACTICAL_PYTHON="${TACTICAL_PYTHON:-${TACTICAL_ROOT}/api/env/bin/python}"
