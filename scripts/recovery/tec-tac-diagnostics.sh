#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"

JSON=0
for arg in "$@"; do
  case "$arg" in
    --json) JSON=1 ;;
    --check|--verbose) : ;;
    -h|--help) echo "Usage: $0 [--json]"; exit 0 ;;
    *) recovery_err "Unknown argument: $arg"; exit 2 ;;
  esac
done
require_root

read_version(){
  local path="$1"
  if [[ -f "$path" ]]; then tr -d '\r\n' < "$path"; else printf 'unknown'; fi
}

fw="$(read_version "${TEC_TAC_ROOT}/VERSION")"
fw_source="$(read_version "${TEC_TAC_FRAMEWORK_SOURCE}/VERSION")"
ui="$(read_version "${TEC_TAC_UI_DEPLOY_ROOT}/VERSION")"
ui_source="$(read_version "${TEC_TAC_UI_SOURCE}/VERSION")"

services=()
for svc in rmm daphne celery celerybeat tec-tac-scheduler.timer; do
  services+=("$svc:$(systemctl is-active "$svc" 2>/dev/null || true)")
done

set +e
perm="$(${HERE}/tec-tac-repair-permissions.sh --check 2>&1)"; prc=$?
mods="$(${HERE}/tec-tac-repair-modules.sh --check 2>&1)"; mrc=$?
set -e

migrations="unknown"
if [[ -x "$VENV_PYTHON" && -f "$MANAGE_PY" ]]; then
  if run_manage "makemigrations tec_tac --dry-run --check" >/dev/null 2>&1; then
    migrations=clean
  else
    migrations=drift
  fi
fi

arch_rc=0
arch_lines=()
arch_add(){
  local status="$1" key="$2" detail="$3"
  arch_lines+=("[${status}] architecture ${key} ${detail}")
  [[ "$status" == "OK" ]] || arch_rc=1
}

canonical(){
  readlink -f -- "$1" 2>/dev/null || printf '%s' "$1"
}

check_source_repo(){
  local label="$1" root="$2" status head branch
  if [[ ! -d "$root/.git" ]] || ! git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    arch_add FAIL "${label}-git" "${root} is not a Git checkout"
    return
  fi
  status="$(git -C "$root" status --porcelain --untracked-files=all 2>/dev/null || true)"
  head="$(git -C "$root" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  branch="$(git -C "$root" symbolic-ref --quiet --short HEAD 2>/dev/null || echo detached)"
  if [[ -n "$status" ]]; then
    arch_add FAIL "${label}-clean" "${root} dirty: $(printf '%s\n' "$status" | head -n1)"
  else
    arch_add OK "${label}-clean" "${root} branch=${branch} head=${head}"
  fi
}

[[ -f "${TEC_TAC_CONFIG_FILE}" ]] \
  && arch_add OK config "${TEC_TAC_CONFIG_FILE}" \
  || arch_add FAIL config "${TEC_TAC_CONFIG_FILE} missing"

expected_pairs=(
  "runtime|${TEC_TAC_ROOT}|/opt/tec-tac"
  "framework-source|${TEC_TAC_FRAMEWORK_SOURCE}|/opt/tec-tac-src/framework"
  "ui-source|${TEC_TAC_UI_SOURCE}|/opt/tec-tac-src/ui"
  "framework-runtime|${TEC_TAC_FRAMEWORK_ROOT}|/opt/tec-tac/framework"
  "ui-runtime|${TEC_TAC_UI_DEPLOY_ROOT}|/var/lib/tec-tac/ui/tec-tac"
)
for spec in "${expected_pairs[@]}"; do
  IFS='|' read -r key actual expected <<< "$spec"
  if [[ "$(canonical "$actual")" == "$(canonical "$expected")" ]]; then
    arch_add OK "${key}-path" "${actual}"
  else
    arch_add FAIL "${key}-path" "configured=${actual} expected=${expected}"
  fi
done

check_source_repo framework "${TEC_TAC_FRAMEWORK_SOURCE}"
check_source_repo ui "${TEC_TAC_UI_SOURCE}"

if [[ -e "${TEC_TAC_ROOT}/.git" ]]; then
  arch_add FAIL runtime-git "${TEC_TAC_ROOT}/.git exists"
else
  arch_add OK runtime-git "${TEC_TAC_ROOT} contains no Git metadata"
fi

if [[ "$(canonical "${TEC_TAC_FRAMEWORK_SOURCE}")" == "$(canonical "${TEC_TAC_FRAMEWORK_ROOT}")" ]]; then
  arch_add FAIL framework-separation "source and runtime resolve to the same path"
else
  arch_add OK framework-separation "${TEC_TAC_FRAMEWORK_SOURCE} != ${TEC_TAC_FRAMEWORK_ROOT}"
fi

if [[ "$fw_source" == "$fw" && "$fw" != "unknown" ]]; then
  arch_add OK framework-version "source=${fw_source} runtime=${fw}"
else
  arch_add FAIL framework-version "source=${fw_source} runtime=${fw}"
fi

if [[ "$ui_source" == "$ui" && "$ui" != "unknown" ]]; then
  arch_add OK ui-version "source=${ui_source} runtime=${ui}"
else
  arch_add FAIL ui-version "source=${ui_source} runtime=${ui}"
fi

import_path="unknown"
if [[ -x "$VENV_PYTHON" && -f "$MANAGE_PY" ]]; then
  tactical_user="$(detect_tactical_user)"
  import_path="$(runuser -u "$tactical_user" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"import tec_tac; print(tec_tac.__file__)\"" 2>/dev/null | tail -n1 || true)"
  [[ -n "$import_path" ]] || import_path="unknown"
fi
case "$import_path" in
  "${TEC_TAC_FRAMEWORK_ROOT%/}/"*) arch_add OK framework-import "$import_path" ;;
  *) arch_add FAIL framework-import "expected under ${TEC_TAC_FRAMEWORK_ROOT}; actual=${import_path}" ;;
esac

if [[ "$JSON" -eq 1 ]]; then
  ARCH_LINES="$(printf '%s\n' "${arch_lines[@]}")" python3 - "$fw" "$fw_source" "$ui" "$ui_source" "$prc" "$mrc" "$migrations" "$arch_rc" "${services[*]}" "$import_path" <<'PY'
import json,os,sys
architecture_lines=[line for line in os.environ.get('ARCH_LINES','').splitlines() if line]
print(json.dumps({
    'framework': sys.argv[1],
    'framework_source': sys.argv[2],
    'ui': sys.argv[3],
    'ui_source': sys.argv[4],
    'permissions_ok': sys.argv[5] == '0',
    'modules_ok': sys.argv[6] == '0',
    'migration_state': sys.argv[7],
    'architecture_ok': sys.argv[8] == '0',
    'services': dict(x.split(':',1) for x in sys.argv[9].split()),
    'framework_import': sys.argv[10],
    'architecture_checks': architecture_lines,
}, indent=2))
PY
else
  recovery_log "Framework: $fw"
  recovery_log "Framework source: $fw_source (${TEC_TAC_FRAMEWORK_SOURCE})"
  recovery_log "Runtime root: ${TEC_TAC_ROOT}"
  recovery_log "Framework runtime: ${TEC_TAC_FRAMEWORK_ROOT}"
  recovery_log "Extensions: ${TEC_TAC_EXTENSIONS_ROOT}"
  recovery_log "Reportsets: ${TEC_TAC_REPORTSETS_ROOT}"
  recovery_log "Config: ${TEC_TAC_CONFIG_FILE}"
  recovery_log "UI: $ui"
  recovery_log "UI source: $ui_source (${TEC_TAC_UI_SOURCE})"
  printf '%s\n' "${services[@]}" | sed 's/^/[SERVICE] /'
  printf '%s\n' "${arch_lines[@]}"
  printf '%s\n' "$perm"
  printf '%s\n' "$mods"
  recovery_log "Migration state: $migrations"
fi

[[ "$prc" -eq 0 && "$mrc" -eq 0 && "$migrations" == clean && "$arch_rc" -eq 0 ]] || exit 1
