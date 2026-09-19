#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"
JSON=0
for arg in "$@"; do case "$arg" in --json) JSON=1;; --check|--verbose) :;; -h|--help) echo "Usage: $0 [--json]"; exit 0;; *) recovery_err "Unknown argument: $arg"; exit 2;; esac; done
require_root
fw="$(cat "${TEC_TAC_ROOT}/VERSION" 2>/dev/null || echo unknown)"
ui="$(cat /var/lib/tec-tac/ui/tec-tac/VERSION 2>/dev/null || echo unknown)"
services=()
for svc in rmm daphne celery celerybeat tec-tac-scheduler.timer; do services+=("$svc:$(systemctl is-active "$svc" 2>/dev/null || true)"); done
set +e; perm="$(${HERE}/tec-tac-repair-permissions.sh --check 2>&1)"; prc=$?; mods="$(${HERE}/tec-tac-repair-modules.sh --check 2>&1)"; mrc=$?; set -e
migrations="unknown"
if [[ -x "$VENV_PYTHON" && -f "$MANAGE_PY" ]]; then
  if run_manage "makemigrations tec_tac --dry-run --check" >/dev/null 2>&1; then migrations=clean; else migrations=drift; fi
fi
if [[ "$JSON" -eq 1 ]]; then
  python3 - "$fw" "$ui" "$prc" "$mrc" "$migrations" "${services[*]}" <<'PY'
import json,sys
print(json.dumps({'framework':sys.argv[1],'ui':sys.argv[2],'permissions_ok':sys.argv[3]=='0','modules_ok':sys.argv[4]=='0','migration_state':sys.argv[5],'services':dict(x.split(':',1) for x in sys.argv[6].split())},indent=2))
PY
else
  recovery_log "Framework: $fw"
  recovery_log "Runtime root: ${TEC_TAC_ROOT}"
  recovery_log "Framework runtime: ${TEC_TAC_FRAMEWORK_ROOT}"
  recovery_log "Extensions: ${TEC_TAC_EXTENSIONS_ROOT}"
  recovery_log "Reportsets: ${TEC_TAC_REPORTSETS_ROOT}"
  recovery_log "Config: ${TEC_TAC_CONFIG_FILE}"
  recovery_log "UI: $ui"
  printf '%s\n' "${services[@]}" | sed 's/^/[SERVICE] /'
  printf '%s\n' "$perm"
  printf '%s\n' "$mods"
  recovery_log "Migration state: $migrations"
fi
[[ "$prc" -eq 0 && "$mrc" -eq 0 && "$migrations" == clean ]] || exit 1
