#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"
MODE=check
JSON=0
VERBOSE=0
for arg in "$@"; do
  case "$arg" in
    --check) MODE=check;;
    --repair) MODE=repair;;
    --json) JSON=1;;
    --verbose) VERBOSE=1;;
    -h|--help) echo "Usage: $0 [--check|--repair] [--json] [--verbose]"; exit 0;;
    *) recovery_err "Unknown argument: $arg"; exit 2;;
  esac
done
require_root
if [[ "$MODE" == repair ]]; then
  repair_module_permissions
fi
set +e
OUTPUT="$(check_module_permissions)"; RC=$?
set -e
if [[ "$JSON" -eq 1 ]]; then
  RECOVERY_OUTPUT="$OUTPUT" python3 - "$RC" <<'PY'
import json,os,sys
rc=int(sys.argv[1]); rows=[]
for line in os.environ.get('RECOVERY_OUTPUT','').splitlines():
    parts=line.split('|')
    rows.append({'status':parts[0], 'check':parts[1] if len(parts)>1 else '', 'path':parts[2] if len(parts)>2 else '', 'details':parts[3:]})
print(json.dumps({'ok':rc==0,'issues':rc,'results':rows},indent=2))
PY
else
  while IFS='|' read -r status check path d1 d2; do
    [[ -n "$status" ]] || continue
    printf '[%s] %-14s %s' "$status" "$check" "$path"
    [[ -n "${d1:-}" ]] && printf '  %s' "$d1"
    [[ -n "${d2:-}" ]] && printf '  %s' "$d2"
    printf '\n'
  done <<< "$OUTPUT"
  if [[ "$RC" -eq 0 ]]; then recovery_log "Module Manager permissions are healthy."; else recovery_err "$RC permission issue(s) remain."; fi
fi
exit "$RC"
