#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"
MODE=check
for arg in "$@"; do case "$arg" in --check) MODE=check;; --repair) MODE=repair;; --verbose|--json) :;; -h|--help) echo "Usage: $0 [--check|--repair]"; exit 0;; *) recovery_err "Unknown argument: $arg"; exit 2;; esac; done
require_root
issues=0
for f in "$LOCAL_SETTINGS" "$VENV_PYTHON" "$MANAGE_PY"; do [[ -e "$f" ]] || { recovery_err "Missing $f"; issues=$((issues+1)); }; done
if [[ -f "$LOCAL_SETTINGS" ]]; then
  grep -q '^# BEGIN TEC-TAC EXTENSION FRAMEWORK$' "$LOCAL_SETTINGS" || { recovery_err "Tec-Tac bootstrap marker missing from local_settings.py"; issues=$((issues+1)); }
fi
if [[ "$issues" -eq 0 ]]; then
  if ! run_manage "check" >/dev/null; then recovery_err "Django system check failed."; issues=$((issues+1)); else recovery_log "Django system check: OK"; fi
  if ! run_manage "shell -c \"from django.urls import resolve; assert resolve('/api/tfd/modules/v2/'); print('routes OK')\"" >/dev/null; then recovery_err "Tec-Tac route verification failed."; issues=$((issues+1)); else recovery_log "Tec-Tac routes: OK"; fi
fi
if [[ "$MODE" == repair && "$issues" -gt 0 ]]; then
  recovery_log "Re-running the installed framework installer non-interactively."
  bash "${TEC_TAC_ROOT}/install.sh" </dev/null
  exit $?
fi
[[ "$issues" -eq 0 ]] || exit 1
