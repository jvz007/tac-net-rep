#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ${EUID} -ne 0 ]]; then echo "Run as root (sudo $0)." >&2; exit 1; fi
while true; do
  cat <<'MENU'

Tec-Tac Recovery Toolkit

1. Run diagnostics
2. Repair permissions
3. Check/repair module registry state
4. Recover missing modules from latest framework backup
5. Repair framework runtime/bootstrap
6. Repair scheduler
7. Run all safe repairs
8. Exit
MENU
  printf 'Selection: '; read -r choice
  case "$choice" in
    1) "${HERE}/tec-tac-diagnostics.sh" || true;;
    2) "${HERE}/tec-tac-repair-permissions.sh" --repair || true;;
    3) "${HERE}/tec-tac-repair-modules.sh" --repair || true;;
    4) "${HERE}/tec-tac-recover-modules-from-backup.sh" --repair || true;;
    5) "${HERE}/tec-tac-repair-runtime.sh" --repair || true;;
    6) "${HERE}/tec-tac-repair-scheduler.sh" --repair || true;;
    7)
      "${HERE}/tec-tac-repair-permissions.sh" --repair || true
      "${HERE}/tec-tac-repair-modules.sh" --repair || true
      "${HERE}/tec-tac-repair-scheduler.sh" --repair || true
      echo "Safe repairs complete. Module restoration and framework reinstallation are intentionally excluded."
      ;;
    8) exit 0;;
    *) echo "Invalid selection.";;
  esac
done
