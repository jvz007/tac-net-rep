#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"
MODE=check
for arg in "$@"; do case "$arg" in --check) MODE=check;; --repair) MODE=repair;; --verbose|--json) :;; -h|--help) echo "Usage: $0 [--check|--repair]"; exit 0;; *) recovery_err "Unknown argument: $arg"; exit 2;; esac; done
require_root
if [[ "$MODE" == repair ]]; then
  if [[ ! -f /etc/systemd/system/tec-tac-scheduler.timer || ! -f /etc/systemd/system/tec-tac-scheduler.service ]]; then
    recovery_log "Scheduler unit files missing; re-running framework installer non-interactively."
    bash "${TEC_TAC_ROOT}/install.sh" </dev/null
  else
    systemctl daemon-reload
    systemctl enable --now tec-tac-scheduler.timer >/dev/null
    systemctl restart tec-tac-scheduler.timer
  fi
fi
systemctl is-enabled --quiet tec-tac-scheduler.timer || { recovery_err "Scheduler timer is not enabled."; exit 1; }
systemctl is-active --quiet tec-tac-scheduler.timer || { recovery_err "Scheduler timer is not active."; exit 1; }
run_manage "shell -c \"from tacticalrmm.celery import app; app.autodiscover_tasks(force=True); assert 'tec_tac.execute_schedule_run' in app.tasks; print('scheduler task OK')\"" >/dev/null
recovery_log "Scheduler timer and Celery registration are healthy."
