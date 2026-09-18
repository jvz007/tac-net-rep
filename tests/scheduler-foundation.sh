#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
grep -q 'class TecTacSchedule' "$ROOT/framwork/tec_tac/models.py"
grep -q 'register_scheduled_action' "$ROOT/framwork/tec_tac/scheduler.py"
grep -q 'tec_tac.execute_schedule_run' "$ROOT/framwork/tec_tac/tasks.py"
grep -q 'scheduler/schedules/' "$ROOT/framwork/tec_tac/urls.py"
grep -q 'tec-tac-scheduler.timer' "$ROOT/install.sh"
grep -q 'migrate tec_tac' "$ROOT/install.sh"
echo 'scheduler foundation: PASS'
