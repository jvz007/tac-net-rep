#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
S="$ROOT/framwork/tec_tac/scheduler.py"
T="$ROOT/framwork/tec_tac/tasks.py"
V="$ROOT/framwork/tec_tac/scheduler_views.py"
M="$ROOT/framwork/tec_tac/models.py"

grep -q 'Stale queued run exceeded' "$S"
grep -q 'Stale running run exceeded action timeout' "$S"
grep -q 'dispatch_failed.append' "$S"
grep -q 'MissedExpired' "$S"
grep -q 'MissedSkip' "$S"
grep -q 'MissedRecoveryWindowExpired' "$S"
grep -q 'if run.status != TecTacScheduleRun.Status.QUEUED' "$T"
grep -q 'run.schedule_snapshot_id' "$T"
grep -q 'parameters_snapshot' "$M"
grep -q 'retry_count_snapshot' "$M"
grep -q 'select_for_update().select_related' "$V"
grep -q 'code": "active_runs"' "$V"
grep -q 'ForceDeleted' "$V"
grep -q '_require_schedule_owner_or_manager' "$V"
echo 'scheduler durability review: PASS'
