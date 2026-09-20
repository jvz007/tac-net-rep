#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL $*" >&2; exit 1; }
grep -q 'def list_jobs' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "persistent lifecycle history reader missing"
grep -q 'modules/v2/jobs/' "${ROOT}/framwork/tec_tac/urls.py" || fail "module lifecycle history route missing"
grep -q 'ModuleV2JobHistoryView' "${ROOT}/framwork/tec_tac/module_v2_views.py" || fail "module lifecycle history API view missing"
grep -q 'requested_by' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "lifecycle requester audit field missing"
echo "[TEST] PASS module lifecycle history contract"
