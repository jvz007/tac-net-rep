#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
DIAG="${ROOT}/framwork/tec_tac/diagnostics.py"
VIEW="${ROOT}/framwork/tec_tac/diagnostic_views.py"
[[ -f "$DIAG" ]] || fail "diagnostics service missing"
[[ -f "$VIEW" ]] || fail "diagnostics view missing"
grep -q 'path("system/diagnostics/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "diagnostics route missing"
grep -q 'MigrationAutodetector' "$DIAG" || fail "read-only migration drift detector missing"
grep -q 'list_capabilities(check_health=live)' "$DIAG" || fail "capability diagnostics must opt into live health"
grep -q 'live_capabilities' "$VIEW" || fail "explicit live capability switch missing"
grep -q '_require_module_manager' "$VIEW" || fail "server-maintenance authorization missing"
grep -q 'Core.*migration' "${ROOT}/docs/troubleshooting-diagnostics.md" || fail "diagnostics documentation missing migration guidance"
python3 -m py_compile "$DIAG" "$VIEW" "${ROOT}/framwork/tec_tac/urls.py"
echo "[TEST] PASS diagnostics foundation"
