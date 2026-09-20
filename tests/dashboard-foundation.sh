#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ -f "${ROOT}/framwork/tec_tac/dashboards.py" ]] || fail "dashboard service missing"
[[ -f "${ROOT}/framwork/tec_tac/dashboard_views.py" ]] || fail "dashboard API views missing"
[[ -f "${ROOT}/framwork/tec_tac/migrations/0005_dashboards.py" ]] || fail "dashboard migration missing"
grep -q 'class TecTacDashboard' "${ROOT}/framwork/tec_tac/models.py" || fail "dashboard model missing"
grep -q 'PRIVATE = "private"' "${ROOT}/framwork/tec_tac/models.py" || fail "private visibility missing"
grep -q 'SHARED = "shared"' "${ROOT}/framwork/tec_tac/models.py" || fail "shared visibility missing"
grep -q 'Q(owner=user).*Q(visibility=TecTacDashboard.Visibility.SHARED)' "${ROOT}/framwork/tec_tac/dashboards.py" || fail "private/shared visibility query missing"
grep -q 'dashboard.owner_id == user.id' "${ROOT}/framwork/tec_tac/dashboards.py" || fail "owner edit rule missing"
grep -q 'path("dashboards/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "dashboard list route missing"
grep -q 'path("dashboards/<uuid:dashboard_id>/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "dashboard detail route missing"
grep -q 'permission_classes = \[IsAuthenticated\]' "${ROOT}/framwork/tec_tac/dashboard_views.py" || fail "dashboard APIs must require authentication"
grep -q 'MAX_LAYOUT_BYTES = 512 \* 1024' "${ROOT}/framwork/tec_tac/dashboards.py" || fail "dashboard layout bound missing"
grep -q '"last_dashboard_id": None' "${ROOT}/framwork/tec_tac/preferences.py" || fail "last dashboard preference missing"
python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/dashboards.py" \
  "${ROOT}/framwork/tec_tac/dashboard_views.py" \
  "${ROOT}/framwork/tec_tac/models.py" \
  "${ROOT}/framwork/tec_tac/migrations/0005_dashboards.py"
echo '[TEST] PASS dashboard foundation'
