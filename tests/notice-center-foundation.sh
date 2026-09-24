#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
for f in framwork/tec_tac/notices.py framwork/tec_tac/notice_views.py framwork/tec_tac/migrations/0009_user_notice_center.py; do
  [[ -f "${ROOT}/${f}" ]] || fail "missing ${f}"
done
grep -q 'class TecTacUserNotice' "${ROOT}/framwork/tec_tac/models.py" || fail "notice model missing"
grep -q 'ui/notices/' "${ROOT}/framwork/tec_tac/urls.py" || fail "notice routes missing"
grep -q 'NOTICE_RETENTION_DAYS = 30' "${ROOT}/framwork/tec_tac/notices.py" || fail "notice retention missing"
grep -q 'MAX_NOTICE_HISTORY = 500' "${ROOT}/framwork/tec_tac/notices.py" || fail "notice history cap missing"
grep -q 'route.startswith("//")' "${ROOT}/framwork/tec_tac/notices.py" || fail "protocol-relative route rejection missing"
grep -q 'plugins = get_plugins()' "${ROOT}/framwork/tec_tac/views.py" || fail "startup plugin snapshot reuse missing"
grep -q 'notice_unread_count' "${ROOT}/framwork/tec_tac/views.py" || fail "unread count missing from UI context"
python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/notices.py" \
  "${ROOT}/framwork/tec_tac/notice_views.py" \
  "${ROOT}/framwork/tec_tac/models.py" \
  "${ROOT}/framwork/tec_tac/rbac.py" \
  "${ROOT}/framwork/tec_tac/module_runtime.py" \
  "${ROOT}/framwork/tec_tac/views.py"
echo '[TEST] PASS notice center foundation'
