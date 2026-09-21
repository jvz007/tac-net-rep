#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ -f "${ROOT}/framwork/tec_tac/preferences.py" ]] || fail "preferences service missing"
[[ -f "${ROOT}/framwork/tec_tac/preference_views.py" ]] || fail "preferences API view missing"
[[ -f "${ROOT}/framwork/tec_tac/migrations/0004_user_preferences.py" ]] || fail "user preferences migration missing"
grep -q 'class TecTacUserPreferences' "${ROOT}/framwork/tec_tac/models.py" || fail "user preferences model missing"
grep -q 'permission_classes = \[IsAuthenticated\]' "${ROOT}/framwork/tec_tac/preference_views.py" || fail "preference endpoint must require authentication"
grep -q 'path("ui/preferences/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "preference route missing"
grep -q 'preferences_initialized' "${ROOT}/framwork/tec_tac/views.py" || fail "UI context preference metadata missing"
grep -q 'MAX_PREFERENCE_BYTES = 128 \* 1024' "${ROOT}/framwork/tec_tac/preferences.py" || fail "preference payload bound missing"
grep -q '"extensions": {}' "${ROOT}/framwork/tec_tac/preferences.py" || fail "extension preference namespace missing"
grep -q '"font_scale": 1.0' "${ROOT}/framwork/tec_tac/preferences.py" || fail "font scale default missing"
grep -q 'FONT_SCALES = {0.9, 1.0, 1.1, 1.2}' "${ROOT}/framwork/tec_tac/preferences.py" || fail "font scale validation set missing"
grep -q 'appearance.font_scale must be one of 0.9, 1.0, 1.1, or 1.2.' "${ROOT}/framwork/tec_tac/preferences.py" || fail "font scale validation missing"
python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/preferences.py" \
  "${ROOT}/framwork/tec_tac/preference_views.py" \
  "${ROOT}/framwork/tec_tac/models.py" \
  "${ROOT}/framwork/tec_tac/migrations/0004_user_preferences.py"
echo '[TEST] PASS user preferences foundation'
