#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

for f in \
  framwork/tec_tac/session_security.py \
  framwork/tec_tac/session_security_views.py \
  framwork/tec_tac/migrations/0007_session_security.py \
  docs/session-security.md; do
  [[ -f "${ROOT}/${f}" ]] || fail "missing ${f}"
done

grep -q 'CAPABILITY_ID = "core.session_security"' "${ROOT}/framwork/tec_tac/session_security.py" || fail "capability id missing"
grep -q 'CAPABILITY_VERSION = "1.0.0"' "${ROOT}/framwork/tec_tac/session_security.py" || fail "capability version missing"
grep -q 'DEFAULT_IDLE_TIMEOUT_MINUTES = 30' "${ROOT}/framwork/tec_tac/session_security.py" || fail "idle default missing"
grep -q 'DEFAULT_ABSOLUTE_LIFETIME_MINUTES = 8 \* 60' "${ROOT}/framwork/tec_tac/session_security.py" || fail "absolute default missing"
grep -q 'DEFAULT_ACTIVITY_HEARTBEAT_SECONDS = 60' "${ROOT}/framwork/tec_tac/session_security.py" || fail "heartbeat default missing"
grep -q 'DEFAULT_IP_CHANGE_POLICY = "reauthenticate"' "${ROOT}/framwork/tec_tac/session_security.py" || fail "IP default missing"
grep -q 'hmac.new' "${ROOT}/framwork/tec_tac/session_security.py" || fail "HMAC credential fingerprint missing"
grep -q 'HTTP_X_FORWARDED_FOR' "${ROOT}/framwork/tec_tac/session_security.py" || fail "forwarded IP handling missing"
grep -q 'class SessionAuthenticated' "${ROOT}/framwork/tec_tac/session_security.py" || fail "session permission missing"
grep -q 'class TecTacSessionTrust' "${ROOT}/framwork/tec_tac/models.py" || fail "session trust model missing"
grep -q 'class TecTacSessionSecurityConfig' "${ROOT}/framwork/tec_tac/models.py" || fail "session config model missing"
grep -q 'class TecTacSessionAudit' "${ROOT}/framwork/tec_tac/models.py" || fail "session audit model missing"
grep -q 'register_core_session_security_capability' "${ROOT}/framwork/tec_tac/apps.py" || fail "Core capability registration missing"

grep -q 'path("session/current/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "current session endpoint missing"
grep -q 'path("session/activity/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "activity endpoint missing"
grep -q 'path("session/policy/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "policy endpoint missing"
grep -q 'path("session/audit/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "audit endpoint missing"
grep -q 'path("session/diagnostics/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "diagnostics endpoint missing"
grep -q '"name": "revoke_user_sessions"' "${ROOT}/framwork/tec_tac/contracts.py" || fail "revocation contract missing"
grep -q '"name": "SessionAuthenticated"' "${ROOT}/framwork/tec_tac/contracts.py" || fail "permission contract missing"

# Core browser endpoints now enforce Core session trust. The TOTP enrollment
# endpoint intentionally remains Tactical-auth-only for setup-stage access.
grep -q 'class TotpQrView' "${ROOT}/framwork/tec_tac/views.py" || fail "TOTP setup endpoint missing"
grep -A3 'class TotpQrView' "${ROOT}/framwork/tec_tac/views.py" | grep -q 'permission_classes = \[IsAuthenticated\]' || fail "TOTP setup must remain Tactical-auth-only"
grep -A3 'class UiContextView' "${ROOT}/framwork/tec_tac/views.py" | grep -q 'permission_classes = \[SessionAuthenticated\]' || fail "UI context must enforce Core session trust"
for f in capability_views.py contract_views.py dashboard_views.py housekeeping_views.py module_repository_views.py module_v2_views.py preference_views.py scheduler_views.py session_security_views.py; do
  if grep -q 'permission_classes = \[IsAuthenticated\]' "${ROOT}/framwork/tec_tac/${f}"; then fail "${f} still uses Tactical-only IsAuthenticated"; fi
done
[[ $(grep -c 'permission_classes = \[IsAuthenticated\]' "${ROOT}/framwork/tec_tac/views.py") -eq 1 ]] || fail "views.py must retain Tactical-only auth only for TOTP setup"
grep -q 'session_ip_change' "${ROOT}/framwork/tec_tac/session_security.py" || fail "stable IP-change failure code missing"
grep -q 'session_invalid_state' "${ROOT}/framwork/tec_tac/session_security.py" || fail "stable invalid-state failure code missing"

python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/session_security.py" \
  "${ROOT}/framwork/tec_tac/session_security_views.py" \
  "${ROOT}/framwork/tec_tac/models.py" \
  "${ROOT}/framwork/tec_tac/migrations/0007_session_security.py" \
  "${ROOT}/framwork/tec_tac/apps.py" \
  "${ROOT}/framwork/tec_tac/urls.py" \
  "${ROOT}/framwork/tec_tac/contracts.py"

echo '[TEST] PASS session security foundation'
