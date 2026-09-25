#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

for f in \
  framwork/tec_tac/mfa_backup.py \
  framwork/tec_tac/mfa_backup_views.py \
  framwork/tec_tac/migrations/0011_access_security.py \
  framwork/tec_tac/migrations/0012_mfa_backup_totp_binding.py; do
  [[ -f "${ROOT}/${f}" ]] || fail "missing ${f}"
done

grep -q 'class TecTacMfaBackupCode' "${ROOT}/framwork/tec_tac/models.py" || fail "MFA backup-code model missing"
grep -q 'code_hash = models.CharField' "${ROOT}/framwork/tec_tac/models.py" || fail "backup codes must be hash-only"
if grep -q 'code = models.CharField' "${ROOT}/framwork/tec_tac/models.py"; then fail "plaintext backup-code field detected"; fi
grep -q 'make_password' "${ROOT}/framwork/tec_tac/mfa_backup.py" || fail "password hashing missing"
grep -q 'check_password' "${ROOT}/framwork/tec_tac/mfa_backup.py" || fail "backup-code hash verification missing"
grep -q 'select_for_update' "${ROOT}/framwork/tec_tac/mfa_backup.py" || fail "atomic one-time consumption missing"
grep -q 'verify_generation_proof' "${ROOT}/framwork/tec_tac/mfa_backup_views.py" || fail "password/TOTP regeneration proof missing"
grep -q 'LoginMinThrottle' "${ROOT}/framwork/tec_tac/mfa_backup_views.py" || fail "Tactical login minute throttle missing"
grep -q 'LoginDayThrottle' "${ROOT}/framwork/tec_tac/mfa_backup_views.py" || fail "Tactical login day throttle missing"
grep -q 'block_local_user_logon' "${ROOT}/framwork/tec_tac/mfa_backup_views.py" || fail "Tactical local-login restriction missing"
grep -q 'AuthToken.objects' "${ROOT}/framwork/tec_tac/session_security.py" || fail "Tactical Knox session administration missing"
grep -q 'token.delete()' "${ROOT}/framwork/tec_tac/session_security.py" || fail "individual Knox token revocation missing"
grep -q 'AuthToken.objects.filter(digest__in=digests).delete()' "${ROOT}/framwork/tec_tac/session_security.py" || fail "bulk Knox token revocation missing"
grep -q 'LOGIN_SESSION_NAMESPACE' "${ROOT}/framwork/tec_tac/session_security.py" || fail "opaque session reference missing"
grep -q 'can_manage_accounts' "${ROOT}/framwork/tec_tac/session_security.py" || fail "account-management authorization missing"
grep -q 'path("auth/mfa/backup-codes/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "backup-code endpoint missing"
grep -q 'path("auth/login/backup-code/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "backup-code login endpoint missing"
grep -q 'path("access/sessions/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "admin session list endpoint missing"

grep -q 'totp_fingerprint = models.CharField' "${ROOT}/framwork/tec_tac/models.py" || fail "TOTP binding fingerprint field missing"
grep -q 'TOTP_BINDING_NAMESPACE' "${ROOT}/framwork/tec_tac/mfa_backup.py" || fail "TOTP backup-code binding HMAC missing"
grep -q 'mfa_backup_codes_invalidated' "${ROOT}/framwork/tec_tac/mfa_backup.py" || fail "stale TOTP-bound codes are not audited/invalidated"
grep -q 'burn_backup_code_hash_cost' "${ROOT}/framwork/tec_tac/mfa_backup_views.py" || fail "constant-cost backup-code failure hashing missing"
grep -q 'mfa_backup_generation_proof_failed' "${ROOT}/framwork/tec_tac/mfa_backup.py" || fail "failed backup-code generation proof audit missing"
grep -q 'throttle_classes = \[LoginMinThrottle, LoginDayThrottle\]' "${ROOT}/framwork/tec_tac/mfa_backup_views.py" || fail "backup-code regeneration throttles missing"
grep -q '_is_protected_login_account' "${ROOT}/framwork/tec_tac/session_security.py" || fail "protected login-account guard missing"
grep -q 'Superuser or root login sessions require superuser authority' "${ROOT}/framwork/tec_tac/session_security.py" || fail "privileged-session revoke guard missing"
grep -A30 'class AdminLoginSessionRevokeView' "${ROOT}/framwork/tec_tac/session_security_views.py" | grep -q 'def post' || fail "POST login-session revoke route handler missing"
grep -A3 'class TotpQrView' "${ROOT}/framwork/tec_tac/views.py" | grep -q 'permission_classes = \[SessionAuthenticated\]' || fail "TOTP QR must require Core SessionAuthenticated"
grep -q 'def _tec_tac_totp_issuer' "${ROOT}/framwork/tec_tac/views.py" || fail "colon-free TOTP issuer helper missing"

python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/mfa_backup.py" \
  "${ROOT}/framwork/tec_tac/mfa_backup_views.py" \
  "${ROOT}/framwork/tec_tac/session_security.py" \
  "${ROOT}/framwork/tec_tac/session_security_views.py" \
  "${ROOT}/framwork/tec_tac/migrations/0011_access_security.py" \
  "${ROOT}/framwork/tec_tac/migrations/0012_mfa_backup_totp_binding.py" \
  "${ROOT}/framwork/tec_tac/urls.py"

echo '[TEST] PASS Access MFA recovery and Tactical session administration'
