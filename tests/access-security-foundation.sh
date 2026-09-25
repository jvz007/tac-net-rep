#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

for f in \
  framwork/tec_tac/mfa_backup.py \
  framwork/tec_tac/mfa_backup_views.py \
  framwork/tec_tac/migrations/0011_access_security.py; do
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

python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/mfa_backup.py" \
  "${ROOT}/framwork/tec_tac/mfa_backup_views.py" \
  "${ROOT}/framwork/tec_tac/session_security.py" \
  "${ROOT}/framwork/tec_tac/session_security_views.py" \
  "${ROOT}/framwork/tec_tac/migrations/0011_access_security.py" \
  "${ROOT}/framwork/tec_tac/urls.py"

echo '[TEST] PASS Access MFA recovery and Tactical session administration'
