#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
VIEW="${ROOT}/framwork/tec_tac/mfa_backup_views.py"
URLS="${ROOT}/framwork/tec_tac/urls.py"
MFA="${ROOT}/framwork/tec_tac/mfa_backup.py"
SEC="${ROOT}/framwork/tec_tac/session_security.py"

grep -q 'class AdminUserMfaRecoveryView' "${VIEW}" || fail "admin recovery view missing"
grep -q 'path("access/users/<int:user_id>/mfa/"' "${URLS}" || fail "admin recovery route missing"
grep -q 'can_manage_account_security(request.user)' "${VIEW}" || fail "manage-accounts guard missing"
grep -q 'can_administer_account_security_target(request.user, target)' "${VIEW}" || fail "protected-target guard missing"
grep -q 'invalidate_backup_codes(' "${VIEW}" || fail "admin invalidation call missing"
grep -q 'def invalidate_backup_codes' "${MFA}" || fail "invalidation service missing"
grep -q '"explicit": True' "${MFA}" || fail "explicit invalidation audit marker missing"
grep -q 'can_manage_accounts' "${SEC}" || fail "Tactical account-management authority missing"

# Admin endpoints must never generate or return plaintext recovery credentials.
python3 - "${VIEW}" <<'PY_CHECK'
from pathlib import Path
import re, sys
text=Path(sys.argv[1]).read_text(encoding='utf-8')
m=re.search(r'class AdminUserMfaRecoveryView\(APIView\):(.*?)(?=\nclass BackupCodeLoginView)', text, re.S)
if not m:
    raise SystemExit('admin view block not found')
block=m.group(1)
for forbidden in ('generate_backup_codes(', '"codes"', "'codes'"):
    if forbidden in block:
        raise SystemExit(f'admin view exposes forbidden recovery-code operation: {forbidden}')
print('[TEST] PASS admin recovery endpoint exposes status/invalidation only')
PY_CHECK

python3 -m py_compile "${VIEW}" "${MFA}" "${SEC}" "${ROOT}/framwork/tec_tac/urls.py"
echo '[TEST] PASS administrative MFA recovery security boundary'
