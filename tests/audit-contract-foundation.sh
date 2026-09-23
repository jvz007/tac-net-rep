#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "${ROOT}/tests/audit-contract-foundation.py"
grep -q 'path("audit/record/"' "${ROOT}/framwork/tec_tac/urls.py"
grep -q 'SessionAuthenticated' "${ROOT}/framwork/tec_tac/audit_views.py"
grep -q '_FORBIDDEN_IDENTITY_FIELDS' "${ROOT}/framwork/tec_tac/audit_views.py"
grep -q 'from logs.models import AuditLog' "${ROOT}/framwork/tec_tac/audit.py"
! grep -R --include='*.py' -n 'from logs.models import AuditLog' "${ROOT}/extensions" >/dev/null 2>&1 || { echo '[TEST] FAIL extension imports Tactical AuditLog directly' >&2; exit 1; }
[[ -f "${ROOT}/docs/module-audit.md" ]]
echo "[TEST] PASS Core-owned audit API/runtime boundary"
