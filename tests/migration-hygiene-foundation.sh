#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
MIGRATION="${ROOT}/framwork/tec_tac/migrations/0008_alter_tectacsessionsecurityconfig_trusted_proxies.py"

[[ -f "${MIGRATION}" ]] || fail "Core migration 0008 missing"
grep -q '0007_session_security' "${MIGRATION}" || fail "Core migration dependency missing"
grep -q 'default=tec_tac.models.default_session_trusted_proxies' "${MIGRATION}" || fail "trusted_proxies callable default migration missing"
grep -q 'makemigrations tec_tac --check --dry-run' "${ROOT}/install.sh" || fail "strict Core migration drift check missing"
grep -q 'Module migration drift detected:' "${ROOT}/install.sh" || fail "module migration drift report missing"
grep -q 'framework installation will continue' "${ROOT}/install.sh" || fail "module drift check must remain non-blocking"
python3 -m py_compile "${MIGRATION}"
bash -n "${ROOT}/install.sh"
echo "[TEST] PASS migration hygiene foundation"
