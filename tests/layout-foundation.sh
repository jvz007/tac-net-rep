#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
for f in scripts/tec-tac-config.sh scripts/migrate-layout.sh framwork/tec_tac/config.py; do
  [[ -f "${ROOT}/${f}" ]] || fail "missing ${f}"
done
bash -n "${ROOT}/scripts/tec-tac-config.sh"
bash -n "${ROOT}/scripts/migrate-layout.sh"
python3 -m py_compile "${ROOT}/framwork/tec_tac/config.py"
grep -q 'FRAMEWORK_DIR="${TEC_TAC_FRAMEWORK_ROOT:-${TEC_TAC_ROOT}/framework}"' "${ROOT}/install.sh" || fail "runtime framework path missing"
grep -q 'SOURCE_FRAMEWORK_DIR=.*framwork' "${ROOT}/install.sh" || fail "source framework path missing"
grep -q 'Deployed framework-owned runtime code without altering dynamic modules' "${ROOT}/install.sh" || fail "runtime deployment boundary missing"
grep -q 'TEC_TAC_CONFIG_FILE=.*tec-tac.conf' "${ROOT}/install.sh" || fail "central config path missing"
grep -q '/opt/tec-tac-src/framework' "${ROOT}/scripts/migrate-layout.sh" || fail "framework source migration target missing"
grep -q '/opt/tec-tac-src/ui' "${ROOT}/scripts/migrate-layout.sh" || fail "UI source migration target missing"
grep -q 'module state/filesystem consistency OK' "${ROOT}/scripts/migrate-layout.sh" || fail "module-state/filesystem preflight missing"
grep -q 'persistent module state references module files that are absent' "${ROOT}/scripts/migrate-layout.sh" || fail "missing-state-module refusal missing"
echo "[TEST] PASS layout foundation"
