#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ -f "${ROOT}/framwork/tec_tac/contracts.py" ]] || fail "contracts.py missing"
[[ -f "${ROOT}/framwork/tec_tac/contract_views.py" ]] || fail "contract_views.py missing"
grep -q 'CORE_CONTRACTS' "${ROOT}/framwork/tec_tac/contracts.py" || fail "core contract catalog missing"
grep -q 'register_scheduled_action' "${ROOT}/framwork/tec_tac/contracts.py" || fail "scheduler public contract missing"
grep -q 'get_capability' "${ROOT}/framwork/tec_tac/contracts.py" || fail "capability public contract missing"
grep -q 'build_operation_context' "${ROOT}/framwork/tec_tac/contracts.py" || fail "operation context contract missing"
grep -q 'build_contract_catalog' "${ROOT}/framwork/tec_tac/contracts.py" || fail "contract catalog builder missing"
grep -q 'render_markdown' "${ROOT}/framwork/tec_tac/contracts.py" || fail "markdown exporter missing"
grep -q 'render_text' "${ROOT}/framwork/tec_tac/contracts.py" || fail "text exporter missing"
grep -q 'path("contracts/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "contract catalog route missing"
grep -q 'path("contracts/export/"' "${ROOT}/framwork/tec_tac/urls.py" || fail "contract export route missing"
grep -q 'server-maintenance authority' "${ROOT}/framwork/tec_tac/contract_views.py" || fail "contract access guard missing"
grep -q 'format must be md or txt' "${ROOT}/framwork/tec_tac/contract_views.py" || fail "export format validation missing"
python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/contracts.py" \
  "${ROOT}/framwork/tec_tac/contract_views.py" \
  "${ROOT}/framwork/tec_tac/urls.py"
echo "[TEST] PASS contracts foundation"
