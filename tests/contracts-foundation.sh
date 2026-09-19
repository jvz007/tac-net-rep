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
grep -q 'export_format must be md or txt' "${ROOT}/framwork/tec_tac/contract_views.py" || fail "export format validation missing"
python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/contracts.py" \
  "${ROOT}/framwork/tec_tac/contract_views.py" \
  "${ROOT}/framwork/tec_tac/urls.py"
echo "[TEST] PASS contracts foundation"

grep -q 'request.query_params.get("export_format")' "${ROOT}/framwork/tec_tac/contract_views.py" || fail "contract export must avoid DRF reserved format query parameter"
! grep -q 'request.query_params.get("format")' "${ROOT}/framwork/tec_tac/contract_views.py" || fail "reserved DRF format query parameter is still used"

# 1.10.2 export content-negotiation regression
grep -q "def perform_content_negotiation" "${ROOT}/framwork/tec_tac/contract_views.py" || fail "contract export must bypass DRF Accept negotiation"
grep -q 'export_format' "${ROOT}/framwork/tec_tac/contract_views.py" || fail "contract export must use export_format selector"

# 1.10.3 execution-result semantics
grep -q "Treat transport acknowledgement as transport state" "${ROOT}/framwork/tec_tac/contracts.py" || fail "transport-vs-execution contract rule missing"
grep -q "Scheduled handlers must propagate downstream execution failures" "${ROOT}/framwork/tec_tac/contracts.py" || fail "scheduled downstream failure propagation rule missing"
grep -q "Windows cmd.exe quoting" "${ROOT}/framwork/tec_tac/contracts.py" || fail "raw command shell-safety rule missing"

# 1.11.0 scheduler retry classification contract
grep -q 'SchedulerPermanentError' "$ROOT/framwork/tec_tac/contracts.py" || fail "scheduler permanent failure contract missing"
grep -q 'SchedulerTransientError' "$ROOT/framwork/tec_tac/contracts.py" || fail "scheduler transient failure contract missing"
