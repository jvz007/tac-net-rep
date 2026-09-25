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

# Contract/catalog discovery is metadata-only: never execute provider health callbacks.
grep -q 'list_capabilities(check_health=False)' "${ROOT}/framwork/tec_tac/contracts.py" || fail "contract catalog must not execute live capability health checks"
grep -q 'check_health: bool = True' "${ROOT}/framwork/tec_tac/capabilities.py" || fail "capability health-check control missing"
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

# 1.15.35 Core Tactical Report Manager registration contract
grep -q 'register_reporting_model' "${ROOT}/framwork/tec_tac/contracts.py" || fail "reporting registration public contract missing"
grep -q 'list_reporting_models' "${ROOT}/framwork/tec_tac/contracts.py" || fail "reporting discovery public contract missing"
grep -q '"reporting_models": reporting_models' "${ROOT}/framwork/tec_tac/contracts.py" || fail "reporting models missing from live contract catalog"
grep -q 'Registered reporting models' "${ROOT}/framwork/tec_tac/contracts.py" || fail "reporting models missing from Markdown export"
echo "[TEST] PASS reporting public contracts"

# 1.15.36 trusted publisher public contracts
grep -q 'list_trusted_publishers' "${ROOT}/framwork/tec_tac/contracts.py" || fail "trusted publisher discovery contract missing"
grep -q 'verify_release_files' "${ROOT}/framwork/tec_tac/contracts.py" || fail "trusted publisher verification contract missing"
echo "[TEST] PASS trusted publisher public contracts"

# 1.15.58 Core Resource Directory public contract
[[ -f "${ROOT}/framwork/tec_tac/resources.py" ]] || fail "Core Resource Directory missing"
[[ -f "${ROOT}/framwork/tec_tac/resources_adapter.py" ]] || fail "Core Tactical resource adapter missing"
grep -q 'core.resources' "${ROOT}/framwork/tec_tac/resources.py" || fail "core.resources contract id missing"
grep -q 'resource_contract_metadata' "${ROOT}/framwork/tec_tac/contracts.py" || fail "Resource Directory metadata missing from live contracts"
grep -q 'Core Resource Directory' "${ROOT}/framwork/tec_tac/contracts.py" || fail "Resource Directory missing from Markdown public-contract export"
grep -q 'CORE RESOURCE DIRECTORY' "${ROOT}/framwork/tec_tac/contracts.py" || fail "Resource Directory missing from text public-contract export"
grep -q 'Feature modules must consume Tactical clients/sites/agents through tec_tac.resources' "${ROOT}/framwork/tec_tac/contracts.py" || fail "resource abstraction development rule missing"
echo "[TEST] PASS Core Resource Directory public contracts"
