#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
REPORTING="${ROOT}/framwork/tec_tac/reporting.py"
CONTRACTS="${ROOT}/framwork/tec_tac/contracts.py"

[[ -f "${REPORTING}" ]] || fail "Core reporting contract missing"
[[ -f "${ROOT}/docs/module-reporting.md" ]] || fail "reporting developer contract missing"
for symbol in register_reporting_model unregister_reporting_model list_reporting_models reporting_model_status; do
  grep -q "def ${symbol}" "${REPORTING}" || fail "public reporting contract missing: ${symbol}"
  grep -q '"name": "'"${symbol}"'"' "${CONTRACTS}" || fail "Public Contracts missing ${symbol}"
done

grep -q 'sync_tactical_reporting_models' "${REPORTING}" || fail "Tactical reporting allow-list synchronization missing"
grep -q 'reporting_constants.REPORTING_MODELS = combined' "${REPORTING}" || fail "constants allow-list synchronization missing"
grep -q 'reporting_utils.REPORTING_MODELS = combined' "${REPORTING}" || fail "utils allow-list synchronization missing"
grep -q '_tec_tac_reporting_bridge' "${REPORTING}" || fail "dynamic Tactical reporting bridge marker missing"
grep -q 'augment_query_schema' "${REPORTING}" || fail "dynamic query schema augmentation missing"
grep -q '_registration_status(registration)' "${REPORTING}" || fail "provider-state enforcement missing"
grep -q 'Duplicate public reporting ID' "${REPORTING}" || fail "duplicate public ID rejection missing"
grep -q 'Duplicate reporting model registration' "${REPORTING}" || fail "duplicate Django model registration rejection missing"
grep -q 'conflicts with a Tactical native reporting model' "${REPORTING}" || fail "native model collision guard missing"
grep -q 'Tactical Report Manager model names must be globally unique' "${REPORTING}" || fail "global model-name collision guard missing"
grep -q 'reporting_models = list_reporting_models()' "${CONTRACTS}" || fail "Public Contracts reporting discovery missing"
grep -q '"reporting_models": reporting_models' "${CONTRACTS}" || fail "Public Contracts reporting payload missing"
grep -q 'Registered reporting models' "${CONTRACTS}" || fail "Public Contracts reporting export section missing"
grep -q 'install_tactical_reporting_bridge' "${ROOT}/framwork/tec_tac/apps.py" || fail "Core AppConfig does not install reporting bridge"
grep -q 'Verifying Core Tactical Report Manager bridge' "${ROOT}/install.sh" || fail "installer reporting bridge verification missing"
grep -q 'modules must not import or mutate ee.reporting internals' "${CONTRACTS}" || fail "reporting ownership rule missing"

python3 -m py_compile "${REPORTING}" "${CONTRACTS}" "${ROOT}/framwork/tec_tac/apps.py"
bash -n "${ROOT}/install.sh"
echo "[TEST] PASS Core reporting registration foundation"

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
if [[ -x "${VENV_PYTHON}" && -f "${MANAGE_PY}" ]]; then
  TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
  [[ -n "${TACTICAL_USER}" ]] || fail "could not determine Tactical service user for reporting runtime test"
  runuser -u "${TACTICAL_USER}" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell < '${ROOT}/tests/reporting-registration-runtime.py'"
else
  echo "[TEST] SKIP Tactical reporting runtime regression (Tactical runtime unavailable)"
fi
