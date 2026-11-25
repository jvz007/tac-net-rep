#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
VERSION="$(tr -d '\r\n' < "${ROOT}/VERSION")"
PACKAGE_VERSION="$(python3 - "${ROOT}/tec_tac_package.json" <<'PY_VERSION'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['version'])
PY_VERSION
)"
[[ "${PACKAGE_VERSION}" == "${VERSION}" ]] || fail "package version ${PACKAGE_VERSION} != VERSION ${VERSION}"

mapfile -t BUILD_JUNK < <(
  find "${ROOT}" \
    \( -type d \( -name '__pycache__' -o -name '.pytest_cache' -o -name '.mypy_cache' -o -name '.ruff_cache' \) -o \
       -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.tmp' -o -name '*.swp' -o -name '.DS_Store' \) \) \
    -print | sort
)

if [[ ${#BUILD_JUNK[@]} -gt 0 ]]; then
  printf '[TEST] FAIL: generated/build junk present in release tree:\n' >&2
  printf ' - %s\n' "${BUILD_JUNK[@]#${ROOT}/}" >&2
  exit 1
fi

mapfile -t ROOT_NOTES < <(
  find "${ROOT}" -maxdepth 1 -type f \
    -name 'RELEASE_NOTES_*.md' \
    -printf '%f\n' | sort
)

[[ ${#ROOT_NOTES[@]} -eq 1 ]] || \
  fail "expected exactly one root release note, found ${#ROOT_NOTES[@]}"

CURRENT_NOTE="RELEASE_NOTES_${VERSION}.md"
printf '%s\n' "${ROOT_NOTES[@]}" | grep -Fxq "${CURRENT_NOTE}" || \
  fail "current release note ${CURRENT_NOTE} not found"

bash "${ROOT}/tests/root-script-crlf-1.17.15.sh"
python3 "${ROOT}/tests/release-archive-integrity.py"
python3 "${ROOT}/tests/migration-no-floating-dependency-1.18.31.py"
python3 "${ROOT}/tests/communicator-service-user-1.18.31.py"
python3 "${ROOT}/tests/communicator-service-user-defaults-1.18.32.py"
python3 "${ROOT}/tests/tactical-operation-file-transfer-1.18.33.py"
python3 "${ROOT}/tests/tactical-operation-file-transfer-audit-1.18.34.py"
python3 "${ROOT}/tests/online-install-plan-1.18.19.py"
python3 "${ROOT}/tests/online-install-run-1.18.20.py"
python3 "${ROOT}/tests/online-install-chain-1.18.21.py"
python3 "${ROOT}/tests/system-command-callers-1.18.36.py"
python3 "${ROOT}/tests/system-command-callers-integration-1.18.36.py"
python3 "${ROOT}/tests/agent-downloads-1.18.37.py"
python3 "${ROOT}/tests/agent-downloads-fixes-1.18.38.py"
python3 "${ROOT}/tests/endpoint-agent-installer-1.18.39.py"
python3 "${ROOT}/tests/audit-agent-column-1.18.39.py"
python3 "${ROOT}/tests/installer-serve-cost-1.18.40.py"
python3 "${ROOT}/tests/reporting-schedule-run-1.18.41.py"
python3 "${ROOT}/tests/online-upgrade-batch-1.18.42.py"
python3 "${ROOT}/tests/module-dispatch-unit-1.18.42.py"
python3 "${ROOT}/tests/system-version-picker-1.18.43.py"
python3 "${ROOT}/tests/result-checks-1.18.44.py"
python3 "${ROOT}/tests/result-checks-system-check-1.18.45.py"
python3 "${ROOT}/tests/probe-transport-identity-1.18.46.py"
python3 "${ROOT}/tests/probe-transport-consumer-1.18.46.py"
python3 "${ROOT}/tests/probe-transport-contract-1.18.47.py"
python3 "${ROOT}/tests/probe-transport-isolation-1.18.46.py"
python3 "${ROOT}/tests/probe-transport-docs-1.18.47.py"
python3 "${ROOT}/tests/probe-tunnel-ticket-1.18.47.py"
python3 "${ROOT}/tests/probe-tunnel-relay-1.18.47.py"
python3 "${ROOT}/tests/probe-tunnel-end-1.18.47.py"
python3 "${ROOT}/tests/probe-tunnel-isolation-1.18.47.py"
python3 "${ROOT}/tests/probe-transport-hardening-1.18.47.py"
python3 "${ROOT}/tests/probe-tunnel-pairing-1.18.48.py"
python3 "${ROOT}/tests/probe-tunnel-hardening-1.18.49.py"
python3 "${ROOT}/tests/access-events-1.18.50.py"
python3 "${ROOT}/tests/tunnel-scope-recheck-1.18.50.py"
python3 "${ROOT}/tests/probe-tunnel-limits-1.18.50.py"
python3 "${ROOT}/tests/access-events-1.18.51.py"
python3 "${ROOT}/tests/probe-tunnel-limits-1.18.51.py"
python3 "${ROOT}/tests/console-certificates-ca-1.18.52.py"
python3 "${ROOT}/tests/console-certificates-enrol-1.18.52.py"
python3 "${ROOT}/tests/console-certificates-routes-1.18.52.py"
python3 "${ROOT}/tests/console-certificates-setting-1.18.52.py"
python3 "${ROOT}/tests/version-1.18.52.py"

echo "[TEST] PASS release integrity ${VERSION}"
