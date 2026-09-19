#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"

if [[ "${MODE}" != "--destructive" ]]; then
    cat <<'EOF'
[TEST] Lifecycle test is destructive because it includes uninstall --purge-data.
[TEST] It will remove Tec-Tac reporting POC tables/data and recreate them empty.
[TEST] Re-run explicitly with:
[TEST]   sudo bash tests/lifecycle.sh --destructive
EOF
    exit 2
fi

[[ ${EUID} -eq 0 ]] || { echo '[TEST] FAIL run as root' >&2; exit 1; }

printf '[TEST] 1/6 install\n'
TEC_TAC_REPORTING_USERNAME="${TEC_TAC_LIFECYCLE_USERNAME:-}" bash "${REPO_ROOT}/install.sh" </dev/null
printf '[TEST] 2/6 reinstall\n'
TEC_TAC_REPORTING_USERNAME="${TEC_TAC_LIFECYCLE_USERNAME:-}" bash "${REPO_ROOT}/install.sh" </dev/null
printf '[TEST] 3/6 uninstall preserving data\n'
bash "${REPO_ROOT}/uninstall.sh"
printf '[TEST] 4/6 reinstall after disconnect\n'
TEC_TAC_REPORTING_USERNAME="${TEC_TAC_LIFECYCLE_USERNAME:-}" bash "${REPO_ROOT}/install.sh" </dev/null
printf '[TEST] 5/6 purge\n'
bash "${REPO_ROOT}/uninstall.sh" --purge-data
printf '[TEST] 6/6 clean reinstall\n'
TEC_TAC_REPORTING_USERNAME="${TEC_TAC_LIFECYCLE_USERNAME:-}" bash "${REPO_ROOT}/install.sh" </dev/null
bash "${REPO_ROOT}/tests/framework-foundation.sh"
bash "${REPO_ROOT}/tests/network-reporting-server.sh"
printf '[TEST] PASS lifecycle\n'
