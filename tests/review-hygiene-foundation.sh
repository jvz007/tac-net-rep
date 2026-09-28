#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "${ROOT}/tests/review-regressions-1.15.52.py"
bash "${ROOT}/tests/review-1.15.52-rebuild.sh"
python3 "${ROOT}/tests/tracker-test-doc-closure-1.15.129.py"
python3 "${ROOT}/tests/tracker-closure-1.15.146.py"

run_portable() {
  local test_path="$1"
  if [[ "$(id -u)" -eq 0 ]] && command -v runuser >/dev/null 2>&1 && id nobody >/dev/null 2>&1; then
    runuser -u nobody -- python3 "${test_path}"
  else
    python3 "${test_path}"
  fi
}

run_portable "${ROOT}/tests/privileged-helper-environment.py"
run_portable "${ROOT}/tests/module-artifact-immutable-claim.py"
run_portable "${ROOT}/tests/server-backup-recovery-trust.py"

echo "[TEST] PASS review hygiene foundation"
