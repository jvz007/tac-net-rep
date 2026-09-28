#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "${ROOT}/tests/review-regressions-1.15.52.py"
bash "${ROOT}/tests/review-1.15.52-rebuild.sh"
python3 "${ROOT}/tests/tracker-test-doc-closure-1.15.129.py"
python3 "${ROOT}/tests/tracker-closure-1.15.146.py"
python3 "${ROOT}/tests/infrastructure-closure-1.15.148.py"

# Portable privileged-boundary coverage delegated to portable-privileged-foundation.sh:
# tests/privileged-helper-environment.py
# tests/module-artifact-immutable-claim.py
# tests/server-backup-recovery-trust.py

if [[ "$(id -u)" -eq 0 ]] && command -v runuser >/dev/null 2>&1 && id nobody >/dev/null 2>&1; then
  runuser -u nobody -- bash "${ROOT}/tests/portable-privileged-foundation.sh"
else
  bash "${ROOT}/tests/portable-privileged-foundation.sh"
fi

echo "[TEST] PASS review hygiene foundation"
