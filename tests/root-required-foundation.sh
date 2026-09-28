#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[TEST] SKIP root-required foundation: requires root privileges"
  exit 0
fi

python3 "${ROOT}/tests/system-update-claim-security.py"
python3 "${ROOT}/tests/module-v2-verified-bytes-boundary.py"

echo "[TEST] PASS root-required foundation"
