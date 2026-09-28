#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_one() { python3 "$1"; }
run_one "${ROOT}/tests/privileged-helper-environment.py"
run_one "${ROOT}/tests/module-artifact-immutable-claim.py"
run_one "${ROOT}/tests/server-backup-recovery-trust.py"
echo "[TEST] PASS portable privileged-boundary regressions run without root"
