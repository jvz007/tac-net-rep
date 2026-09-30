#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "${ROOT}/tests/review-regressions-1.15.52.py"
bash "${ROOT}/tests/review-1.15.52-rebuild.sh"
python3 "${ROOT}/tests/tracker-test-doc-closure-1.15.129.py"
python3 "${ROOT}/tests/tracker-closure-1.15.146.py"
python3 "${ROOT}/tests/infrastructure-closure-1.15.148.py"
python3 "${ROOT}/tests/tracker-behavior-closure-1.15.161.py"
python3 "${ROOT}/tests/tracker-final-review-1.15.164.py"
python3 "${ROOT}/tests/scheduler-native-type-compat-1.15.164-1.py"
python3 "${ROOT}/tests/tracker-closure-1.15.165.py"
python3 "${ROOT}/tests/scheduler-run-now-scope-1.15.165-1.py"
python3 "${ROOT}/tests/my-account-features-1.15.167.py"
python3 "${ROOT}/tests/tracker-http-feature-boundary-1.15.172.py"
python3 "${ROOT}/tests/l10-publication-atomicity-1.15.172.py"
python3 "${ROOT}/tests/d2-d3-final-acceptance-1.15.172.py"
python3 "${ROOT}/tests/d2-d3-restore-orchestration-1.15.173.py"
python3 "${ROOT}/tests/l10-publication-final-1.15.173.py"
python3 "${ROOT}/tests/tracker-acceptance-1.15.173.py"
python3 "${ROOT}/tests/f11-openapi-final-1.15.178.py"
python3 "${ROOT}/tests/f11-tracker-closure-1.15.184.py"
python3 "${ROOT}/tests/f8-sso-session-pipeline-1.15.185.py"
python3 "${ROOT}/tests/f8-ad4-acceptance-1.15.187.py"
python3 "${ROOT}/tests/d3-ad3-final-acceptance-1.15.188.py"
python3 "${ROOT}/tests/f9-f10-browser-contract-1.15.175.py"


# D2/D3 recovery continuity must be ordinary-CI portable; run it explicitly as
# an unprivileged account when the test host permits that.
if [[ "$(id -u)" -eq 0 ]] && command -v runuser >/dev/null 2>&1 && id nobody >/dev/null 2>&1; then
  runuser -u nobody -- python3 "${ROOT}/tests/server-backup-d2-d3.py"
python3 "${ROOT}/tests/server-backup-decision-closure-1.15.166.py"
python3 "${ROOT}/tests/server-backup-d3-rclone-hash-1.15.188-1.py"
python3 "${ROOT}/tests/tracker-open-closure-1.15.169.py"
python3 "${ROOT}/tests/l10-publication-atomicity-1.15.171.py"
else
  python3 "${ROOT}/tests/server-backup-d2-d3.py"
python3 "${ROOT}/tests/server-backup-decision-closure-1.15.166.py"
python3 "${ROOT}/tests/tracker-open-closure-1.15.169.py"
python3 "${ROOT}/tests/l10-publication-atomicity-1.15.171.py"
fi

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

python3 "${ROOT}/tests/server-backup-registered-restore-1.15.162.py"

python3 "${ROOT}/tests/backup-restore-ui-boundary-1.15.162.py"

python3 "${ROOT}/tests/d3-l10-tracker-closure-1.15.183.py"
