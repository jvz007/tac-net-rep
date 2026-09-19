#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
for f in \
  scripts/recovery/lib.sh \
  scripts/recovery/tec-tac-repair.sh \
  scripts/recovery/tec-tac-diagnostics.sh \
  scripts/recovery/tec-tac-repair-permissions.sh \
  scripts/recovery/tec-tac-repair-modules.sh \
  scripts/recovery/tec-tac-recover-modules-from-backup.sh \
  scripts/recovery/tec-tac-repair-runtime.sh \
  scripts/recovery/tec-tac-repair-scheduler.sh; do
  [[ -x "${ROOT}/${f}" ]] || fail "missing/non-executable ${f}"
  bash -n "${ROOT}/${f}"
done
grep -q 'repair_module_permissions' "${ROOT}/install.sh" || fail "installer is not using recovery permission contract"
grep -q 'staged/bundles' "${ROOT}/scripts/recovery/lib.sh" || fail "bundle staging permission repair missing"
grep -q 'staged/batches' "${ROOT}/scripts/recovery/lib.sh" || fail "batch staging permission repair missing"
grep -q 'Recover missing modules' "${ROOT}/scripts/recovery/tec-tac-repair.sh" || fail "interactive recovery menu missing module recovery"
grep -q "find \"\${REPO_ROOT}/scripts/recovery\".*chmod 0755" "${ROOT}/install.sh" || fail "installer does not repair recovery script executable bits"
! grep -q 'ln -sfn.*tec-tac-repair' "${ROOT}/install.sh" || fail "installer must not expose recovery toolkit in /usr/local/sbin"
echo "[TEST] PASS recovery foundation"
