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

grep -q 'rm -rf "$dst"' "${ROOT}/scripts/recovery/tec-tac-recover-modules-from-backup.sh" || fail "recovery does not replace exact destination before restore"
grep -q 'tec-tac-repair-modules.sh.*--check' "${ROOT}/scripts/recovery/tec-tac-recover-modules-from-backup.sh" || fail "post-restore module validation missing"
grep -q 'run_manage "check"' "${ROOT}/scripts/recovery/tec-tac-recover-modules-from-backup.sh" || fail "post-restore Django validation missing"
grep -q 'tec-tac.conf' "${ROOT}/scripts/recovery/lib.sh" || fail "recovery does not load central layout config"
echo "[TEST] PASS recovery layout hardening"

DIAG="${ROOT}/scripts/recovery/tec-tac-diagnostics.sh"
grep -q 'check_source_repo framework' "$DIAG" || fail "framework source Git diagnostics missing"
grep -q 'check_source_repo ui' "$DIAG" || fail "UI source Git diagnostics missing"
grep -q 'runtime-git' "$DIAG" || fail "runtime Git contamination diagnostics missing"
grep -q 'framework-separation' "$DIAG" || fail "source/runtime separation diagnostics missing"
grep -q 'framework-version' "$DIAG" || fail "framework source/runtime version diagnostics missing"
grep -q 'ui-version' "$DIAG" || fail "UI source/runtime version diagnostics missing"
grep -q 'framework-import' "$DIAG" || fail "live framework import diagnostics missing"
grep -q 'architecture_ok' "$DIAG" || fail "JSON architecture status missing"
grep -q '/opt/tec-tac-src/framework' "$DIAG" || fail "expected framework source path assertion missing"
grep -q '/opt/tec-tac-src/ui' "$DIAG" || fail "expected UI source path assertion missing"
grep -q '/var/lib/tec-tac/ui/tec-tac' "$DIAG" || fail "expected deployed UI path assertion missing"
echo "[TEST] PASS recovery architecture diagnostics"
