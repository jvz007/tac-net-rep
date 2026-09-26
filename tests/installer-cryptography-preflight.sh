#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="${ROOT}/install.sh"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

check='/usr/bin/python3 -I -c '\''import cryptography'\'''
count=$(grep -Fxc "$check >/dev/null 2>&1 || fail \"System Python cryptography support is required for root-side Tec-Tac signature verification.\"" "$INSTALL" || true)
[[ "$count" -eq 1 ]] || fail "expected exactly one isolated system-Python cryptography preflight check, found ${count}"

check_line=$(grep -Fn "$check" "$INSTALL" | cut -d: -f1)
preflight_line=$(grep -Fn 'Preflight source repository layout: OK' "$INSTALL" | cut -d: -f1)
first_mutation_line=$(grep -nE '^[[:space:]]*(mkdir|install|cp|rm|mv|chown|chmod|cat[[:space:]]*>|python3[[:space:]]+-[[:space:]].*PY_)' "$INSTALL" | awk -F: -v after="$preflight_line" '$1 > after {print $1; exit}')
[[ -n "$check_line" && -n "$first_mutation_line" ]] || fail "unable to determine preflight/mutation ordering"
(( check_line > preflight_line )) || fail "cryptography check is not in the validated preflight block"
(( check_line < first_mutation_line )) || fail "cryptography check occurs after the first installer mutation"

migrate_line=$(grep -Fn "migrate '${APP_NAME:-tfdreporting}' --noinput" "$INSTALL" | head -n1 | cut -d: -f1 || true)
[[ -z "$migrate_line" || "$check_line" -lt "$migrate_line" ]] || fail "cryptography check occurs after migrations"

policy_line=$(grep -Fn 'POLICY_FILE="${POLICY_ROOT}/update-trust-policy.json"' "$INSTALL" | cut -d: -f1)
sudoers_line=$(grep -Fn 'MODULE_SUDOERS="/etc/sudoers.d/tec-tac-module-manager"' "$INSTALL" | cut -d: -f1)
(( check_line < policy_line )) || fail "cryptography check occurs after trust-policy mutation block"
(( check_line < sudoers_line )) || fail "cryptography check occurs after sudoers mutation block"

echo "[TEST] PASS installer cryptography dependency is preflight-only"
