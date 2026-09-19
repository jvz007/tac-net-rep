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
[[ "${PACKAGE_VERSION}" == "${VERSION}" ]] || fail "VERSION (${VERSION}) does not match tec_tac_package.json (${PACKAGE_VERSION})"
for f in \
  framwork/tec_tac/apps.py \
  framwork/tec_tac/urls.py \
  framwork/tec_tac/views.py \
  framwork/tec_tac/rbac.py; do
  [[ -f "${ROOT}/${f}" ]] || fail "missing ${f}"
done

grep -q 'FRAMEWORK_APP = "tec_tac.apps.TecTacFrameworkConfig"' "${ROOT}/framwork/tec_tac/bootstrap.py" || fail "framework app bootstrap missing"
grep -q 'ui/context/' "${ROOT}/framwork/tec_tac/urls.py" || fail "context route missing"
grep -q 'access/extensions/' "${ROOT}/framwork/tec_tac/urls.py" || fail "permission catalog route missing"
grep -q 'access/roles/<int:role_id>/permissions/' "${ROOT}/framwork/tec_tac/urls.py" || fail "role permission route missing"
grep -q 'effective_permissions' "${ROOT}/framwork/tec_tac/rbac.py" || fail "effective permission helper missing"
grep -q 'permission_catalog' "${ROOT}/framwork/tec_tac/rbac.py" || fail "permission catalog helper missing"

python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/apps.py" \
  "${ROOT}/framwork/tec_tac/bootstrap.py" \
  "${ROOT}/framwork/tec_tac/rbac.py" \
  "${ROOT}/framwork/tec_tac/urls.py" \
  "${ROOT}/framwork/tec_tac/views.py"
bash -n "${ROOT}/install.sh"
echo "[TEST] PASS access API foundation"
