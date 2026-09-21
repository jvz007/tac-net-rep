#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
VERSION="$(tr -d '\r\n' < "${ROOT}/VERSION")"
PACKAGE_VERSION="$(python3 - "${ROOT}/tec_tac_package.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['version'])
PY
)"
[[ "${PACKAGE_VERSION}" == "${VERSION}" ]] || fail "package version ${PACKAGE_VERSION} != VERSION ${VERSION}"

mapfile -t ROOT_NOTES < <(
  find "${ROOT}" -maxdepth 1 -type f \
    -name 'RELEASE_NOTES_*.md' \
    -printf '%f\n' | sort
)

[[ ${#ROOT_NOTES[@]} -le 2 ]] || \
  fail "expected no more than two root release notes, found ${#ROOT_NOTES[@]}"

CURRENT_NOTE="RELEASE_NOTES_${VERSION}.md"
printf '%s\n' "${ROOT_NOTES[@]}" | grep -Fxq "${CURRENT_NOTE}" || \
  fail "current release note ${CURRENT_NOTE} not found"

find "${ROOT}/scripts/recovery" -maxdepth 1 -type f -name '*.sh' -print0 | while IFS= read -r -d '' script; do
  [[ -x "${script}" ]] || fail "recovery script is not executable: ${script}"
done
echo "[TEST] PASS release integrity ${VERSION}"
