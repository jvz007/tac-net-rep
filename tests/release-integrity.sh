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
[[ -f "${ROOT}/RELEASE_NOTES_${VERSION}.md" ]] || fail "current release note missing"
mapfile -t ROOT_NOTES < <(find "${ROOT}" -maxdepth 1 -type f -name 'RELEASE_NOTES_*.md' -printf '%f\n' | sort)
[[ ${#ROOT_NOTES[@]} -eq 1 ]] || fail "expected exactly one root release note, found ${#ROOT_NOTES[@]}"
[[ "${ROOT_NOTES[0]}" == "RELEASE_NOTES_${VERSION}.md" ]] || fail "root release note does not match current version"
find "${ROOT}/scripts/recovery" -maxdepth 1 -type f -name '*.sh' -print0 | while IFS= read -r -d '' script; do
  [[ -x "${script}" ]] || fail "recovery script is not executable: ${script}"
done
echo "[TEST] PASS release integrity ${VERSION}"
