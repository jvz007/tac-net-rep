#!/usr/bin/env bash
# 1.17.15 regression: root helpers under scripts/ carry LF line endings only, and install.sh strips a trailing carriage
# return when it copies each one to /usr/local/sbin (or its library folder). A CRLF shebang makes sudo fail with
# "unable to execute ...: No such file or directory".
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

# Count CR bytes with tr: grep's handling of CR differs between Windows and Linux builds, so it is not used here.
cr_count(){ tr -cd '\r' < "$1" | wc -c | tr -d ' '; }

# 1. No CR byte in any file under scripts/, named one by one.
offenders=()
while IFS= read -r -d '' file; do
  if [[ "$(cr_count "${file}")" -gt 0 ]]; then
    offenders+=("${file#"${ROOT}"/}")
  fi
done < <(find "${ROOT}/scripts" -type f -print0)
if [[ ${#offenders[@]} -gt 0 ]]; then
  printf '[TEST] FAIL: carriage return bytes (Windows line endings) in scripts/, root helpers will not run:\n' >&2
  printf ' - %s\n' "${offenders[@]}" >&2
  exit 1
fi

# 2. install.sh copies the helper through the strip, and no script under scripts/ is installed directly any more.
STRIP_LINE='sed '\''s/\r$//'\'' "${source}" > "${staged}"'
grep -Fq -- "${STRIP_LINE}" "${ROOT}/install.sh" || fail "install.sh does not strip the trailing CR in install_root_script"
grep -Fq -- 'install -o root -g root -m 0755 "${staged}" "${target}"' "${ROOT}/install.sh" || fail "install_root_script does not install the stripped copy"
if grep -Fq -- 'install -o root -g root -m 0755 "${REPO_ROOT}/scripts/' "${ROOT}/install.sh"; then
  fail "install.sh still installs a scripts/ file directly, without the CR strip"
fi

# 3. The strip does what the installer relies on: a CRLF shebang comes out LF-only, and the content is kept.
sample="$(printf '#!/usr/bin/python3\r\nprint("ok")\r\n' | sed 's/\r$//')"
expected="$(printf '#!/usr/bin/python3\nprint("ok")')"
[[ "${sample}" == "${expected}" ]] || fail "the CR strip does not return the expected LF text"
[[ "$(printf '%s\n' "${sample}" | tr -cd '\r' | wc -c | tr -d ' ')" -eq 0 ]] || fail "the CR strip left a carriage return"

echo "[TEST] PASS root script CRLF 1.17.15"
