#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="${ROOT}/scripts/install-extension.sh"
REMOVE="${ROOT}/scripts/remove-extension.sh"
HOTFIX="${ROOT}/scripts/module-hotfix-job-helper.py"
SYSTEM_UPDATE="${ROOT}/scripts/system-update-helper.py"
MIGRATE="${ROOT}/scripts/migrate-layout.sh"

fail(){ printf '[TEST] FAIL %s\n' "$*" >&2; exit 1; }

# Root-only structural/archive/registry checks must use isolated system Python.
grep -Fq 'SYSTEM_PYTHON="/usr/bin/python3"' "${INSTALL}" || fail 'install-extension missing fixed system Python'
grep -Fq '"${SYSTEM_PYTHON}" -I - "${PACKAGE}" "${PAYLOAD_ROOT}"' "${INSTALL}" || fail 'archive extraction is not isolated system Python'
grep -Fq 'DISCOVERY="$("${SYSTEM_PYTHON}" -I - "${PAYLOAD_ROOT}"' "${INSTALL}" || fail 'package discovery is not isolated system Python'
grep -Fq '"${SYSTEM_PYTHON}" -I - "${FRAMEWORK_DIR}" "${STAGE_ROOT}"' "${INSTALL}" || fail 'staged registry validation is not isolated system Python'
grep -Fq '"${SYSTEM_PYTHON}" -I - "${FRAMEWORK_DIR}" <<' "${INSTALL}" || fail 'live registry validation is not isolated system Python'
grep -Fq 'PERMISSION_GROUPS="$("${SYSTEM_PYTHON}" -I - "${PERMISSION_MANIFEST}"' "${INSTALL}" || fail 'permission manifest parser is not isolated system Python'

# Removal root-side registry checks follow the same rule.
grep -Fq 'SYSTEM_PYTHON="/usr/bin/python3"' "${REMOVE}" || fail 'remove-extension missing fixed system Python'
grep -Fq '"${SYSTEM_PYTHON}" -I - "${FRAMEWORK_DIR}" "${PLUGIN_ID}"' "${REMOVE}" || fail 'remove preflight registry validation is not isolated system Python'
grep -Fq '"${SYSTEM_PYTHON}" -I - "${FRAMEWORK_DIR}" <<' "${REMOVE}" || fail 'remove post-delete registry validation is not isolated system Python'

# No legacy direct root execution of Tactical Python may remain in those scripts.
if grep -Fq 'PYTHONPATH="${FRAMEWORK_DIR}" \\' "${INSTALL}" && grep -Fq '"${VENV_PYTHON}" -' "${INSTALL}"; then
  fail 'install-extension retains root Tactical Python registry execution'
fi
if grep -Fq 'PYTHONPATH="${FRAMEWORK_DIR}" \\' "${REMOVE}" && grep -Fq '"${VENV_PYTHON}" -' "${REMOVE}"; then
  fail 'remove-extension retains root Tactical Python registry execution'
fi

# Hotfix syntax validation uses system Python; Django validation stays Tactical-owned.
grep -Fq 'system_python = Path("/usr/bin/python3")' "${HOTFIX}" || fail 'hotfix helper missing system Python'
grep -Fq '[str(system_python), "-I", "-m", "py_compile"' "${HOTFIX}" || fail 'hotfix helper compiles with Tactical Python as root'
grep -Fq '["runuser", "-u", tactical_user, "--", str(tactical_python), str(manage), "check"]' "${HOTFIX}" || fail 'hotfix Django check is not demoted to Tactical user'

# System Update may construct Tactical manage.py commands, but must demote before execution.
grep -Fq 'command = ["runuser", "-u", tactical_user, "--", *command]' "${SYSTEM_UPDATE}" || fail 'system update Django checks are not demoted'

# One-time layout migration must obey the same invariant.
grep -Fq 'runuser -u "${TACTICAL_USER}" -- "${TACTICAL_PYTHON}" "${MANAGE_PY}" check' "${MIGRATE}" || fail 'layout migration Django check runs Tactical Python as root'
grep -Fq 'runuser -u "${TACTICAL_USER}" -- "${TACTICAL_PYTHON}" "${MANAGE_PY}" shell' "${MIGRATE}" || fail 'layout migration Django shell runs Tactical Python as root'

# Python isolated mode must ignore a hostile PYTHONPATH/sitecustomize injection.
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
cat > "${tmp}/sitecustomize.py" <<'PY'
from pathlib import Path
Path('/tmp/tec-tac-r1-sitecustomize-hit').write_text('executed', encoding='utf-8')
PY
rm -f /tmp/tec-tac-r1-sitecustomize-hit
PYTHONPATH="${tmp}" /usr/bin/python3 -I -c 'print("isolated")' >/dev/null
[[ ! -e /tmp/tec-tac-r1-sitecustomize-hit ]] || fail 'system Python isolated mode loaded hostile PYTHONPATH sitecustomize'

printf '[TEST] PASS root Python privilege boundary\n'
