#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_DIR="${REPO_ROOT}/framwork"

printf '[TEST] Checking Tec-Tac framework roots, registry, reference pair and compatibility plugin.\n'

for path in \
    "${FRAMEWORK_DIR}/tec_tac/registry.py" \
    "${REPO_ROOT}/extensions" \
    "${REPO_ROOT}/reportsets" \
    "${REPO_ROOT}/templates/plugin/extension/tec_tac.json" \
    "${REPO_ROOT}/templates/plugin/reportset/tec_tac.json" \
    "${REPO_ROOT}/scripts/plugin-info.sh" \
    "${REPO_ROOT}/scripts/scaffold-plugin.sh" \
    "${REPO_ROOT}/scripts/install-extension.sh" \
    "${REPO_ROOT}/scripts/remove-extension.sh" \
    "${REPO_ROOT}/docs/extension-reportset-tutorial.md" \
    "${REPO_ROOT}/docs/extension-reportset-tutorial.html" \
    "${REPO_ROOT}/docs/capabilities.md" \
    "${REPO_ROOT}/docs/core-functions.md" \
    "${REPO_ROOT}/docs/module-interoperability.md" \
    "${REPO_ROOT}/extensions/example/tec_tac.json" \
    "${REPO_ROOT}/reportsets/example/tec_tac.json" \
    "${REPO_ROOT}/tests/example-plugin.sh"; do
    [[ -e "${path}" ]] || { echo "[TEST] FAIL missing ${path}" >&2; exit 1; }
done

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || { echo '[TEST] FAIL could not determine Tactical service user' >&2; exit 1; }

CODE="import sys; sys.path.insert(0, '${FRAMEWORK_DIR}'); from pathlib import Path; from tec_tac.registry import EXTENSIONS_ROOT, REPORTSETS_ROOT, get_plugins; assert EXTENSIONS_ROOT == Path('${REPO_ROOT}/extensions'); assert REPORTSETS_ROOT == Path('${REPO_ROOT}/reportsets'); plugins=get_plugins(); example=[p for p in plugins if p.plugin_id == 'example']; assert {(p.plugin_type,p.version) for p in example} == {('extension','1.0.0'),('reportset','1.0.0')}; legacy=[p for p in plugins if p.plugin_id == 'legacy-reporting-poc']; assert len(legacy) == 1; assert legacy[0].legacy is True; assert 'tfdreporting.apps.TfdreportingConfig' in legacy[0].django_apps; print('plugins=', [(p.plugin_type,p.plugin_id,p.version,p.legacy) for p in plugins])"
runuser -u "${TACTICAL_USER}" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${CODE}\""


# Repeat installs must remain non-interactive when reporting permission already exists.
! grep -q 'Change/add reporting ingest permission assignment?' "${REPO_ROOT}/install.sh" || { echo '[TEST] FAIL legacy repeat-install reporting permission prompt remains' >&2; exit 1; }
grep -q 'Keeping existing reporting permission assignment(s) unchanged.' "${REPO_ROOT}/install.sh" || { echo '[TEST] FAIL existing reporting permission preservation log missing' >&2; exit 1; }
printf '[TEST] PASS reporting permission repeat-install behavior\n'
printf '[TEST] PASS framework foundation\n'
