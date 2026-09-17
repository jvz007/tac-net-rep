#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_DIR="${REPO_ROOT}/framwork"

printf '[TEST] Checking Tec-Tac framework roots, registry, templates and compatibility plugin.\n'

for path in \
    "${FRAMEWORK_DIR}/tec_tac/registry.py" \
    "${REPO_ROOT}/extensions" \
    "${REPO_ROOT}/reportsets" \
    "${REPO_ROOT}/templates/plugin/extension/tec_tac.json" \
    "${REPO_ROOT}/templates/plugin/reportset/tec_tac.json" \
    "${REPO_ROOT}/scripts/plugin-info.sh" \
    "${REPO_ROOT}/scripts/scaffold-plugin.sh"; do
    [[ -e "${path}" ]] || { echo "[TEST] FAIL missing ${path}" >&2; exit 1; }
done

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || { echo '[TEST] FAIL could not determine Tactical service user' >&2; exit 1; }

CODE="import sys; sys.path.insert(0, '${FRAMEWORK_DIR}'); from pathlib import Path; from tec_tac.registry import EXTENSIONS_ROOT, REPORTSETS_ROOT, get_plugins; assert EXTENSIONS_ROOT == Path('${REPO_ROOT}/extensions'); assert REPORTSETS_ROOT == Path('${REPO_ROOT}/reportsets'); plugins=get_plugins(); legacy=[p for p in plugins if p.plugin_id == 'legacy-reporting-poc']; assert len(legacy) == 1; assert legacy[0].legacy is True; assert 'tfdreporting.apps.TfdreportingConfig' in legacy[0].django_apps; print('plugins=', [(p.plugin_type,p.plugin_id,p.version,p.legacy) for p in plugins])"
runuser -u "${TACTICAL_USER}" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${CODE}\""

printf '[TEST] PASS framework foundation\n'
