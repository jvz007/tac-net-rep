#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_DIR="${REPO_ROOT}/framwork"

printf '[TEST] Checking Tec-Tac framework roots, registry and compatibility plugin.\n'

[[ -f "${FRAMEWORK_DIR}/tec_tac/registry.py" ]] || { echo '[TEST] FAIL missing registry.py' >&2; exit 1; }
[[ -d "${REPO_ROOT}/extensions" ]] || { echo '[TEST] FAIL missing extensions/' >&2; exit 1; }
[[ -d "${REPO_ROOT}/reportsets" ]] || { echo '[TEST] FAIL missing reportsets/' >&2; exit 1; }

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || { echo '[TEST] FAIL could not determine Tactical service user' >&2; exit 1; }

CODE="import sys; sys.path.insert(0, '${FRAMEWORK_DIR}'); from tec_tac.registry import EXTENSIONS_ROOT, REPORTSETS_ROOT, get_plugins; assert EXTENSIONS_ROOT == __import__('pathlib').Path('${REPO_ROOT}/extensions'); assert REPORTSETS_ROOT == __import__('pathlib').Path('${REPO_ROOT}/reportsets'); plugins=get_plugins(); legacy=[p for p in plugins if p.plugin_id == 'legacy-reporting-poc']; assert len(legacy) == 1; assert legacy[0].legacy is True; assert 'tfdreporting.apps.TfdreportingConfig' in legacy[0].django_apps; print('plugins=', [(p.plugin_type,p.plugin_id,p.legacy) for p in plugins])"
runuser -u "${TACTICAL_USER}" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${CODE}\""

printf '[TEST] PASS framework foundation\n'
