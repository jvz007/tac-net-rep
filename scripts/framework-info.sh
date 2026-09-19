#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_DIR="${REPO_ROOT}/framwork"

if [[ ${EUID} -ne 0 ]]; then
    printf '[TEC-TAC] ERROR: Run this script as root.\n' >&2
    exit 1
fi

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || { printf '[TEC-TAC] ERROR: Could not determine Tactical service user.\n' >&2; exit 1; }

CODE="import sys; sys.path.insert(0, '${FRAMEWORK_DIR}'); from tec_tac.registry import EXTENSIONS_ROOT, REPORTSETS_ROOT, get_plugins; print('extensions_root=', EXTENSIONS_ROOT); print('reportsets_root=', REPORTSETS_ROOT); plugins=get_plugins(); print('plugin_count=', len(plugins)); [print(f'{p.plugin_type}:{p.plugin_id}:version={p.version}:legacy={p.legacy}:apps={list(p.django_apps)}:root={p.root}') for p in plugins]"
runuser -u "${TACTICAL_USER}" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${CODE}\""
