#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_DIR="${REPO_ROOT}/framwork"
PLUGIN_ID="${1:-}"
PLUGIN_TYPE="${2:-}"

if [[ ${EUID} -ne 0 ]]; then
    printf '[TEC-TAC] ERROR: Run this script as root.\n' >&2
    exit 1
fi

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || { printf '[TEC-TAC] ERROR: Could not determine Tactical service user.\n' >&2; exit 1; }

if [[ -z "${PLUGIN_ID}" ]]; then
    CODE="import sys; sys.path.insert(0, '${FRAMEWORK_DIR}'); from tec_tac.registry import get_plugins; plugins=get_plugins(); [print(f'{p.plugin_type}:{p.plugin_id}:version={p.version}:legacy={p.legacy}:apps={list(p.django_apps)}:root={p.root}') for p in plugins]"
else
    TYPE_ARG="None"; [[ -n "${PLUGIN_TYPE}" ]] && TYPE_ARG="'${PLUGIN_TYPE}'"
    CODE="import sys; sys.path.insert(0, '${FRAMEWORK_DIR}'); from tec_tac.registry import get_plugin; p=get_plugin('${PLUGIN_ID}', ${TYPE_ARG}); print('id=',p.plugin_id); print('type=',p.plugin_type); print('version=',p.version); print('legacy=',p.legacy); print('root=',p.root); print('python_paths=',list(map(str,p.python_paths))); print('django_apps=',list(p.django_apps))"
fi

runuser -u "${TACTICAL_USER}" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${CODE}\""
