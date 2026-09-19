#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_DIR="${REPO_ROOT}/framwork"

printf '[TEST] Checking reference extension/reportset pair.\n'

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || { echo '[TEST] FAIL could not determine Tactical service user' >&2; exit 1; }

CODE="import sys; sys.path.insert(0, '${FRAMEWORK_DIR}'); from django.apps import apps; from tec_tac.registry import get_plugin; e=get_plugin('example','extension'); r=get_plugin('example','reportset'); assert e.version == '1.0.0'; assert r.version == '1.0.0'; assert apps.get_app_config('tec_tac_example_extension').name == 'tec_tac_example_extension'; assert apps.get_app_config('tec_tac_example_reportset').name == 'tec_tac_example_reportset'; from tec_tac_example_extension.sample import get_sample_data; from tec_tac_example_reportset.sample import map_sample_data; raw=get_sample_data(); mapped=map_sample_data(raw); assert mapped == {'device':'example-device','status':'up','latency_ms':12.5}; print('reference_pair=', e.plugin_id, e.plugin_type, r.plugin_type, mapped)"
runuser -u "${TACTICAL_USER}" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell -c \"${CODE}\""

printf '[TEST] PASS reference extension/reportset pair\n'
