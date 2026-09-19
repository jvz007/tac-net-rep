#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_DIR="${REPO_ROOT}/framwork"

printf '[TEST] Checking Tec-Tac manifest validation and extension/reportset pairing.\n'
TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
[[ -n "${TACTICAL_USER}" ]] || { echo '[TEST] FAIL could not determine Tactical service user' >&2; exit 1; }

TMP_PY="$(mktemp)"
trap 'rm -f "${TMP_PY}"' EXIT
cat > "${TMP_PY}" <<PY
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "${FRAMEWORK_DIR}")
from tec_tac.registry import RegistryError, discover_plugins

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    ext = root / "extensions"
    rep = root / "reportsets"
    ext.mkdir()
    rep.mkdir()
    (ext / "demo").mkdir()
    (rep / "demo").mkdir()
    (ext / "demo" / "tec_tac.json").write_text(json.dumps({
        "id": "demo", "type": "extension", "version": "0.1.0",
        "python_paths": ["."], "django_apps": []
    }))
    (rep / "demo" / "tec_tac.json").write_text(json.dumps({
        "id": "demo", "type": "reportset", "version": "0.1.0",
        "python_paths": ["."], "django_apps": []
    }))
    plugins = discover_plugins(ext, rep)
    assert [(p.plugin_type, p.plugin_id) for p in plugins] == [
        ("extension", "demo"), ("reportset", "demo")
    ]
    (rep / "demo" / "tec_tac.json").unlink()
    try:
        discover_plugins(ext, rep)
    except RegistryError as exc:
        assert "without matching reportset" in str(exc)
    else:
        raise AssertionError("missing reportset was not rejected")

print("registry_validation=OK")
PY

chown "${TACTICAL_USER}" "${TMP_PY}"
runuser -u "${TACTICAL_USER}" -- bash -lc "cd '${BACKEND_DIR}' && '${VENV_PYTHON}' '${MANAGE_PY}' shell < '${TMP_PY}'"
printf '[TEST] PASS registry validation\n'
