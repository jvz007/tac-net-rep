#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_PREFIX="${REPO_ROOT}/extensions/reporting/"

fail() { printf '[TEST] FAIL: %s\n' "$*" >&2; exit 1; }
log() { printf '[TEST] %s\n' "$*"; }

[[ -x "$VENV_PYTHON" ]] || fail "Tactical Python not found: $VENV_PYTHON"
[[ -f "$MANAGE_PY" ]] || fail "manage.py not found: $MANAGE_PY"

CODE="import tfdreporting; from django.apps import apps; from django.urls import resolve; p='${EXPECTED_PREFIX}'; assert tfdreporting.__file__.startswith(p), tfdreporting.__file__; m=apps.get_model('tfdreporting','NetworkAvailability'); rp=apps.get_model('tfdreporting','ExtensionRolePermission'); from ee.reporting.utils import resolve_model; assert resolve_model(data_source={'model':'NetworkAvailability'})['model'] is m; match=resolve('/api/tfd/reporting/network-availability/'); assert match.url_name == 'network-availability'; print('module=', tfdreporting.__file__); print('rows=', m.objects.count()); print('rbac_rows=', rp.objects.count()); print('route=', match.route)"

log "Checking Django registration, repository module path, Report Manager and route."
cd "$BACKEND_DIR"
"$VENV_PYTHON" "$MANAGE_PY" check
"$VENV_PYTHON" "$MANAGE_PY" shell -c "$CODE"
log "PASS"
