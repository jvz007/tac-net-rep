#!/usr/bin/env bash
set -euo pipefail

TACTICAL_ROOT="${TACTICAL_ROOT:-/rmm}"
BACKEND_DIR="${TACTICAL_ROOT}/api/tacticalrmm"
VENV_PYTHON="${TACTICAL_ROOT}/api/env/bin/python"
MANAGE_PY="${BACKEND_DIR}/manage.py"

log() { printf '[TEC-TAC] %s\n' "$*"; }
fail() { printf '[TEC-TAC] ERROR: %s\n' "$*" >&2; exit 1; }

if [[ ${EUID} -ne 0 ]]; then
    fail "Run this script as root (for example: sudo bash scripts/reporting-permission.sh bob)."
fi

USERNAME="${1:-}"
MODE="${2:-manage}"

if [[ -z "${USERNAME}" ]]; then
    printf 'Usage: sudo bash scripts/reporting-permission.sh <username> [manage|list|both|show]\n' >&2
    exit 2
fi

case "${MODE}" in
    manage|list|both|show) ;;
    *) fail "Unknown mode '${MODE}'. Use manage, list, both, or show." ;;
esac

[[ -f "${MANAGE_PY}" ]] || fail "Tactical manage.py was not found at ${MANAGE_PY}."
[[ -x "${VENV_PYTHON}" ]] || fail "Tactical Python was not found at ${VENV_PYTHON}."

TACTICAL_USER="$(systemctl show rmm.service -p User --value 2>/dev/null || true)"
if [[ -z "${TACTICAL_USER}" ]]; then
    TACTICAL_USER="$(awk -F= '$1 == "User" {print $2; exit}' /etc/systemd/system/rmm.service 2>/dev/null || true)"
fi
[[ -n "${TACTICAL_USER}" ]] || fail "Could not determine the Tactical service user from rmm.service."

PY_CODE=$(cat <<'PYEOF'
import os
import sys
from django.contrib.auth import get_user_model
from tfdreporting.rbac import (
    PERMISSION_NETWORK_AVAILABILITY_LIST,
    PERMISSION_NETWORK_AVAILABILITY_MANAGE,
    get_role_permissions,
    grant_extension_permission,
)

username = os.environ["TEC_TAC_PERMISSION_USERNAME"]
mode = os.environ["TEC_TAC_PERMISSION_MODE"]
User = get_user_model()

try:
    user = User.objects.get(username=username)
except User.DoesNotExist:
    print(f"[TEC-TAC] ERROR: Tactical user '{username}' was not found.", file=sys.stderr)
    raise SystemExit(3)

role = user.get_and_set_role_cache()
if not role:
    print(f"[TEC-TAC] ERROR: Tactical user '{username}' does not have a role assigned.", file=sys.stderr)
    raise SystemExit(4)

if mode in ("manage", "both"):
    grant_extension_permission(role, PERMISSION_NETWORK_AVAILABILITY_MANAGE)
if mode in ("list", "both"):
    grant_extension_permission(role, PERMISSION_NETWORK_AVAILABILITY_LIST)

permissions = get_role_permissions(role)
print(f"[TEC-TAC] User: {user.username}")
print(f"[TEC-TAC] Tactical role: {role.name} (id={role.id})")
for codename, granted in permissions.items():
    print(f"[TEC-TAC] {codename}={granted}")
print("[TEC-TAC] NOTE: Tec-Tac permissions are role-based. Every Tactical user sharing this role inherits these permissions.")
PYEOF
)

log "Resolving Tactical user '${USERNAME}' and its role."
runuser -u "${TACTICAL_USER}" -- env \
    TEC_TAC_PERMISSION_USERNAME="${USERNAME}" \
    TEC_TAC_PERMISSION_MODE="${MODE}" \
    "${VENV_PYTHON}" "${MANAGE_PY}" shell -c "${PY_CODE}"

if [[ "${MODE}" == "show" ]]; then
    log "Permission inspection complete."
else
    log "Reporting permission update complete."
fi
