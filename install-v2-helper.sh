#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="${1:-/opt/tec-tac}"
TACTICAL_USER="${TACTICAL_USER:-$(systemctl show rmm.service -p User --value)}"
[[ -n "$TACTICAL_USER" ]] || { echo "Unable to determine Tactical user" >&2; exit 1; }
TACTICAL_GROUP="$(id -gn "$TACTICAL_USER")"
HELPER_SRC="${REPO_ROOT}/scripts/module-v2-job-helper.py"
HELPER_DST="/usr/local/sbin/tec-tac-module-v2-job"
[[ -f "$HELPER_SRC" ]] || { echo "Missing $HELPER_SRC" >&2; exit 1; }
install -o root -g root -m 0755 "$HELPER_SRC" "$HELPER_DST"
mkdir -p /var/lib/tec-tac/module-manager/running-v2 /var/lib/tec-tac/module-manager/bundle-backups
chown root:"$TACTICAL_GROUP" /var/lib/tec-tac/module-manager/running-v2 /var/lib/tec-tac/module-manager/bundle-backups
chmod 2750 /var/lib/tec-tac/module-manager/running-v2 /var/lib/tec-tac/module-manager/bundle-backups
SUDOERS=/etc/sudoers.d/tec-tac-module-manager-v2
printf '%s ALL=(root) NOPASSWD: %s --dispatch *\n' "$TACTICAL_USER" "$HELPER_DST" > "$SUDOERS"
chown root:root "$SUDOERS"; chmod 0440 "$SUDOERS"
command -v visudo >/dev/null 2>&1 && visudo -cf "$SUDOERS" >/dev/null
echo "Module Management v2 helper installed."
