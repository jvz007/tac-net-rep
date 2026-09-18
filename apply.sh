#!/usr/bin/env bash
set -euo pipefail
TARGET="${TEC_TAC_FRAMEWORK_ROOT:-/opt/tec-tac}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ ${EUID} -eq 0 ]] || { echo "Run as root: sudo bash apply.sh" >&2; exit 1; }
[[ -f "$TARGET/VERSION" && -f "$TARGET/install.sh" && -d "$TARGET/framwork/tec_tac" ]] || { echo "Tec-Tac framework repo not found at $TARGET" >&2; exit 1; }
CURRENT="$(tr -d '[:space:]' < "$TARGET/VERSION")"
case "$CURRENT" in 1.3.*|1.4.0) ;; *) echo "Expected framework 1.3.x or 1.4.0; found $CURRENT" >&2; exit 1;; esac
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/var/lib/tec-tac/patch-backups/framework-${CURRENT}-${STAMP}"
mkdir -p "$BACKUP/framwork/tec_tac" "$BACKUP/scripts"
for f in bootstrap.py module_manager_v2.py module_state.py module_v2_views.py urls.py; do
  [[ -f "$TARGET/framwork/tec_tac/$f" ]] && cp -a "$TARGET/framwork/tec_tac/$f" "$BACKUP/framwork/tec_tac/$f" || true
done
[[ -f "$TARGET/scripts/module-v2-job-helper.py" ]] && cp -a "$TARGET/scripts/module-v2-job-helper.py" "$BACKUP/scripts/" || true
cp -a "$TARGET/VERSION" "$BACKUP/VERSION"
cp -a "$HERE/framwork/tec_tac/." "$TARGET/framwork/tec_tac/"
cp -a "$HERE/scripts/." "$TARGET/scripts/"
printf '1.4.0\n' > "$TARGET/VERSION"
cat > "$TARGET/tec_tac_package.json" <<'JSON'
{
  "type": "tec-tac-framework",
  "id": "tec-tac",
  "version": "1.4.0"
}
JSON
bash "$TARGET/install.sh"
bash "$HERE/install-v2-helper.sh" "$TARGET"
echo "Tec-Tac Framework 1.4.0 patch applied. Backup: $BACKUP"
