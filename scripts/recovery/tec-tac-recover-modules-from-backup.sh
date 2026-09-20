#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"
MODE=check; BACKUP=""; YES=0
for arg in "$@"; do
  case "$arg" in --check) MODE=check;; --repair) MODE=repair;; --yes) YES=1;; --verbose) :;; --json) :;; --backup=*) BACKUP="${arg#*=}";; -h|--help) echo "Usage: $0 [--check|--repair] [--backup=/path/framework-*.tar.gz] [--yes]"; exit 0;; *) recovery_err "Unknown argument: $arg"; exit 2;; esac
done
require_root
if [[ -z "$BACKUP" ]]; then
  BACKUP="$(ls -1t "${SYSTEM_UPDATE_ROOT}"/backups/framework-*.tar.gz 2>/dev/null | head -1 || true)"
fi
[[ -f "$BACKUP" ]] || { recovery_err "No framework backup found. Use --backup=/path/file.tar.gz"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tar -xzf "$BACKUP" -C "$TMP"
BASE="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)"
[[ -d "$BASE/extensions" ]] || { recovery_err "Backup does not contain a framework extensions tree."; exit 1; }
missing=()
for top in extensions reportsets; do
  [[ -d "$BASE/$top" ]] || continue
  for src in "$BASE/$top"/*; do
    [[ -d "$src" && -f "$src/tec_tac.json" ]] || continue
    name="$(basename "$src")"
    [[ "$name" == example || "$name" == reporting ]] && continue
    dst="${TEC_TAC_ROOT}/${top}/${name}"
    if [[ ! -f "$dst/tec_tac.json" ]]; then missing+=("$top/$name"); fi
  done
done
recovery_log "Backup: $BACKUP"
if [[ ${#missing[@]} -eq 0 ]]; then recovery_log "No missing managed module trees found."; exit 0; fi
printf '[MISSING] %s\n' "${missing[@]}"
[[ "$MODE" == repair ]] || exit 1
if [[ "$YES" -ne 1 ]]; then
  printf 'Restore these missing module trees only? [y/N]: '
  read -r answer
  case "$answer" in y|Y|yes|YES|Yes) ;; *) recovery_log "No changes made."; exit 1;; esac
fi
SAFETY="${SYSTEM_UPDATE_ROOT}/backups/recovery-modules-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
tar -czf "$SAFETY" -C "${TEC_TAC_ROOT}" extensions reportsets
chmod 0640 "$SAFETY"
for rel in "${missing[@]}"; do
  dst="${TEC_TAC_ROOT}/$rel"
  mkdir -p "$(dirname "$dst")"
  rm -rf "$dst"
  cp -a "$BASE/$rel" "$dst"
done
chmod -R a+rX "${TEC_TAC_ROOT}/extensions" "${TEC_TAC_ROOT}/reportsets"
if ! "${HERE}/tec-tac-repair-modules.sh" --check; then
  recovery_err "Restored files failed module-pair validation. Safety backup: $SAFETY"
  exit 1
fi
if ! run_manage "check"; then
  recovery_err "Restored modules failed Django validation. Safety backup: $SAFETY"
  exit 1
fi
recovery_log "Restored ${#missing[@]} tree(s) and validated module registry/Django. Safety backup: $SAFETY"
