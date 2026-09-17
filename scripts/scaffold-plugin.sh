#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_ID="${1:-}"
VERSION="${2:-0.1.0}"

fail() { printf '[TEC-TAC] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[TEC-TAC] %s\n' "$*"; }

[[ -n "${PLUGIN_ID}" ]] || fail "Usage: sudo bash scripts/scaffold-plugin.sh <extension-id> [version]"
[[ "${PLUGIN_ID}" =~ ^[A-Za-z0-9_-]+$ ]] || fail "Extension ID may contain only letters, numbers, hyphen and underscore."

EXT_DIR="${REPO_ROOT}/extensions/${PLUGIN_ID}"
REP_DIR="${REPO_ROOT}/reportsets/${PLUGIN_ID}"
[[ ! -e "${EXT_DIR}" ]] || fail "Extension path already exists: ${EXT_DIR}"
[[ ! -e "${REP_DIR}" ]] || fail "Reportset path already exists: ${REP_DIR}"

mkdir -p "${EXT_DIR}" "${REP_DIR}"
cat > "${EXT_DIR}/tec_tac.json" <<JSON
{
  "id": "${PLUGIN_ID}",
  "type": "extension",
  "version": "${VERSION}",
  "python_paths": ["."],
  "django_apps": []
}
JSON
cat > "${REP_DIR}/tec_tac.json" <<JSON
{
  "id": "${PLUGIN_ID}",
  "type": "reportset",
  "version": "${VERSION}",
  "python_paths": ["."],
  "django_apps": []
}
JSON
printf '# %s extension\n\nOperational/runtime implementation for the `%s` Tec-Tac extension.\n' "${PLUGIN_ID}" "${PLUGIN_ID}" > "${EXT_DIR}/README.md"
printf '# %s reportset\n\nReporting mappings, enrichment and report-facing definitions owned by the `%s` extension.\n' "${PLUGIN_ID}" "${PLUGIN_ID}" > "${REP_DIR}/README.md"

log "Created extension: ${EXT_DIR}"
log "Created reportset: ${REP_DIR}"
log "Edit both tec_tac.json manifests before adding Django apps or Python packages."
