#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${ROOT}/packagetest-0.1.0.zip"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
mkdir -p "${TMP}/packagetest-0.1.0"
cp -a "${ROOT}/source/extensions" "${TMP}/packagetest-0.1.0/"
cp -a "${ROOT}/source/reportsets" "${TMP}/packagetest-0.1.0/"
cd "${TMP}"
python3 -m zipfile -c "${OUT}" packagetest-0.1.0
printf 'Built %s\n' "${OUT}"
