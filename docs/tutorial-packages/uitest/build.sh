#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${ROOT}/uitest-0.1.1.zip"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
mkdir -p "${TMP}/uitest-0.1.1"
cp -a "${ROOT}/source/extensions" "${TMP}/uitest-0.1.1/"
cp -a "${ROOT}/source/reportsets" "${TMP}/uitest-0.1.1/"
cd "${TMP}"
python3 - "${OUT}" <<'PY'
import sys, zipfile
from pathlib import Path
out=Path(sys.argv[1])
root=Path('uitest-0.1.1')
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(root.rglob('*')):
        if path.is_file(): zf.write(path, path.as_posix())
print(out)
PY
