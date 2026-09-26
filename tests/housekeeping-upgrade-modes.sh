#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="$ROOT/install.sh"

grep -Fq 'chmod 00755 "${HOUSEKEEPING_ROOT}"' "$INSTALL"
grep -Fq 'chmod 00700 "${HOUSEKEEPING_ROOT}/running"' "$INSTALL"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
HOUSEKEEPING_ROOT="$TMP/housekeeping"
mkdir -p "$HOUSEKEEPING_ROOT/running"
chmod 2770 "$HOUSEKEEPING_ROOT"
chmod 2770 "$HOUSEKEEPING_ROOT/running"

# Mirror the installer's mode-normalization semantics. A three-digit numeric
# chmod on GNU coreutils preserves setgid on directories; the explicit leading
# zero is required to clear inherited special bits from the legacy layout.
chmod 00755 "$HOUSEKEEPING_ROOT"
chmod 00700 "$HOUSEKEEPING_ROOT/running"

[[ "$(stat -c %a "$HOUSEKEEPING_ROOT")" == "755" ]]
[[ "$(stat -c %a "$HOUSEKEEPING_ROOT/running")" == "700" ]]

echo 'housekeeping upgrade modes: PASS'
