#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }
VERSION="$(tr -d '\r\n' < "${ROOT}/VERSION")"
PACKAGE_VERSION="$(python3 - "${ROOT}/tec_tac_package.json" <<'PY_VERSION'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['version'])
PY_VERSION
)"
[[ "${PACKAGE_VERSION}" == "${VERSION}" ]] || fail "VERSION (${VERSION}) does not match tec_tac_package.json (${PACKAGE_VERSION})"
for f in framwork/tec_tac/system_update.py scripts/system-update-helper.py tec_tac_package.json; do
  [[ -f "${ROOT}/${f}" ]] || fail "missing ${f}"
done
grep -q 'system/updates/online/stage/' "${ROOT}/framwork/tec_tac/urls.py" || fail "online stage route missing"
grep -q 'systemd-run' "${ROOT}/scripts/system-update-helper.py" || fail "transient worker missing"
grep -q 'flock' "${ROOT}/scripts/system-update-helper.py" || fail "global update lock missing"
grep -q 'backup_root' "${ROOT}/scripts/system-update-helper.py" || fail "backup lifecycle missing"
grep -q 'restore_backup' "${ROOT}/scripts/system-update-helper.py" || fail "rollback lifecycle missing"

grep -q 'snapshot_dynamic_plugins' "${ROOT}/scripts/system-update-helper.py" || fail "dynamic module pre-update inventory missing"
grep -q 'verify_dynamic_plugins' "${ROOT}/scripts/system-update-helper.py" || fail "dynamic module preservation verification missing"
grep -q 'FRAMEWORK_OWNED_PLUGIN_PATHS' "${ROOT}/scripts/system-update-helper.py" || fail "framework-owned plugin boundary missing"
grep -q 'FRAMEWORK_REPOSITORY' "${ROOT}/install.sh" || fail "framework repository config missing"
grep -q 'UI_REPOSITORY' "${ROOT}/install.sh" || fail "UI repository config missing"
python3 -m py_compile "${ROOT}/framwork/tec_tac/system_update.py" "${ROOT}/scripts/system-update-helper.py"
bash -n "${ROOT}/install.sh"
bash -n "${ROOT}/uninstall.sh"
echo "[TEST] PASS system update foundation"

# Framework self-update must preserve dynamically installed module trees byte-for-byte.
python3 - "${ROOT}/scripts/system-update-helper.py" <<'PY_PRESERVE'
import importlib.util, tempfile
from pathlib import Path
import sys
spec=importlib.util.spec_from_file_location('tt_update', sys.argv[1]); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as tmp:
    base=Path(tmp); target=base/'target'; source=base/'source'
    for root in (target,source):
        (root/'framwork').mkdir(parents=True); (root/'scripts').mkdir(); (root/'tests').mkdir(); (root/'docs').mkdir(); (root/'templates').mkdir(); (root/'extensions'/'example').mkdir(parents=True); (root/'extensions'/'reporting').mkdir(parents=True); (root/'reportsets'/'example').mkdir(parents=True)
        (root/'VERSION').write_text('x')
    dyn=target/'extensions'/'customer-module'; dyn.mkdir(parents=True); (dyn/'tec_tac.json').write_text('{"id":"customer-module"}')
    rep=target/'reportsets'/'customer-module'; rep.mkdir(parents=True); (rep/'tec_tac.json').write_text('{"id":"customer-module"}')
    before=mod.snapshot_dynamic_plugins(target)
    mod.deploy_framework(source,target)
    mod.verify_dynamic_plugins(target,before)
    assert (dyn/'tec_tac.json').is_file() and (rep/'tec_tac.json').is_file()
print('[TEST] dynamic module preservation OK')
PY_PRESERVE

# Release/install verification must never hardcode a prior framework version.
! grep -Eq "framework_version'\][[:space:]]*==[[:space:]]*'1\\.[0-9]+\\.[0-9]+'" "${ROOT}/install.sh" || fail "installer contains a hardcoded framework contract version assertion"
grep -q "expected='\${PACKAGE_VERSION}'" "${ROOT}/install.sh" || fail "installer contract verification is not driven by VERSION"
grep -q 'INSTALL_TIMEOUT_SECONDS' "${ROOT}/scripts/system-update-helper.py" || fail "bounded installer timeout missing"
grep -q 'migrate.*tec_tac.*--check' "${ROOT}/scripts/system-update-helper.py" || fail "post-install framework migration verification missing"
grep -q 'package manifest verification failed' "${ROOT}/scripts/system-update-helper.py" || fail "post-install package manifest verification missing"
grep -q 'contract version OK' "${ROOT}/scripts/system-update-helper.py" || fail "post-install contract version verification missing"
echo "[TEST] PASS system update transactional verification"
