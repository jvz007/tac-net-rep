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
grep -q 'VOLATILE_PLUGIN_DIRS' "${ROOT}/scripts/system-update-helper.py" || fail "volatile plugin cache exclusion missing"
grep -q 'VOLATILE_PLUGIN_SUFFIXES' "${ROOT}/scripts/system-update-helper.py" || fail "volatile plugin bytecode exclusion missing"
grep -q 'FRAMEWORK_OWNED_PLUGIN_PATHS' "${ROOT}/scripts/system-update-helper.py" || fail "framework-owned plugin boundary missing"
grep -q 'TEC_TAC_FRAMEWORK_SOURCE' "${ROOT}/install.sh" || fail "framework source layout config missing"
grep -q 'TEC_TAC_UI_SOURCE' "${ROOT}/install.sh" || fail "UI source layout config missing"
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

    # Service restarts/imports may create or rewrite Python bytecode. These are
    # runtime cache artifacts, not module package mutations, and must not trip
    # framework preservation verification.
    cache=dyn/'__pycache__'; cache.mkdir(); (cache/'apps.cpython-312.pyc').write_bytes(b'first-cache')
    mod.verify_dynamic_plugins(target,before)
    (cache/'apps.cpython-312.pyc').write_bytes(b'second-cache')
    (dyn/'orphan.pyc').write_bytes(b'cache-outside-pycache')
    mod.verify_dynamic_plugins(target,before)

    # Real persistent module content must still be protected.
    (dyn/'tec_tac.json').write_text('{"id":"customer-module","changed":true}')
    try:
        mod.verify_dynamic_plugins(target,before)
    except RuntimeError as exc:
        assert 'changed: extensions/customer-module' in str(exc), exc
    else:
        raise AssertionError('persistent module source mutation was not detected')
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

# 1.13.0 source/runtime separation contract.
grep -q '/opt/tec-tac/etc/tec-tac.conf' "${ROOT}/scripts/system-update-helper.py" || fail "system updater is not using central Tec-Tac config"
grep -q 'TEC_TAC_FRAMEWORK_SOURCE' "${ROOT}/scripts/system-update-helper.py" || fail "system updater is not targeting framework source checkout"
grep -q 'TEC_TAC_UI_SOURCE' "${ROOT}/scripts/system-update-helper.py" || fail "system updater is not targeting UI source checkout"
grep -q 'runtime_root = Path' "${ROOT}/scripts/system-update-helper.py" || fail "runtime module inventory verification missing"
echo "[TEST] PASS source/runtime update layout"

# 1.13.2 source checkout integrity: online updates must land on exact commits,
# offline packages must become auditable local commits, and rollback must restore HEAD.
python3 - "${ROOT}/scripts/system-update-helper.py" <<'PY_GIT_SOURCE'
import importlib.util, json, subprocess, tempfile
from pathlib import Path
import sys
spec=importlib.util.spec_from_file_location('tt_update_git', sys.argv[1]); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def out(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()

with tempfile.TemporaryDirectory() as tmp:
    base=Path(tmp)
    remote=base/'remote.git'; run('git','init','--bare',str(remote))
    seed=base/'seed'; run('git','init',str(seed)); run('git','config','user.name','test',cwd=seed); run('git','config','user.email','test@example.invalid',cwd=seed)
    (seed/'VERSION').write_text('1.0.0\n'); (seed/'install.sh').write_text('#!/bin/sh\n'); (seed/'framwork'/'tec_tac').mkdir(parents=True); (seed/'framwork'/'tec_tac'/'__init__.py').write_text('')
    run('git','add','-A',cwd=seed); run('git','commit','-m','one',cwd=seed); run('git','branch','-M','main',cwd=seed); run('git','remote','add','origin',str(remote),cwd=seed); run('git','push','-u','origin','main',cwd=seed)
    checkout=base/'checkout'; run('git','clone','-b','main',str(remote),str(checkout))
    old=out('git','rev-parse','HEAD',cwd=checkout)

    # Create a second exact online commit in origin.
    (seed/'VERSION').write_text('1.0.1\n'); (seed/'online.txt').write_text('exact commit\n'); run('git','add','-A',cwd=seed); run('git','commit','-m','two',cwd=seed); run('git','push',cwd=seed)
    online=out('git','rev-parse','HEAD',cwd=seed)
    source=base/'online-source'; source.mkdir(); (source/'VERSION').write_text('1.0.1\n')
    state=mod.apply_source_update(source,checkout,'framework',{'id':'12345678-x','version':'1.0.1','source':{'type':'branch','commit':online}})
    assert out('git','rev-parse','HEAD',cwd=checkout)==online
    assert not out('git','status','--porcelain',cwd=checkout)
    mod.restore_git_source(checkout,state)
    assert out('git','rev-parse','HEAD',cwd=checkout)==old
    assert out('git','symbolic-ref','--short','HEAD',cwd=checkout)=='main'

    # Offline package becomes its own clean local branch/commit.
    offline=base/'offline'; offline.mkdir(); (offline/'VERSION').write_text('1.0.2\n'); (offline/'install.sh').write_text('#!/bin/sh\n'); (offline/'framwork'/'tec_tac').mkdir(parents=True); (offline/'framwork'/'tec_tac'/'__init__.py').write_text(''); (offline/'offline.txt').write_text('package\n')
    state=mod.apply_source_update(offline,checkout,'framework',{'id':'abcdef12-0000','version':'1.0.2','source':{'type':'offline'}})
    branch=out('git','symbolic-ref','--short','HEAD',cwd=checkout)
    assert branch.startswith('tec-tac/offline/framework-1.0.2-abcdef12'), branch
    assert not out('git','status','--porcelain',cwd=checkout)
    assert (checkout/'offline.txt').read_text()=='package\n'
    mod.restore_git_source(checkout,state)
    assert out('git','rev-parse','HEAD',cwd=checkout)==old
    assert out('git','symbolic-ref','--short','HEAD',cwd=checkout)=='main'

    # Reinstalling an identical offline tree must still produce an auditable
    # local commit instead of failing with 'nothing to commit'.
    identical=base/'identical'; identical.mkdir()
    for item in checkout.iterdir():
        if item.name == '.git':
            continue
        dest=identical/item.name
        if item.is_dir():
            import shutil; shutil.copytree(item,dest)
        else:
            import shutil; shutil.copy2(item,dest)
    state=mod.apply_source_update(identical,checkout,'framework',{'id':'feedbeef-0000','version':'1.0.0','source':{'type':'offline'}})
    branch=out('git','symbolic-ref','--short','HEAD',cwd=checkout)
    assert branch.startswith('tec-tac/offline/framework-1.0.0-feedbeef'), branch
    assert out('git','rev-parse','HEAD',cwd=checkout) != old
    assert not out('git','status','--porcelain',cwd=checkout)
    mod.restore_git_source(checkout,state)
    assert out('git','rev-parse','HEAD',cwd=checkout)==old
    assert out('git','symbolic-ref','--short','HEAD',cwd=checkout)=='main'
print('[TEST] PASS source Git transaction and rollback')
PY_GIT_SOURCE

grep -q 'verify_source_runtime_layout' "${ROOT}/scripts/system-update-helper.py" || fail "post-update source/runtime separation verification missing"
grep -q 'source checkout is not clean' "${ROOT}/scripts/system-update-helper.py" || fail "dirty source preflight missing"
grep -q 'tec-tac/offline/' "${ROOT}/scripts/system-update-helper.py" || fail "offline update Git branch missing"
grep -q 'git.*fetch' "${ROOT}/scripts/system-update-helper.py" || fail "online exact-commit Git update missing"
echo "[TEST] PASS source checkout hardening"

# 1.13.5 cross-lifecycle serialization: module mutations and system updates must
# never overlap because module preservation verification assumes a stable tree.
for helper in scripts/system-update-helper.py scripts/module-job-helper.py scripts/module-v2-job-helper.py; do
  grep -q 'LIFECYCLE_LOCK_PATH = Path("/var/lib/tec-tac/lifecycle.lock")' "${ROOT}/${helper}" || fail "shared lifecycle lock path missing from ${helper}"
  grep -q 'acquire_lifecycle_lock()' "${ROOT}/${helper}" || fail "shared lifecycle lock acquisition missing from ${helper}"
done
grep -q 'another Tec-Tac lifecycle operation is already running' "${ROOT}/scripts/system-update-helper.py" || fail "system update lifecycle contention error missing"
grep -q 'another Tec-Tac lifecycle operation is already running' "${ROOT}/scripts/module-job-helper.py" || fail "module v1 lifecycle contention error missing"
grep -q 'another Tec-Tac lifecycle operation is already running' "${ROOT}/scripts/module-v2-job-helper.py" || fail "module v2 lifecycle contention error missing"
echo "[TEST] PASS shared lifecycle serialization"
