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
grep -q 'RELEASE_CACHE_TTL = timedelta(hours=24)' "${ROOT}/framwork/tec_tac/system_update.py" || fail "24-hour stable release cache TTL missing"
grep -q 'release-cache.json' "${ROOT}/framwork/tec_tac/system_update.py" || fail "stable release cache file missing"
grep -q '"release_cache"' "${ROOT}/framwork/tec_tac/system_update.py" || fail "system status does not expose cached release discovery"
grep -q 'force=force' "${ROOT}/framwork/tec_tac/views.py" || fail "manual stable release refresh does not bypass cache"
grep -q 'SYSTEM_UPDATE_ROOT}/cache' "${ROOT}/install.sh" || fail "system update cache runtime directory missing"

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

# Source checkout integrity: privileged execution uses only the root-verified
# staged source bytes. Web-tier online/offline provenance is non-authoritative;
# every update becomes an auditable local verified-package commit.
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

    # Even when web metadata claims an online branch/commit, privileged
    # deployment commits only the already root-verified staged bytes.
    (seed/'VERSION').write_text('1.0.1\n'); (seed/'online.txt').write_text('remote-only\n'); run('git','add','-A',cwd=seed); run('git','commit','-m','two',cwd=seed); run('git','push',cwd=seed)
    online=out('git','rev-parse','HEAD',cwd=seed)
    source=base/'online-source'; source.mkdir(); (source/'VERSION').write_text('1.0.1\n'); (source/'verified.txt').write_text('signed bytes\n')
    state=mod.apply_source_update(source,checkout,'framework',{'id':'12345678-x','version':'1.0.1','source':{'type':'branch','commit':online}})
    branch=out('git','symbolic-ref','--short','HEAD',cwd=checkout)
    assert branch.startswith('tec-tac/verified/framework-1.0.1-12345678'), branch
    assert (checkout/'verified.txt').read_text()=='signed bytes\n'
    assert not (checkout/'online.txt').exists()
    assert not out('git','status','--porcelain',cwd=checkout)
    mod.restore_git_source(checkout,state)
    assert out('git','rev-parse','HEAD',cwd=checkout)==old
    assert out('git','symbolic-ref','--short','HEAD',cwd=checkout)=='main'

    # UI online updates must remove ignored build/dependency residue before the
    # signed execution-tree verification. git clean -fd is insufficient because
    # node_modules is ignored and contains symlinks such as .bin/rollup.
    ui_remote=base/'ui-remote.git'; run('git','init','--bare',str(ui_remote))
    ui_seed=base/'ui-seed'; run('git','init',str(ui_seed)); run('git','config','user.name','test',cwd=ui_seed); run('git','config','user.email','test@example.invalid',cwd=ui_seed)
    (ui_seed/'VERSION').write_text('0.1.0\n'); (ui_seed/'package.json').write_text('{}\n'); (ui_seed/'src').mkdir(); (ui_seed/'src'/'App.vue').write_text('<template/>\n'); (ui_seed/'scripts').mkdir(); (ui_seed/'scripts'/'install.sh').write_text('#!/bin/sh\n'); (ui_seed/'.gitignore').write_text('node_modules/\ndist/\n.env\n')
    run('git','add','-A',cwd=ui_seed); run('git','commit','-m','ui one',cwd=ui_seed); run('git','branch','-M','main',cwd=ui_seed); run('git','remote','add','origin',str(ui_remote),cwd=ui_seed); run('git','push','-u','origin','main',cwd=ui_seed)
    ui_checkout=base/'ui-checkout'; run('git','clone','-b','main',str(ui_remote),str(ui_checkout))
    (ui_checkout/'node_modules'/'.bin').mkdir(parents=True); (ui_checkout/'node_modules'/'rollup').write_text('binary')
    (ui_checkout/'node_modules'/'.bin'/'rollup').symlink_to('../rollup')
    (ui_checkout/'dist').mkdir(); (ui_checkout/'dist'/'index.html').write_text('generated')
    (ui_checkout/'.env').write_text('SHOULD_NOT_SURVIVE=1\n')
    (ui_seed/'VERSION').write_text('0.1.1\n'); (ui_seed/'src'/'App.vue').write_text('<template>updated</template>\n'); run('git','add','-A',cwd=ui_seed); run('git','commit','-m','ui two',cwd=ui_seed); run('git','push',cwd=ui_seed)
    ui_online=out('git','rev-parse','HEAD',cwd=ui_seed)
    ui_source=base/'ui-source'; ui_source.mkdir(); (ui_source/'VERSION').write_text('0.1.1\n')
    mod.apply_source_update(ui_source,ui_checkout,'ui',{'id':'ui-clean-1','version':'0.1.1','source':{'type':'release','commit':ui_online}})
    assert not (ui_checkout/'node_modules').exists()
    assert not (ui_checkout/'dist').exists()
    assert not (ui_checkout/'.env').exists()
    assert not out('git','status','--porcelain',cwd=ui_checkout)

    # Offline package becomes its own clean local branch/commit.
    offline=base/'offline'; offline.mkdir(); (offline/'VERSION').write_text('1.0.2\n'); (offline/'install.sh').write_text('#!/bin/sh\n'); (offline/'framwork'/'tec_tac').mkdir(parents=True); (offline/'framwork'/'tec_tac'/'__init__.py').write_text(''); (offline/'offline.txt').write_text('package\n')
    state=mod.apply_source_update(offline,checkout,'framework',{'id':'abcdef12-0000','version':'1.0.2','source':{'type':'offline'}})
    branch=out('git','symbolic-ref','--short','HEAD',cwd=checkout)
    assert branch.startswith('tec-tac/verified/framework-1.0.2-abcdef12'), branch
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
    assert branch.startswith('tec-tac/verified/framework-1.0.0-feedbeef'), branch
    assert out('git','rev-parse','HEAD',cwd=checkout) != old
    assert not out('git','status','--porcelain',cwd=checkout)
    mod.restore_git_source(checkout,state)
    assert out('git','rev-parse','HEAD',cwd=checkout)==old
    assert out('git','symbolic-ref','--short','HEAD',cwd=checkout)=='main'
print('[TEST] PASS source Git transaction and rollback')
PY_GIT_SOURCE

grep -q 'verify_source_runtime_layout' "${ROOT}/scripts/system-update-helper.py" || fail "post-update source/runtime separation verification missing"
grep -q 'source checkout is not clean' "${ROOT}/scripts/system-update-helper.py" || fail "dirty source preflight missing"
grep -q 'tec-tac/verified/' "${ROOT}/scripts/system-update-helper.py" || fail "verified source update Git branch missing"
! grep -A60 'def apply_source_update' "${ROOT}/scripts/system-update-helper.py" | grep -q 'source_meta' || fail "web-tier source metadata still controls privileged deployment"
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

# 1.15.37 publisher-tool v0.2.0 signed source releases
python3 "${ROOT}/tests/system-update-signed-tree.py"
grep -q 'verify_release_tree' "${ROOT}/framwork/tec_tac/system_update.py" || fail "signed source-tree verifier not wired into System Updates"
grep -q 'root-verify-staged' "${ROOT}/scripts/system-update-helper.py" || fail "root worker staged tree verification missing"
grep -q 'root-verify-execution' "${ROOT}/scripts/system-update-helper.py" || fail "root worker checkout tree verification missing"
grep -q 'SIGNED_RELEASE_MIN_VERSION' "${ROOT}/framwork/tec_tac/system_update.py" || fail "Framework signed release cutoff missing"
! sed -n '/def queue_install/,/def public_job/p' "${ROOT}/framwork/tec_tac/system_update.py" | grep -A8 '_new_job({' | grep -q '"release_trust"' || fail "mutable release trust leaked into privileged job request"
echo "[TEST] PASS signed source release integration"

# Shared System Update / Module Management acceptance policy.
grep -q 'system/updates/trust-policy/' "${ROOT}/framwork/tec_tac/urls.py" || fail "update trust policy route missing"
grep -q 'update_trust_policy' "${ROOT}/framwork/tec_tac/system_update.py" || fail "system status trust policy visibility missing"
grep -q 'require_trust_accepted' "${ROOT}/framwork/tec_tac/system_update.py" || fail "system update trust floor enforcement missing"
grep -q 'require_trust_accepted' "${ROOT}/framwork/tec_tac/module_manager.py" || fail "module trust floor enforcement missing"
PYTHONPATH="${ROOT}/framwork" python3 "${ROOT}/tests/update-trust-policy.py"
python3 "${ROOT}/tests/trust-policy-upgrade-migration.py"
python3 "${ROOT}/tests/review-regressions-1.15.50.py"

# R2: privileged extraction is root-private, ephemeral, and release mode metadata
# cannot carry setuid/setgid or group/world-write bits into root installer execution.
python3 "${ROOT}/tests/system-update-root-extraction-boundary.py"
grep -q 'with private_update_work_dir(job_id) as work:' "${ROOT}/scripts/system-update-helper.py" || fail "root-private update work context missing"
grep -q 'normalize_release_tree_security(target)' "${ROOT}/scripts/system-update-helper.py" || fail "execution tree ownership/mode normalization missing"
echo "[TEST] PASS system update R2 extraction boundary"

# Privileged claim must never follow Tactical-controlled staged symlinks or
# retain the original writable inode across root verification/install.
python3 "${ROOT}/tests/system-update-claim-security.py"
