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

# Source checkout integrity (1.17.98): the checkout is a Tactical-owned working copy. System Update logs and restores tracked
# changes, moves it to exactly the selected commit, and never writes release bytes into it. Root runs installers only from a
# verified staging copy (tests/system-update-linux-staging-1.17.98.py covers ownership, staging and rollback as root).
python3 - "${ROOT}/scripts/system-update-helper.py" <<'PY_GIT_SOURCE'
import importlib.util, subprocess, tempfile
from pathlib import Path
import sys
spec=importlib.util.spec_from_file_location('tt_update_git', sys.argv[1]); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
# The owner rule needs the Tactical account, which a test machine may not have; the Linux staging test covers it as root.
mod._git_runas=lambda cfg: None
mod.normalise_source_owner=lambda *a, **k: 0

def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def out(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()

class Log:
    def __init__(self): self.text=''
    def write(self, value): self.text+=value
    def flush(self): pass

with tempfile.TemporaryDirectory() as tmp:
    base=Path(tmp)
    remote=base/'remote.git'; run('git','init','-q','--bare',str(remote))
    seed=base/'seed'; run('git','init','-q',str(seed)); run('git','config','user.name','test',cwd=seed); run('git','config','user.email','test@example.invalid',cwd=seed)
    (seed/'VERSION').write_text('1.0.0\n'); (seed/'install.sh').write_text('#!/bin/sh\n'); (seed/'framwork'/'tec_tac').mkdir(parents=True); (seed/'framwork'/'tec_tac'/'__init__.py').write_text('')
    (seed/'.gitignore').write_text('node_modules/\n')
    run('git','add','-A',cwd=seed); run('git','commit','-q','-m','one',cwd=seed); run('git','branch','-M','dev',cwd=seed); run('git','remote','add','origin',str(remote),cwd=seed); run('git','push','-q','-u','origin','dev',cwd=seed)
    checkout=base/'checkout'; run('git','clone','-q','-b','dev',str(remote),str(checkout))
    cfg={'TEC_TAC_FRAMEWORK_SOURCE': str(checkout), 'TEC_TAC_UI_SOURCE': str(base/'ui'), 'TEC_TAC_ROOT': str(base/'runtime')}
    mod.load_config=lambda: dict(cfg)
    old=out('git','rev-parse','HEAD',cwd=checkout)

    # Tracked changes are logged and restored to HEAD; known generated files go; ignored files stay; HEAD is recorded.
    (checkout/'install.sh').write_text('#!/bin/sh\necho changed\n'); (checkout/'VERSION').unlink()
    (checkout/'framwork'/'tec_tac'/'__pycache__').mkdir(); (checkout/'framwork'/'tec_tac'/'__pycache__'/'x.pyc').write_bytes(b'cache')
    (checkout/'node_modules').mkdir(); (checkout/'node_modules'/'kept.js').write_text('ignored\n')
    log=Log()
    state=mod.prepare_source_checkout(checkout,'framework',cfg,log)
    assert state['head']==old and state['branch']=='dev', state
    assert any('install.sh' in line for line in state['restored_changes']) and any('VERSION' in line for line in state['restored_changes']), state
    assert 'tracked change(s); restoring them to HEAD' in log.text, log.text
    assert (checkout/'install.sh').read_text()=='#!/bin/sh\n' and (checkout/'VERSION').is_file()
    assert not (checkout/'framwork'/'tec_tac'/'__pycache__'/'x.pyc').exists()
    assert (checkout/'node_modules'/'kept.js').is_file(), 'ignored files are never deleted'
    assert not out('git','status','--porcelain',cwd=checkout)

    # An unknown untracked file may be an administrator's: the update stops and nothing is deleted.
    (checkout/'notes.txt').write_text('mine\n')
    try:
        mod.prepare_source_checkout(checkout,'framework',cfg,Log())
    except RuntimeError as exc:
        assert 'untracked files that System Update will not delete' in str(exc) and 'notes.txt' in str(exc), exc
    else:
        raise AssertionError('an unknown untracked file was not refused')
    assert (checkout/'notes.txt').read_text()=='mine\n'
    (checkout/'notes.txt').unlink()

    # The exact selected commit, with no second branch lookup: the remote moves on after the selection, HEAD does not follow it.
    (seed/'VERSION').write_text('1.0.1\n'); run('git','add','-A',cwd=seed); run('git','commit','-q','-m','two',cwd=seed); run('git','push','-q',cwd=seed)
    selected=out('git','rev-parse','HEAD',cwd=seed)
    (seed/'VERSION').write_text('1.0.2\n'); run('git','add','-A',cwd=seed); run('git','commit','-q','-m','three',cwd=seed); run('git','push','-q',cwd=seed)
    state=mod.prepare_source_checkout(checkout,'framework',cfg,Log())
    mod.move_source_to_commit(checkout,'framework',{'type':'branch','ref':'dev','commit':selected},cfg,Log())
    assert out('git','rev-parse','HEAD',cwd=checkout)==selected
    assert out('git','symbolic-ref','--short','HEAD',cwd=checkout)=='dev'
    assert (checkout/'VERSION').read_text()=='1.0.1\n'
    assert not out('git','status','--porcelain',cwd=checkout)
    assert (checkout/'node_modules'/'kept.js').is_file()

    # Rollback: back to the exact old HEAD and branch, clean.
    mod.restore_source_checkout(checkout,'framework',state,cfg)
    assert out('git','rev-parse','HEAD',cwd=checkout)==old
    assert out('git','symbolic-ref','--short','HEAD',cwd=checkout)=='dev'
    assert not out('git','status','--porcelain',cwd=checkout)

    # A release source leaves a detached HEAD at the tag's commit.
    mod.move_source_to_commit(checkout,'framework',{'type':'release','ref':'v1.0.1','commit':selected},cfg,Log())
    assert out('git','rev-parse','HEAD',cwd=checkout)==selected
    assert subprocess.run(['git','symbolic-ref','-q','HEAD'],cwd=checkout).returncode!=0
    mod.restore_source_checkout(checkout,'framework',state,cfg)

    # A commit the remote does not have stops the update with the fetch command to check.
    try:
        mod.move_source_to_commit(checkout,'framework',{'type':'branch','ref':'dev','commit':'f'*40},cfg,Log())
    except RuntimeError as exc:
        assert 'does not have commit' in str(exc) and 'fetch origin' in str(exc), exc
    else:
        raise AssertionError('an unknown commit was accepted')
    assert out('git','rev-parse','HEAD',cwd=checkout)==old

    # Unsafe refs are never passed to Git as a branch name.
    for bad in ('-x','a..b','a/','.hidden','x.lock','a//b','a@{1}'):
        assert not mod._SAFE_REF.fullmatch(bad), bad
    assert mod._SAFE_REF.fullmatch('dev') and mod._SAFE_REF.fullmatch('release/1.17') and mod._SAFE_REF.fullmatch('v1.17.98')
    # An offline package has no commit, so the checkout is not moved.
    assert mod._source_commit({'type':'offline','commit':selected}) is None
    assert mod._source_commit({'type':'branch','commit':selected.upper()})==selected
print('[TEST] PASS source Git transaction and rollback')
PY_GIT_SOURCE

grep -q 'verify_source_runtime_layout' "${ROOT}/scripts/system-update-helper.py" || fail "post-update source/runtime separation verification missing"
grep -q 'source checkout is not clean' "${ROOT}/scripts/system-update-helper.py" || fail "dirty source preflight missing"
grep -q 'def move_source_to_commit' "${ROOT}/scripts/system-update-helper.py" || fail "exact-commit source move missing"
! grep -Eq 'def (finish_source_update|apply_source_update|seal_execution_tree|restore_source_owner)\b' "${ROOT}/scripts/system-update-helper.py" || fail "the helper still writes release bytes into, seals or hands back the source checkout"
grep -q 'not staged and verified by the root helper' "${ROOT}/scripts/system-update-helper.py" || fail "installers may run from an unverified tree"
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
python3 "${ROOT}/tests/trust-policy-batch-1.15.133.py"
python3 "${ROOT}/tests/trust-policy-closure-1.15.150.py"
python3 "${ROOT}/tests/review-regressions-1.15.51.py"
python3 "${ROOT}/tests/review-regressions-1.15.50.py"

# R2: privileged extraction is root-private, ephemeral, and release mode metadata
# cannot carry setuid/setgid or group/world-write bits into root installer execution.
python3 "${ROOT}/tests/system-update-root-extraction-boundary.py"
grep -q 'with private_update_work_dir(job_id) as work:' "${ROOT}/scripts/system-update-helper.py" || fail "root-private update work context missing"
# 1.17.98: the execution tree is a root-only staging copy written with explicit root ownership and safe modes, not the checkout.
grep -q 'staged = stage_release_tree(' "${ROOT}/scripts/system-update-helper.py" || fail "execution tree staging missing"
grep -q 'os.fchown(out, 0, 0)' "${ROOT}/scripts/system-update-helper.py" || fail "execution tree ownership/mode normalization missing"
echo "[TEST] PASS system update R2 extraction boundary"

# Privileged claim must never follow Tactical-controlled staged symlinks or
# retain the original writable inode across root verification/install.
