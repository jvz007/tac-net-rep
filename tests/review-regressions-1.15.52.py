#!/usr/bin/env python3
import importlib.util, json, pathlib, tempfile, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]

def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(spec); sys.modules[name]=m; spec.loader.exec_module(m); return m

# C14: corrupt module state fails closed and cannot be overwritten by mutation.
ms=load('ms152', ROOT/'framwork/tec_tac/module_state.py')
with tempfile.TemporaryDirectory() as td:
    base=pathlib.Path(td); ms.STATE_ROOT=base; ms.STATE_FILE=base/'module-state.json'; ms.STATE_LOCK=base/'module-state.lock'
    ms.STATE_FILE.write_text('{bad json')
    state=ms.load_state(); assert state.get('_corrupt') is True and ms.is_enabled('demo',state) is False and ms.is_visible('demo',state) is False
    try: ms.set_enabled('demo',True); raise AssertionError('corrupt state overwritten')
    except ms.ModuleStateError: pass

# C5: active staging is protected and zero destructive policy requires explicit override.
hk=load('hk152', ROOT/'scripts/housekeeping-helper.py')
with tempfile.TemporaryDirectory() as td:
    base=pathlib.Path(td); hk.STATE=base; hk.ROOT=base/'housekeeping'; hk.RESULTS=hk.ROOT/'results'
    jobs=base/'module-manager'/'jobs'; staged=base/'module-manager'/'staged'; jobs.mkdir(parents=True); staged.mkdir(parents=True)
    (jobs/'abc.json').write_text(json.dumps({'id':'abc','status':'running'})); (staged/'old.zip').write_bytes(b'x')
    hk.CATEGORY_PATHS={'module_staging':[(staged,'files','*')]}; hk.JOB_ROOTS={'module_staging':jobs}; hk.STAGING_CATEGORIES={'module_staging'}; hk.HISTORY_CATEGORIES=set()
    items,purge,protected,active_ids,unreadable=hk.select('module_staging',{'mode':'age_days','days':0},allow_zero=True)
    assert items and not purge and protected and active_ids=={'abc'} and not unreadable
    try: hk.select('module_staging',{'mode':'age_days','days':0},allow_zero=False); raise AssertionError('zero policy accepted')
    except RuntimeError: pass

# C11: repository fetch validates initial and redirected URLs and blocks private/local address classes.
repo_text=(ROOT/'framwork/tec_tac/module_repository.py').read_text()
assert 'class _SafeRedirectHandler' in repo_text and '_validate_remote_url(newurl)' in repo_text
for token in ('address.is_loopback','address.is_private','address.is_link_local','address.is_reserved','address.is_unspecified'):
    assert token in repo_text

# Static security contracts.
audit_view=(ROOT/'framwork/tec_tac/audit_views.py').read_text(); audit=(ROOT/'framwork/tec_tac/audit.py').read_text()
assert 'Browser audit events may not claim Core provenance' in audit_view
assert 'HTTP_X_REQUEST_ID' not in audit and 'HTTP_X_CORRELATION_ID' not in audit
assert '_bounded_value(before' in audit and '_bounded_value(after' in audit
session=(ROOT/'framwork/tec_tac/session_security.py').read_text()
assert 'network.prefixlen == 0' in session and 'session_policy_changed' in session and 'active_knox_digests' in session
mm=(ROOT/'framwork/tec_tac/module_manager_v2.py').read_text(); assert '"type": "disabled_dependency"' in mm
install=(ROOT/'install.sh').read_text(); cfg=(ROOT/'scripts/tec-tac-config.sh').read_text()
assert 'source "${TEC_TAC_CONFIG_FILE}"' not in install and 'source "${TEC_TAC_CONFIG_FILE}"' not in cfg
assert 'chmod 0600 "${GITHUB_TOKEN_PATH}"' in install
update=(ROOT/'framwork/tec_tac/system_update.py').read_text(); assert 'mode 0600 or stricter' in update
print('[TEST] PASS 1.15.52 review regressions')
