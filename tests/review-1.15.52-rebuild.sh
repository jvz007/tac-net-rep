#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 1. module-state lock must be usable by a non-owner Tactical-style reader.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
chmod 0755 "$tmp"
printf '%s\n' '{"schema":1,"modules":{}}' > "$tmp/module-state.json"
chown root:root "$tmp/module-state.json"
chmod 0644 "$tmp/module-state.json"
touch "$tmp/module-state.lock"
chown root:nogroup "$tmp/module-state.lock"
chmod 0664 "$tmp/module-state.lock"
runuser -u nobody -- env PYTHONPATH="$ROOT/framwork" STATE_ROOT_TEST="$tmp" python3 - <<'PY'
import os
from pathlib import Path
from tec_tac import module_state as m
root=Path(os.environ['STATE_ROOT_TEST'])
m.STATE_ROOT=root; m.STATE_FILE=root/'module-state.json'; m.STATE_LOCK=root/'module-state.lock'
assert m.load_state() == {'schema':1,'modules':{}}, m.load_state()
PY


# 1b. Shared load_state() must survive a genuinely missing lock during bootstrap.
tmp_missing="$(mktemp -d)"
chmod 0755 "$tmp_missing"
printf '%s\n' '{"schema":1,"modules":{}}' > "$tmp_missing/module-state.json"
chmod 0644 "$tmp_missing/module-state.json"
runuser -u nobody -- env PYTHONPATH="$ROOT/framwork" STATE_ROOT_TEST="$tmp_missing" python3 - <<'PY'
import os
from pathlib import Path
from tec_tac import module_state as m
root=Path(os.environ['STATE_ROOT_TEST'])
m.STATE_ROOT=root; m.STATE_FILE=root/'module-state.json'; m.STATE_LOCK=root/'module-state.lock'
assert not m.STATE_LOCK.exists()
assert m.load_state() == {'schema':1,'modules':{}}, m.load_state()
assert not m.STATE_LOCK.exists(), 'shared bootstrap read must not create the root-owned lock'
PY
rm -rf "$tmp_missing"

# 1c. Installer must create the lock before the bootstrap and first manage.py call.
python3 - "$ROOT/install.sh" <<'PY'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text()
lock=s.index('MODULE_STATE_LOCK="${MODULE_STATE_ROOT}/module-state.lock"')
bootstrap=s.index('from tec_tac.bootstrap import load_extensions')
manage=s.index('log "Running Django system checks."')
assert lock < bootstrap < manage, (lock, bootstrap, manage)
PY

# 2. root:tactical-group 0640 GitHub token must be readable by the service user.
printf '%s\n' 'test-token-value' > "$tmp/github-token"
chown root:nogroup "$tmp/github-token"
chmod 0640 "$tmp/github-token"
runuser -u nobody -- env PYTHONPATH="$ROOT/framwork" TOKEN_TEST="$tmp/github-token" python3 - <<'PY'
import os
from tec_tac import system_update as s
s._read_config=lambda:{'GITHUB_TOKEN_FILE':os.environ['TOKEN_TEST'],'TACTICAL_USER':'nobody'}
assert s._github_headers()['Authorization'] == 'Bearer test-token-value'
PY

grep -q 'chown root:"${TACTICAL_GROUP}" "${GITHUB_TOKEN_PATH}"' "$ROOT/install.sh"
grep -q 'chmod 0640 "${GITHUB_TOKEN_PATH}"' "$ROOT/install.sh"

# 3. Numeric rebuild suffixes are upgrades, not prereleases/downgrades.
PYTHONPATH="$ROOT/framwork" python3 - <<'PY'
from tec_tac import system_update as s
assert s._version_key('1.15.52') < s._version_key('1.15.52-1') < s._version_key('1.15.52-2')
PY
python3 - "$ROOT" <<'PY'
import importlib.util, pathlib, sys
root=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('helper', root/'scripts/system-update-helper.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert m._version_key('1.15.52') < m._version_key('1.15.52-1') < m._version_key('1.15.52-2')
PY

# 4. SSRF guard permits explicit internal RFC1918 repos, blocks them otherwise,
#    blocks CGNAT/public trust and IPv4-mapped loopback, and pins connections.
python3 - "$ROOT" <<'PY'
import importlib.util, pathlib, sys, types
root=pathlib.Path(sys.argv[1])
pkg=types.ModuleType('tec_tac'); pkg.__path__=[]; sys.modules['tec_tac']=pkg
mm=types.ModuleType('tec_tac.module_manager'); mm.MAX_PACKAGE_BYTES=1024; mm.STAGED_ROOT=pathlib.Path('/tmp'); mm._atomic_json=lambda *a,**k:None; mm._load_stage=lambda *a,**k:{}; sys.modules[mm.__name__]=mm
mv=types.ModuleType('tec_tac.module_manager_v2')
class E(Exception): pass
mv.LicensingRequirementError=E; mv.ModuleManagerV2Error=E; mv._check_runtime_requirements=lambda *a,**k:[]; mv.installed_catalog_v2=lambda:[]; mv.stage_uploaded_artifact=lambda *a,**k:{}; mv.discard_v2_stage=lambda *a,**k:None; mv.attach_source_provenance=lambda *a,**k:None; sys.modules[mv.__name__]=mv
ms=types.ModuleType('tec_tac.module_state'); ms.ModuleStateError=E; ms.version_satisfies=lambda *a,**k:True; sys.modules[ms.__name__]=ms
spec=importlib.util.spec_from_file_location('tec_tac.module_repository', root/'framwork/tec_tac/module_repository.py')
m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m; spec.loader.exec_module(m)
assert m._validate_remote_url('http://10.1.2.3/repository.json', trust='internal')
for url, trust in [
    ('http://10.1.2.3/repository.json','custom'),
    ('http://100.64.0.1/repository.json','official'),
    ('http://[::ffff:127.0.0.1]/repository.json','internal'),
]:
    try: m._validate_remote_url(url, trust=trust)
    except m.ModuleRepositoryError: pass
    else: raise AssertionError((url, trust))
source=(root/'framwork/tec_tac/module_repository.py').read_text()
assert 'socket.create_connection((str(address), port)' in source
assert 'opener.open(' not in source
PY

# 5. A legacy zero housekeeping policy is visible in scans but remains blocked
#    from destructive purge unless explicitly acknowledged.
python3 - "$ROOT" <<'PY'
import importlib.util, pathlib, tempfile, sys
root=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('hk',root/'scripts/housekeeping-helper.py'); h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
with tempfile.TemporaryDirectory() as td:
    base=pathlib.Path(td); h.STATE=base; h.ROOT=base/'housekeeping'; h.RESULTS=h.ROOT/'results'
    h.CATEGORY_PATHS={'x':[(base/'x','files','*')]}; h.DEFAULTS={'x':{'mode':'keep_count','keep':0}}
    (base/'x').mkdir(); (base/'x'/'a').write_text('a')
    items,purge,protected,active,unreadable,blocked,reason=h.select('x',{'mode':'keep_count','keep':0},dry_run=True)
    assert len(items)==1 and purge==[] and blocked and 'allow_zero_destructive' in reason
    try: h.select('x',{'mode':'keep_count','keep':0},dry_run=False)
    except RuntimeError: pass
    else: raise AssertionError('destructive zero policy was not blocked')
PY

# Legacy zero policies may be re-saved unchanged without authorizing purge.
python3 - "$ROOT" <<'PY'
import importlib.util, json, pathlib, tempfile, sys
root=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('hkcore',root/'framwork/tec_tac/housekeeping.py'); h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
with tempfile.TemporaryDirectory() as td:
    base=pathlib.Path(td); h.ROOT=base; h.CONFIG=base/'config.json'
    legacy={k:dict(v) for k,v in h.DEFAULT_POLICIES.items()}
    first=next(iter(legacy)); field='days' if legacy[first]['mode']=='age_days' else 'keep'; legacy[first][field]=0
    h.CONFIG.write_text(json.dumps({'policies':legacy}))
    saved=h.save_config({'policies':legacy})
    assert saved['policies'][first][field] == 0 and saved['allow_zero_destructive'] is False
PY

# 6. Shared config loader must propagate malformed-config failure.
printf '%s\n' 'BROKEN KEY=value' > "$tmp/bad.conf"
if TEC_TAC_CONFIG_FILE="$tmp/bad.conf" bash -c "source '$ROOT/scripts/tec-tac-config.sh'" >/dev/null 2>&1; then
  echo 'config loader accepted malformed config' >&2
  exit 1
fi

echo '1.15.52 rebuild review regressions: PASS'
