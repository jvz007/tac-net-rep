#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
grep -q 'system/storage/' "$ROOT/framwork/tec_tac/urls.py"
grep -q 'tec-tac-housekeeping' "$ROOT/install.sh"
grep -q 'local_settings_backups' "$ROOT/scripts/housekeeping-helper.py"
python3 - "$ROOT" <<'PY'
import importlib.util, pathlib, tempfile, time, sys
root=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('hk',root/'scripts/housekeeping-helper.py'); h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
with tempfile.TemporaryDirectory() as td:
  base=pathlib.Path(td); h.STATE=base; h.ROOT=base/'housekeeping'; h.RESULTS=h.ROOT/'results'
  h.CATEGORY_PATHS={'x':[(base/'x','files','*')]}; h.DEFAULTS={'x':{'mode':'keep_count','keep':1}}
  (base/'x').mkdir(); (base/'x'/'a').write_bytes(b'a'*10); time.sleep(.01); (base/'x'/'b').write_bytes(b'b'*20)
  items,purge=h.select('x',{'mode':'keep_count','keep':1})
  assert len(items)==2 and len(purge)==1 and purge[0]['path'].name=='a'
print('housekeeping foundation: PASS')
PY
