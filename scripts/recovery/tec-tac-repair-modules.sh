#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"
MODE=check
JSON=0
for arg in "$@"; do
  case "$arg" in --check) MODE=check;; --repair) MODE=repair;; --json) JSON=1;; --verbose) :;; -h|--help) echo "Usage: $0 [--check|--repair] [--json]"; exit 0;; *) recovery_err "Unknown argument: $arg"; exit 2;; esac
done
require_root
if [[ "$MODE" == repair ]]; then repair_module_permissions >/dev/null; fi
EXT="${TEC_TAC_ROOT}/extensions"; REP="${TEC_TAC_ROOT}/reportsets"; STATE="${MODULE_ROOT}/module-state.json"
python3 - "$EXT" "$REP" "$STATE" "$JSON" <<'PY'
import json,sys
from pathlib import Path
ext,rep,state=map(Path,sys.argv[1:4]); as_json=sys.argv[4]=='1'
def ids(root):
    out={}
    if not root.is_dir(): return out
    for d in root.iterdir():
        if d.is_dir() and (d/'tec_tac.json').is_file():
            try: p=json.loads((d/'tec_tac.json').read_text())
            except Exception as e: out[d.name]={'error':str(e)}; continue
            out[d.name]=p
    return out
e=ids(ext); r=ids(rep); issues=[]; rows=[]
for mid in sorted(set(e)|set(r)):
    if mid not in e: issues.append(f'{mid}: reportset exists without extension')
    elif mid not in r: issues.append(f'{mid}: extension exists without reportset')
    else:
        if e[mid].get('id',mid)!=mid: issues.append(f'{mid}: extension manifest id mismatch')
        if r[mid].get('id',mid)!=mid: issues.append(f'{mid}: reportset manifest id mismatch')
        if e[mid].get('version')!=r[mid].get('version'): issues.append(f'{mid}: extension/reportset version mismatch')
    rows.append({'id':mid,'extension':mid in e,'reportset':mid in r,'extension_version':e.get(mid,{}).get('version'),'reportset_version':r.get(mid,{}).get('version')})
try: s=json.loads(state.read_text()) if state.is_file() else {'modules':{}}
except Exception as exc: issues.append(f'module-state.json unreadable: {exc}'); s={'modules':{}}
for mid in sorted((s.get('modules') or {})):
    if mid not in e and mid not in r: issues.append(f'{mid}: state exists but module files are absent')
result={'ok':not issues,'issues':issues,'modules':rows}
if as_json: print(json.dumps(result,indent=2))
else:
    for row in rows: print(f"[OK] {row['id']}: extension={row['extension']} reportset={row['reportset']} versions={row['extension_version']}/{row['reportset_version']}")
    for issue in issues: print('[FAIL]',issue)
    print(f"{len(rows)} module pair(s), {len(issues)} issue(s).")
sys.exit(0 if not issues else 1)
PY
