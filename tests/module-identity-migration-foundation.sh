#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

python3 - "$ROOT/framwork/tec_tac/module_manager_v2.py" <<'PY'
import ast,sys
from pathlib import Path
source=Path(sys.argv[1]).read_text(encoding='utf-8')
tree=ast.parse(source)
node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_identity_migration_metadata')
module=ast.Module(body=[node],type_ignores=[]);ast.fix_missing_locations(module)
class ModuleManagerV2Error(RuntimeError): pass
ns={'ModuleManagerV2Error':ModuleManagerV2Error}
exec(compile(module,'<identity-migration>','exec'),ns)
parse=ns['_identity_migration_metadata']
meta=parse({
 'migration':{
   'previous_module_ids':['security'],
   'permissions':{'security.read':'securityWAF.read','security.manage':'securityWAF.manage'},
   'scheduler_actions':{'security.scan':'securityWAF.scan'},
   'ui_routes':{'/extensions/security':'/extensions/securityWAF'},
 }
},'securityWAF')
assert meta['previous_module_ids']==['security']
assert meta['permissions']['security.read']=='securityWAF.read'
assert meta['scheduler_actions']['security.scan']=='securityWAF.scan'
try:
    parse({'migration':{'previous_module_ids':['securityWAF']}},'securityWAF')
except ModuleManagerV2Error:
    pass
else:
    raise AssertionError('self rename accepted')
try:
    parse({'migration':{'previous_module_ids':['security'],'permissions':{'other.read':'securityWAF.read'}}},'securityWAF')
except ModuleManagerV2Error:
    pass
else:
    raise AssertionError('foreign permission namespace accepted')
print('PASS module identity migration metadata contract')
PY

grep -q '"action": action_name' "$ROOT/framwork/tec_tac/module_manager_v2.py" || fail "rename lifecycle action missing"
grep -q 'rename_destination_exists' "$ROOT/framwork/tec_tac/module_manager_v2.py" || fail "rename destination collision guard missing"
grep -q 'rename_breaks_dependant' "$ROOT/framwork/tec_tac/module_manager_v2.py" || fail "rename dependant guard missing"
grep -q 'preflight_identity_migration' "$ROOT/framwork/tec_tac/module_manager_v2.py" || fail "persisted-state rename preflight missing"
grep -q 'run_identity_migration' "$ROOT/scripts/module-v2-job-helper.py" || fail "privileged identity migration execution missing"
grep -q 'migrate_module_state_identity' "$ROOT/scripts/module-v2-job-helper.py" || fail "module state identity migration missing"
grep -q 'previous_module_ids' "$ROOT/framwork/tec_tac/registry.py" || fail "registry migration schema missing"
grep -q 'previous_module_ids' "$ROOT/docs/module-identifiers.md" || fail "module rename contract documentation missing"
echo "[TEST] PASS module identity migration foundation"
