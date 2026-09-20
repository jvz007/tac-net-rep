#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT/framwork/tec_tac/module_manager_v2.py" <<'PY'
import ast
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding='utf-8')
tree = ast.parse(source)
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'resolve_install_plan')
module = ast.Module(body=[node], type_ignores=[])
ast.fix_missing_locations(module)

class ModuleManagerV2Error(RuntimeError):
    pass

def version_satisfies(version, constraint):
    return True

def _future_catalog(candidates):
    return {
        item['id']: {
            'id': item['id'],
            'extension_version': item['extension_version'],
            'enabled': True,
            'dependencies': item.get('dependencies', {}),
        }
        for item in candidates
    }

def installed_catalog_v2():
    return []

ns = {
    'ModuleManagerV2Error': ModuleManagerV2Error,
    'version_satisfies': version_satisfies,
    '_future_catalog': _future_catalog,
    'installed_catalog_v2': installed_catalog_v2,
}
exec(compile(module, '<resolve_install_plan>', 'exec'), ns)
resolve = ns['resolve_install_plan']

def candidate(module_id, dependencies=None):
    return {
        'id': module_id,
        'extension_version': '1.0.0',
        'dependencies': dependencies or {},
        'optional_dependencies': {},
        'runtime_requirements': [],
    }

# A multi-file upload does not need dependency relationships between packages.
independent = [candidate('zeta'), candidate('alpha'), candidate('middle')]
plan = resolve(independent)
assert plan['valid'] is True, plan
assert plan['problems'] == [], plan
assert plan['order'] == ['zeta', 'alpha', 'middle'], plan
assert [a['id'] for a in plan['actions']] == ['zeta', 'alpha', 'middle'], plan

# Dependencies constrain only the packages that actually declare them; unrelated
# packages remain valid members of the same sequential install batch.
mixed = [candidate('consumer', {'base': '>=1'}), candidate('independent'), candidate('base')]
plan = resolve(mixed)
assert plan['valid'] is True, plan
assert plan['order'].index('base') < plan['order'].index('consumer'), plan
assert set(plan['order']) == {'consumer', 'independent', 'base'}, plan

print('PASS independent multi-package batches do not require dependencies')
PY
