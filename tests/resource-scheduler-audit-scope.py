#!/usr/bin/env python3
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
resources_path = ROOT / 'framwork' / 'tec_tac' / 'resources.py'
scheduler_path = ROOT / 'framwork' / 'tec_tac' / 'scheduler_views.py'


def fn_node(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f'{name} missing from {path}')


def compile_function(path: Path, name: str, namespace: dict):
    node = fn_node(path, name)
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(path), 'exec'), namespace)
    return namespace[name]


# M17: execute the resource mutations with a fake adapter. The mutations must
# make transaction-critical audit calls with before/after state.
class ResourceDirectoryError(RuntimeError): pass
class ResourceNotFound(ResourceDirectoryError): pass
class ResourceValidationError(ResourceDirectoryError): pass

class Atomic:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False

class Tx:
    @staticmethod
    def atomic(): return Atomic()

class Adapter:
    def __init__(self):
        self.client = {'type':'client','id':7,'name':'Old','active':True}
        self.site = {'type':'site','id':11,'name':'Old Site','client_id':7,'active':True}
    def create_client_row(self, **kw): return {'type':'client','id':8,'name':kw['name'],'active':True}
    def update_client_row(self, **kw): return {'type':'client','id':kw['client_id'],'name':kw['name'],'active':True}
    def create_site_row(self, **kw): return {'type':'site','id':12,'name':kw['name'],'client_id':kw['client_id'],'active':True}
    def update_site_row(self, **kw):
        return {'type':'site','id':kw['site_id'],'name':kw['name'] or self.site['name'],'client_id':kw['client_id'] or self.site['client_id'],'active':True}
    def clients_queryset(self, **kw): return object()
    def sites_queryset(self, **kw): return object()
    def get_client_row(self, qs, resource_id): return dict(self.client) if resource_id == 7 else None
    def get_site_row(self, qs, resource_id): return dict(self.site) if resource_id == 11 else None
    def client_write_in_scope(self, **kw): return True

adapter = Adapter()
audits = []

def record_change(**kw):
    audits.append(kw)

def authorize_write(context, resource_type): return context

def clean_name(value, label): return str(value).strip()

def clean_id(value, label): return int(value)

def adapter_write(callable_obj, **kwargs): return callable_obj(**kwargs)

ns = {
    'Any': object, 'ResourceAccessContext': object, 'ResourceDirectoryError': ResourceDirectoryError,
    'ResourceNotFound': ResourceNotFound, 'ResourceValidationError': ResourceValidationError,
    'adapter': adapter, '_authorize_write': authorize_write, '_transaction_atomic': lambda: Atomic(),
    '_clean_name': clean_name, '_clean_positive_int': clean_id, '_adapter_write': adapter_write,
    '_record_resource_change': record_change,
}
for name in ('create_client','update_client','create_site','update_site'):
    ns[name] = compile_function(resources_path, name, ns)

user = SimpleNamespace(username='operator')
ns['create_client'](name='New Client', context=user)
ns['update_client'](7, name='Renamed', context=user)
ns['create_site'](client_id=7, name='Branch', context=user)
ns['update_site'](11, name='HQ', client_id=8, context=user)
assert [a['action'] for a in audits] == ['add','modify','add','modify'], audits
assert [a['resource_type'] for a in audits] == ['client','client','site','site'], audits
assert audits[1]['before']['name'] == 'Old' and audits[1]['after']['name'] == 'Renamed'
assert audits[3]['before']['client_id'] == 7 and audits[3]['after']['client_id'] == 8

# The Core audit helper itself must be strict.
helper = fn_node(resources_path, '_record_resource_change')
helper_text = ast.unparse(helper)
assert 'strict=True' in helper_text, 'Resource Directory audit is not transaction-critical'

# L23: execute the real scope function body with fake scope services. none and
# module-defined targets must require unrestricted Tactical scope.
class PermissionDenied(Exception): pass
class SchedulerError(Exception): pass
class ScopeAdapter:
    unrestricted = False
    @classmethod
    def tactical_scope_unrestricted(cls, *, user): return cls.unrestricted
    @staticmethod
    def explicit_client_target_ids_in_scope(**kw): return set(kw['client_ids'])
    @staticmethod
    def site_target_ids_in_scope(**kw): return set(kw['site_ids'])
    @staticmethod
    def agent_target_identifiers_in_scope(**kw): return set(str(x) for x in kw['identifiers'])

scope_ns = {
    'SchedulerError': SchedulerError, 'PermissionDenied': PermissionDenied,
    'resources_adapter': ScopeAdapter,
    '_native_scheduler_manager': lambda user: False,
    '_scope_target_refs': lambda targets: [targets],
}
require_scope = compile_function(scheduler_path, '_require_target_scope', scope_ns)
for kind in ('none','module'):
    ScopeAdapter.unrestricted = False
    try:
        require_scope(object(), {'kind':kind,'values':[]}, payload=False)
    except PermissionDenied:
        pass
    else:
        raise AssertionError(f'restricted user accepted for {kind} target')
    ScopeAdapter.unrestricted = True
    require_scope(object(), {'kind':kind,'values':[]}, payload=False)

# L18/L20: structural guard on the real DELETE method. Action authorization must
# precede target authorization, and force deletion must use a strict Core audit.
tree = ast.parse(scheduler_path.read_text(encoding='utf-8'))
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'SchedulerDetailView')
delete = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'delete')
text = ast.unparse(delete)
assert '_require_action(request.user, schedule.action_id)' in text
assert text.index('_require_action(request.user, schedule.action_id)') < text.index('_require_target_scope(request.user, schedule.targets, payload=False)')
assert 'audit_record(' in text and 'strict=True' in text and "'force': True" in text

print('resource-scheduler-audit-scope: PASS')
