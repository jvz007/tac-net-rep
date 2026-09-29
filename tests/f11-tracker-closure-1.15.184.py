#!/usr/bin/env python3
from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

api = load('openapi184', ROOT / 'framwork' / 'tec_tac' / 'openapi.py')


def callback(module, name):
    cls = type(name, (), {})
    cls.__module__ = module
    return SimpleNamespace(cls=cls)

# 1) No generic Framework grouping may survive anywhere in the production hook.
source = (ROOT / 'framwork' / 'tec_tac' / 'openapi.py').read_text(encoding='utf-8')
assert '"Tec-Tac · Framework"' not in source and "'Tec-Tac · Framework'" not in source, 'generic Framework group remains in production openapi.py'

# 2) Every currently mounted Core class-based /api/tfd route must resolve through
# explicit callback ownership. This is the drift guard the tracker done-when asks for.
urls = ROOT / 'framwork' / 'tec_tac' / 'urls.py'
tree = ast.parse(urls.read_text(encoding='utf-8'))
imports = {}
for node in tree.body:
    if isinstance(node, ast.ImportFrom) and node.module:
        module = 'tec_tac.' + node.module.lstrip('.')
        for alias in node.names:
            imports[alias.asname or alias.name] = module

missing = []
for node in ast.walk(tree):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != 'path' or len(node.args) < 2:
        continue
    route = node.args[0]
    if not isinstance(route, ast.Constant) or not isinstance(route.value, str):
        continue
    view = node.args[1]
    if not (isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute) and view.func.attr == 'as_view' and isinstance(view.func.value, ast.Name)):
        continue
    cls = view.func.value.id
    module = imports.get(cls)
    if not module:
        missing.append(f'{route.value}: import owner unknown for {cls}')
        continue
    group = api.core_group_for_callback(callback(module, cls))
    if group is None:
        missing.append(f'{route.value}: {module}.{cls}')
assert not missing, 'unclassified mounted Core routes: ' + ', '.join(missing)

# 3) Module callback ownership must win over a Core-looking URL prefix, and
# category/name must decide the final group label.
core_mod = SimpleNamespace(plugin_id='globalsettings', plugin_type='extension', name='Global Settings', category='core', django_apps=('tec_tac_globalsettings.apps.GlobalSettingsConfig',))
audit_mod = SimpleNamespace(plugin_id='audit', plugin_type='extension', name='Audit', category='', django_apps=('tec_tac_audit.apps.AuditConfig',))
api.registered_module_specs = lambda: (core_mod, audit_mod)
generator = SimpleNamespace(endpoints=[
    ('/api/tfd/audit/events/', '', 'GET', callback('tec_tac_audit.views', 'AuditEventView')),
    ('/api/tfd/globalsettings/sso/', '', 'GET', callback('tec_tac_globalsettings.views', 'SsoView')),
    ('/api/tfd/system/updates/', '', 'GET', callback('tec_tac.views', 'SystemUpdateStatusView')),
])
schema = {'tags':[{'name':'Agents'}], 'paths':{
    '/api/tfd/audit/events/': {'get': {'tags':['stale']}},
    '/api/tfd/globalsettings/sso/': {'get': {'tags':['stale']}},
    '/api/tfd/system/updates/': {'get': {'tags':['stale']}},
    '/api/v3/agents/': {'get': {'tags':['Agents']}},
}}
out = api.postprocess_tec_tac_groups(schema, generator=generator)
assert out['paths']['/api/tfd/audit/events/']['get']['tags'] == ['Module · Audit']
assert out['paths']['/api/tfd/globalsettings/sso/']['get']['tags'] == ['Core module · Global Settings']
assert out['paths']['/api/tfd/system/updates/']['get']['tags'] == ['Tec-Tac · System Updates']
assert out['paths']['/api/v3/agents/']['get']['tags'] == ['Agents']
assert all(row.get('name') != 'Tec-Tac · Framework' for row in out.get('tags', []))

# 4) Current acceptance runner must execute the final F11 regression directly.
tracker = (ROOT / 'tests' / 'tracker-acceptance-1.15.173.py').read_text(encoding='utf-8')
assert 'f11-openapi-final-1.15.178.py' in tracker
review = (ROOT / 'tests' / 'review-hygiene-foundation.sh').read_text(encoding='utf-8')
assert 'f11-openapi-final-1.15.178.py' in review

print('[TEST] PASS F11 tracker closure 1.15.184')
