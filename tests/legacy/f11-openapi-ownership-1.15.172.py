#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('openapi172', ROOT / 'framwork' / 'tec_tac' / 'openapi.py')
api = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(api)


def must(value, message):
    if not value:
        raise AssertionError(message)


# Real-world mismatch from the live public contract: stable module ID is
# `serverhealth`, while the HTTP path is `/api/tfd/server-health/`.
serverhealth = SimpleNamespace(
    plugin_id='serverhealth',
    plugin_type='extension',
    django_apps=('tec_tac_serverhealth.apps.ServerHealthConfig',),
)
scriptmanager = SimpleNamespace(
    plugin_id='scriptmanager',
    plugin_type='extension',
    django_apps=('tec_tac_scriptmanager.apps.ScriptManagerConfig',),
)

class ServerHealthView: pass
ServerHealthView.__module__ = 'tec_tac_serverhealth.views'
server_cb = SimpleNamespace(cls=ServerHealthView)

class ScriptManagerView: pass
ScriptManagerView.__module__ = 'tec_tac_scriptmanager.views'
script_cb = SimpleNamespace(cls=ScriptManagerView)

class CoreFutureView: pass
CoreFutureView.__module__ = 'tec_tac.future_views'
core_cb = SimpleNamespace(cls=CoreFutureView)

generator = SimpleNamespace(endpoints=[
    ('/api/tfd/server-health/', r'^api/tfd/server-health/$', 'GET', server_cb),
    ('/api/tfd/scriptmanager/', r'^api/tfd/scriptmanager/$', 'GET', script_cb),
    ('/api/tfd/future-core/health/', r'^api/tfd/future-core/health/$', 'GET', core_cb),
])

api.registered_module_specs = lambda: (serverhealth, scriptmanager)
schema = {
    'tags': [{'name': 'Agents', 'description': 'native Tactical tag'}],
    'paths': {
        '/api/tfd/server-health/': {'get': {'tags': ['api']}},
        '/api/tfd/scriptmanager/': {'get': {'tags': ['api']}},
        '/api/tfd/future-core/health/': {'get': {'tags': ['api']}},
        '/api/tfd/account/': {'get': {'tags': ['api']}},
        '/api/v3/agents/': {'get': {'tags': ['Agents']}},
    },
}
out = api.postprocess_tec_tac_groups(schema, generator=generator)

must(out['paths']['/api/tfd/server-health/']['get']['tags'] == ['Tec-Tac Module · serverhealth'],
     'module route whose path prefix differs from module ID was not grouped by callback ownership')
must(out['paths']['/api/tfd/scriptmanager/']['get']['tags'] == ['Tec-Tac Module · scriptmanager'],
     'module route with matching path/module ID was not grouped')
must(out['paths']['/api/tfd/future-core/health/']['get']['tags'] == ['Tec-Tac · Framework'],
     'unknown Core route did not use Framework fallback')
must(out['paths']['/api/tfd/account/']['get']['tags'] == ['Tec-Tac · My Account'],
     'known Core area did not keep its Core group')
must(out['paths']['/api/v3/agents/']['get']['tags'] == ['Agents'],
     'native Tactical route was changed')

names = {item['name'] for item in out['tags']}
for required in ('Tec-Tac Module · serverhealth', 'Tec-Tac Module · scriptmanager', 'Tec-Tac · Framework', 'Tec-Tac · My Account'):
    must(required in names, f'missing top-level Swagger tag {required}')
must('Agents' in names, 'native Tactical top-level tag disappeared')

# If spectacular callback metadata is unavailable, URL-prefix matching remains
# a safe compatibility fallback for the common module-id == path-prefix case.
must(api.schema_group_for_path('/api/tfd/scriptmanager/', module_ids={'scriptmanager'}) == 'Tec-Tac Module · scriptmanager',
     'module-id path fallback broke')
must(api.schema_group_for_path('/api/tfd/server-health/', module_ids={'serverhealth'}) == 'Tec-Tac · Framework',
     'mismatched prefix should not be guessed without callback ownership')

print('[TEST] PASS F11 callback-owned Swagger grouping including serverhealth/server-health mismatch')
