#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def must(condition, message):
    if not condition:
        raise AssertionError(message)


# F11: Core groups are deterministic, registered extension IDs are module groups,
# and a future/unknown Core prefix uses the real Framework catch-all.
api = load('openapi171', 'framwork/tec_tac/openapi.py')
module_ids = frozenset({'alerts', 'globalsettings'})
for prefix, expected in api.CORE_GROUPS.items():
    must(api.schema_group_for_path(f'/api/tfd/{prefix}/x/', module_ids=module_ids) == expected, f'wrong Core group for {prefix}')
must(api.schema_group_for_path('/api/tfd/alerts/events/', module_ids=module_ids) == 'Tec-Tac Module · alerts', 'registered module not grouped by module ID')
must(api.schema_group_for_path('/api/tfd/globalsettings/sso/', module_ids=module_ids) == 'Tec-Tac Module · globalsettings', 'second registered module not grouped by module ID')
must(api.schema_group_for_path('/api/tfd/future-core/health/', module_ids=module_ids) == 'Tec-Tac · Framework', 'unknown Core prefix did not use Framework fallback')
must(api.schema_group_for_path('/api/tfd/', module_ids=module_ids) == 'Tec-Tac · Framework', 'framework root did not use Framework group')
must(api.schema_group_for_path('/api/v3/agents/', module_ids=module_ids) is None, 'non Tec-Tac path was grouped')

api.registered_module_ids = lambda: module_ids
schema = {
    'tags': [{'name': 'Tactical', 'description': 'native'}],
    'paths': {
        '/api/tfd/account/': {'get': {'tags': ['old']}},
        '/api/tfd/alerts/events/': {'get': {'tags': ['old']}},
        '/api/tfd/future-core/health/': {'get': {'tags': ['old']}},
        '/api/v3/agents/': {'get': {'tags': ['Agents']}},
    },
}
out = api.postprocess_tec_tac_groups(schema)
must(out['paths']['/api/tfd/account/']['get']['tags'] == ['Tec-Tac · My Account'], 'account route not grouped')
must(out['paths']['/api/tfd/alerts/events/']['get']['tags'] == ['Tec-Tac Module · alerts'], 'module route not grouped')
must(out['paths']['/api/tfd/future-core/health/']['get']['tags'] == ['Tec-Tac · Framework'], 'framework fallback route not grouped')
must(out['paths']['/api/v3/agents/']['get']['tags'] == ['Agents'], 'Tactical route tag changed')
tag_rows = {row['name']: row for row in out['tags']}
must(tag_rows['Tactical']['description'] == 'native', 'non Tec-Tac top-level tag metadata was not preserved')
must('Tec-Tac · Framework' in tag_rows and 'Tec-Tac Module · alerts' in tag_rows, 'Tec-Tac top-level groups incomplete')

# Grouping remains optional/non-fatal if registry discovery is unavailable.
api.registered_module_ids = lambda: frozenset()
out = api.postprocess_tec_tac_groups({'paths': {'/api/tfd/new-core/': {'get': {}}}})
must(out['paths']['/api/tfd/new-core/']['get']['tags'] == ['Tec-Tac · Framework'], 'registry-unavailable fallback is not Core-safe')

# Hook installation preserves drf-spectacular's enum hook when no custom list exists.
settings = SimpleNamespace(SPECTACULAR_SETTINGS={'TITLE': 'Tactical RMM API'})
api.install_openapi_grouping(settings)
hooks = settings.SPECTACULAR_SETTINGS['POSTPROCESSING_HOOKS']
must(api.DEFAULT_ENUM_HOOK in hooks and api.GROUP_HOOK in hooks, 'OpenAPI hook installation incomplete')

print('[TEST] PASS final F11 Swagger grouping acceptance')
