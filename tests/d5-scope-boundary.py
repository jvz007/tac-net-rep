#!/usr/bin/env python3
from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORE = ROOT / 'framwork' / 'tec_tac'
ADAPTER = CORE / 'resources_adapter.py'

violations: list[str] = []

for path in sorted(CORE.rglob('*.py')):
    rel = path.relative_to(ROOT).as_posix()
    if path == ADAPTER:
        continue
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {'clients.models', 'agents.models'}:
            violations.append(f'{rel}:{node.lineno}: direct Tactical resource-model import from {node.module}')
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {'clients.models', 'agents.models'}:
                    violations.append(f'{rel}:{node.lineno}: direct Tactical resource-model import {alias.name}')
        elif isinstance(node, ast.Attribute) and node.attr == 'filter_by_role':
            violations.append(f'{rel}:{node.lineno}: Tactical filter_by_role scope must remain centralized in resources_adapter.py')

assert not violations, 'D5 scope-boundary violations:\n' + '\n'.join(violations)

adapter = ADAPTER.read_text(encoding='utf-8')
assert 'return filter_by_role(user)' in adapter, 'Resource Directory no longer delegates interactive scope to Tactical filter_by_role(user).'
assert 'def tactical_scope_unrestricted' in adapter, 'central unrestricted-scope decision missing from Resource Directory adapter.'
assert 'def explicit_client_target_ids_in_scope' in adapter, 'central client-target scope decision missing.'
assert 'def site_target_ids_in_scope' in adapter, 'central site-target scope decision missing.'
assert 'def agent_target_identifiers_in_scope' in adapter, 'central endpoint-target scope decision missing.'

scheduler = (CORE / 'scheduler_views.py').read_text(encoding='utf-8')
for required in (
    'resources_adapter.tactical_scope_unrestricted(user=user)',
    'resources_adapter.explicit_client_target_ids_in_scope',
    'resources_adapter.site_target_ids_in_scope',
    'resources_adapter.agent_target_identifiers_in_scope',
    'resources_adapter.scheduler_scope_snapshot(user=request.user)',
):
    assert required in scheduler, f'Scheduler no longer consumes centralized Tactical scope helper: {required}'

resources = (CORE / 'resources.py').read_text(encoding='utf-8')
assert 'from . import resources_adapter' in resources, 'Resource Directory HTTP layer no longer uses the Tactical resource adapter.'
assert 'clients.models' not in resources and 'agents.models' not in resources, 'Resource Directory HTTP layer imports Tactical resource models directly.'

print('D5 Tactical scope boundary: PASS')
