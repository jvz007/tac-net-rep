#!/usr/bin/env python3
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'framwork/tec_tac/contracts.py'
source = PATH.read_text(encoding='utf-8')
tree = ast.parse(source)

assignment = next(
    node for node in tree.body
    if isinstance(node, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == 'BROWSER_CONTRACTS' for t in node.targets)
)
rows = ast.literal_eval(assignment.value)
ids = [row['id'] for row in rows]
assert len(ids) == len(set(ids)), ids
expected = {
    'ui.authenticated.transport',
    'ui.authenticated.audit',
    'ui.authenticated.context-actions',
    'ui.authenticated.context-interactions',
    'ui.authenticated.resource-views',
    'ui.authenticated.code-editor',
    'ui.authenticated.dashboard-widgets',
    'ui.authenticated.quick-actions',
    'ui.authenticated.notifications',
    'ui.authenticated.help',
    'ui.authenticated.header',
    'ui.authenticated.module-status',
    'ui.authenticated.runtime-context',
    'ui.public.sso-providers',
    'ui.public.module-runtime',
}
assert set(ids) == expected, (set(ids) ^ expected)
for row in rows:
    assert row['phase'] in {'authenticated', 'public'}, row
    assert row['service'] and row['purpose'] and row['audience'], row
    assert row['docs'].startswith('tec-tac-ui/docs/'), row
    assert isinstance(row['operations'], list) and row['operations'], row

functions = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name in {'render_markdown', 'render_text'}
]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns = {}
exec(compile(module, str(PATH), 'exec'), ns)

catalog = {
    'framework_version': '1.15.170',
    'generated_at': '2026-09-29T00:00:00+00:00',
    'rules': [],
    'core': [],
    'browser': list(rows),
    'resource_directory': {},
    'capabilities': [],
    'scheduler_actions': [],
    'permissions': [],
    'reporting_models': [],
    'http': [],
}
md = ns['render_markdown'](catalog)
txt = ns['render_text'](catalog)
assert '## Browser / UI module contracts' in md
assert 'BROWSER / UI MODULE CONTRACTS' in txt
for row in rows:
    assert row['id'] in md and row['id'] in txt, row['id']
    assert row['docs'] in md and row['docs'] in txt, row['docs']
    for op in row['operations']:
        assert op in md and op in txt, (row['id'], op)

assert 'browser = [dict(row) for row in BROWSER_CONTRACTS]' in source
assert '"browser": browser' in source
assert '"browser": len(browser)' in source
print('[TEST] PASS browser contract catalog exports stable UI runtime contracts')
