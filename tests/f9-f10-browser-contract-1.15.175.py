#!/usr/bin/env python3
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'framwork/tec_tac/contracts.py').read_text(encoding='utf-8')
tree = ast.parse(source)
contracts = None
for node in tree.body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'BROWSER_CONTRACTS' for t in node.targets):
        contracts = ast.literal_eval(node.value)
        break
assert contracts is not None, 'BROWSER_CONTRACTS not found'
row = next(item for item in contracts if item.get('id') == 'ui.authenticated.context-actions')
placements = set(row.get('placements') or [])
assert {'client.context-menu', 'site.context-menu'} <= placements
contexts = row.get('context') or {}
assert contexts.get('client.context-menu') == ['resource_type', 'resource', 'client', 'selection']
assert contexts.get('site.context-menu') == ['resource_type', 'resource', 'site', 'client', 'selection']
print('[TEST] PASS F10 client/site context-action public contract')
