#!/usr/bin/env python3
from pathlib import Path
import ast
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

def must(cond, msg):
    if not cond:
        raise AssertionError(msg)

source = (ROOT / 'framwork/tec_tac/account_self_service.py').read_text()
tree = ast.parse(source)
fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'tactical_ui_context')
module = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(module)
ns = {'Any': object, '_can_run_url_actions': lambda user: bool(getattr(user.role, 'can_run_urlactions', False))}
exec(compile(module, 'tactical_ui_context', 'exec'), ns)
user = SimpleNamespace(agent_dblclick_action='urlaction', url_action_id=77, role=SimpleNamespace(can_run_urlactions=True))
ctx = ns['tactical_ui_context'](user)
must(ctx == {'agent_dblclick_action': 'urlaction', 'url_action_id': 77, 'can_run_url_actions': True}, f'wrong Tactical UI context: {ctx}')
views = (ROOT / 'framwork/tec_tac/views.py').read_text()
must('"tactical_ui": tactical_ui_context(request.user)' in views, 'UiContextView does not publish Tactical UI values')
print('[TEST] PASS F4 Core Tactical UI context')
