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
# 1.17.35: the context also carries the small Tactical UI scalars, so the helper and its constants are extracted with the function
wanted_functions = {'tactical_ui_context', '_tactical_ui_scalars'}
body = [
    node for node in tree.body
    if (isinstance(node, ast.FunctionDef) and node.name in wanted_functions)
    or (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id.startswith('TACTICAL_UI_') for t in node.targets))
]
module = ast.Module(body=body, type_ignores=[])
ast.fix_missing_locations(module)
ns = {'Any': object, '_can_run_url_actions': lambda user: bool(getattr(user.role, 'can_run_urlactions', False))}
exec(compile(module, 'tactical_ui_context', 'exec'), ns)
scalars = {
    'dark_mode': False, 'show_community_scripts': True, 'default_agent_tbl_tab': 'server', 'client_tree_sort': 'alpha',
    'client_tree_splitter': 20, 'loading_bar_color': 'deep-purple-3', 'dash_info_color': 'info', 'dash_positive_color': '#1b5e20',
    'dash_negative_color': 'negative', 'dash_warning_color': 'warning', 'clear_search_when_switching': False, 'date_format': 'DD/MM/YYYY',
}
user = SimpleNamespace(agent_dblclick_action='urlaction', url_action_id=77, role=SimpleNamespace(can_run_urlactions=True), **scalars)
ctx = ns['tactical_ui_context'](user)
# the three keys from 1.15.178 keep their values; the scalars are added
must({k: ctx[k] for k in ('agent_dblclick_action', 'url_action_id', 'can_run_url_actions')}
     == {'agent_dblclick_action': 'urlaction', 'url_action_id': 77, 'can_run_url_actions': True}, f'wrong Tactical UI context: {ctx}')
must({k: ctx[k] for k in scalars} == scalars, f'the Tactical UI scalars are published: {ctx}')
must(set(ctx) == {'agent_dblclick_action', 'url_action_id', 'can_run_url_actions'} | set(scalars), f'no catalogue or choice list in the context: {sorted(ctx)}')
views = (ROOT / 'framwork/tec_tac/views.py').read_text()
must('"tactical_ui": tactical_ui_context(request.user)' in views, 'UiContextView does not publish Tactical UI values')
print('[TEST] PASS F4 Core Tactical UI context')
