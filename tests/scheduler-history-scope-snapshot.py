#!/usr/bin/env python3
from pathlib import Path
import ast, sys, types

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
path = root / 'framwork/tec_tac/scheduler_views.py'
source = path.read_text(encoding='utf-8')
tree = ast.parse(source)
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'SchedulerRunListView')
fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_scope_snapshot_allows')
module = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(module)

def ref(targets):
    return targets['ref']

ns = {'tactical_scope_ref': ref, 'SchedulerTargetShapeError': ValueError}
exec(compile(module, str(path), 'exec'), ns)
allows = ns['_scope_snapshot_allows'].__func__
scope = {
    'unrestricted': False,
    'client_ids': frozenset({1,2}),
    'site_ids': frozenset({10}),
    'endpoint_ids': frozenset({'21','agent-a'}),
}
assert allows({'ref': {'kind':'client','values':[1,2]}}, scope)
assert not allows({'ref': {'kind':'client','values':[1,3]}}, scope)
assert allows({'ref': {'kind':'site','values':[10]}}, scope)
assert not allows({'ref': {'kind':'site','values':[10,11]}}, scope)
assert allows({'ref': {'kind':'endpoint','values':['21','agent-a']}}, scope)
assert not allows({'ref': {'kind':'endpoint','values':['agent-b']}}, scope)
assert allows({'ref': {'kind':'none','values':[]}}, scope)
assert allows({'ref': {'kind':'module','values':[]}}, scope)
assert not allows({'ref': {'kind':'dynamic_unscoped','values':[]}}, scope)
assert allows({'ref': {'kind':'client','values':[999]}}, {'unrestricted': True})
print('scheduler history scope snapshot regression: PASS')
