#!/usr/bin/env python3
import ast
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'framwork/tec_tac/views.py').read_text()
tree = ast.parse(source)
fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_tactical_web_ui_context')
module = ast.Module(body=[fn], type_ignores=[])
ns = {'Path': Path}
exec(compile(module, 'tactical_web_ui_context', 'exec'), ns)
probe = ns['_tactical_web_ui_context']

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    index = root / 'dist/index.html'
    nginx = root / 'frontend.conf'
    index.parent.mkdir(parents=True)
    assert probe(index, nginx) == {'installed': False, 'url': None}
    index.write_text('<html></html>')
    assert probe(index, nginx) == {'installed': False, 'url': None}
    nginx.write_text('server {}')
    assert probe(index, nginx) == {'installed': True, 'url': '/'}
    nginx.unlink()
    assert probe(index, nginx) == {'installed': False, 'url': None}

assert '"tactical_web_ui": _tactical_web_ui_context()' in source
contracts = (ROOT / 'framwork/tec_tac/contracts.py').read_text()
assert 'tactical_web_ui.installed' in contracts and 'tactical_web_ui.url' in contracts
print('Tactical web UI runtime capability 1.15.182: PASS')
