#!/usr/bin/env python3
from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]
session = (ROOT / 'framwork/tec_tac/session_security.py').read_text(encoding='utf-8')
installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
doc = (ROOT / 'docs/session-security.md').read_text(encoding='utf-8')

assert 'CAPABILITY_VERSION = "2.0.0"' in session
assert "get_capability('core.session_security',version='>=2.0.0,<3.0.0')" in installer
assert "status['capability_version']=='2.0.0'" in installer
assert '`core.session_security` v2.0.0' in doc
assert 'version=">=2.0.0,<3.0.0"' in doc

mod = ast.parse(session)
provider = next(n for n in mod.body if isinstance(n, ast.ClassDef) and n.name == 'SessionSecurityProvider')
methods = {n.name: n for n in provider.body if isinstance(n, ast.FunctionDef)}
assert 'update_policy' not in methods
cleanup = methods['cleanup']
args = [arg.arg for arg in cleanup.args.args + cleanup.args.kwonlyargs]
assert args == ['self', 'context'], args
print('[TEST] PASS core.session_security breaking contract is versioned as 2.0.0')
