#!/usr/bin/env python3
"""Tracker closures for L50/L51/L54 without requiring Django/Tactical runtime."""
from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]

# L50: the admin MFA recovery endpoint and its GET/DELETE semantics are durable docs.
doc = (ROOT / 'docs/session-security.md').read_text(encoding='utf-8')
for token in (
    'GET    /api/tfd/access/users/<user_id>/mfa/',
    'DELETE /api/tfd/access/users/<user_id>/mfa/',
    'protected superuser/root targets additionally require effective-superuser authority',
    'Responses are marked `no-store`',
):
    assert token in doc, token

# L51: views.py must not reintroduce the dead timedelta import.
views = ast.parse((ROOT / 'framwork/tec_tac/views.py').read_text(encoding='utf-8'))
for node in ast.walk(views):
    if isinstance(node, ast.ImportFrom) and node.module == 'datetime':
        assert all(alias.name != 'timedelta' for alias in node.names), 'unused timedelta import returned'
    if isinstance(node, ast.Import):
        assert all(alias.name != 'timedelta' for alias in node.names), 'unused timedelta import returned'

# L54: both paged session endpoints must return stable text, never raw int() errors.
session_views = (ROOT / 'framwork/tec_tac/session_security_views.py').read_text(encoding='utf-8')
assert session_views.count('"Invalid pagination parameters."') >= 2
assert 'str(exc)' not in '\n'.join(
    line for line in session_views.splitlines()
    if 'pagination' in line.lower() or 'page_size' in line or 'page=int' in line
)

print('[TEST] PASS tracker test/doc closures L50 L51 L54')
