#!/usr/bin/env python3
"""Behavioral regression for bounded page numbers in Resource/Session pagination."""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class SessionSecurityError(RuntimeError):
    pass

class QS(list):
    def count(self): return len(self)

session_source = (ROOT / "framwork" / "tec_tac" / "session_security.py").read_text(encoding="utf-8")
tree = ast.parse(session_source)
selected = []
for node in tree.body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "SESSION_PAGINATION_MAX_PAGE" for t in node.targets):
        selected.append(node)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in {"page_active_login_sessions", "page_audit_events"}:
        selected.append(node)
mod = ast.Module(body=selected, type_ignores=[])
ns = {
    "SessionSecurityError": SessionSecurityError,
    "_visible_active_knox_tokens": lambda **kwargs: QS(),
    "_serialize_active_login_sessions": lambda rows, **kwargs: list(rows),
    "_audit_queryset": lambda **kwargs: QS(),
    "_serialize_audit_event": lambda item: item,
}
exec(compile(mod, "session-pagination", "exec"), ns)
for name in ("page_active_login_sessions", "page_audit_events"):
    fn = ns[name]
    ok = fn(page=10000, page_size=100)
    assert ok["page"] == 10000 and ok["page_size"] == 100
    try:
        fn(page=10001, page_size=100)
        raise AssertionError(f"{name} accepted unbounded page")
    except SessionSecurityError as exc:
        assert "10000" in str(exc)

print("[TEST] PASS pagination upper bounds")
