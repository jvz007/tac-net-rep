#!/usr/bin/env python3
"""Verify Clients/Sites paging is present in the published contract renderer."""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
tree = ast.parse(source)
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
ns = {}
exec(compile(ast.Module(body=nodes, type_ignores=[]), "contracts-render", "exec"), ns)
catalog = {
    "framework_version": "test",
    "generated_at": "test",
    "rules": [],
    "core": [],
    "resource_directory": {
        "id": "core.resources",
        "version": "1.2.0",
        "namespace": "tec_tac.resources",
        "read_only": False,
        "resource_types": {},
        "write_support": {},
        "authorization": {},
        "rbac": {},
        "errors": {},
        "active_semantics": "test",
        "compatibility": "test",
        "pagination": {"default_page_size": 100, "maximum_page_size": 500, "maximum_page_number": 10000},
        "list_contracts": {
            "clients": {"http": "GET /api/tfd/resources/clients/", "query": {"page": "integer 1..10000", "page_size": "integer 1..500"}, "response": {"items": "array[client]", "pages": "integer"}},
            "sites": {"http": "GET /api/tfd/resources/sites/", "query": {"client_id": "optional positive integer", "page": "integer 1..10000", "page_size": "integer 1..500"}, "response": {"items": "array[site]", "pages": "integer"}},
        },
    },
    "capabilities": [],
    "scheduler_actions": [],
    "permissions": [],
    "reporting_models": [],
    "http": [],
}
text = ns["render_markdown"](catalog)
assert "### Pagination" in text
assert "Maximum page number: `10000`" in text
assert "`clients` | `GET /api/tfd/resources/clients/`" in text
assert "`sites` | `GET /api/tfd/resources/sites/`" in text
assert "`page_size`=integer 1..500" in text
plain = ns["render_text"](catalog)
assert "pagination: default=100 max_size=500 max_page=10000" in plain
assert "list.clients: GET /api/tfd/resources/clients/" in plain
assert "list.sites: GET /api/tfd/resources/sites/" in plain
print("[TEST] PASS Resource Directory published paging contract")
