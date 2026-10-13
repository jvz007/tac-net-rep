#!/usr/bin/env python3
"""1.17.30 regression: audit.py and resources.py load by file path, outside the package (precheck fix).

Two older tests load audit.py with spec_from_file_location. A module-level relative import of caller_identity broke them with
"attempted relative import with no known parent package". The import now sits inside the function that uses it, so no module-level
import of caller_identity remains in either file.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.dont_write_bytecode = True
PKG = Path(__file__).resolve().parent.parent / "framwork" / "tec_tac"
for name in ("audit.py", "resources.py"):
    tree = ast.parse((PKG / name).read_text(encoding="utf-8"))
    top = [n for n in tree.body if isinstance(n, ast.ImportFrom) and n.level and n.module == "caller_identity"]
    assert not top, f"{name}: module-level relative import of caller_identity"
    inner = [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level and n.module == "caller_identity"]
    assert inner, f"{name}: the function-level import is missing"

# audit._server_module_deny_allowed keeps the import inside its try block, so a failed import is a refusal.
tree = ast.parse((PKG / "audit.py").read_text(encoding="utf-8"))
fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_server_module_deny_allowed")
tries = [n for n in ast.walk(fn) if isinstance(n, ast.Try)]
assert any(isinstance(s, ast.ImportFrom) for t in tries for s in ast.walk(t) if s in ast.walk(ast.Module(body=t.body, type_ignores=[]))), "import must sit in the try block"
print("ok")
