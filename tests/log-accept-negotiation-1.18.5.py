#!/usr/bin/env python3
"""Regression: the three job-log routes never answer 406 for Accept: text/plain (Core 1.18.5). No Django needed."""
import ast
import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"
MIXIN = PKG / "log_negotiation.py"
assert b"\r" not in MIXIN.read_bytes()
msrc = MIXIN.read_text(encoding="utf-8")
assert not [n for n in ast.parse(msrc).body if isinstance(n, (ast.Import, ast.ImportFrom))], "no imports needed"

spec = importlib.util.spec_from_file_location("log_negotiation_t", MIXIN)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class NotAcceptable(Exception):
    pass


class JSONRenderer:
    media_type = "application/json"


class FakeView(mod.LogNegotiationMixin):
    def get_renderers(self):
        return [JSONRenderer()]


class Req:
    def __init__(self, accept):
        self.META = {"HTTP_ACCEPT": accept} if accept is not None else {}


for accept in ("text/plain", "text/markdown", "*/*", None, "application/xml"):
    renderer, media = FakeView().perform_content_negotiation(Req(accept))
    assert isinstance(renderer, JSONRenderer) and media == "application/json", accept
    assert FakeView().perform_content_negotiation(Req(accept), force=True)[1] == "application/json"

CASES = (
    ("views.py", "SystemUpdateJobLogView", "_require_module_manager"),
    ("module_v2_views.py", "ModuleV2JobLogView", "_require_module_manager"),
    ("server_maintenance_views.py", "ServerMaintenanceJobLogView", "_require_server_maintenance"),
)
for fname, cls, guard in CASES:
    text = (PKG / fname).read_text(encoding="utf-8")
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.ClassDef) and n.name == cls)
    bases = [b.id for b in node.bases]
    assert bases.index("LogNegotiationMixin") < bases.index("APIView"), (cls, bases)
    assert "from .log_negotiation import LogNegotiationMixin" in text
    assert re.search(r"permission_classes = \[SessionAuthenticated\]", ast.get_source_segment(text, node)), cls
    get = next(n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == "get")
    first = get.body[0]
    assert isinstance(first, ast.Expr) and isinstance(first.value, ast.Call) and getattr(first.value.func, "id", "") == guard, (cls, ast.dump(first)[:120])

contract = (PKG / "contract_views.py").read_text(encoding="utf-8")
assert "class ContractExportView(" in contract and "LogNegotiationMixin" not in contract
assert "renderer, renderer.media_type" in contract

print("log accept negotiation 1.18.5 regression: PASS")
