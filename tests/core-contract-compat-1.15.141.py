#!/usr/bin/env python3
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

class Response:
    def __init__(self, data, status=200):
        self.data = data
        self.status_code = status

class APIView:
    pass

class SessionAuthenticated:
    pass


def _class_method(path: Path, class_name: str, method_name: str, namespace: dict):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    body = []
    for node in cls.body:
        if isinstance(node, ast.FunctionDef) and node.name == method_name:
            body.append(node)
    assert len(body) == 1, (class_name, method_name)
    synthetic = ast.ClassDef(name=class_name, bases=[ast.Name(id="APIView", ctx=ast.Load())], keywords=[], body=[body[0]], decorator_list=[])
    module = ast.Module(body=[synthetic], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(path), "exec"), namespace)
    return namespace[class_name]

# L06: pre-pagination calls with no paging/filter params still receive the
# historical bounded 200-row path instead of silently shrinking to 50.
module_calls = {}
def list_jobs(*, limit):
    module_calls["legacy_limit"] = limit
    return [{"id": i} for i in range(3)]
def page_jobs(**kwargs):
    module_calls["paged"] = kwargs
    return {"items": [], "count": 0, "page": kwargs["page"], "page_size": kwargs["page_size"], "pages": 0, "next_page": None, "previous_page": None}
ns = {
    "APIView": APIView,
    "SessionAuthenticated": SessionAuthenticated,
    "Response": Response,
    "_require_module_manager": lambda user: None,
    "list_jobs": list_jobs,
    "page_jobs": page_jobs,
    "ModuleManagerError": RuntimeError,
}
Cls = _class_method(ROOT / "framwork/tec_tac/module_v2_views.py", "ModuleV2JobHistoryView", "get", ns)
resp = Cls().get(SimpleNamespace(user=object(), query_params={}))
assert resp.status_code == 200
assert module_calls["legacy_limit"] == 200
assert resp.data["count"] == 3

module_calls.clear()
resp = Cls().get(SimpleNamespace(user=object(), query_params={"page": "1"}))
assert resp.status_code == 200
assert module_calls["paged"]["page_size"] == 50

session_calls = {}
def list_audit_events(*, username, event_type, limit):
    session_calls["legacy"] = (username, event_type, limit)
    return [{"id": 1}]
def page_audit_events(**kwargs):
    session_calls["paged"] = kwargs
    return {"items": [], "count": 0, "page": kwargs["page"], "page_size": kwargs["page_size"], "pages": 0, "next_page": None, "previous_page": None}
ns = {
    "APIView": APIView,
    "SessionAuthenticated": SessionAuthenticated,
    "Response": Response,
    "can_manage_session_security": lambda user: True,
    "_forbidden": lambda: Response({"detail": "forbidden"}, status=403),
    "list_audit_events": list_audit_events,
    "page_audit_events": page_audit_events,
    "SessionSecurityError": RuntimeError,
}
Cls = _class_method(ROOT / "framwork/tec_tac/session_security_views.py", "SessionAuditView", "get", ns)
resp = Cls().get(SimpleNamespace(user=object(), query_params={}))
assert resp.status_code == 200
assert session_calls["legacy"] == (None, None, 200)
assert resp.data["count"] == 1

session_calls.clear()
resp = Cls().get(SimpleNamespace(user=object(), query_params={"page_size": "25"}))
assert resp.status_code == 200
assert session_calls["paged"]["page_size"] == 25

# U2: the live public contract must publish the exact console guidance shape
# consumed by the UI when a trust-floor lowering requires root-console action.
contracts_tree = ast.parse((ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8"))
assignment = next(
    node for node in contracts_tree.body
    if isinstance(node, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == "HTTP_CONTRACT_DETAILS" for t in node.targets)
)
details = ast.literal_eval(assignment.value)
trust = details["/api/tfd/system/updates/trust-policy/"]
guidance = trust["PUT"]["responses"]["console_required"]
assert guidance["status"] == "console_required"
for field in ("requested_level", "environment", "command", "help_article", "help_url"):
    assert field in guidance, field
assert guidance["help_article"] == "core.trust-policy"

# L07: the privileged helper Bash boundary is executable in the normal suite.
for rel in (
    "scripts/server-backup-helper.py",
    "scripts/system-update-helper.py",
    "scripts/module-job-helper.py",
    "scripts/module-v2-job-helper.py",
    "scripts/module-hotfix-job-helper.py",
):
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert 'for raw in ("/bin/bash", "/usr/bin/bash")' in text, rel
    assert "def _trusted_bash" in text, rel

print("core-contract-compat-1.15.141: PASS")
