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


def class_method(path: Path, class_name: str, method_name: str, namespace: dict):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method_name)
    synthetic = ast.ClassDef(
        name=class_name,
        bases=[ast.Name(id="APIView", ctx=ast.Load())],
        keywords=[],
        body=[fn],
        decorator_list=[],
    )
    module = ast.Module(body=[synthetic], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(path), "exec"), namespace)
    return namespace[class_name]

# U4: live public contract publishes the account-security policy endpoint the UI consumes.
contracts_tree = ast.parse((ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8"))
assignment = next(
    n for n in contracts_tree.body
    if isinstance(n, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == "HTTP_CONTRACT_DETAILS" for t in n.targets)
)
details = ast.literal_eval(assignment.value)
policy = details["/api/tfd/access/security-policy/"]
assert policy["GET"]["response"]["policy"]["protect_superuser_accounts"] == "boolean"
assert "can_change" in policy["GET"]["response"]
assert policy["PUT"]["request"] == {"protect_superuser_accounts": "boolean"}
assert policy["PUT"]["response"]["can_change"] is True
assert "403" in policy["GET"]["errors"] and "500" in policy["PUT"]["errors"]

# L50: docs describe the real admin MFA status shape and explicitly keep GET read-only/protected.
docs = (ROOT / "docs/session-security.md").read_text(encoding="utf-8")
for text in (
    "GET` is read-only",
    "`user.id`",
    "`user.username`",
    "`can_invalidate`",
    "`totp_configured`",
    "`generated_at`",
    "before** status is read or mutation occurs",
):
    assert text in docs, text

# L51: the old unused timedelta import must stay gone from the shared views module.
views_tree = ast.parse((ROOT / "framwork/tec_tac/views.py").read_text(encoding="utf-8"))
for node in views_tree.body:
    if isinstance(node, ast.ImportFrom) and node.module == "datetime":
        names = {alias.name for alias in node.names}
        assert "timedelta" not in names, names
    if isinstance(node, ast.Import):
        assert all(alias.name != "timedelta" for alias in node.names)

# L54: malformed pagination is normalized to fixed 400 text, never raw int()/ValueError details.
ssv = ROOT / "framwork/tec_tac/session_security_views.py"

def bad_page_audit_events(**kwargs):
    raise ValueError("invalid literal for int() with base 10: 'oops'")
ns = {
    "APIView": APIView,
    "SessionAuthenticated": SessionAuthenticated,
    "Response": Response,
    "can_manage_session_security": lambda user: True,
    "_forbidden": lambda: Response({"detail": "forbidden"}, status=403),
    "list_audit_events": lambda **kwargs: [],
    "page_audit_events": bad_page_audit_events,
    "SessionSecurityError": RuntimeError,
}
Cls = class_method(ssv, "SessionAuditView", "get", ns)
resp = Cls().get(SimpleNamespace(user=object(), query_params={"page": "oops"}))
assert resp.status_code == 400
assert resp.data == {"detail": "Invalid pagination parameters."}
assert "invalid literal" not in resp.data["detail"]

ns = {
    "APIView": APIView,
    "SessionAuthenticated": SessionAuthenticated,
    "Response": Response,
    "can_manage_login_sessions": lambda user: True,
    "_login_sessions_forbidden": lambda: Response({"detail": "forbidden"}, status=403),
    "list_active_login_sessions": lambda **kwargs: [],
    "page_active_login_sessions": lambda **kwargs: (_ for _ in ()).throw(ValueError("invalid literal for int() with base 10: 'oops'")),
    "SessionSecurityError": RuntimeError,
}
Cls = class_method(ssv, "AdminLoginSessionListView", "get", ns)
resp = Cls().get(SimpleNamespace(user=object(), query_params={"page_size": "oops"}))
assert resp.status_code == 400
assert resp.data == {"detail": "Invalid pagination parameters."}
assert "invalid literal" not in resp.data["detail"]

print("access-contract-hygiene-1.15.142: PASS")
