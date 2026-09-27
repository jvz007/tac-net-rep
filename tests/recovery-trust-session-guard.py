#!/usr/bin/env python3
"""Regression: recovery trust must use the Core session-security permission boundary."""
from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]
view_path = ROOT / "framwork" / "tec_tac" / "server_backup_views.py"
session_path = ROOT / "framwork" / "tec_tac" / "session_security.py"
view_source = view_path.read_text()
session_source = session_path.read_text()

# Structural contract: the view imports and uses SessionAuthenticated, not plain IsAuthenticated.
assert "from .session_security import SessionAuthenticated" in view_source
assert "permission_classes = [SessionAuthenticated]" in view_source
assert "from rest_framework.permissions import IsAuthenticated" not in view_source

module = ast.parse(view_source)
recovery = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == "RecoveryTrustView")
assign = next(n for n in recovery.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "permission_classes" for t in n.targets))
assert isinstance(assign.value, ast.List) and len(assign.value.elts) == 1
assert isinstance(assign.value.elts[0], ast.Name) and assign.value.elts[0].id == "SessionAuthenticated"

# Behavioral contract provided by the shared permission: pre-TOTP Knox setup credentials are denied,
# and every accepted request is resolved through the live Tec-Tac session record (which enforces revocation).
assert '"mfa_enrollment_required"' in session_source
assert "request_knox_digest(request)" in session_source
assert "request.tec_tac_session = ensure_request_session(request)" in session_source
assert "class SessionAuthenticated(IsAuthenticated):" in session_source

print("[TEST] PASS recovery trust uses Core session-security guard")
