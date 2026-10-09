#!/usr/bin/env python3
"""1.17.10: the browser contract catalog lists the UI 0.12.87 helpers tacticalOperation and hasTacticalPermission."""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
tree = ast.parse((ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8"))
assignment = next(
    node for node in tree.body
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "BROWSER_CONTRACTS" for t in node.targets)
)
rows = ast.literal_eval(assignment.value)
by_id = {row["id"]: row for row in rows}
ids = [row["id"] for row in rows]
assert len(ids) == len(set(ids)), "duplicate ids"
for row in rows:
    assert "details" not in row or (isinstance(row["details"], list) and row["details"] and all(isinstance(x, str) and x for x in row["details"])), row["id"]


def details(row_id):
    return " ".join(by_id[row_id]["details"])


op = by_id["ui.authenticated.tactical-operation"]
assert op["docs"].startswith("tec-tac-ui/docs/") and op["operations"] == ["tacticalOperation"] and op["service"] == "tacticalOperation"
text = details("ui.authenticated.tactical-operation")
for needle in ("POST /api/tfd/tactical-operations/<moduleId>/<operationId>/", "^[A-Za-z0-9][A-Za-z0-9_-]*$", "params", "body", "plain object",
               "headers", "audit field", "X-Tec-Tac-Audit", "auditRecorded", "tactical_permission_denied", "object_not_found",
               "Public modules (registerPublic) do not get", "Core 1.17.7", "UI 0.12.87",
               "declared by the moduleId in the URL", "Tactical permission", "role scope", "route is owned", "AD-19",
               "cannot tell which module's browser code made the call", "its own id", "AD-20 core module"):
    assert needle in text, f"tacticalOperation details lack {needle!r}"
# 1.17.11: UI 0.12.88 enforces the scoping rule for the helper, so the 1.17.10 sentence that said otherwise is gone
assert "UI 0.12.87 does not enforce" not in text and "does not enforce that scoping rule yet" not in text, "stale 0.12.87 wording is still in the row"

perm = by_id["ui.authenticated.tactical-permissions"]
assert perm["docs"].startswith("tec-tac-ui/docs/") and perm["operations"] == ["hasTacticalPermission"] and perm["service"] == "hasTacticalPermission"
text = details("ui.authenticated.tactical-permissions")
for needle in ("context.context.tactical_permissions[flag]", "exactly true", "unknown flag", "empty map", "older Core", "non-backend", "Display only", "AD-12"):
    assert needle in text, f"hasTacticalPermission details lack {needle!r}"
assert "1.17.7" in perm["purpose"] and "0.12.87" in perm["purpose"]

runtime = by_id["ui.authenticated.runtime-context"]
text = details("ui.authenticated.runtime-context")
for needle in ("can_*", "strict boolean", "drops", "empty map", "tactical_permission_catalog"):
    assert needle in text, f"runtime-context details lack {needle!r}"
assert "tactical_permissions.<flag>" in runtime["operations"]

assert "Browser helpers" in (ROOT / "docs/tactical-operations.md").read_text(encoding="utf-8")
print("[TEST] PASS 1.17.10 browser contract rows for the UI helpers")
