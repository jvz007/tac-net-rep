#!/usr/bin/env python3
"""Regression: Core 1.18.31 - no migration may depend on a floating "__latest__" or "__first__" node.

Parses every migration with ast (no Django needed). migrations.swappable_dependency(settings.AUTH_USER_MODEL) is
Django's standard form: it resolves to the first migration of the user model's app, which never moves, so it is allowed.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "framwork" / "tec_tac" / "migrations"
FLOATING = ("__latest__", "__first__")
PIN = ("accounts", "0042_copy_mesh_permission_to_terminal")


def dependencies(source):
    """Return the literal (app, name) tuples of Migration.dependencies."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ClassDef) and node.name == "Migration":
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "dependencies" for t in stmt.targets):
                    for elt in getattr(stmt.value, "elts", []):
                        if isinstance(elt, ast.Tuple):
                            found.append(tuple(e.value for e in elt.elts if isinstance(e, ast.Constant)))
    return found


def floating(source):
    return [d for d in dependencies(source) if any(part in FLOATING for part in d)]


# (1) no floating dependency in any migration
files = sorted(MIGRATIONS.glob("[0-9]*.py"))
assert files, "no migrations found"
for path in files:
    assert not floating(path.read_text(encoding="utf-8")), f"{path.name} has a floating dependency"

# (2) 0038 is pinned to exactly one accounts migration
deps = dependencies((MIGRATIONS / "0038_communicator_service_user.py").read_text(encoding="utf-8"))
assert [d for d in deps if d[0] == "accounts"] == [PIN], deps

# (3) the checker itself works
assert floating('class Migration:\n    dependencies = [("accounts", "__latest__")]\n') == [("accounts", "__latest__")]
assert floating('class Migration:\n    dependencies = [("agents", "__first__")]\n') == [("agents", "__first__")]
assert not floating('class Migration:\n    dependencies = [("tec_tac", "0001_initial"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]\n')

# (4) the pinned migration exists in Tactical and the flag the RunPython uses is defined (when the reference tree is present)
ref = ROOT.parents[1] / "reference" / "tacticalrmm" / "api" / "tacticalrmm" / "accounts" / "migrations"
if ref.is_dir():
    assert (ref / (PIN[1] + ".py")).is_file(), "pinned accounts migration missing in the Tactical reference"
    assert "can_send_cmd" in next(ref.glob("0017_*.py")).read_text(encoding="utf-8")
else:
    print("note: reference/tacticalrmm not present, check 4 skipped")

# (5) the pre-pack guard calls this test, and 0038 keeps LF
assert "migration-no-floating-dependency-1.18.31.py" in (ROOT / "tests" / "release-integrity.sh").read_text(encoding="utf-8")
assert b"\r" not in (MIGRATIONS / "0038_communicator_service_user.py").read_bytes()
print("migration no-floating-dependency 1.18.31 regression: PASS")
