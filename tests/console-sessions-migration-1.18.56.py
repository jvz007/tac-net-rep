#!/usr/bin/env python3
"""Regression: Core 1.18.56 (C1). Migration 0050 against the models.

An AST pass compares the migration with models.py field for field (always), and, where Django is importable, Django's own autodetector must find
nothing left to migrate once 0050's operations are applied to the state before them (`manage.py makemigrations --check` itself needs Tactical's other
apps and cannot run on this PC). Also pins the 1.18.44 lesson (no field named check, delete, save or clean), the indexes, the unique columns and a real
SQLite create with the constraint checks.
"""
import ast
import importlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
spec = importlib.util.spec_from_file_location("cs_harness", Path(__file__).with_name("console_sessions_harness.py"))
harness = importlib.util.module_from_spec(spec)
sys.modules["cs_harness"] = harness
spec.loader.exec_module(harness)
must = harness.must

SHADOWED = {"check", "save", "delete", "clean", "full_clean", "validate_unique", "validate_constraints", "refresh_from_db", "from_db", "pk", "objects"}
NEW_MODELS = ("TecTacConsoleSession", "TecTacConsoleSignin")


def call_name(call):
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def kwarg(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


models_tree = ast.parse((APP / "models.py").read_bytes().decode("utf-8"))
classes = {n.name: n for n in models_tree.body if isinstance(n, ast.ClassDef)}
model_fields = {}
for name in NEW_MODELS:
    fields = {}
    for stmt in classes[name].body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute) and getattr(stmt.value.func.value, "id", "") == "models":
            fields[stmt.targets[0].id] = stmt.value
    must(not (set(fields) & SHADOWED), f"{name} has a field that shadows a Model attribute: {set(fields) & SHADOWED}")
    for forbidden in ("check", "delete", "save", "clean"):
        must(forbidden not in fields, f"{name}.{forbidden} must not be a field name")
    model_fields[name] = fields

migration = ast.parse((APP / "migrations" / "0050_console_sessions.py").read_text(encoding="utf-8"))
created = {}
for node in ast.walk(migration):
    if isinstance(node, ast.Call) and call_name(node) == "CreateModel":
        created[kwarg(node, "name").value] = {e.elts[0].value: e.elts[1] for e in kwarg(node, "fields").elts}
must(set(created) == set(NEW_MODELS), f"0050 creates the two models: {sorted(created)}")
for name in NEW_MODELS:
    must(set(created[name]) == set(model_fields[name]), f"{name}: 0050 and models.py agree on the fields: {set(created[name]) ^ set(model_fields[name])}")
    for field, call in model_fields[name].items():
        m_call = created[name][field]
        must(call_name(call) == call_name(m_call), f"{name}.{field}: the same field type in the migration")
        for key in ("max_length", "null", "blank", "unique", "default", "primary_key"):
            a, b = kwarg(call, key), kwarg(m_call, key)
            must((ast.unparse(a) if a else None) == (ast.unparse(b) if b else None), f"{name}.{field}.{key} agrees: {a and ast.unparse(a)} vs {b and ast.unparse(b)}")
tail = ast.unparse(migration)
for needle in ("0049_console_certificates", "core_console_session", "core_console_signin", "tectac_consess_user_idx", "tectac_consess_serial_idx", "tectac_consess_trust_idx"):
    must(needle in tail, f"0050 mentions {needle}")
must("swappable_dependency" not in tail and "AUTH_USER_MODEL" not in tail and "ForeignKey" not in tail, "no foreign key, so no swappable dependency")
for model in NEW_MODELS:
    must("ForeignKey" not in ast.unparse(classes[model]), f"{model} has no foreign key")
must(ast.unparse(model_fields["TecTacConsoleSession"]["token_hash"]).count("unique=True") == 1, "the token hash is unique")
must(ast.unparse(model_fields["TecTacConsoleSignin"]["code_hash"]).count("unique=True") == 1, "the code hash is unique")
must("max_length=64" in ast.unparse(model_fields["TecTacConsoleSession"]["token_hash"]) and "max_length=43" in ast.unparse(model_fields["TecTacConsoleSignin"]["code_challenge"]), "the widths of the SHA-256 hex and the challenge")
must("max_length=253" in ast.unparse(model_fields["TecTacConsoleSignin"]["host"]), "a host is up to 253 characters")

h = harness.boot()
if h is None:
    print("console sessions migration 1.18.56 regression: PASS (AST branch only: Django is not installed)")
    sys.exit(0)

from django.apps import apps  # noqa: E402
from django.db.migrations.autodetector import MigrationAutodetector  # noqa: E402
from django.db.migrations.state import ProjectState  # noqa: E402

current = ProjectState.from_apps(apps)
before = current.clone()
for name in ("tectacconsolesession", "tectacconsolesignin"):
    before.remove_model("tec_tac", name)
mig = importlib.import_module("tec_tac.migrations.0050_console_sessions").Migration
state = before.clone()
for op in mig.operations:
    op.state_forwards("tec_tac", state)
changes = MigrationAutodetector(state, current)._detect_changes()
leftover = {app: [(m.name, [type(o).__name__ + ":" + str(getattr(o, "name", getattr(o, "model_name", ""))) for o in m.operations]) for m in ms] for app, ms in changes.items() if app == "tec_tac"}
must(not leftover, f"0050 and the models disagree (makemigrations would still write): {leftover}")
must(mig.dependencies == [("tec_tac", "0049_console_certificates")], "0050 depends on 0049 only")

sql_state = before.clone()
with h.connection.schema_editor(collect_sql=True, atomic=False) as editor:
    for op in mig.operations:
        target = sql_state.clone()
        op.state_forwards("tec_tac", target)
        op.database_forwards("tec_tac", editor, sql_state, target)
        sql_state = target
sql = "\n".join(editor.collected_sql)
for needle in ("core_console_session", "core_console_signin", "tectac_consess_user_idx", "tectac_consess_serial_idx", "tectac_consess_trust_idx"):
    must(needle in sql, f"the SQL has {needle}")

# real SQLite: the unique columns refuse a second row
from django.db import IntegrityError, transaction  # noqa: E402
import uuid  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

M = h.models
h.reset()
M.TecTacConsoleSession.objects.create(user_id=1, trust_id=uuid.uuid4(), token_hash="a" * 64, serial="1" * 32, pc_label="PC")
try:
    with transaction.atomic():
        M.TecTacConsoleSession.objects.create(user_id=2, trust_id=uuid.uuid4(), token_hash="a" * 64, serial="2" * 32, pc_label="PC2")
    raise AssertionError("a second row with the same token hash was accepted")
except IntegrityError:
    pass
now = datetime.now(timezone.utc)
M.TecTacConsoleSignin.objects.create(code_hash="b" * 64, user_id=1, serial="1" * 32, code_challenge="c" * 43, redirect_port=40000, host="tec.example.com", expires_at=now + timedelta(seconds=60))
try:
    with transaction.atomic():
        M.TecTacConsoleSignin.objects.create(code_hash="b" * 64, user_id=2, serial="2" * 32, code_challenge="d" * 43, redirect_port=40001, host="tec.example.com", expires_at=now)
    raise AssertionError("a second row with the same code hash was accepted")
except IntegrityError:
    pass
row = M.TecTacConsoleSession.objects.get()
must(row.revoked is False and row.revoked_reason == "" and row.last_used_at is None and row.created_at is not None, "the defaults")
must(M.TecTacConsoleSignin.objects.get().used_at is None, "a new code is unused")

print("console sessions migration 1.18.56 regression: PASS")
