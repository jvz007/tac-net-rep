#!/usr/bin/env python3
"""1.17.68 regression: migration 0037 and the models agree, and the migration is additive.

Django is not installed on the development PC, so this reads the files as source (ast). It checks that 0037 follows 0036, holds one AddField
on tectacschedule (creation_scope, a JSON column with an empty default, so every existing row stays valid and nothing needs a data migration), the
CreateModel of TecTacDelegationGrant, its index and its unique constraint, and nothing else; that every field of the new model equals the model
class (type and arguments); and that the model keeps the shape the delegation design needs (the unique owner and key pair, the person kept by
name when the user row is gone, the stored scope). The dev-server step is `manage.py makemigrations --check --dry-run`, named in the release notes.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def call_signature(node: ast.Call) -> tuple:
    def value(n):
        try:
            return ast.literal_eval(n)
        except ValueError:
            return f"expr:{ast.unparse(n)}"

    return (ast.unparse(node.func), tuple(sorted((kw.arg, repr(value(kw.value))) for kw in node.keywords)))


def kwargs_of(call: ast.Call) -> dict:
    return {kw.arg: kw.value for kw in call.keywords}


migration = ast.parse((APP / "migrations" / "0037_creation_scope_and_delegation.py").read_text(encoding="utf-8"))
cls = next(n for n in migration.body if isinstance(n, ast.ClassDef) and n.name == "Migration")
assigns = {t.id: n.value for n in cls.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
deps = [ast.unparse(e) for e in assigns["dependencies"].elts]
must("('tec_tac', '0036_schedule_creator_name')" in deps and any("swappable_dependency" in d for d in deps), deps)
ops = assigns["operations"].elts
names = [ast.unparse(op.func) for op in ops]
must(names == ["migrations.AddField", "migrations.CreateModel", "migrations.AddIndex", "migrations.AddConstraint"], names)

# (1) the column on the schedule: empty by default, blank allowed
add = kwargs_of(ops[0])
must(ast.literal_eval(add["model_name"]) == "tectacschedule" and ast.literal_eval(add["name"]) == "creation_scope", add)
column = call_signature(add["field"])
must(column[0] == "models.JSONField" and dict(column[1]) == {"blank": "True", "default": "'expr:dict'"}, column)
models_tree = ast.parse((APP / "models.py").read_text(encoding="utf-8"))


def model_fields(name: str) -> dict:
    node = next(n for n in models_tree.body if isinstance(n, ast.ClassDef) and n.name == name)
    out = {}
    for item in node.body:
        if isinstance(item, ast.Assign) and isinstance(item.targets[0], ast.Name) and isinstance(item.value, ast.Call):
            out[item.targets[0].id] = call_signature(item.value)
    return out


must(model_fields("TecTacSchedule")["creation_scope"] == column, "the model's creation_scope equals the migration's")
print("       0037 follows 0036 and adds one blank, empty-by-default JSON column to the schedule that equals the model's field")

# (2) the delegation model
create = kwargs_of(ops[1])
must(ast.literal_eval(create["name"]) == "TecTacDelegationGrant", create)
migration_fields = {}
for field in create["fields"].elts:
    name = ast.literal_eval(field.elts[0])
    migration_fields[name] = call_signature(field.elts[1])
grant_fields = model_fields("TecTacDelegationGrant")
must(set(migration_fields) == set(grant_fields), (sorted(migration_fields), sorted(grant_fields)))
for name, signature in migration_fields.items():
    if name == "id":
        must(signature[0] == "models.UUIDField" and grant_fields[name][0] == "models.UUIDField", name)
        continue
    if name == "created_by":  # the migration spells the user model as ``to=`` and the delete rule by its full path
        wanted = dict(grant_fields[name][1])
        got = dict(signature[1])
        must(got["null"] == wanted["null"] == "True" and got["blank"] == wanted["blank"] == "True" and got["related_name"] == wanted["related_name"], (wanted, got))
        must(wanted["on_delete"] == "'expr:models.SET_NULL'", wanted)
        continue
    must(grant_fields[name] == signature, f"{name}: model {grant_fields[name]} != migration {signature}")
must({"id", "owner_module", "grant_key", "provider_module", "action_id", "targets", "parameters", "parameters_digest", "created_by", "created_by_username",
      "confirmed_by_username", "creation_scope", "enabled", "created_at", "updated_at"} == set(migration_fields), sorted(migration_fields))
must(dict(migration_fields["created_by"][1])["on_delete"] == "'expr:django.db.models.deletion.SET_NULL'" and dict(migration_fields["created_by"][1])["null"] == "True",
     "a deleted user leaves the grant in place (the stored name stays)")
print("       the new table equals the model field for field; the person is kept by row (SET_NULL) and by stored name")

# (3) unique pair and index
index = kwargs_of(ops[2])
must(ast.literal_eval(index["model_name"]) == "tectacdelegationgrant" and "tectac_deleg_provider_idx" in ast.unparse(index["index"]), ast.unparse(ops[2]))
constraint = kwargs_of(ops[3])
text = ast.unparse(constraint["constraint"])
must("tectac_deleg_owner_key_unique" in text and "'owner_module', 'grant_key'" in text, text)
source = (APP / "models.py").read_text(encoding="utf-8")
must('name="tectac_deleg_owner_key_unique"' in source and 'name="tectac_deleg_provider_idx"' in source, "the model carries the same index and constraint names")
print("       the owner module and grant key are unique together; the provider and action are indexed")

# (4) the earlier migrations are untouched
numbers = sorted(p.name for p in (APP / "migrations").glob("0*.py"))
must(numbers.index("0037_creation_scope_and_delegation.py") - 1 == numbers.index("0036_schedule_creator_name.py"), numbers[-3:])
print("PASS scheduler migration 0037 1.17.68")
