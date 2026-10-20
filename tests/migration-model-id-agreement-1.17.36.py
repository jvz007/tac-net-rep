#!/usr/bin/env python3
"""1.17.36 regression: every model in models.py agrees with the migrations on its primary key, fields, indexes and constraints.

Core 1.17.35 failed ``manage.py makemigrations --check`` on the dev server. TecTacNoticeLedger and TecTacModulePreference declared
``id = models.BigAutoField(primary_key=True)`` explicitly, while migrations 0030 and 0031 created the same column as Django's implicit
id (``auto_created=True``, ``verbose_name="ID"``). Django sees those two as different and wants a new migration. The fix removes the
explicit lines from the two models: no database change and no migration 0032.

Django is not installed on the development PC, so this reads the code with ast. It replays every migration in order into a state (the
last CreateModel of a model wins; CreateModel, DeleteModel, AddField, AlterField, RemoveField, AddIndex, RemoveIndex, AddConstraint,
RemoveConstraint, and the state_operations of SeparateDatabaseAndState or RunSQL). RunPython and AlterModelOptions change no field.
The real proof is ``manage.py makemigrations --check --dry-run`` on the dev server.

Covered: (1) apps.py sets default_auto_field to BigAutoField, the class of an implicit id; (2) the models and the state have the same set
of models (no model without a migration, no migration without a model); (3) for each model, an implicit id in the state means the model
declares no id and no primary_key field, and the state id is BigAutoField with serialize=False and verbose_name "ID"; an explicit primary
key in the state is declared by the model too. (4) Every model has the same field names and field classes as the state. For the two
new tables every literal kwarg (max_length, auto_now, auto_now_add, related_name, on_delete, the target, defaults) must match too; other
models use class constants (choices, defaults) that ast cannot evaluate, so their kwargs are not compared here. (5) Every model has the
same index and constraint names as the state, and for the two new tables the same kwargs and fields. (6) TecTacNoticeLedger and
TecTacModulePreference declare no id, and migrations 0030 and 0031 carry exactly the implicit id line. (7) No migration 0032 exists.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork/tec_tac"
MIGRATIONS = APP / "migrations"

IMPLICIT_ID_LINE = '("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),'
IMPLICIT_ID_SPEC = ("BigAutoField", {"auto_created": True, "primary_key": True, "serialize": False, "verbose_name": "ID"})
NEW_TABLES = {
    "TecTacNoticeLedger": ("0030_notice_ledger.py", ["tectac_nledger_key_idx", "tectac_nledger_age_idx"], ["tectac_nledger_unique"]),
    "TecTacModulePreference": ("0031_module_preferences.py", [], ["tectac_modpref_unique"]),
    "TecTacEventJobStat": ("0032_event_jobs.py", [], ["tectac_evjobstat_unique"]),  # 1.17.45: TecTacEventJob has an explicit uuid key and is not in this list
}


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def call_name(call):
    return call.func.attr if isinstance(call.func, ast.Attribute) else call.func.id


def canon(node):
    """A literal as a comparable value. An attribute or a name compares by its last part (models.CASCADE and
    django.db.models.deletion.CASCADE are the same), a call by its name and kwargs."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(canon(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return tuple((canon(k), canon(v)) for k, v in zip(node.keys, node.values))
    if isinstance(node, ast.UnaryOp):
        return (type(node.op).__name__, canon(node.operand))
    if isinstance(node, ast.BinOp):
        return (type(node.op).__name__, canon(node.left), canon(node.right))
    if isinstance(node, ast.Call):
        return (call_name(node), canon_kwargs(node))
    raise AssertionError(f"unsupported value in a field, index or constraint: {ast.unparse(node)}")


def canon_kwargs(call):
    out = {}
    for kw in call.keywords:
        must(kw.arg is not None, f"**kwargs is not supported here: {ast.unparse(call)}")
        out[kw.arg] = canon(kw.value)
    return out


def field_spec(call):
    """(class name, kwargs). A positional first argument is a relation's target, which migrations write as to=."""
    kwargs = canon_kwargs(call)
    if call.args:
        kwargs["to"] = canon(call.args[0])
    return (call_name(call), kwargs)


def is_models_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "models")


def model_classes(tree):
    out = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and any(ast.unparse(base) == "models.Model" for base in node.bases):
            out[node.name] = node
    return out


def model_fields(cls):
    fields = {}
    for stmt in cls.body:
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)
                and is_models_call(stmt.value)):
            fields[stmt.targets[0].id] = field_spec(stmt.value)
    return fields


def declares_id(cls):
    return any(isinstance(s, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "id" for t in s.targets) for s in cls.body)


def meta_items(cls, attr):
    """The Meta indexes or constraints of a model, keyed by name."""
    for stmt in cls.body:
        if isinstance(stmt, ast.ClassDef) and stmt.name == "Meta":
            for s in stmt.body:
                if isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name) and s.targets[0].id == attr:
                    items = {}
                    for call in s.value.elts:
                        spec = (call_name(call), canon_kwargs(call))
                        items[spec[1]["name"]] = spec
                    return items
    return {}


def migration_ops(tree):
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Migration":
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id == "operations":
                    return stmt.value.elts
    return []


def add_index_like(state, model, kind, call):
    spec = (call_name(call), canon_kwargs(call))
    state[model][kind][spec[1]["name"]] = spec


def apply_op(state, op):
    name = call_name(op)
    kw = {k.arg: k.value for k in op.keywords}
    if "state_operations" in kw:
        for sub in kw["state_operations"].elts:
            apply_op(state, sub)
        return
    if name in ("RunPython", "RunSQL", "AlterModelOptions"):
        return
    if name == "CreateModel":
        model = canon(kw["name"]).lower()
        entry = {"fields": {}, "indexes": {}, "constraints": {}}
        for tup in kw["fields"].elts:
            entry["fields"][canon(tup.elts[0])] = field_spec(tup.elts[1])
        state[model] = entry
        if "options" in kw:
            for key, value in zip(kw["options"].keys, kw["options"].values):
                if canon(key) == "indexes":
                    for call in value.elts:
                        add_index_like(state, model, "indexes", call)
                elif canon(key) == "constraints":
                    for call in value.elts:
                        add_index_like(state, model, "constraints", call)
        return
    if name == "DeleteModel":
        state.pop(canon(kw["name"]).lower(), None)
        return
    model = canon(kw["model_name"]).lower()
    if name in ("AddField", "AlterField"):
        state[model]["fields"][canon(kw["name"])] = field_spec(kw["field"])
    elif name == "RemoveField":
        state[model]["fields"].pop(canon(kw["name"]), None)
    elif name == "AddIndex":
        add_index_like(state, model, "indexes", kw["index"])
    elif name == "RemoveIndex":
        state[model]["indexes"].pop(canon(kw["name"]), None)
    elif name == "AddConstraint":
        add_index_like(state, model, "constraints", kw["constraint"])
    elif name == "RemoveConstraint":
        state[model]["constraints"].pop(canon(kw["name"]), None)
    else:
        raise AssertionError(f"migration operation not replayed by this test: {name}")


def replay_migrations():
    state = {}
    for path in sorted(MIGRATIONS.glob("*.py")):
        if not re.fullmatch(r"\d{4}_.+\.py", path.name):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for op in migration_ops(tree):
            apply_op(state, op)
    return state


# ------------------------------------------------------------------------------------------------ (1) the default auto field
apps_tree = ast.parse((APP / "apps.py").read_text(encoding="utf-8"))
config = next(n for n in apps_tree.body if isinstance(n, ast.ClassDef) and n.name == "TecTacFrameworkConfig")
dfa = next(s.value for s in config.body if isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name)
           and s.targets[0].id == "default_auto_field")
must(isinstance(dfa, ast.Constant) and dfa.value == "django.db.models.BigAutoField",
     f"apps.py default_auto_field is {ast.unparse(dfa)}, expected django.db.models.BigAutoField")

# ------------------------------------------------------------------------------------------------ (2) the same set of models
models_tree = ast.parse((APP / "models.py").read_text(encoding="utf-8"))
classes = model_classes(models_tree)
state = replay_migrations()
model_keys = {name.lower() for name in classes}
must(model_keys == set(state),
     f"models without a migration: {sorted(model_keys - set(state))}; migrations without a model: {sorted(set(state) - model_keys)}")

# ------------------------------------------------------------------------------------------------ (3) and (4) primary keys and fields
for name, cls in classes.items():
    entry = state[name.lower()]
    fields = entry["fields"]
    declared = model_fields(cls)
    explicit_state = sorted(n for n, (_, kw) in fields.items() if kw.get("primary_key") is True and not kw.get("auto_created"))
    explicit_model = sorted(n for n, (_, kw) in declared.items() if kw.get("primary_key") is True)
    if explicit_state:
        must(explicit_state == explicit_model,
             f"{name}: primary key in the migrations {explicit_state}, in the model {explicit_model}")
        state_cmp = dict(fields)
    else:
        must(fields.get("id") == IMPLICIT_ID_SPEC,
             f"{name}: the migrations create id as {fields.get('id')}, expected the implicit {IMPLICIT_ID_SPEC}")
        must(not declares_id(cls) and not explicit_model,
             f"{name}: the migrations use the implicit id, so the model must not declare id or a primary key (Django 1.17.35 bug)")
        state_cmp = {k: v for k, v in fields.items() if k != "id"}
    # Every model: the same field names, and the same field class for each. Django writes serialize=False on an explicit primary key,
    # and other models use class constants (choices, defaults) that ast cannot evaluate, so their kwargs are compared only for the two
    # new tables below.
    must(set(state_cmp) == set(declared),
         f"{name}: fields differ between migrations and model: migration {sorted(state_cmp)} model {sorted(declared)}")
    for field_name, (cls_name, _) in declared.items():
        must(state_cmp[field_name][0] == cls_name,
             f"{name}.{field_name}: migration {state_cmp[field_name][0]} model {cls_name}")
    must(set(entry["indexes"]) == set(meta_items(cls, "indexes")),
         f"{name}: index names differ: migrations {sorted(entry['indexes'])} model {sorted(meta_items(cls, 'indexes'))}")
    must(set(entry["constraints"]) == set(meta_items(cls, "constraints")),
         f"{name}: constraint names differ: migrations {sorted(entry['constraints'])} model {sorted(meta_items(cls, 'constraints'))}")

    if name in NEW_TABLES:
        # (4) and (5) in full for the two new tables: every kwarg, index and constraint, literal by literal.
        if state_cmp != declared:
            diff = sorted(k for k in set(state_cmp) | set(declared) if state_cmp.get(k) != declared.get(k))
            raise AssertionError(f"{name}: field specs differ: {diff}; migration {[state_cmp.get(k) for k in diff]} "
                                 f"model {[declared.get(k) for k in diff]}")
        must(entry["indexes"] == meta_items(cls, "indexes"),
             f"{name}: index specs differ: migrations {entry['indexes']} model {meta_items(cls, 'indexes')}")
        must(entry["constraints"] == meta_items(cls, "constraints"),
             f"{name}: constraint specs differ: migrations {entry['constraints']} model {meta_items(cls, 'constraints')}")

# ------------------------------------------------------------------------------------------------ (6) the two new tables
for name, (migration_file, index_names, constraint_names) in NEW_TABLES.items():
    cls = classes[name]
    must(not declares_id(cls), f"{name} must not declare id (the implicit id matches {migration_file})")
    text = (MIGRATIONS / migration_file).read_text(encoding="utf-8")
    must(IMPLICIT_ID_LINE in text, f"{migration_file} no longer carries the implicit id line exactly as written")
    must(f'name="{name}"' in text, f"{migration_file} does not create {name}")
    must(sorted(state[name.lower()]["indexes"]) == sorted(index_names),
         f"{name}: index names {sorted(state[name.lower()]['indexes'])} != {sorted(index_names)}")
    must(sorted(state[name.lower()]["constraints"]) == sorted(constraint_names),
         f"{name}: constraint names {sorted(state[name.lower()]['constraints'])} != {sorted(constraint_names)}")

# ------------------------------------------------------------------------------------------------ (7) no migration 0032
# 1.17.45: the one migration 0032 is the event jobs one (core.event_jobs). The id fix of 1.17.36 itself added none.
must(sorted(p.name for p in MIGRATIONS.glob("0032_*.py")) == ["0032_event_jobs.py"], "the only migration 0032 is 0032_event_jobs (1.17.45)")
must(sorted(p.name for p in MIGRATIONS.glob("0033_*.py")) == ["0033_runtime_licensing_mode.py"], "the only migration 0033 is the licensing mode column (1.17.58)")
must(sorted(p.name for p in MIGRATIONS.glob("0034_*.py")) == ["0034_scheduler_run_completion.py"], "the only migration 0034 is the scheduler run completion columns (1.17.61)")
must(not list(MIGRATIONS.glob("0035_*.py")), "no migration 0035 yet")

print("[TEST] PASS migration and model id agreement 1.17.36")
