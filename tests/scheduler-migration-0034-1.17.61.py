#!/usr/bin/env python3
"""1.17.61 regression: migration 0034 and the TecTacScheduleRun model agree, and the migration is additive.

Django is not installed on the development PC, so this reads both files as source (ast). It checks that 0034 depends on 0033, holds
four AddField operations on tectacschedulerun and nothing else, that every field is blank, empty or null by default (so every existing
row stays valid and nothing needs a data migration), and that each field's type and arguments equal the model's. The dev-server step is
`manage.py makemigrations --check --dry-run`, named in the release notes.
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
            return f"expr:{ast.unparse(n)}"  # dict, Status.choices, a class name: compared as written

    return (ast.unparse(node.func), tuple(sorted((kw.arg, repr(value(kw.value))) for kw in node.keywords)))


migration = ast.parse((APP / "migrations" / "0034_scheduler_run_completion.py").read_text(encoding="utf-8"))
cls = next(n for n in migration.body if isinstance(n, ast.ClassDef) and n.name == "Migration")
assigns = {t.id: n.value for n in cls.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
deps = ast.literal_eval(assigns["dependencies"])
must(deps == [("tec_tac", "0033_runtime_licensing_mode")], deps)
ops = assigns["operations"].elts
must(len(ops) == 4 and all(ast.unparse(op.func) == "migrations.AddField" for op in ops), "four AddField operations and nothing else")
fields = {}
for op in ops:
    kwargs = {kw.arg: kw.value for kw in op.keywords}
    must(ast.literal_eval(kwargs["model_name"]) == "tectacschedulerun", "only the schedule run model")
    fields[ast.literal_eval(kwargs["name"])] = call_signature(kwargs["field"])
must(set(fields) == {"completion_state", "completion_ref", "completion_started_at", "system_action_marks"}, set(fields))

for name, (_func, args) in fields.items():
    arg = dict(args)
    has_default = "default" in arg
    nullable = arg.get("null") == "True"
    must(has_default or nullable, f"{name} must have a default or be null: existing rows need a value")
    must(arg.get("blank") == "True", f"{name} is blank=True")

models_tree = ast.parse((APP / "models.py").read_text(encoding="utf-8"))
model_cls = next(n for n in models_tree.body if isinstance(n, ast.ClassDef) and n.name == "TecTacScheduleRun")
model_fields = {}
for node in model_cls.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call):
        model_fields[node.targets[0].id] = call_signature(node.value)
for name, signature in fields.items():
    must(name in model_fields, f"model lacks {name}")
    must(model_fields[name] == signature, f"{name}: model {model_fields[name]} != migration {signature}")
print("       0034 depends on 0033, adds exactly four blank-by-default columns, and each equals the model's field")

# the other migrations of this release line are untouched: 0034 is the newest
numbers = sorted(p.name for p in (APP / "migrations").glob("0*.py"))
must(numbers[-1] == "0034_scheduler_run_completion.py" and numbers[-2] == "0033_runtime_licensing_mode.py", numbers[-3:])
print("PASS scheduler migration 0034 1.17.61")
