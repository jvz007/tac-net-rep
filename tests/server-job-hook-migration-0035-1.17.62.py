#!/usr/bin/env python3
"""1.17.62 regression: migration 0035 and the TecTacServerJobHook model agree, and the migration is additive.

Django is not installed on the development PC, so this reads both files as source (ast). It checks that 0035 depends on 0034, holds one
CreateModel and one AddIndex and nothing else (no existing table changes, so nothing needs a data migration), that the implicit id line
is the same as the other tables', that every field's type and literal arguments equal the model's, that the state choices in the migration
are exactly the model's TextChoices members, that the unique job id and the index name agree, and that the table holds no column that
could carry job output or parameters. The dev-server step is `manage.py makemigrations --check --dry-run` (release notes).
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


def literal(node):
    try:
        return ast.literal_eval(node)
    except ValueError:
        return f"expr:{ast.unparse(node)}"


def signature(call: ast.Call) -> tuple:
    return (ast.unparse(call.func).split(".")[-1], {kw.arg: literal(kw.value) for kw in call.keywords}, [literal(a) for a in call.args])


migration = ast.parse((APP / "migrations" / "0035_server_job_hook.py").read_text(encoding="utf-8"))
cls = next(n for n in migration.body if isinstance(n, ast.ClassDef) and n.name == "Migration")
assigns = {t.id: n.value for n in cls.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
must(ast.literal_eval(assigns["dependencies"]) == [("tec_tac", "0034_scheduler_run_completion")], "0035 depends on 0034")
ops = assigns["operations"].elts
kinds = [ast.unparse(op.func) for op in ops]
must(kinds == ["migrations.CreateModel", "migrations.AddIndex"], kinds)
create, add_index = ops
create_kw = {kw.arg: kw.value for kw in create.keywords}
must(ast.literal_eval(create_kw["name"]) == "TecTacServerJobHook", "the one new table")
must(ast.literal_eval(create_kw["options"]) == {"ordering": ("created_at",)}, "ordering")
mig_fields = {}
for entry in create_kw["fields"].elts:
    name = ast.literal_eval(entry.elts[0])
    mig_fields[name] = signature(entry.elts[1])
must(mig_fields["id"] == ("BigAutoField", {"auto_created": True, "primary_key": True, "serialize": False, "verbose_name": "ID"}, []), "the implicit id, as the other tables")
index_kw = {kw.arg: kw.value for kw in add_index.keywords}
must(ast.literal_eval(index_kw["model_name"]) == "tectacserverjobhook", "the index is on the new table")
index_sig = signature(index_kw["index"])
must(index_sig[1] == {"fields": ["created_at"], "name": "tectac_svjobhook_created"}, index_sig)

models_tree = ast.parse((APP / "models.py").read_text(encoding="utf-8"))
model = next(n for n in models_tree.body if isinstance(n, ast.ClassDef) and n.name == "TecTacServerJobHook")
model_fields = {}
choices = {}
member_values = {}
for node in model.body:
    if isinstance(node, ast.ClassDef) and node.name == "State":
        for item in node.body:
            if isinstance(item, ast.Assign):
                value = ast.literal_eval(item.value)
                choices[value[0]] = value[1]
                member_values[item.targets[0].id] = value[0]
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call):
        model_fields[node.targets[0].id] = signature(node.value)
must("id" not in model_fields, "the model declares no id: the implicit one matches the migration")
must(set(model_fields) == set(mig_fields) - {"id"}, (sorted(model_fields), sorted(mig_fields)))
for name, (klass, kwargs, args) in model_fields.items():
    m_klass, m_kwargs, m_args = mig_fields[name]
    must(klass == m_klass and args == m_args, f"{name}: {klass}{args} != {m_klass}{m_args}")
    for key, value in kwargs.items():
        if key == "choices":
            continue  # compared below
        if isinstance(value, str) and value.startswith("expr:State."):
            value = member_values[value.split(".", 1)[1]]  # the TextChoices member's stored value
        must(m_kwargs.get(key) == value, f"{name}.{key}: model {value!r} != migration {m_kwargs.get(key)!r}")
    must(set(m_kwargs) - {"choices"} == set(kwargs) - {"choices"}, f"{name}: the argument names differ: {sorted(m_kwargs)} != {sorted(kwargs)}")
must(mig_fields["state"][1]["choices"] == [[k, v] for k, v in choices.items()] or mig_fields["state"][1]["choices"] == [(k, v) for k, v in choices.items()], (mig_fields["state"][1]["choices"], choices))
must(set(choices) == {"claiming", "retry", "queued", "skipped", "ignored", "abandoned"}, choices)
must(mig_fields["state"][1]["default"] == "claiming" and member_values["CLAIMING"] == "claiming", "the default state is claiming")
must(mig_fields["job_id"][1] == {"unique": True} and model_fields["job_id"][1] == {"unique": True}, "unique on the job id: the at-most-once claim")
meta = next(n for n in model.body if isinstance(n, ast.ClassDef) and n.name == "Meta")
meta_text = ast.unparse(meta)
must("tectac_svjobhook_created" in meta_text and "('created_at',)" in meta_text, meta_text)
print("       0035 depends on 0034, adds one table and one index, and every field, choice, the unique job id and the index equal the model's")

# nothing in the table can hold output or parameters
must(not ({"output", "stdout", "stderr", "parameters", "payload", "result", "message", "error"} & set(mig_fields)), sorted(mig_fields))
must(all(kw.get("max_length", 0) <= 128 for _k, kw, _a in mig_fields.values()), "every text column is short")
print("       the table holds ids, a status and a reason code; no column can carry job output or parameters")

# 0035 is the only migration of this release and the newest
names = sorted(p.name for p in (APP / "migrations").glob("0*.py"))
must(names[-1] == "0035_server_job_hook.py" and names[-2] == "0034_scheduler_run_completion.py", names[-3:])
must(len([n for n in names if n.startswith("0035_")]) == 1, "one 0035")
text = (APP / "migrations" / "0035_server_job_hook.py").read_text(encoding="utf-8")
must("RunPython" not in text and "RunSQL" not in text and "AlterField" not in text and "RemoveField" not in text and "DeleteModel" not in text, "additive only")
print("PASS server job hook migration 0035 1.17.62")
