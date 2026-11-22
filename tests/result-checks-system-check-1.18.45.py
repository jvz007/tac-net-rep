#!/usr/bin/env python3
"""Regression: Core 1.18.45. A model field must never shadow a Django Model attribute (models.E020).

Core 1.18.44 never installed: `TecTacResultCheckItem.check` shadowed `Model.check()`, so `manage.py check` stopped every install before migrate.

Two branches:
  1. Django importable: configure minimal settings, load the tec_tac models and assert `run_checks()` returns no Error.
  2. Always (the only branch on a PC without Django): an AST pass over models.py and migration 0048.
"""
import ast
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
SHADOWED = {
    "check", "save", "delete", "clean", "full_clean", "validate_unique", "validate_constraints", "refresh_from_db", "from_db", "pk", "objects",
    "serializable_value", "get_deferred_fields", "prepare_database_save", "date_error_message", "unique_error_message",
}


def must(condition, message):
    if not condition:
        raise AssertionError(message)


def strings(node):
    return [e.value for e in node.elts if isinstance(e, ast.Constant)] if isinstance(node, (ast.Tuple, ast.List)) else None


def fields_kwarg(call):
    for keyword in call.keywords:
        if keyword.arg == "fields":
            return strings(keyword.value)
    return None


def call_name(call):
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


# Branch 1: the real Django system check.
try:
    import django
    HAVE_DJANGO = True
except ImportError:
    HAVE_DJANGO = False
if HAVE_DJANGO:
    from django.conf import settings

    sys.path.insert(0, str(ROOT / "framwork"))
    shim = types.ModuleType("_tectac_system_check_apps")
    from django.apps import AppConfig

    class QuietConfig(AppConfig):  # the real ready() registers capabilities; a model check does not need them
        name = "tec_tac"
        label = "tec_tac"
        default_auto_field = "django.db.models.BigAutoField"

        def ready(self):
            return None

    shim.QuietConfig = QuietConfig
    sys.modules[shim.__name__] = shim
    settings.configure(
        INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth", f"{shim.__name__}.QuietConfig"],
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        USE_TZ=True,
        SECRET_KEY="system-check-only",
    )
    django.setup()
    from django.apps import apps
    from django.core import checks

    errors = [e for e in checks.run_checks(app_configs=[apps.get_app_config("tec_tac")]) if e.level >= checks.ERROR]
    must(not errors, "run_checks() reports errors: " + "; ".join(f"{e.id} {e.msg}" for e in errors))
    must(not any(e.id == "models.E020" for e in errors), "no models.E020")

# Branch 2: AST, always.
models_tree = ast.parse((APP / "models.py").read_bytes().decode("utf-8"))
model_classes = {}
for node in models_tree.body:
    if isinstance(node, ast.ClassDef) and any(isinstance(b, ast.Attribute) and b.attr == "Model" for b in node.bases):
        model_classes[node.name] = node
must(len(model_classes) > 20 and "TecTacResultCheckItem" in model_classes, "models.py parsed: the model classes are found")
for name, cls in model_classes.items():
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute) \
                and isinstance(stmt.value.func.value, ast.Name) and stmt.value.func.value.id == "models":
            for target in stmt.targets:
                must(isinstance(target, ast.Name) and target.id not in SHADOWED, f"{name}.{getattr(target, 'id', '?')} shadows a Django Model attribute (models.E020)")

item = model_classes["TecTacResultCheckItem"]
field_names = [t.id for s in item.body if isinstance(s, ast.Assign) and isinstance(s.value, ast.Call) for t in s.targets if isinstance(t, ast.Name)]
must("result_check" in field_names and "check" not in field_names, f"TecTacResultCheckItem declares result_check and not check: {field_names}")

model_constraint = model_index = None
for cls in item.body:
    if isinstance(cls, ast.ClassDef) and cls.name == "Meta":
        for stmt in cls.body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.List):
                for element in stmt.value.elts:
                    if isinstance(element, ast.Call) and call_name(element) == "UniqueConstraint":
                        model_constraint = fields_kwarg(element)
                    if isinstance(element, ast.Call) and call_name(element) == "Index":
                        model_index = fields_kwarg(element)
must(model_constraint == ["result_check", "endpoint_id"], f"model constraint fields: {model_constraint}")
must(model_index == ["result_check", "state"], f"model index fields: {model_index}")

migration = ast.parse((APP / "migrations" / "0048_result_checks.py").read_text(encoding="utf-8"))
mig_fields = mig_constraint = mig_index = None
for node in ast.walk(migration):
    if isinstance(node, ast.Call) and call_name(node) in ("CreateModel", "AddConstraint", "AddIndex"):
        kw = {k.arg: k.value for k in node.keywords}
        model_name = kw.get("model_name") or kw.get("name")
        if not (isinstance(model_name, ast.Constant) and str(model_name.value).lower() == "tectacresultcheckitem"):
            continue
        if call_name(node) == "CreateModel":
            mig_fields = [e.elts[0].value for e in kw["fields"].elts]
        elif call_name(node) == "AddConstraint":
            mig_constraint = fields_kwarg(kw["constraint"])
        else:
            mig_index = fields_kwarg(kw["index"])
must(mig_fields and "result_check" in mig_fields and "check" not in mig_fields, f"0048 item fields: {mig_fields}")
must(mig_constraint == model_constraint, f"0048 constraint {mig_constraint} agrees with models.py {model_constraint}")
must(mig_index == model_index, f"0048 index {mig_index} agrees with models.py {model_index}")
must(sorted(n for n in mig_fields if n != "id") == sorted(field_names), f"0048 and models.py agree on the item fields: {mig_fields} vs {field_names}")

# No stale `check_id=` lookup on the item remains in the code that uses it.
for name in ("result_checks.py", "result_check_views.py"):
    for number, line in enumerate((APP / name).read_text(encoding="utf-8").splitlines(), 1):
        if "TecTacResultCheckItem" in line and "check_id=" in line.replace("result_check_id=", ""):
            raise AssertionError(f"{name}:{number} uses check_id= on TecTacResultCheckItem")

print("result checks system check 1.18.45 regression: PASS" + ("" if HAVE_DJANGO else " (AST branch only: Django is not installed)"))
