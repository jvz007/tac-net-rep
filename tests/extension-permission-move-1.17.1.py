#!/usr/bin/env python3
"""1.17.1 CQ2 regression: ExtensionRolePermission moved into tec_tac and the tfdreporting POC is retired.

Django is not needed: the migrations are loaded against small recording stubs and their
functions are run against fake schema editors. A real migrate on an upgraded and on an
empty database still has to be run on the dev server.
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
OLD_TABLE = "tfdreporting_extensionrolepermission"


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ---------------------------------------------------------------- (a) the model
tree = ast.parse((APP / "models.py").read_text(encoding="utf-8"))
cls = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ExtensionRolePermission"), None)
must(cls is not None, "models.py does not declare ExtensionRolePermission")
fields = [t.id for n in cls.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name) and t.id not in {"__str__"}]
must(fields == ["role_id", "codename", "granted", "created_at", "updated_at"], f"unexpected fields {fields}")
meta = next(n for n in cls.body if isinstance(n, ast.ClassDef) and n.name == "Meta")
meta_src = ast.unparse(meta)
must(f"db_table = '{OLD_TABLE}'" in meta_src, "Meta.db_table must keep the old table name")
must("tfd_unique_role_permission" in meta_src, "constraint name changed")
must("tfd_role_perm_lookup" in meta_src, "index name changed")
must("ordering = ['role_id', 'codename']" in meta_src, "ordering changed")
must("fields=['role_id', 'codename']" in meta_src, "constraint/index fields changed")
cls_src = ast.unparse(cls)
must("models.ForeignKey(" not in cls_src, "role_id must stay a plain integer (no foreign key)")
must("role_id = models.PositiveIntegerField()" in cls_src, "role_id must be a PositiveIntegerField")


# ---------------------------------------------------------------- migration stubs
class Recorder:
    def __init__(self, *args, **kwargs):
        self.args, self.kwargs = args, kwargs


class RunPython(Recorder):
    noop = staticmethod(lambda *a, **k: None)


class RunSQL(Recorder):
    noop = ":noop:"


class SeparateDatabaseAndState(Recorder):
    pass


class CreateModel(Recorder):
    pass


class AddConstraint(Recorder):
    pass


class AddIndex(Recorder):
    pass


class Migration:
    pass


class _Models(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return type(name, (Recorder,), {})


def load_migration(filename):
    for name in ("django", "django.db", "django.db.migrations", "django.db.models"):
        sys.modules.pop(name, None)
    django = types.ModuleType("django")
    db = types.ModuleType("django.db")
    migrations = types.ModuleType("django.db.migrations")
    migrations.Migration = Migration
    migrations.RunPython = RunPython
    migrations.RunSQL = RunSQL
    migrations.SeparateDatabaseAndState = SeparateDatabaseAndState
    migrations.CreateModel = CreateModel
    migrations.AddConstraint = AddConstraint
    migrations.AddIndex = AddIndex
    models = _Models("django.db.models")
    db.migrations, db.models = migrations, models
    sys.modules.update({"django": django, "django.db": db, "django.db.migrations": migrations, "django.db.models": models})
    spec = importlib.util.spec_from_file_location(f"mig_{filename}", APP / "migrations" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql):
        self.conn.executed.append(sql)
        m = re.search(r"COUNT\(\*\) FROM (\w+)", sql)
        self.rows = [(self.conn.counts.get(m.group(1), 0),)] if m else []

    def fetchone(self):
        return self.rows[0]


class FakeConnection:
    def __init__(self, tables, counts=None):
        self.tables, self.counts, self.executed = list(tables), counts or {}, []
        self.introspection = types.SimpleNamespace(table_names=lambda cursor: list(self.tables))

    def cursor(self):
        return FakeCursor(self)


class FakeSchemaEditor:
    def __init__(self, tables, counts=None):
        self.connection = FakeConnection(tables, counts)
        self.created, self.deleted = [], []

    def create_model(self, model):
        self.created.append(model)

    def delete_model(self, model):
        self.deleted.append(model)


class FakeApps:
    def __init__(self, model):
        self.model = model

    def get_model(self, app, name):
        must((app, name) == ("tec_tac", "ExtensionRolePermission"), f"unexpected model {app}.{name}")
        return self.model


# ---------------------------------------------------------------- (b) migration 0023
m23 = load_migration("0023_extension_role_permission.py")
ops = m23.Migration.operations
must(m23.Migration.dependencies == [("tec_tac", "0022_runtime_config")], "0023 must follow 0022")
must(len(ops) == 2, f"0023 must have exactly two operations, has {len(ops)}")
sep, run = ops
must(isinstance(sep, SeparateDatabaseAndState), "0023 operation 1 must be SeparateDatabaseAndState")
must(not sep.kwargs.get("database_operations"), "0023 must change no database objects in operation 1")
state_ops = sep.kwargs["state_operations"]
must(isinstance(state_ops[0], CreateModel), "state operation 1 must be CreateModel")
must(state_ops[0].kwargs["options"] == {"ordering": ["role_id", "codename"], "db_table": OLD_TABLE}, "state options differ from the old model")
must([f[0] for f in state_ops[0].kwargs["fields"]] == ["id", "role_id", "codename", "granted", "created_at", "updated_at"], "state field list differs from old 0002")
must(isinstance(state_ops[1], AddConstraint) and state_ops[1].kwargs["constraint"].kwargs["name"] == "tfd_unique_role_permission", "constraint state missing")
must(isinstance(state_ops[2], AddIndex) and state_ops[2].kwargs["index"].kwargs["name"] == "tfd_role_perm_lookup", "index state missing")
must(isinstance(run, RunPython), "0023 operation 2 must be a separate RunPython (it must see the new model state)")
must(run.args[0] is m23.create_if_missing and run.args[1] is m23.drop_table, "RunPython must pair create_if_missing with drop_table")

model = types.SimpleNamespace(_meta=types.SimpleNamespace(db_table=OLD_TABLE))
upgraded = FakeSchemaEditor([OLD_TABLE, "other"])
m23.create_if_missing(FakeApps(model), upgraded)
must(upgraded.created == [], "an upgraded server already has the table; it must not be created again")
fresh = FakeSchemaEditor(["other"])
m23.create_if_missing(FakeApps(model), fresh)
must(fresh.created == [model], "a fresh install must create the table")
back = FakeSchemaEditor([OLD_TABLE])
m23.drop_table(FakeApps(model), back)
must(back.deleted == [model], "reverse must drop the table")
none = FakeSchemaEditor([])
m23.drop_table(FakeApps(model), none)
must(none.deleted == [], "reverse must not fail when the table is already gone")

# ---------------------------------------------------------------- (c) migration 0024
m24 = load_migration("0024_retire_tfdreporting_poc.py")
must(m24.Migration.dependencies == [("tec_tac", "0023_extension_role_permission")], "0024 must follow 0023")
py, sql = m24.Migration.operations
must(isinstance(py, RunPython) and isinstance(sql, RunSQL), "0024 must be RunPython then RunSQL")
must(sql.kwargs["sql"] == "DROP TABLE IF EXISTS tfdreporting_networkavailability", f"0024 SQL drops the wrong thing: {sql.kwargs['sql']}")
must(sql.kwargs["reverse_sql"] == RunSQL.noop, "0024 is irreversible by design: the reverse must be a no-op")
must(py.args[1] is RunPython.noop, "0024 data step reverse must be a no-op")


class Filtered:
    def __init__(self, log):
        self.log = log

    def filter(self, **kwargs):
        self.log.append(kwargs)
        return types.SimpleNamespace(delete=lambda: self.log.append("deleted"))


log = []
perm_model = types.SimpleNamespace(objects=Filtered(log))
editor = FakeSchemaEditor(["tfdreporting_networkavailability"], {"tfdreporting_networkavailability": 7})
out = io.StringIO()
with contextlib.redirect_stdout(out):
    py.args[0](FakeApps(perm_model), editor)
must("rows dropped: 7" in out.getvalue(), f"0024 must print the number of network rows dropped, printed {out.getvalue()!r}")
must(log == [{"codename__startswith": "tfdreporting."}, "deleted"], f"0024 must delete only tfdreporting.* codenames: {log}")
must(all("DROP" not in s for s in editor.connection.executed), "the data step must not drop anything; the RunSQL does")
out = io.StringIO()
with contextlib.redirect_stdout(out):
    py.args[0](FakeApps(types.SimpleNamespace(objects=Filtered([]))), FakeSchemaEditor([]))
must("rows dropped: 0" in out.getvalue(), "0024 must cope with the table already being gone")

# ---------------------------------------------------------------- (d) nothing else names tfdreporting
allowed = {
    (APP / "models.py").resolve(): "models.py: only the db_table string",
    (APP / "migrations" / "0023_extension_role_permission.py").resolve(): "0023: only the table name",
    (APP / "migrations" / "0024_retire_tfdreporting_poc.py").resolve(): "0024",
    (APP / "migrations" / "0025_runtime_update_sources.py").resolve(): "0025: only the dependency line",
}
scan = [ROOT / "install.sh", ROOT / "uninstall.sh", *(ROOT / "scripts").rglob("*"), *(ROOT / "framwork").rglob("*")]
pattern = re.compile(r"tfdreporting|legacy-reporting|reporting-permission|network-availability|NetworkAvailability")
for path in scan:
    if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    resolved = path.resolve()
    if resolved in allowed:
        if resolved.name == "models.py":
            for line in text.splitlines():
                if pattern.search(line):
                    must(OLD_TABLE in line and "db_table" in line, f"models.py names the old app outside db_table: {line.strip()}")
        elif resolved.name.startswith("0023"):
            for line in text.splitlines():
                if pattern.search(line):
                    must(OLD_TABLE in line, f"0023 names the old app outside the table name: {line.strip()}")
        elif resolved.name.startswith("0025"):
            for line in text.splitlines():
                if pattern.search(line):
                    must('("tec_tac", "0024_retire_tfdreporting_poc")' in line, f"0025 names the old app outside its dependency line: {line.strip()}")
        continue
    for line in text.splitlines():
        hit = pattern.search(line)
        if hit and path.name == "install.sh":
            # The installer may check the table name, and nothing else of the old app.
            must(OLD_TABLE in line and "tfdreporting." not in line and "import tfdreporting" not in line, f"install.sh still names {hit.group(0)}")
        else:
            must(hit is None, f"{path.relative_to(ROOT)} still names {hit.group(0) if hit else ''}")

must(not (ROOT / "extensions" / "reporting").exists(), "extensions/reporting must be deleted")
must(not (ROOT / "scripts" / "reporting-permission.sh").exists(), "scripts/reporting-permission.sh must be deleted")
for name in ("network-reporting-api.sh", "network-reporting-server.sh"):
    must(not (ROOT / "tests" / name).exists(), f"tests/{name} must be deleted")
must("network-reporting" not in (ROOT / "tests" / "lifecycle.sh").read_text(encoding="utf-8"), "lifecycle.sh still calls a deleted test")

# ---------------------------------------------------------------- (e) imports
for name in ("rbac.py", "module_identity.py"):
    text = (APP / name).read_text(encoding="utf-8")
    must("from .models import ExtensionRolePermission" in text, f"{name} must import the model from .models")
for script in ("install-extension.sh", "remove-extension.sh"):
    text = (ROOT / "scripts" / script).read_text(encoding="utf-8")
    must("from tec_tac.models import ExtensionRolePermission" in text, f"{script} must import the model from tec_tac.models")
rbac_tree = ast.parse((APP / "rbac.py").read_text(encoding="utf-8"))
public = {n.name for n in rbac_tree.body if isinstance(n, ast.FunctionDef)}
must({"has_extension_permission", "effective_permissions", "registered_permissions", "set_extension_permission"} <= public, "rbac public functions changed")

# ---------------------------------------------------------------- (f) registry has no legacy plugin
reg_text = (APP / "registry.py").read_text(encoding="utf-8")
must("legacy_plugins" not in reg_text, "legacy_plugins must be deleted")
spec = importlib.util.spec_from_file_location("registry_under_test", APP / "registry.py")
registry = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = registry
spec.loader.exec_module(registry)
plugins = registry.get_plugins()
must(not any(p.legacy or p.plugin_type == "legacy" or p.plugin_id == "legacy-reporting-poc" for p in plugins), "get_plugins still returns a legacy plugin")
must(any(p.plugin_id == "example" for p in plugins), "get_plugins lost the example plugin")

# ---------------------------------------------------------------- (g) protected ids
mm = ast.parse((APP / "module_manager.py").read_text(encoding="utf-8"))
node = next(n for n in mm.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "PROTECTED_PLUGIN_IDS" for t in n.targets))
ids = ast.literal_eval(node.value.args[0])
must(ids == {"example"}, f"PROTECTED_PLUGIN_IDS should be only example, is {ids}")

# ---------------------------------------------------------------- installers
install = (ROOT / "install.sh").read_text(encoding="utf-8")
must("migrate tec_tac --noinput" in install, "install.sh must still migrate tec_tac")
must("ExtensionRolePermission" in install and OLD_TABLE in install, "install.sh must verify tec_tac.ExtensionRolePermission and its db_table")
must("runtime_settings.py" in install and "/api/tfd/system/runtime-settings/" in install, "install.sh must list runtime_settings.py and verify its route")
uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
must("migrate tec_tac 0022_runtime_config" in uninstall and "0023_extension_role_permission" in uninstall, "uninstall --purge-data must roll tec_tac back to 0022 only when 0023 is applied")
helper = (ROOT / "scripts" / "system-update-helper.py").read_text(encoding="utf-8")
must('("extensions", "reporting")' in helper, "system-update-helper must be left unchanged (root-run, rollback-sensitive)")

print("[TEST] PASS 1.17.1 ExtensionRolePermission moved into tec_tac and the tfdreporting POC is retired")
