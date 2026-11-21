#!/usr/bin/env python3
"""Regression: Core 1.18.31 creates the Communicator service user from the live accounts columns (Tactical 1.6.1 adds NOT NULL booleans without a
database default after accounts 0042). Django is not needed: it is stubbed and a real sqlite table stands in for accounts_role and accounts_user."""
import ast
import datetime
import importlib.util
import sqlite3
import sys
import types
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
MIG = ROOT / "framwork" / "tec_tac" / "migrations"

# --- stub the few Django names the migration imports
django = types.ModuleType("django")
db = types.ModuleType("django.db")
db.migrations = SimpleNamespace(Migration=object, RunPython=type('RunPython', (), {'noop': None, '__init__': lambda self, *a: None}))
db.transaction = SimpleNamespace(atomic=lambda **kw: SimpleNamespace(__enter__=lambda s: None, __exit__=lambda s, *a: False))
utils = types.ModuleType("django.utils")
utils.timezone = SimpleNamespace(now=lambda: datetime.datetime(2026, 11, 21, 10, 0, 0, tzinfo=datetime.UTC))
for name, mod in (("django", django), ("django.db", db), ("django.utils", utils)):
    sys.modules[name] = mod
django.db, django.utils = db, utils
spec = importlib.util.spec_from_file_location("mig0038", MIG / "0038_communicator_service_user.py")
mig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mig)

KIND = {"INTEGER": "IntegerField", "BOOL": "BooleanField", "VARCHAR": "CharField", "DATETIME": "DateTimeField"}


class Conn:
    """The slice of a Django connection the migration uses, over sqlite."""
    def __init__(self, raw):
        self.raw = raw
        self.introspection = SimpleNamespace(get_table_description=self._desc, get_field_type=lambda code, d: KIND[code])
        self.ops = SimpleNamespace(quote_name=lambda n: f'"{n}"')

    def _desc(self, cursor, table):
        return [SimpleNamespace(name=r[1], type_code=r[2], null_ok=not r[3], default=r[4]) for r in self.raw.execute(f'PRAGMA table_info("{table}")')]

    def cursor(self):
        raw = self.raw

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, params=()):
                raw.execute(sql.replace("%s", "?"), params)
        return Cur()


def model(table, pk="id"):
    return SimpleNamespace(_meta=SimpleNamespace(db_table=table, pk=SimpleNamespace(column=pk)))


raw = sqlite3.connect(":memory:")
# accounts 0042 columns plus 1.6.1 additions: NOT NULL booleans and an integer, none with a database default (Django defaults are app-level).
raw.execute("CREATE TABLE accounts_role (id INTEGER PRIMARY KEY, name VARCHAR NOT NULL, can_send_cmd BOOL NOT NULL, can_reboot BOOL NOT NULL, "
            "can_new_in_1_6_1 BOOL NOT NULL, can_default_true BOOL NOT NULL DEFAULT 1, notes VARCHAR)")
raw.execute("CREATE TABLE accounts_user (id INTEGER PRIMARY KEY, username VARCHAR NOT NULL, email VARCHAR NOT NULL, password VARCHAR NOT NULL, "
            "is_active BOOL NOT NULL, is_superuser BOOL NOT NULL, is_staff BOOL NOT NULL, block_dashboard_login BOOL NOT NULL, role_id INTEGER, "
            "new_flag_1_6_1 BOOL NOT NULL, new_count INTEGER NOT NULL, date_joined DATETIME NOT NULL, last_name VARCHAR NOT NULL)")
conn = Conn(raw)
editor = SimpleNamespace(connection=conn)

mig._insert(editor, model("accounts_role"), {"name": mig.ROLE, mig.FLAG: True}, True)
mig._insert(editor, model("accounts_user"), {"username": mig.USERNAME, "email": "", "password": "!", "is_active": True, "is_superuser": False,
                                              "is_staff": False, "block_dashboard_login": True, "role_id": 1}, False)
raw.row_factory = sqlite3.Row
role = dict(raw.execute("SELECT * FROM accounts_role").fetchone())
assert role["name"] == mig.ROLE and role["can_send_cmd"] == 1, role
assert [k for k, v in role.items() if k.startswith("can_") and v] == ["can_send_cmd"], f"can_send_cmd is the only true flag (a true database default is overridden): {role!r}"
user = dict(raw.execute("SELECT * FROM accounts_user").fetchone())
assert user["username"] == mig.USERNAME and user["new_flag_1_6_1"] == 0 and user["new_count"] == 0 and user["last_name"] == "" and user["block_dashboard_login"] == 1, user
assert user["is_superuser"] == 0 and user["is_staff"] == 0 and user["role_id"] == 1, user

# the old way fails on this schema (documents the fault this release fixes)
try:
    raw.execute("INSERT INTO accounts_role (name, can_send_cmd, can_reboot) VALUES ('x', 1, 0)")
    raise AssertionError("expected a NOT NULL failure")
except sqlite3.IntegrityError:
    pass

# unknown NOT NULL column kind is refused (logged by create_service_user), never guessed
try:
    mig._row_values([("weird", "BinaryField", False, False, False)], {}, False, datetime.datetime.now(tz=datetime.UTC))
    raise AssertionError("expected ValueError")
except ValueError:
    pass

# 0045 retries idempotently, on top of 0044, with the same pin and no floating dependency
tree = ast.parse((MIG / "0045_communicator_service_user_retry.py").read_text(encoding="utf-8"))
text = (MIG / "0045_communicator_service_user_retry.py").read_text(encoding="utf-8")
assert '("tec_tac", "0044_core_secret")' in text and '("accounts", "0042_copy_mesh_permission_to_terminal")' in text and "__latest__" not in text
assert "create_service_user" in text and b"\r" not in (MIG / "0045_communicator_service_user_retry.py").read_bytes()
src = (MIG / "0038_communicator_service_user.py").read_text(encoding="utf-8")
assert "Role.objects.using(db).create" not in src and "User.objects.using(db).create" not in src, "no create() through the historical model"
print("communicator service user 1.18.31 regression: PASS")
