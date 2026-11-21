#!/usr/bin/env python3
"""Regression: Core 1.18.32 gives the Communicator service user the historical model's own defaults (dark_mode, agents_per_page ...) in the raw INSERT of
migration 0038, as Django's create() did. Columns the model does not know keep the neutral value. Django is stubbed; sqlite stands in for the tables."""
import datetime
import importlib.util
import json
import sqlite3
import sys
import types
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
MIG = ROOT / "framwork" / "tec_tac" / "migrations"

django = types.ModuleType("django")
db = types.ModuleType("django.db")
db.migrations = SimpleNamespace(Migration=object, RunPython=type("RunPython", (), {"noop": None, "__init__": lambda self, *a: None}))
db.transaction = SimpleNamespace(atomic=lambda **kw: SimpleNamespace(__enter__=lambda s: None, __exit__=lambda s, *a: False))
utils = types.ModuleType("django.utils")
utils.timezone = SimpleNamespace(now=lambda: datetime.datetime(2026, 11, 21, 10, 0, 0, tzinfo=datetime.UTC))
for name, mod in (("django", django), ("django.db", db), ("django.utils", utils)):
    sys.modules[name] = mod
django.db, django.utils = db, utils
spec = importlib.util.spec_from_file_location("mig0038", MIG / "0038_communicator_service_user.py")
mig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mig)

KIND = {"INTEGER": "IntegerField", "BOOL": "BooleanField", "VARCHAR": "CharField", "DATETIME": "DateTimeField", "JSON": "JSONField"}


class Conn:
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


NO_DEFAULT = object()


class Field:
    """The slice of a Django field the migration uses."""
    def __init__(self, column, default=NO_DEFAULT):
        self.column, self._default = column, default

    def has_default(self):
        return self._default is not NO_DEFAULT

    def get_default(self):
        return self._default() if callable(self._default) else self._default

    def get_db_prep_save(self, value, connection):
        return json.dumps(value) if isinstance(value, dict) else value


def model(table, fields=None, pk="id"):
    meta = SimpleNamespace(db_table=table, pk=SimpleNamespace(column=pk))
    if fields is not None:
        meta.concrete_fields = [Field(pk)] + fields
    return SimpleNamespace(_meta=meta)


raw = sqlite3.connect(":memory:")
raw.row_factory = sqlite3.Row
raw.execute("CREATE TABLE accounts_role (id INTEGER PRIMARY KEY, name VARCHAR NOT NULL, can_send_cmd BOOL NOT NULL, can_reboot BOOL NOT NULL, "
            "can_flag_true_default BOOL NOT NULL, can_new_in_1_6_1 BOOL NOT NULL)")
raw.execute("CREATE TABLE accounts_user (id INTEGER PRIMARY KEY, username VARCHAR NOT NULL, email VARCHAR NOT NULL, password VARCHAR NOT NULL, "
            "is_active BOOL NOT NULL, is_superuser BOOL NOT NULL, is_staff BOOL NOT NULL, block_dashboard_login BOOL NOT NULL, role_id INTEGER, "
            "dark_mode BOOL NOT NULL, show_community_scripts BOOL NOT NULL, agents_per_page INTEGER NOT NULL, client_tree_splitter INTEGER NOT NULL, "
            "loading_bar_color VARCHAR NOT NULL, agent_dblclick_action VARCHAR NOT NULL, default_agent_tbl_tab VARCHAR NOT NULL, "
            "agent_tbl_tabs JSON NOT NULL, new_flag_1_6_1 BOOL NOT NULL, new_count INTEGER NOT NULL, new_text VARCHAR NOT NULL)")
conn = Conn(raw)
editor = SimpleNamespace(connection=conn)

role_model = model("accounts_role", [Field("name"), Field("can_send_cmd", False), Field("can_reboot", False), Field("can_flag_true_default", True)])
user_model = model("accounts_user", [
    Field("username"), Field("is_active", True), Field("is_superuser", False), Field("block_dashboard_login", False),
    Field("dark_mode", True), Field("show_community_scripts", True), Field("agents_per_page", 50), Field("client_tree_splitter", 11),
    Field("loading_bar_color", "red"), Field("agent_dblclick_action", "editagent"), Field("default_agent_tbl_tab", "server"),
    Field("agent_tbl_tabs", lambda: {"a": 1}),
])

mig._insert(editor, role_model, {"name": mig.ROLE, mig.FLAG: True}, True)
mig._insert(editor, user_model, {"username": mig.USERNAME, "email": "", "password": "!", "is_active": True, "is_superuser": False,
                                  "is_staff": False, "block_dashboard_login": True, "role_id": 1}, False)

role = dict(raw.execute("SELECT * FROM accounts_role").fetchone())
assert role["name"] == mig.ROLE and role["can_send_cmd"] == 1, role
assert [k for k, v in role.items() if k.startswith("can_") and v] == ["can_send_cmd"], f"model default true must not leak into the role: {role!r}"
user = dict(raw.execute("SELECT * FROM accounts_user").fetchone())
assert user["dark_mode"] == 1 and user["show_community_scripts"] == 1, user
assert user["agents_per_page"] == 50 and user["client_tree_splitter"] == 11, user
assert user["loading_bar_color"] == "red" and user["agent_dblclick_action"] == "editagent" and user["default_agent_tbl_tab"] == "server", user
assert json.loads(user["agent_tbl_tabs"]) == {"a": 1}, "a callable default is evaluated"
# the model does not know these (Tactical 1.6.1 columns): neutral values
assert user["new_flag_1_6_1"] == 0 and user["new_count"] == 0 and user["new_text"] == "", user
# passed values win over model defaults
assert user["block_dashboard_login"] == 1 and user["role_id"] == 1 and user["username"] == mig.USERNAME and user["is_active"] == 1, user

# _insert is one row per call; the existence checks of _make keep a second run from inserting again
assert raw.execute("SELECT COUNT(*) FROM accounts_role").fetchone()[0] == 1 and raw.execute("SELECT COUNT(*) FROM accounts_user").fetchone()[0] == 1

# a model stub without concrete_fields still works (no defaults, neutral values as in 1.18.31)
raw.execute("DELETE FROM accounts_user")
mig._insert(editor, model("accounts_user"), {"username": "plain", "email": "", "password": "!", "is_active": True, "is_superuser": False,
                                              "is_staff": False, "block_dashboard_login": True, "role_id": 1}, False)
plain = dict(raw.execute("SELECT * FROM accounts_user").fetchone())
assert plain["agents_per_page"] == 0 and plain["dark_mode"] == 0 and plain["loading_bar_color"] == "", plain

# the pure function: model default beats neutral, force_bool_false beats model default, known beats both
now = datetime.datetime(2026, 11, 21, tzinfo=datetime.UTC)
cols = [("id", "AutoField", False, False, True), ("a", "IntegerField", False, False, False), ("b", "BooleanField", False, False, False), ("c", "IntegerField", False, False, False)]
assert mig._row_values(cols, {"c": 9}, False, now, {"a": 5, "b": True, "c": 1}) == {"a": 5, "b": True, "c": 9}
assert mig._row_values(cols, {}, True, now, {"a": 5, "b": True}) == {"a": 5, "b": False, "c": 0}
assert mig._row_values(cols, {}, False, now) == {"a": 0, "b": False, "c": 0}

for name in ("0038_communicator_service_user.py", "0045_communicator_service_user_retry.py"):
    assert b"\r" not in (MIG / name).read_bytes(), name
assert b"\r" not in Path(__file__).read_bytes()
print("communicator service user defaults 1.18.32 regression: PASS")
