#!/usr/bin/env python3
"""1.17.35: every Tactical UI preference a person can save through Core (GET and PUT /api/tfd/account/tactical-ui/).

Modelled on tests/my-account-features-1.15.167.py: the real account_self_service functions run with narrow Django stubs and a fake user
table. The table is a store, so a PUT that fails is checked against what is stored, not only against the exception. Covered: every new
field round-trips; each invalid value (a non-bool, an unknown choice, splitter 0, 100 and a string, a colour with a semicolon, a quote or
more than 40 characters, a date_format over 30 characters or with a brace or an angle bracket) raises and changes nothing, also in a mixed
payload (all or nothing); block_dashboard_login and an unknown key are refused; the two-field payload of 1.15.167 still works; the audit
row holds field names and no values; an empty date_format stores null; the hot-path context keeps its three keys and adds the scalars.
Django is not installed on this PC, so the choices come from stub fields that carry Tactical's own choice values (tacticalrmm/constants.py).
"""
from __future__ import annotations

import importlib
import json
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------------------------------------ stubs (the same narrow set as 1.15.167)
pyotp_mod = types.ModuleType("pyotp")
pyotp_mod.TOTP = lambda secret: types.SimpleNamespace(now=lambda: "123456", verify=lambda token, valid_window=0: str(token) == "123456")
pyotp_mod.random_base32 = lambda: "JBSWY3DPEHPK3PXP"
sys.modules["pyotp"] = pyotp_mod

django_auth = types.ModuleType("django.contrib.auth")
django_validation = types.ModuleType("django.contrib.auth.password_validation")
django_ex = types.ModuleType("django.core.exceptions")
django_db = types.ModuleType("django.db")


class ValidationError(Exception):
    pass


django_ex.ValidationError = ValidationError
django_validation.validate_password = lambda value, user=None: None


class Atomic:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


django_db.transaction = types.SimpleNamespace(atomic=lambda: Atomic())
sys.modules["django.contrib.auth"] = django_auth
sys.modules["django.contrib.auth.password_validation"] = django_validation
sys.modules["django.core.exceptions"] = django_ex
sys.modules["django.db"] = django_db

mfa = types.ModuleType("tec_tac.mfa_backup")
mfa.invalidate_backup_codes = lambda user, **kwargs: {"invalidated": 0}
sys.modules["tec_tac.mfa_backup"] = mfa
sess = types.ModuleType("tec_tac.session_security")


class SessionSecurityError(Exception):
    pass


sess.SessionSecurityError = SessionSecurityError
AUDITS: list = []
sess._audit = lambda event, **kwargs: AUDITS.append((event, kwargs))
sess.revoke_user_sessions = lambda username, **kwargs: {"revoked": 0, "session_ids": []}
sys.modules["tec_tac.session_security"] = sess


# ------------------------------------------------------------------------------------------------ the fake Tactical model
class Field:
    def __init__(self, choices):
        self.choices = choices


TAB_CHOICES = [("server", "Servers"), ("workstation", "Workstations"), ("mixed", "Mixed")]  # tacticalrmm/constants.py AgentTableTabs
SORT_CHOICES = [("alphafail", "Move failing clients to the top"), ("alpha", "Sort alphabetically")]  # ClientTreeSort
DBL_CHOICES = [("editagent", "Edit Agent"), ("takecontrol", "Take Control"), ("remotebg", "Remote Background"), ("urlaction", "URL Action")]
FIELDS = {
    "agent_dblclick_action": Field(DBL_CHOICES), "default_agent_tbl_tab": Field(TAB_CHOICES), "client_tree_sort": Field(SORT_CHOICES),
}


class UrlActionModel:
    class _Query:
        def __init__(self, rows):
            self.rows = rows

        def order_by(self, *args):
            return self

        def values(self, *fields):
            return [{f: r[f] for f in fields} for r in self.rows]

        def filter(self, **kwargs):
            return UrlActionModel._Query([r for r in self.rows if r["id"] == kwargs.get("pk")])

        def exists(self):
            return bool(self.rows)

    objects = _Query([{"id": 7, "name": "Open Portal"}, {"id": 8, "name": "Ticket"}])


class Meta:
    def get_field(self, name):
        if name == "url_action":
            return types.SimpleNamespace(remote_field=types.SimpleNamespace(model=UrlActionModel))
        return FIELDS[name]


DEFAULTS = {
    "pk": 1, "username": "alice", "is_superuser": False, "is_sso_user": False, "password": "x",
    "role": types.SimpleNamespace(is_superuser=False, can_run_urlactions=True),
    "agent_dblclick_action": "editagent", "url_action_id": None,
    "dark_mode": True, "show_community_scripts": True, "default_agent_tbl_tab": "mixed", "client_tree_sort": "alphafail",
    "client_tree_splitter": 11, "loading_bar_color": "red", "dash_info_color": "info", "dash_positive_color": "positive",
    "dash_negative_color": "negative", "dash_warning_color": "warning", "clear_search_when_switching": True, "date_format": None,
}
STORE: dict = {1: dict(DEFAULTS)}
SAVES: list = []


class User:
    _meta = Meta()

    def __init__(self, **values):
        self.__dict__.update(values)

    def save(self, update_fields=None):
        SAVES.append(tuple(update_fields or ()))
        STORE[self.pk] = {k: v for k, v in self.__dict__.items()}


class UserManager:
    def select_for_update(self):
        return self

    def get(self, pk):
        return User(**STORE[pk])  # a copy, as a row lock returns: a failed PUT changes nothing stored


User.objects = UserManager()
django_auth.get_user_model = lambda: User

mod = importlib.import_module("tec_tac.account_self_service")
Error = mod.AccountSelfServiceError


def me():
    return User(**STORE[1])


def stored():
    return dict(STORE[1])


def reset():
    STORE[1] = dict(DEFAULTS)
    SAVES.clear()
    AUDITS.clear()


# ------------------------------------------------------------------------------------------------ 1. every new field round-trips
reset()
good = {
    "dark_mode": False, "show_community_scripts": False, "default_agent_tbl_tab": "server", "client_tree_sort": "alpha",
    "client_tree_splitter": 50, "loading_bar_color": "deep-purple-3", "dash_info_color": "#abc", "dash_positive_color": "#12345678",
    "dash_negative_color": "red", "dash_warning_color": "#1234", "clear_search_when_switching": False, "date_format": "DD/MM/YYYY HH:mm",
}
prefs = mod.update_tactical_ui_preferences(me(), good)
for name, value in good.items():
    must(stored()[name] == value, f"{name} is stored as {value!r}: {stored()[name]!r}")
    must(prefs[name] == value, f"{name} is in the answer")
must([c["value"] for c in prefs["default_agent_tbl_choices"]] == ["server", "workstation", "mixed"], "the tab choices come from the model")
must([c["value"] for c in prefs["client_tree_sort_choices"]] == ["alphafail", "alpha"], "the sort choices come from the model")
must([c["value"] for c in prefs["agent_dblclick_choices"]] == ["editagent", "takecontrol", "remotebg", "urlaction"], "double-click choices unchanged")
got = mod.tactical_ui_preferences(me())
must(all(got[name] == value for name, value in good.items()), "GET returns every value")
must(len(SAVES) == 1 and set(SAVES[0]) == set(good), f"one save with exactly the fields sent: {SAVES}")

# the limits that must pass
for splitter in (1, 99):
    reset()
    mod.update_tactical_ui_preferences(me(), {"client_tree_splitter": splitter})
    must(stored()["client_tree_splitter"] == splitter, f"splitter {splitter} is allowed")
for colour in ("red", "deep-purple-3", "#fff", "#ffff", "#a1b2c3", "#a1b2c3d4", "grey-10"):
    reset()
    mod.update_tactical_ui_preferences(me(), {"loading_bar_color": colour})
    must(stored()["loading_bar_color"] == colour, f"colour {colour} is allowed")
reset()
mod.update_tactical_ui_preferences(me(), {"date_format": "D" * 30})
must(stored()["date_format"] == "D" * 30, "a 30 character date format is allowed")

# ------------------------------------------------------------------------------------------------ 2. invalid values raise and change nothing
BAD = [
    ("dark_mode", "false"), ("dark_mode", 1), ("show_community_scripts", None), ("clear_search_when_switching", "true"),
    ("default_agent_tbl_tab", "desktop"), ("default_agent_tbl_tab", None), ("client_tree_sort", "beta"), ("client_tree_sort", 1),
    ("client_tree_splitter", 0), ("client_tree_splitter", 100), ("client_tree_splitter", "20"), ("client_tree_splitter", True),
    ("client_tree_splitter", 20.0),
    ("loading_bar_color", "red;"), ("dash_info_color", "red'"), ("dash_positive_color", "a" * 41), ("dash_negative_color", "#12"),
    ("dash_warning_color", "#12345"), ("dash_warning_color", "#ggg"), ("loading_bar_color", 'red"'), ("loading_bar_color", "red black"),
    ("date_format", "D" * 31), ("date_format", "DD {x}"), ("date_format", "DD<x>"), ("date_format", 5), ("date_format", "DD;"),
]
for name, value in BAD:
    reset()
    before = stored()
    try:
        mod.update_tactical_ui_preferences(me(), {"dark_mode": False, name: value})  # a valid field first: all or nothing
    except Error:
        pass
    else:
        raise AssertionError(f"{name}={value!r} was accepted")
    must(stored() == before and not SAVES and not AUDITS, f"{name}={value!r} changed nothing")

# ------------------------------------------------------------------------------------------------ 3. refusals
for payload in ({"block_dashboard_login": True}, {"no_such_field": 1}, {"dark_mode": False, "block_dashboard_login": False}):
    reset()
    before = stored()
    try:
        mod.update_tactical_ui_preferences(me(), payload)
    except Error as exc:
        must("Unknown Tactical UI preference" in str(exc), str(exc))
    else:
        raise AssertionError(f"{payload} was accepted")
    must(stored() == before and not SAVES, "a refused unknown field changes nothing")
must("block_dashboard_login" not in mod.TACTICAL_UI_SCALAR_FIELDS, "block_dashboard_login is not a UI preference here")

# ------------------------------------------------------------------------------------------------ 4. the 1.15.167 two-field payload is unchanged
reset()
prefs = mod.update_tactical_ui_preferences(me(), {"agent_dblclick_action": "takecontrol", "url_action_id": 8})
must(stored()["agent_dblclick_action"] == "takecontrol" and stored()["url_action_id"] == 8, "the two old fields still save")
must(SAVES[-1] == ("agent_dblclick_action", "url_action") and prefs["url_action_id"] == 8, "and only those two columns are written")
reset()
try:
    mod.update_tactical_ui_preferences(me(), {"agent_dblclick_action": "urlaction", "url_action_id": "x"})
except Error:
    pass
else:
    raise AssertionError("an invalid URL Action id is refused")
must(stored() == DEFAULTS, "and nothing changed")
reset()
mod.update_tactical_ui_preferences(me(), {"url_action_id": None})
must(stored()["url_action_id"] is None and SAVES[-1] == ("url_action",), "clearing the URL Action still works")

# ------------------------------------------------------------------------------------------------ 5. empty date_format stores null
reset()
STORE[1]["date_format"] = "DD/MM"
mod.update_tactical_ui_preferences(me(), {"date_format": ""})
must(stored()["date_format"] is None, "an empty date_format stores null")
STORE[1]["date_format"] = "DD/MM"
mod.update_tactical_ui_preferences(me(), {"date_format": None})
must(stored()["date_format"] is None, "a null date_format stores null")

# ------------------------------------------------------------------------------------------------ 6. the audit row holds names, never values
reset()
mod.update_tactical_ui_preferences(me(), {"dark_mode": False, "date_format": "DD/MM/YYYY HH:mm", "client_tree_sort": "alpha"})
event, kwargs = AUDITS[-1]
must(event == "self_tactical_ui_preferences_changed", event)
meta = kwargs["metadata"]
must(meta == {"fields": ["client_tree_sort", "dark_mode", "date_format"]}, f"audit metadata holds field names only, sorted: {meta}")
must("DD/MM/YYYY" not in json.dumps(meta) and "alpha" not in json.dumps(meta), "no value in the audit row")

# ------------------------------------------------------------------------------------------------ 7. the hot-path context
reset()
mod.update_tactical_ui_preferences(me(), {"client_tree_splitter": 30, "date_format": "YYYY"})
ctx = mod.tactical_ui_context(me())
must({"agent_dblclick_action", "url_action_id", "can_run_url_actions"} <= set(ctx), "the three existing keys stay")
must(ctx["client_tree_splitter"] == 30 and ctx["date_format"] == "YYYY" and ctx["dark_mode"] is True, "the scalars are added")
must("default_agent_tbl_choices" not in ctx and "url_actions" not in ctx and "client_tree_sort_choices" not in ctx,
     "no choice list or catalogue on the hot path")
must(set(ctx) == {"agent_dblclick_action", "url_action_id", "can_run_url_actions"} | set(mod.TACTICAL_UI_SCALAR_FIELDS), sorted(ctx))

# ------------------------------------------------------------------------------------------------ 8. a non-object payload and an empty one
for payload in (["dark_mode"], "dark_mode"):
    try:
        mod.update_tactical_ui_preferences(me(), payload)
    except Error:
        pass
    else:
        raise AssertionError("a non-object payload is refused")
reset()
mod.update_tactical_ui_preferences(me(), {})
must(not SAVES, "an empty payload saves nothing")

print("[TEST] PASS tactical UI preferences 1.17.35")
