#!/usr/bin/env python3
"""1.17.24 regression: the session theme choice, Core side (CO9, C5).

A theme chosen in the dropdown is held for the signed-in session only: never written to the saved preference, and it dies with the
session. Django is not installed on the development PC, so the real session_security.py and session_security_views.py run against
the stubs of tests/session-revoke-all-1.17.24.py, and the migration is checked with ast. The real migration 0028 and the three calls
run on the dev server with tests/session-theme-runtime-1.17.24.py.
"""
from __future__ import annotations

import ast
import pathlib
import types

_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "session-revoke-all-1.17.24.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index('ss = load("session_security")')], str(_here / "session-revoke-all-1.17.24.py"), "exec"), globals())
H = globals()
must, load, APP, ROOT = H["must"], H["load"], H["APP"], H["ROOT"]

# the real list of themes, read from preferences.py without importing Django models
_prefs_tree = ast.parse((APP / "preferences.py").read_text(encoding="utf-8"))
THEMES = next(ast.literal_eval(n.value) for n in _prefs_tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "THEMES" for t in n.targets))
must(THEMES == {"dark", "light", "high-contrast"}, THEMES)
H["mod"]("tec_tac.preferences", THEMES=THEMES)

ROWS_BY_ID: dict = {}


class Row:
    def __init__(self, id, username, theme="", revoked=False):
        self.id = self.pk = id
        self.username, self.session_theme, self.revoked = username, theme, revoked


class Updatable:
    def __init__(self, rows):
        self.rows = rows

    def update(self, **kw):
        for row in self.rows:
            for key, value in kw.items():
                setattr(row, key, value)
        return len(self.rows)


class Manager:
    @staticmethod
    def filter(**kw):
        rows = [r for r in ROWS_BY_ID.values() if all(getattr(r, k) == v for k, v in kw.items())]
        return Updatable(rows)


ss = load("session_security")
ss.TecTacSessionTrust = types.SimpleNamespace(objects=Manager)
views = load("session_security_views")

mine = Row(1, "alice")
same_user_other = Row(2, "alice")
other_user = Row(3, "bob")
revoked_row = Row(4, "alice", theme="dark", revoked=True)
for row in (mine, same_user_other, other_user, revoked_row):
    ROWS_BY_ID[row.id] = row


class Req:
    def __init__(self, session, data=None):
        self.tec_tac_session, self.data, self.user = session, data, types.SimpleNamespace(username=session.username)


view = views.SessionThemeView()
saved_preference = {"appearance": {"theme": "dark", "font_scale": 1.0}}  # the saved preference document: never touched

# (1) default, set, read, clear; each theme accepted
must(view.get(Req(mine)).data == {"theme": None}, "default")
for theme in ("dark", "light", "high-contrast"):
    resp = view.put(Req(mine, {"theme": theme}))
    must(resp.status_code == 200 and resp.data == {"theme": theme} and mine.session_theme == theme, (theme, resp.__dict__))
    must(view.get(Req(mine)).data == {"theme": theme}, "read back")
resp = view.delete(Req(mine))
must(resp.status_code == 200 and resp.data == {"theme": None} and mine.session_theme == "", resp.__dict__)
must(view.get(Req(mine)).data == {"theme": None}, "cleared")
must(view.delete(Req(mine)).data == {"theme": None}, "clearing again is fine")

# (2) other values, bool, null, numbers, other keys: 400 and nothing saved
view.put(Req(mine, {"theme": "light"}))
for body in ({"theme": "blue"}, {"theme": ""}, {"theme": " dark"}, {"theme": "DARK"}, {"theme": True}, {"theme": False}, {"theme": None}, {"theme": 1},
             {"theme": ["dark"]}, {"theme": {"a": 1}}, {}, {"colour": "dark"}, {"theme": "dark", "font_scale": 1.2}, {"theme": "dark", "extra": 1}, ["dark"], "dark", None):
    resp = view.put(Req(mine, body))
    must(resp.status_code == 400 and mine.session_theme == "light", (body, resp.__dict__, mine.session_theme))

# (3) only the caller's own session row changes
view.put(Req(mine, {"theme": "high-contrast"}))
must(mine.session_theme == "high-contrast" and same_user_other.session_theme == "" and other_user.session_theme == "", "other rows untouched")
view.delete(Req(other_user))
must(mine.session_theme == "high-contrast", "another user's clear never reaches this row")
# a revoked row is never written
stale = types.SimpleNamespace(pk=4, id=4, username="alice", session_theme="dark")  # the row was revoked while this request ran
resp = view.put(Req(stale, {"theme": "light"}))
must(ROWS_BY_ID[4].revoked is True and ROWS_BY_ID[4].session_theme == "dark", "a revoked row is never written in the store")
# the tombstone is never read as a live choice by a fresh object with an unknown value
must(ss.session_theme_of(types.SimpleNamespace(session_theme="neon")) is None, "an unknown stored value reads as none")
must(ss.session_theme_of(None) is None and ss.session_theme_of(types.SimpleNamespace()) is None, "no session reads as none")
must(ss.session_theme_of(types.SimpleNamespace(session_theme="light")) == "light", "a known theme reads")

# (4) the helper refuses anything but a known theme or None, and writes nothing
before = mine.session_theme
for bad in ("neon", "", True, 3, ["dark"], b"dark"):
    try:
        ss.set_session_theme(mine, bad)
    except ss.SessionSecurityError:
        pass
    else:
        raise AssertionError(f"{bad!r} must be refused")
must(mine.session_theme == before, "refused values change nothing")
must(ss.set_session_theme(mine, None) is None and mine.session_theme == "", "None clears")

# (5) the saved preference is untouched, and the view never imports the preference store
must(saved_preference == {"appearance": {"theme": "dark", "font_scale": 1.0}}, "saved preference")
views_src = (APP / "session_security_views.py").read_text(encoding="utf-8")
helper_src = (APP / "session_security.py").read_text(encoding="utf-8")
theme_view = views_src.split("class SessionThemeView")[1].split("class SessionPolicyView")[0]
must(not any(name in theme_view for name in ("get_user_preferences", "set_user_preferences", "TecTacUserPreferences", "preferences import")), "the theme view never writes the saved preference")
helper_body = helper_src.split("def set_session_theme")[1].split("def revoke_all_login_sessions")[0]
must("TecTacUserPreferences" not in helper_body and "set_user_preferences" not in helper_body and "audit" not in helper_body.lower().replace("not audited", ""), "no preference write, no audit")
must("permission_classes = [SessionAuthenticated]" in theme_view, "needs a signed-in session")

# (6) the context carries session_theme next to preferences
views_py = (APP / "views.py").read_text(encoding="utf-8")
ctx = views_py.split("class UiContextView")[1].split("class ExtensionPermissionCatalogView")[0]
must('"session_theme": session_theme_of(getattr(request, "tec_tac_session", None))' in ctx, "ui/context carries it")
must(ctx.index('"preferences": preferences') < ctx.index('"session_theme"'), "next to preferences")
must("session_theme_of" in views_py.split("from .session_security import")[1].split("\n")[0], "imported")

# (7) the model field, the migration (adds exactly one field, depends on 0027, reversible) and the route
models_src = (APP / "models.py").read_text(encoding="utf-8")
must('session_theme = models.CharField(max_length=16, blank=True, default="")' in models_src, "model field")
trust_class = models_src.split("class TecTacSessionTrust")[1].split("class TecTacSessionAudit")[0]
must("session_theme" in trust_class, "on the trust row")
mig_path = APP / "migrations" / "0028_session_theme.py"
tree = ast.parse(mig_path.read_text(encoding="utf-8"))
migration = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Migration")
assign = {t.id: n.value for n in migration.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
must(ast.literal_eval(assign["dependencies"]) == [("tec_tac", "0027_runtime_system_name")], "depends on 0027")
ops = assign["operations"].elts
must(len(ops) == 1 and ast.unparse(ops[0].func) == "migrations.AddField", "exactly one AddField")
kw = {k.arg: k.value for k in ops[0].keywords}
must(ast.literal_eval(kw["model_name"]) == "tectacsessiontrust" and ast.literal_eval(kw["name"]) == "session_theme", "the field")
field = ast.unparse(kw["field"])
must("max_length=16" in field and "default=''" in field and "blank=True" in field, field)
must("RunPython" not in mig_path.read_text(encoding="utf-8") and "RunSQL" not in mig_path.read_text(encoding="utf-8"), "no data step, so AddField reverses by dropping the column")
must(sorted(p.name for p in (APP / "migrations").glob("00*.py"))[-1] == "0036_schedule_creator_name.py", "0036 is the newest migration (1.17.63); 0035 is 1.17.62; 0034 is 1.17.61; 0033 is 1.17.58; 0032, 0031, 0030, 0029 and 0028 are still there")
must((APP / "migrations" / "0029_priority_mail_private_relay.py").is_file(), "0029 is still there")
must(mig_path.is_file(), "0028 is still there")
urls = (APP / "urls.py").read_text(encoding="utf-8")
must('path("session/theme/", SessionThemeView.as_view()' in urls and "SessionThemeView," in urls, "route")

# (8) the contract table and the docs
contracts = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
table = next(ast.literal_eval(n.value) for n in contracts.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in n.targets))
row = table["/api/tfd/session/theme/"]
must(set(row) == {"GET", "PUT", "DELETE"} and "theme" in row["PUT"]["request"], row)
must("session_theme" in table["/api/tfd/ui/context/"]["GET"]["response"], "context row")
doc = (ROOT / "docs" / "user-preferences.md").read_text(encoding="utf-8")
must("/api/tfd/session/theme/" in doc and "session_theme" in doc and "0028_session_theme" in doc, "docs")

print("session theme 1.17.24: ok")
