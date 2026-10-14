#!/usr/bin/env python3
"""1.17.37: the dev-server probe tests/tactical-ui-preferences-runtime-1.17.37.py runs end to end with narrow Django stubs.

The probe needs Tactical's Django models, which are not installed on this PC, so this test stubs them the same narrow way as
tests/tactical-ui-preferences-1.17.35.py. The stub User table is a store, and the outer transaction really rolls back (a snapshot is
restored when the atomic block raises), so the probe's "no probe rows left" check means something here too.

Covered: the real probe file runs unchanged and prints five PASS lines, 'no probe rows left' and 'tactical-ui-preferences-runtime-1.17.37: ok';
the hot-path step compares every name in TACTICAL_UI_SCALAR_FIELDS to the stored row and checks the exact key set; a negative control runs
the 1.17.35 hot-path step (asserting the value set by an earlier step, after the empty-date step had cleared it) and it fails with
'the scalars are published', so the order bug would have been caught; the Tactical UI contract text still says the runtime context carries
no choice lists, while GET /api/tfd/account/ keeps 'allowed choices' because that answer does carry them.
"""
from __future__ import annotations

import contextlib
import importlib
import io
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
PROBE = ROOT / "tests" / "tactical-ui-preferences-runtime-1.17.37.py"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------------------------------------ stubs
pyotp_mod = types.ModuleType("pyotp")
pyotp_mod.TOTP = lambda secret: types.SimpleNamespace(now=lambda: "123456", verify=lambda token, valid_window=0: str(token) == "123456")
pyotp_mod.random_base32 = lambda: "JBSWY3DPEHPK3PXP"
sys.modules["pyotp"] = pyotp_mod

django_auth = types.ModuleType("django.contrib.auth")
django_validation = types.ModuleType("django.contrib.auth.password_validation")
django_validation.validate_password = lambda value, user=None: None
django_ex = types.ModuleType("django.core.exceptions")


class ValidationError(Exception):
    pass


django_ex.ValidationError = ValidationError
django_db = types.ModuleType("django.db")
django_contrib = types.ModuleType("django.contrib")
django_root = types.ModuleType("django")
django_core = types.ModuleType("django.core")
django_root.contrib = django_contrib
django_root.core = django_core
django_root.db = django_db
accounts_pkg = types.ModuleType("accounts")
accounts_models = types.ModuleType("accounts.models")

STORE: dict = {}
NEXT_PK = [1]


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
    "is_superuser": False, "is_sso_user": False, "block_dashboard_login": False, "role": None,
    "agent_dblclick_action": "editagent", "url_action_id": None,
    "dark_mode": True, "show_community_scripts": True, "default_agent_tbl_tab": "mixed", "client_tree_sort": "alphafail",
    "client_tree_splitter": 11, "loading_bar_color": "red", "dash_info_color": "info", "dash_positive_color": "positive",
    "dash_negative_color": "negative", "dash_warning_color": "warning", "clear_search_when_switching": True, "date_format": None,
}


class User:
    _meta = Meta()

    def __init__(self, **values):
        self.__dict__.update(DEFAULTS)
        self.__dict__.update(values)
        self.__dict__.setdefault("pk", None)

    def set_password(self, raw):
        self.__dict__["password"] = raw

    def save(self, update_fields=None):
        if self.pk is None:
            self.pk = NEXT_PK[0]
            NEXT_PK[0] += 1
        STORE[self.pk] = {k: v for k, v in self.__dict__.items()}


class _Filtered:
    def __init__(self, rows):
        self.rows = rows

    def count(self):
        return len(self.rows)


class UserManager:
    def select_for_update(self):
        return self

    def get(self, pk):
        return User(**STORE[pk])  # a copy, as a row lock returns: a failed PUT changes nothing stored

    def filter(self, **kwargs):
        prefix = kwargs["username__startswith"]
        return _Filtered([row for row in STORE.values() if str(row.get("username", "")).startswith(prefix)])


User.objects = UserManager()


class Atomic:
    """Restores the store when the block raises, as a real database transaction does."""

    def __enter__(self):
        self.snapshot = {pk: dict(row) for pk, row in STORE.items()}
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            STORE.clear()
            STORE.update(self.snapshot)
        return False


django_db.transaction = types.SimpleNamespace(atomic=lambda: Atomic())
django_auth.get_user_model = lambda: User
accounts_models.User = User
accounts_pkg.models = accounts_models
sys.modules.update({
    "django": django_root, "django.contrib": django_contrib, "django.core": django_core,
    "django.contrib.auth": django_auth, "django.contrib.auth.password_validation": django_validation,
    "django.core.exceptions": django_ex, "django.db": django_db,
    "accounts": accounts_pkg, "accounts.models": accounts_models,
})

mfa = types.ModuleType("tec_tac.mfa_backup")
mfa.invalidate_backup_codes = lambda user, **kwargs: {"invalidated": 0}
sys.modules["tec_tac.mfa_backup"] = mfa
sess = types.ModuleType("tec_tac.session_security")


class SessionSecurityError(Exception):
    pass


sess.SessionSecurityError = SessionSecurityError
sess._audit = lambda event, **kwargs: None
sess.revoke_user_sessions = lambda username, **kwargs: {"revoked": 0, "session_ids": []}
sys.modules["tec_tac.session_security"] = sess

svc = importlib.import_module("tec_tac.account_self_service")


def run_probe(source: str) -> tuple[int, str]:
    """Run a probe source as manage.py shell would: stdout captured, SystemExit(1) read as a failed run."""
    STORE.clear()
    NEXT_PK[0] = 1
    buffer = io.StringIO()
    code = 0
    with contextlib.redirect_stdout(buffer):
        try:
            exec(compile(source, str(PROBE), "exec"), {"__name__": "__probe__"})
        except SystemExit as exc:
            code = int(exc.code or 0)
    return code, buffer.getvalue()


source = PROBE.read_text(encoding="utf-8")

# ------------------------------------------------------------------------------------------------ 1. the real probe passes end to end
code, out = run_probe(source)
lines = out.splitlines()
must(code == 0, f"the probe exits 0: {code}\n{out}")
passes = [line for line in lines if line.startswith("PASS ")]
must(len(passes) == 5, f"five PASS lines: {out}")
must(not [line for line in lines if line.startswith("FAIL")], f"no FAIL line: {out}")
must("no probe rows left" in lines, f"no probe rows left: {out}")
must(lines[-1] == "tactical-ui-preferences-runtime-1.17.37: ok", f"the run ends ok: {out}")
must(not STORE, f"the store holds no probe row after the run: {STORE}")

# ------------------------------------------------------------------------------------------------ 2. the hot-path step checks every scalar against the stored row
hot = source[source.index("    def hot_path_context():"):source.index('    step("save every')]
must("for name in svc.TACTICAL_UI_SCALAR_FIELDS:" in hot, "the hot-path step loops over every scalar")
must("getattr(fresh, name)" in hot, "and compares each one with the stored row")
must("set(context) ==" in hot and "TACTICAL_UI_SCALAR_FIELDS" in hot, "and checks the exact key set")
must("svc.update_tactical_ui_preferences(user, values)" in hot, "the hot-path step sets its own state first")

# ------------------------------------------------------------------------------------------------ 3. negative control: the 1.17.35 order fails
OLD_HOT_PATH = '''    def hot_path_context():
        context = svc.tactical_ui_context(User.objects.get(pk=user.pk))
        assert {"agent_dblclick_action", "url_action_id", "can_run_url_actions"} <= set(context), "the three keys stay"
        assert context["client_tree_splitter"] == 30 and context["date_format"] == "YYYY-MM-DD HH:mm", "the scalars are published"
        assert "default_agent_tbl_choices" not in context, "no choice list on the hot path"

'''
must(hot in source, "the hot-path block is found in the probe")
old_source = source.replace(hot, OLD_HOT_PATH)
must(old_source != source, "the negative control replaced the hot-path block")
code, out = run_probe(old_source)
lines = out.splitlines()
must(code == 1, f"the 1.17.35 order exits 1: {code}\n{out}")
must(any(line.startswith("FAIL the runtime context carries the scalars") and "the scalars are published" in line for line in lines),
     f"the 1.17.35 order fails with 'the scalars are published': {out}")
must(lines[-1] == "tactical-ui-preferences-runtime-1.17.37: FAILED", f"the negative run ends FAILED: {out}")
must(not STORE, "the negative run also leaves no probe row")

# ------------------------------------------------------------------------------------------------ 4. contract text
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
must("tactical_ui (added 1.17.35): the scalars dark_mode" in contracts, "the runtime-context row is present")
runtime_row = contracts[contracts.index("tactical_ui (added 1.17.35):"):]
runtime_row = runtime_row[:runtime_row.index('",')]
must("the choice lists are not in the context" in runtime_row, "the runtime context says it carries no choice lists")
must("plus allowed choices" not in runtime_row, "the runtime context row does not say 'allowed choices'")
account_row = contracts[contracts.index('"tactical_ui": "current Tactical UI preferences plus allowed choices'):]
account_row = account_row[:account_row.index('",')]
must("plus allowed choices" in account_row, "GET /api/tfd/account/ keeps 'allowed choices' because its answer carries the choice lists")

print("[TEST] PASS tactical UI preferences probe 1.17.37")
