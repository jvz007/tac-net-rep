#!/usr/bin/env python3
"""1.18.41 regression (CQ93 option 2, AD-76): a scheduled report reads a server-wide model only when its owner is an effective superuser.

Uses the harness of tests/reporting-row-scope-1.17.4.py (fake Django, users, roles and models) and the real ``is_effective_superuser`` cut
out of rbac.py, as tests/reporting-server-wide-scope-1.17.30.py does. Django is not installed on this PC. Covered: using() on a server-wide
manager raises the plain message outside a run; inside schedule_run a Django superuser or role superuser owner passes; a plain user, scoped
role, no role, inactive, unknown, None, empty name and a failing role cache each fail with the message; Run now (the owner decides, the clicker
is ignored); Tactical's fallback path; the context variable is reset after normal exit, after an exception and for nested runs; schedule_run
never raises; scoped managers and on-screen runs are unchanged; model_row_scope is unchanged; contract row, docs and release notes.
"""
# ruff: noqa: F821  (names come from the shared harness that is exec'd below)
from __future__ import annotations

import ast
import sys
import types as _types
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "reporting-row-scope-1.17.4.py"
_src = HARNESS.read_text(encoding="utf-8")
_cut = "# ------------------------------------------------------------------ status rows and the bridge status carry it"
assert _cut in _src
exec(compile(_src.split(_cut)[0], str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

_rbac_tree = ast.parse((APP / "rbac.py").read_text(encoding="utf-8"))
_fn = next(n for n in _rbac_tree.body if isinstance(n, ast.FunctionDef) and n.name == "is_effective_superuser")
_rbac = _types.ModuleType("tec_tac.rbac")
exec(compile(ast.Module(body=[_fn], type_ignores=[]), "rbac.py", "exec"), _rbac.__dict__)  # noqa: S102 - the real function, not user input
sys.modules["tec_tac.rbac"] = _rbac
User.is_authenticated = True

MESSAGE = "A scheduled report may show server-wide data only when the person who last saved the schedule is a superuser."

# the stub Manager has no using(); the real one returns a queryset for the alias
Manager.using = lambda self, alias: ("using", alias)

# a fake user table behind django.contrib.auth.get_user_model
USERS = {}


class DoesNotExist(Exception):
    pass


class _Objects:
    @staticmethod
    def get(username):
        try:
            return USERS[username]
        except KeyError:
            raise DoesNotExist(username) from None


auth = mod("django.contrib.auth", get_user_model=lambda: SimpleNamespace(objects=_Objects))
contrib = mod("django.contrib")
sys.modules.update({"django.contrib": contrib, "django.contrib.auth": auth})


class BrokenUser(User):
    def get_and_set_role_cache(self):
        raise RuntimeError("cache down")


inactive = User(superuser=True)
inactive.is_active = False
USERS.update({
    "root": User(superuser=True), "roleroot": User(Role(superuser=True)), "plain": User(Role()), "scoped": User(Role(clients=[10])),
    "norole": User(None), "inactive": inactive, "broken": BrokenUser(Role(superuser=True)),
})

wide = rep.scoped_report_manager(server_wide=True)
normal = rep.scoped_report_manager(client="client_id", site="site_id")
pathless = rep.scoped_report_manager()
Refused = rep.ScheduledReportRefused


def refuses(fn, label):
    try:
        fn()
    except Refused as exc:
        must(str(exc) == MESSAGE, f"{label}: plain message, got {exc}")
        must(isinstance(exc, PermissionError), f"{label}: a PermissionError")
        return
    raise AssertionError(f"{label}: expected a refusal")


def state():
    return rep._SCHEDULE_RUN.get()


# ---- outside a run -----------------------------------------------------------------------------------------------------------------
must(state() is None, "no run at start")
refuses(lambda: wide.using("default"), "using outside a run")
must(wide.filter_by_role(User(superuser=True)).is_none is False, "on screen: a superuser sees rows (1.17.30)")
must(wide.filter_by_role(User(Role())).is_none is True, "on screen: a plain role sees none, no raise")
must(wide.filter_by_role(None).is_none is True, "on screen: no user, none, no raise")

# ---- inside a run: the owner decides -------------------------------------------------------------------------------------------------
for owner in ("root", "roleroot"):
    with rep.schedule_run(owner) as ok:
        must(ok is True, f"{owner} is ok")
        must(wide.using("default") == ("using", "default"), f"{owner}: using passes")
        qs = wide.filter_by_role(User(superuser=True))
        must(qs.is_none is False and qs.condition is None, f"{owner}: every row")
    must(state() is None, "reset after exit")

for owner, label in (("plain", "plain user"), ("scoped", "scoped role"), ("norole", "no role"), ("inactive", "inactive user"),
                     ("ghost", "unknown username"), (None, "None"), ("", "empty name"), ("   ", "blank name"), ("broken", "failing role cache"),
                     (42, "not a string")):
    with rep.schedule_run(owner) as ok:  # never raises
        must(ok is False, f"{label}: not ok")
        refuses(lambda: wide.filter_by_role(User(superuser=True)), f"{label} filter_by_role")
        refuses(lambda: wide.using("default"), f"{label} using")
    must(state() is None, f"{label}: reset")

# a lookup error (database down) or a raising rbac fails closed and does not raise
real_get = _Objects.get


def db_down(username):
    raise RuntimeError("database down")


_Objects.get = staticmethod(db_down)
with rep.schedule_run("root") as ok:
    must(ok is False, "a lookup error means not ok")
_Objects.get = staticmethod(real_get)
real_check = _rbac.is_effective_superuser


def rbac_down(user):
    raise RuntimeError("rbac down")


_rbac.is_effective_superuser = rbac_down
with rep.schedule_run("root") as ok:
    must(ok is False, "a raising rbac means not ok")
_rbac.is_effective_superuser = real_check

# ---- Run now: the owner decides, the clicker is ignored -----------------------------------------------------------------------------
with rep.schedule_run("plain"):
    refuses(lambda: wide.filter_by_role(User(superuser=True)), "superuser clicker, non-superuser owner")
with rep.schedule_run("root"):
    must(wide.filter_by_role(User(Role())).is_none is False, "non-superuser clicker, superuser owner: rows")
    must(wide.filter_by_role(None).is_none is False, "no clicker, superuser owner: rows")


# ---- Tactical's fallback: filter_by_role raises, then Model.objects.using('default') -----------------------------------------------
def tactical_path(manager):
    try:
        return manager.filter_by_role(None)
    except Refused:
        return manager.using("default")


with rep.schedule_run("plain"):
    refuses(lambda: tactical_path(wide), "fallback, owner fails")
with rep.schedule_run("root"):
    must(tactical_path(wide).is_none is False, "owner ok: rows")
refuses(lambda: wide.using("default"), "the user-less scheduler path outside a run")

# ---- the variable is reset ---------------------------------------------------------------------------------------------------------
try:
    with rep.schedule_run("root"):
        must(state() == {"owner_ok": True}, "inside")
        raise ValueError("boom")
except ValueError:
    pass
must(state() is None, "reset after an exception inside the block")
with rep.schedule_run("root"):
    with rep.schedule_run("plain"):
        must(state() == {"owner_ok": False}, "inner state")
        refuses(lambda: wide.using("default"), "inner owner fails")
    must(state() == {"owner_ok": True}, "outer state restored")
    must(wide.using("x") == ("using", "x"), "outer owner still passes")
must(state() is None, "nested: back to None")

# ---- other managers are unchanged ----------------------------------------------------------------------------------------------------
for owner in (None, "plain", "root"):
    with rep.schedule_run(owner):
        must(normal.using("default") == ("using", "default"), "scoped manager using is untouched")
        must(pathless.using("default") == ("using", "default"), "pathless manager using is untouched")
        must(normal.filter_by_role(User(Role())).is_none is False, "scoped manager filter is untouched")
        must(normal.filter_by_role(User(None)).is_none is True, "scoped manager, no role: none")
must(normal.using("default") == ("using", "default") and pathless.using("default") == ("using", "default"), "outside a run too")

# ---- model_row_scope is unchanged ------------------------------------------------------------------------------------------------------
MODELS[("tec_tac_x", "wide")] = make_model("Wide", base, rep.scoped_report_manager(server_wide=True))
got = scope("tec_tac_x", "Wide")
must(got == {"enforced": True, "source": "core", "client_field": None, "site_field": None, "include_unassigned": False, "server_wide": True}, got)

# ---- contract rows, docs, release notes -------------------------------------------------------------------------------------------------
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
contracts = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
rows = {row["name"]: row for row in contracts if row["area"] == "reporting"}
must("schedule_run" in rows and rows["schedule_run"]["kind"] == "python" and rows["schedule_run"]["audience"] == "provider/backend", "schedule_run row")
purpose = rows["schedule_run"]["purpose"]
for word in ("since 1.18.41", "AD-76", "additive", "framework >=1.18.41", "Report Manager", "ScheduledReportRefused", MESSAGE):
    must(word in purpose, f"schedule_run row mentions {word}")
swm = rows["scoped_report_manager"]["purpose"]
must("1.18.41" in swm and "schedule_run" in swm and "AD-76" in swm, "scoped_report_manager row has the Since 1.18.41 sentence")
must("stays unscoped, so scheduling" not in swm, "a server-wide user-less run is no longer called unscoped")
docs = (ROOT / "docs" / "module-reporting.md").read_text(encoding="utf-8")
for word in ("AD-76", "CQ93", "schedule_run", MESSAGE):
    must(word in docs, f"docs/module-reporting.md mentions {word}")
must("Johan has been asked" not in docs and "open for Johan's decision" not in docs, "the open-question text is gone")
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip().split("-")[0]
notes = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
for word in ("CQ93", "AD-76", "## Module-facing change", "## Johan dev02 checklist", "schedule_run", "reportmanager", "sentinelone"):
    must(word in notes, f"release notes mention {word}")
checklist = notes[notes.index("## Johan dev02 checklist"):notes.index("## Exit list")]
must(checklist.count("PASS:") >= 5 and checklist.count("PASS:") == checklist.count("FAIL:"), "checklist has equal PASS and FAIL lines")

print("reporting schedule run 1.18.41: ok")
