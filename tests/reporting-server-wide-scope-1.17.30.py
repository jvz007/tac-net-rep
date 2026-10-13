#!/usr/bin/env python3
"""1.17.30 regression (AD-34 condition 3, Johan CQ91 b): rows of a server_wide report model are visible to effective superusers only.

Uses the harness of tests/reporting-row-scope-1.17.4.py, as the 1.17.29 test does, so the real reporting.py runs against fake Django, users,
roles and models. The real ``is_effective_superuser`` is cut out of rbac.py (the module needs Tactical's Role model). Covered: a Django
superuser and a role superuser see every row; a role with no limits (the 1.17.29 rule gave it every row), a client-limited, a site-limited and
a both-limited role, no role, no user, an unauthenticated user (an installer user is refused by the same check in production) and a raising rbac
each see none, and nothing raises; a manager that is not server_wide is unchanged (an unrestricted role still sees every row) and does not use
the superuser rule; model_row_scope is unchanged (enforced true, server_wide true); a user-less run never calls filter_by_role (Core cannot
scope it, CQ15 a), and the docs, contract rows and release notes say so and cite AD-34.
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
User.is_authenticated = True  # the harness user stands in for a signed-in Tactical user

wide = rep.scoped_report_manager(server_wide=True)
normal = rep.scoped_report_manager(client="client_id", site="site_id")
pathless = rep.scoped_report_manager()

# ---- who sees what -------------------------------------------------------------------------------------------------------------------
for person, label in ((User(superuser=True), "Django superuser"), (User(Role(superuser=True)), "role superuser"),
                      (User(Role(superuser=True), superuser=True), "both")):
    qs = wide.filter_by_role(person)
    must(qs.is_none is False and qs.condition is None, f"{label} sees every row")
for person, label in ((User(Role()), "a role with no limits"), (User(Role(clients=[10])), "client-limited"), (User(Role(sites=[3])), "site-limited"),
                      (User(Role(clients=[10], sites=[3])), "client and site limited"), (User(None), "no role"), (None, "no user")):
    must(wide.filter_by_role(person).is_none is True, f"{label} sees no row")
anonymous = User(superuser=True)
anonymous.is_authenticated = False
must(wide.filter_by_role(anonymous).is_none is True, "an unauthenticated user sees no row, even with the flag")


class BrokenUser(User):
    def get_and_set_role_cache(self):
        raise RuntimeError("cache down")


# the real check falls back to .role when the cache call fails, so a broken cache on a role superuser still answers
must(wide.filter_by_role(BrokenUser(Role(superuser=True))).is_none is False, "a failing role cache falls back to the role")
must(wide.filter_by_role(BrokenUser(Role())).is_none is True, "a failing role cache and no superuser: none")

real_check = _rbac.is_effective_superuser


def boom(user):
    raise RuntimeError("rbac down")


_rbac.is_effective_superuser = boom
must(wide.filter_by_role(User(superuser=True)).is_none is True, "a raising rbac gives no rows and does not raise, even for a superuser")
must(wide.filter_by_role(User(Role())).is_none is True, "a raising rbac gives no rows")
_rbac.is_effective_superuser = real_check
must(wide.filter_by_role(User(superuser=True)).is_none is False, "the check is back")

# the client and site rule is not used for a server-wide model
adapter_real = adapter.report_scope_ids


def adapter_boom(user):
    raise RuntimeError("adapter must not be called")


adapter.report_scope_ids = adapter_boom
must(wide.filter_by_role(User(superuser=True)).is_none is False, "server-wide does not read the scope ids")
adapter.report_scope_ids = adapter_real

# ---- a manager that is not server_wide is unchanged ----------------------------------------------------------------------------------
must(normal.filter_by_role(User(Role())).is_none is False and normal.filter_by_role(User(Role())).condition is None, "an unrestricted role still sees all")
must(normal.filter_by_role(User(superuser=True)).is_none is False, "a superuser sees all")
must(normal.filter_by_role(User(None)).is_none is True, "no role: none")
must(pathless.filter_by_role(User(Role())).is_none is False, "a pathless manager keeps Tactical's rule")
must(pathless.filter_by_role(User(Role(clients=[10]))).is_none is True, "a pathless manager hides rows from a scoped role")
_rbac.is_effective_superuser = boom
must(normal.filter_by_role(User(Role())).is_none is False, "a manager that is not server_wide never calls the superuser check")
_rbac.is_effective_superuser = real_check

# ---- model_row_scope unchanged -------------------------------------------------------------------------------------------------------
MODELS[("tec_tac_x", "wide")] = make_model("Wide", base, rep.scoped_report_manager(server_wide=True))
got = scope("tec_tac_x", "Wide")
must(got == {"enforced": True, "source": "core", "client_field": None, "site_field": None, "include_unassigned": False, "server_wide": True}, got)

# ---- a user-less run never calls the filter --------------------------------------------------------------------------------------------
src = (APP / "reporting.py").read_text(encoding="utf-8")
must("filter_by_role" in src and "_server_wide_queryset" in src, "the server-wide branch exists")
must("is_effective_superuser" in src.split("def _server_wide_queryset", 1)[1].split("def _scoped_manager_class", 1)[0], "it uses Core's effective-superuser check")
doc_string = src.split("def scoped_report_manager", 1)[1].split('"""', 2)[1]
must("AD-34" in doc_string and "effective superuser" in doc_string and "CQ15" in doc_string and "AD-34 condition 4" in doc_string, "docstring")

# ---- contract rows, docs, release notes --------------------------------------------------------------------------------------------------
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
contracts = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
named = {row["name"]: row["purpose"] for row in contracts if row["area"] == "reporting"}
must("effective superusers only" in named["scoped_report_manager"] and "1.17.30" in named["scoped_report_manager"] and "AD-34 condition 3" in named["scoped_report_manager"], "row")
must("1.17.30" in named["model_row_scope"] and "superusers only" in named["model_row_scope"], "model_row_scope row")
docs = (ROOT / "docs" / "module-reporting.md").read_text(encoding="utf-8")
section = docs.split("### Server-wide data", 1)[1].split("### Reading the result", 1)[0]
for word in ("effective superusers only", "AD-34 condition 3", "AD-34 condition 4", "1.17.30", "CQ93", "no signed-in user", "unscoped"):
    must(word in section, f"docs/module-reporting.md server-wide section mentions {word}")
notes = (ROOT / "RELEASE_NOTES_1.17.30.md").read_text(encoding="utf-8")
for word in ("superusers only", "AD-34", "no signed-in user", "replaces", "1.17.29"):
    must(word in notes, f"release notes mention {word}")

print("reporting server-wide scope 1.17.30: ok")
