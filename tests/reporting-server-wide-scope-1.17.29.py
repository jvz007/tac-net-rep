#!/usr/bin/env python3
"""1.17.29 regression: server-wide row scope for a report model (scoped_report_manager(server_wide=True)).

1.17.30 (AD-34 condition 3) changed who sees the rows: effective superusers only. A role with no limits now sees none (see
tests/reporting-server-wide-scope-1.17.30.py); this test follows that rule.

Extends the stubs of tests/reporting-row-scope-1.17.4.py (its text runs here up to the status-row section, so the real reporting.py and
resources_adapter.py run against fake Django, users, roles and models). Covered: scope_filter_spec and the manager with server_wide give
all rows to an unrestricted person, none to a scoped person, none for no role and none when the adapter raises; server_wide together
with client, site or include_unassigned is refused at declaration, and a non-bool is refused; model_row_scope reports enforced and
server_wide for a server-wide model, and enforced false with server_wide false for a pathless manager that did not opt in (the way
certificatemanagement declares today); a subclass that replaces filter_by_role is source model and not enforced; client and site models are
unchanged; the bridge status counts the server-wide model as enforced; the contract rows and docs name the keyword.
"""
# ruff: noqa: F821  (names come from the shared harness that is exec'd below)
from __future__ import annotations

import ast
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "reporting-row-scope-1.17.4.py"
_src = HARNESS.read_text(encoding="utf-8")
_cut = "# ------------------------------------------------------------------ status rows and the bridge status carry it"
assert _cut in _src
exec(compile(_src.split(_cut)[0], str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input


# ---- rbac stand-in (1.17.30): the real is_effective_superuser, cut out of rbac.py (the module itself needs Tactical's Role model) --------
import types as _types

_rbac_tree = ast.parse((APP / "rbac.py").read_text(encoding="utf-8"))
_fn = next(n for n in _rbac_tree.body if isinstance(n, ast.FunctionDef) and n.name == "is_effective_superuser")
_rbac = _types.ModuleType("tec_tac.rbac")
exec(compile(ast.Module(body=[_fn], type_ignores=[]), "rbac.py", "exec"), _rbac.__dict__)  # noqa: S102 - the real function, not user input
sys.modules["tec_tac.rbac"] = _rbac
User.is_authenticated = True  # the harness user stands in for a signed-in Tactical user

# ---- declaration ---------------------------------------------------------------------------------------------------------------------
wide = rep.scoped_report_manager(server_wide=True)
must(isinstance(wide, Manager) and wide._tec_tac_scoped_report_manager is True and wide._server_wide is True, "server-wide manager state")
must((wide.client_field, wide.site_field, wide.include_unassigned) == (None, None, False), "no path, no unassigned")
must(rep.scoped_report_manager()._server_wide is False and rep.scoped_report_manager(client="client_id")._server_wide is False, "off by default")
must(rep.scoped_report_manager(server_wide=False, client="client_id").client_field == "client_id", "an explicit False changes nothing")
for kwargs in ({"client": "client_id"}, {"site": "site_id"}, {"include_unassigned": True}, {"client": "client_id", "site": "site_id"}):
    try:
        rep.scoped_report_manager(server_wide=True, **kwargs)
    except rep.ReportingRegistrationError as exc:
        must("client or site" in str(exc), str(exc))
    else:
        raise AssertionError(f"server_wide with {kwargs} must be refused")
for bad_flag in (1, 0, "yes", None, "true", [True]):
    try:
        rep.scoped_report_manager(server_wide=bad_flag)
    except rep.ReportingRegistrationError:
        pass
    else:
        raise AssertionError(f"server_wide {bad_flag!r} must be refused")
rep.scoped_report_manager(server_wide=True, include_unassigned=False)  # an explicit False include_unassigned is fine

# ---- who sees what -------------------------------------------------------------------------------------------------------------------
must(rep.scope_filter_spec(UNRESTRICTED, client_path=None, site_path=None)["mode"] == "all", "spec: unrestricted sees all (a pathless model, not server_wide)")
must(rep.scope_filter_spec(client_only, client_path=None, site_path=None)["mode"] == "none", "spec: a scoped person sees none")
must(rep.scope_filter_spec(none, client_path=None, site_path=None)["mode"] == "none", "spec: denied sees none")
for person, label in ((User(superuser=True), "superuser"), (User(Role(superuser=True)), "role superuser")):
    qs = wide.filter_by_role(person)
    must(qs.is_none is False and qs.condition is None, f"{label} sees every row")
for person, label in ((User(Role()), "a role with no limits (1.17.30)"), (User(Role(clients=[10])), "client-limited"), (User(Role(sites=[3])), "site-limited"),
                      (User(Role(clients=[10], sites=[3])), "client and site limited"), (User(None), "no role"), (None, "no user")):
    must(wide.filter_by_role(person).is_none is True, f"{label} sees no row")
real = adapter.report_scope_ids


def boom(user):
    raise RuntimeError("database down")


adapter.report_scope_ids = boom
must(wide.filter_by_role(User(Role(clients=[10]))).is_none is True, "an adapter error gives no rows and does not raise")
must(wide.filter_by_role(User(superuser=True)).is_none is False, "1.17.30: the scope adapter is not used for a server-wide model")
adapter.report_scope_ids = real

# ---- model_row_scope -----------------------------------------------------------------------------------------------------------------
class OverriddenWide(type(wide)):
    def filter_by_role(self, user):
        return self.get_queryset()


MODELS.update({
    ("tec_tac_x", "wide"): make_model("Wide", base, rep.scoped_report_manager(server_wide=True)),
    ("tec_tac_x", "replacedwide"): make_model("ReplacedWide", base, OverriddenWide(server_wide=True)),
    ("tec_tac_x", "wideandpath"): make_model("WideAndPath", base, type(wide)("client_id", None, False, True)),  # built by hand, bypassing the check
    ("tec_tac_x", "pathless"): make_model("Pathless", base, rep.scoped_report_manager()),
})
got = scope("tec_tac_x", "Wide")
must(got == {"enforced": True, "source": "core", "client_field": None, "site_field": None, "include_unassigned": False, "server_wide": True}, got)
pathless = scope("tec_tac_x", "Pathless")
must(pathless == {"enforced": False, "source": "core", "client_field": None, "site_field": None, "include_unassigned": False, "server_wide": False}, pathless)
replaced = scope("tec_tac_x", "ReplacedWide")
must(replaced["enforced"] is False and replaced["source"] == "model" and replaced["server_wide"] is False, replaced)
must(scope("tec_tac_x", "WideAndPath")["enforced"] is False, "server_wide with a path is never enforced")
good = scope("tec_tac_x", "Good")
must(good["enforced"] is True and good["server_wide"] is False and good["client_field"] == "client_id", good)  # a client and site model is unchanged
must(scope("tec_tac_x", "Plain") == NOT and scope("tec_tac_x", "Own") == {**NOT, "source": "model"}, "plain and own-scope models unchanged")
must(scope("tec_tac_x", "NoObjects") == NOT and scope("nope", "x") == NOT and NOT["server_wide"] is False, "unknown models: server_wide false")

# ---- status rows and the bridge status ---------------------------------------------------------------------------------------------------
rep._provider_status = lambda module_id: {"installed": True, "enabled": True, "version": "1.0.0", "state": "available"}
rep._clear_reporting_registry_for_tests()
for public_id, model_name in (("x.wide", "Wide"), ("x.pathless", "Pathless"), ("x.good", "Good")):
    rep._REGISTRY[public_id] = rep.ReportingModelRegistration(id=public_id, module_id="x", app_label="tec_tac_x", model=model_name)
rows = {row["id"]: row for row in rep.list_reporting_models()}
must(rows["x.wide"]["row_scope"]["enforced"] is True and rows["x.wide"]["row_scope"]["server_wide"] is True, rows["x.wide"])
must(rows["x.pathless"]["row_scope"]["enforced"] is False, rows["x.pathless"])
status = rep.reporting_bridge_status()
must(status["row_scope_models"] == {"enforced": ["x.good", "x.wide"], "unscoped": ["x.pathless"]}, status["row_scope_models"])

# ---- contract rows and docs ----------------------------------------------------------------------------------------------------------------
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
contracts = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
named = {row["name"]: row["purpose"] for row in contracts if row["area"] == "reporting"}
must("server_wide=True" in named["scoped_report_manager"] and "1.17.29" in named["scoped_report_manager"] and "include_unassigned" in named["scoped_report_manager"], "scoped_report_manager row")
must("server_wide" in named["model_row_scope"] and "1.17.29" in named["model_row_scope"], "model_row_scope row")
docs = (ROOT / "docs" / "module-reporting.md").read_text(encoding="utf-8")
for word in ("Server-wide data (since 1.17.29)", "server_wide=True", "enforced", "can_view_clients", "ReportingRegistrationError", "{enforced, source, client_field, site_field, include_unassigned, server_wide}"):
    must(word in docs, f"docs/module-reporting.md mentions {word}")
src = (APP / "reporting.py").read_text(encoding="utf-8")
must("server_wide" in src.split("def scoped_report_manager", 1)[1].split('"""', 2)[1], "docstring")

print("reporting server-wide scope 1.17.29: ok")
