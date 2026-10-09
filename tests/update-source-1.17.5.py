#!/usr/bin/env python3
"""1.17.5 regression: PATCH /api/tfd/system/update-source/ is superuser-only (CQ12, Johan, 9 October 2026).

Closes the held 1.17.2 Medium. Django is not installed on the development PC, so the real runtime_settings.py is
loaded against the stubs of tests/update-source-1.17.2.py (loaded by executing the part of that file that precedes
its first scenario), with the rbac stubs replaced so each right can be held on its own.
"""
from __future__ import annotations

import ast
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "update-source-1.17.2.py"
source = HARNESS.read_text(encoding="utf-8")
marker = 'rs = load("runtime_settings")'
H = {"__file__": str(HARNESS), "__name__": "update_source_harness"}
exec(compile(source[: source.index(marker)], "update-source-1.17.2.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse of the 1.17.x harness
must, mods, load = H["must"], H["mods"], H["load"]
ROOT, APP, CONFIG, AUDITS, Config = H["ROOT"], H["APP"], H["CONFIG"], H["AUDITS"], H["Config"]
PermissionDenied = H["PermissionDenied"]

# Each user holds exactly the rights named; the stubs mirror rbac.py (a superuser also passes the runtime-settings rule).
mods["tec_tac.rbac"].is_effective_superuser = lambda user: bool(getattr(user, "superuser", False))
mods["tec_tac.rbac"].can_manage_runtime_settings = lambda user: bool(
    getattr(user, "superuser", False) or getattr(user, "manage", False) or getattr(user, "privileged", False)
)
rs = load("runtime_settings")


def person(**rights):
    return types.SimpleNamespace(**{"username": "u", "superuser": False, "manage": False, "privileged": False, **rights})


view = rs.UpdateSourceView()
GOOD = {"component": "framework", "type": "branch", "ref": "dev"}


def patch(body, who):
    return view.patch(types.SimpleNamespace(user=who, data=body))


def refused(body, who, why):
    before = (dict(CONFIG.update_sources), len(AUDITS), len(Config.saved))
    try:
        patch(body, who)
    except PermissionDenied as exc:
        must(str(exc) == "Only a Tec-Tac superuser may change the update source.", f"{why}: 403 text {exc}")
        must(str(exc) == rs.UPDATE_SOURCE_DENIED, f"{why}: constant")
    else:
        raise AssertionError(f"{why}: must be refused with 403")
    must((dict(CONFIG.update_sources), len(AUDITS), len(Config.saved)) == before, f"{why}: nothing saved or audited")


CONFIG.update_sources = {}

# (2) core.runtime_settings.manage only, (3) core.privileged_operations only, (4) no right: 403
refused(GOOD, person(manage=True), "manage only")
refused(GOOD, person(privileged=True), "privileged only")
refused(GOOD, person(manage=True, privileged=True), "both rights, not a superuser")
refused(GOOD, person(), "no right")

# (5) a non-superuser with an invalid body gets 403, not 400
for body in ({"component": "agents", "type": "release"}, {"component": "ui", "type": "branch", "ref": "a..b"}, ["ui"], None, {}):
    refused(body, person(manage=True, privileged=True), f"invalid body {body!r}")
    refused(body, person(), f"invalid body {body!r}, no right")

# (1) a superuser can PATCH, and the audit row is written
resp = patch(GOOD, person(superuser=True))
must(resp.status_code == 200, resp.data)
must(resp.data["update_sources"]["framework"] == {"type": "branch", "ref": "dev"}, resp.data)
must(CONFIG.update_sources == {"framework": {"type": "branch", "ref": "dev"}}, CONFIG.update_sources)
must(len(AUDITS) == 1 and AUDITS[0]["object_type"] == "update_source" and AUDITS[0]["strict"] is True, AUDITS)
# a superuser still gets 400 for a bad body
must(patch({"component": "agents", "type": "release"}, person(superuser=True)).status_code == 400, "a superuser sees validation errors")

# (6) GET stays open to any signed-in user
for who in (person(), person(manage=True), person(privileged=True)):
    got = view.get(types.SimpleNamespace(user=who)).data
    must(got["update_sources"]["framework"] == {"type": "branch", "ref": "dev"}, got)

# (7) RuntimeSettingsView.patch keeps its rule (CQ10): manage or privileged still allowed, nothing else
rt = rs.RuntimeSettingsView()
for who, label in ((person(manage=True), "manage"), (person(privileged=True), "privileged"), (person(superuser=True), "superuser")):
    out = rt.patch(types.SimpleNamespace(user=who, data={rs.SETTING_MODULE_REGISTER_TIMEOUT: 45 if label == "manage" else 50}))
    must(out.status_code == 200, (label, out.data))
try:
    rt.patch(types.SimpleNamespace(user=person(), data={rs.SETTING_MODULE_REGISTER_TIMEOUT: 60}))
except PermissionDenied as exc:
    must(str(exc) == rs.RUNTIME_SETTINGS_DENIED and "core.runtime_settings.manage" in str(exc), exc)
else:
    raise AssertionError("a user with no right must not change runtime settings")

# (8) the contract
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
details = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in n.targets))
row = details["/api/tfd/system/update-source/"]["PATCH"]
auth = row["authorization"]
must("effective superuser only" in auth and "1.17.5" in auth, auth)
must("core.runtime_settings.manage or core.privileged_operations" not in auth.split("Tightened")[0], "old rule wording removed from the rule")
must("Only a Tec-Tac superuser may change the update source." in row["errors"]["403"], row["errors"])
stage = details["/api/tfd/system/updates/online/stage/"]["POST"]
must(any("only a superuser can set the saved source" in n for n in stage["notes"]), stage["notes"])

# (9) the docs
doc = (ROOT / "docs" / "update-source.md").read_text(encoding="utf-8")
who = next(line for line in doc.splitlines() if line.startswith("Who may change it:"))
must("superuser only" in who and "1.17.5" in who, who)
must("same rule as runtime settings" not in doc, "docs no longer point at the runtime-settings rule")
rdoc = (ROOT / "docs" / "runtime-settings.md").read_text(encoding="utf-8")
must("no longer covers the update source" in rdoc, "runtime-settings.md says manage no longer covers the update source")

print("update source superuser only 1.17.5: ok")
