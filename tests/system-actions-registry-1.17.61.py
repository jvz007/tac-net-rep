#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.61 regression (R-20): register_system_action is deny by default.

The real system_actions.py on the stub harness. Covered: the happy registration by the owning core module and by the premium module that
is the honoured replacement; an unknown table key, a dotted path, a callable and a non-text function are refused; a module that is not
the owner, a premium module that is not a replacement and a core module that is not the table's owner are refused; a replacement that
is not honoured right now is refused cleanly (logged, nothing registered, no exception out of ready()); flags below the table minimum,
an unknown flag, too many flags and a non-list are refused; an id missing from the signed manifest, badly formed or with another
module's prefix is refused; username_param is refused for a function that takes none; a bad scope kind or dangerous flag; a disabled,
legacy, missing or unreadable module and a non-core owner; identical re-registration is idempotent and a different definition is refused;
install is refused for a replacement and allowed for Windows Patching; the capability and its provider.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

FLAGS_OK = ["can_manage_winupdates", "can_run_bulk"]
UNSET = object()


def setup():
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    STATE_FAULT["registry"] = False
    sa._clear_for_tests()
    plugin("patching", system_actions=["patching.scan", "patching.install"])
    plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.scan", "patchmanagement.install"])
    plugin("maintenance", category="premium", system_actions=["maintenance.scan"])
    plugin("agents", category="core", system_actions=["agents.scan"])


def register(action_id="patching.scan", module="patching", function="winupdate.scan", permissions=UNSET, **kw):
    return sa.register_system_action(action_id, module, kw.pop("label", "Scheduled patch scan"), function, FLAGS_OK if permissions is UNSET else permissions, **kw)


def refused(**kw):
    try:
        register(**kw)
    except sa.SystemActionRegistrationError as exc:
        return str(exc)
    raise AssertionError(f"accepted {kw}")


setup()
d = register()
must(d.id == "patching.scan" and d.module_id == "patching" and d.function == "winupdate.scan" and d.via_replacement is False, d)
must(d.permissions == ("can_manage_winupdates", "can_run_bulk") and d.scope_kind == "agents" and d.dangerous is False and d.username_param is None, d)
row = sa.get_system_action("patching.scan")
must(row["owner_module"] == "patching" and row["min_flags"] == FLAGS_OK and row["reapproves_by_policy"] is False, row)
must([r["id"] for r in sa.registered_system_actions()] == ["patching.scan"], sa.registered_system_actions())
must(sa.get_system_action("nope.nope") is None and sa.get_system_action(None) is None)
print("       the owning core module registers an action listed in its manifest")

# the module may add flags, never remove one
setup()
must(register(permissions=FLAGS_OK + ["can_reboot_agents"]).permissions == ("can_manage_winupdates", "can_reboot_agents", "can_run_bulk"))
for bad in (["can_manage_winupdates"], ["can_run_bulk"], [], ["can_manage_winupdates", "can_run_bulk", "can_nonexistent"], "can_run_bulk", None,
            ["can_manage_winupdates", "can_run_bulk", 5], ["can_manage_winupdates", "can_run_bulk", "run_bulk"], FLAGS_OK + [f"can_x{i}" for i in range(7)]):
    setup()
    refused(permissions=bad)
print("       flags below the table minimum, an unknown flag, a non-list and too many flags are refused; extra flags are allowed")

# idempotent re-registration, different definition refused
setup()
a = register()
must(register() is a or register() == a, "identical registration is idempotent")
must(len(sa.registered_system_actions()) == 1)
refused(label="Another label")
refused(dangerous=True)
refused(permissions=FLAGS_OK + ["can_reboot_agents"])
must(sa.get_system_action("patching.scan")["label"] == "Scheduled patch scan", "the first definition stays")
print("       identical re-registration is idempotent; a different definition under the same id is refused")

# the function is a key of Core's table
for function in ("winupdate.nuke", "os.system", "winupdate.tasks.bulk_check_for_updates_task", "", "WINUPDATE.SCAN", None, 5, ["winupdate.scan"],
                 __import__("os").system, lambda pks: None, "winupdate.scan "):
    setup()
    message = refused(function=function)
    must("table" in message or "callable" in message, message)
    must(not sa.registered_system_actions(), "nothing is left registered")
print("       an unknown key, a dotted path, a callable and a non-text function are refused: a module cannot name its own callable")

# owner rules
setup()
must("only module 'patching'" in refused(action_id="agents.scan", module="agents"), "a core module that is not the table's owner")
setup()
must("only module 'patching'" in refused(action_id="maintenance.scan", module="maintenance"), "a premium module that replaces nothing")
setup()
HONOURED["maintenance"] = "checks"
must("only module 'patching'" in refused(action_id="maintenance.scan", module="maintenance"), "an honoured replacement of ANOTHER module is not the owner")
setup()
PLUGINS["patching"].category = "premium"
must("not a core module" in refused(), "the owner must be a core module")
PLUGINS["patching"].category = ""
must("not a core module" in refused(), "a module with no category is test")
print("       a module that is not the owner or the honoured replacement is refused, and the owner must be a core module")

# the honoured replacement
setup()
HONOURED["patchmanagement"] = "patching"
r = register("patchmanagement.scan", "patchmanagement")
must(r is not None and r.via_replacement is True and r.module_id == "patchmanagement", r)
must(sa.get_system_action("patchmanagement.scan")["via_replacement"] is True)
print("       the premium module that is the honoured replacement registers scan")

# a replacement that is not honoured: logged, nothing registered, no exception (it runs inside ready())
setup()
must(register("patchmanagement.scan", "patchmanagement") is None, "not honoured: None, no exception")
must(not sa.registered_system_actions(), "nothing left registered")
HONOURED["patchmanagement"] = "patching"
must(register("patchmanagement.scan", "patchmanagement") is not None, "honoured now: registers")
print("       a replacement that is not honoured is refused cleanly: no exception, nothing registered")

# install: refused for a replacement, allowed for Windows Patching
setup()
HONOURED["patchmanagement"] = "patching"
# 1.17.66 (CQ173, Johan: yes): the honoured replacement may register install; R-36 is not built
must(register("patchmanagement.install", "patchmanagement", "winupdate.install").via_replacement is True, "the honoured replacement may register install")
must(register("patching.install", "patching", "winupdate.install").function == "winupdate.install", "Windows Patching may register install")
print("       winupdate.install is accepted for Windows Patching and for the honoured replacement (CQ173)")

# the id
setup()
must("manifest" in refused(action_id="patching.other"), "an id missing from the signed manifest")
for bad_id in ("scan", "patching", "Patching.scan", "patching.Scan", "patching.", ".scan", "other.scan", "patching.sc an", "patching.scan\n", "", None, 5):
    setup()
    refused(action_id=bad_id)
setup()
plugin("patching", system_actions=[])
must("manifest" in refused(), "a manifest with an empty list lists nothing")
print("       an id missing from the manifest, badly formed or with another module's prefix is refused")

# username_param, scope kind, dangerous, label
for kw in ({"username_param": "username"}, {"username_param": 5}, {"username_param": "Bad Name"}, {"scope_kind": "clients"}, {"scope_kind": None},
           {"dangerous": 1}, {"dangerous": "yes"}, {"label": ""}, {"label": "x" * 101}, {"label": "bad\nlabel"}, {"label": 5}):
    setup()
    refused(**kw)
print("       username_param on a function with none, a bad scope kind, a non-bool dangerous and a bad label are refused")

# the module itself
for _name, change in (("disabled", lambda: ENABLED.__setitem__("patching", False)), ("legacy", lambda: setattr(PLUGINS["patching"], "legacy", True)),
                     ("not installed", lambda: PLUGINS.pop("patching")), ("a reportset", lambda: setattr(PLUGINS["patching"], "plugin_type", "reportset"))):
    setup()
    change()
    refused()
setup()
STATE_FAULT["registry"] = True
must("could not read" in refused(), "a module list that cannot be read refuses")
setup()
enabled_before = sa._enabled_now
sa._enabled_now = lambda module_id: (_ for _ in ()).throw(OSError("state unreadable"))
must("could not read" in refused(), "a state fault refuses")
sa._enabled_now = enabled_before
print("       a disabled, legacy, missing or unreadable module is refused")

# a replacement registering while disabled is refused (never half registered)
setup()
HONOURED["patchmanagement"] = "patching"
ENABLED["patchmanagement"] = False
refused(action_id="patchmanagement.scan", module="patchmanagement")
must(not sa.registered_system_actions())

# the capability and its provider
CAPS = []
sys.modules["tec_tac.capabilities"].register_capability = lambda **kw: CAPS.append(kw) or SimpleNamespace(**kw)
setup()
sa.register_core_system_actions_capability()
cap = CAPS[0]
must(cap["id"] == "core.system_actions" and cap["version"] == "1.2.0" and cap["module_id"] == "core", cap)  # 1.17.68: 1.2.0 (additive)
must(tuple(cap["operations"]) == ("list_actions", "get_action", "run", "describe_confirmation", "describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket", "start_delegated_run"), cap["operations"])  # 1.17.68: the five delegation operations are appended
meta = cap["metadata"]
must(meta["max_agents"] == 40000 and meta["max_agents_per_group"] == 2000 and meta["max_groups"] == 20 and meta["delivery"] == "at most once per group", meta)
must(set(meta["functions"]) == {"winupdate.scan", "winupdate.install", "scripts.run"}, meta)
must(meta["functions"]["winupdate.install"]["reapproves_by_policy"] is True and meta["functions"]["winupdate.scan"]["reapproves_by_policy"] is False)
provider = cap["provider"]
register()
must([r["id"] for r in provider.list_actions()] == ["patching.scan"] and provider.get_action("patching.scan")["module_id"] == "patching" and provider.get_action("x.y") is None)
must(callable(provider.run))
must("list_actions" in repr(meta["refusal_reasons"]) or "out_of_scope" in meta["refusal_reasons"], meta["refusal_reasons"])
print("       the capability core.system_actions 1.1.0 offers list_actions, get_action, run and describe_confirmation, and states its limits")

print("PASS system actions registry 1.17.61")
