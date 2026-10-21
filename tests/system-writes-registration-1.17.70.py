#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.70 regression (CQ203, AD-45): who may register the write row winupdate.set_action.

The real system_actions.py on the stub harness. Covered: the module that is the honoured replacement of patching registers it; Windows Patching itself is
refused (it uses a person's own request); a premium module that replaces nothing is refused; a premium module that is honoured for ANOTHER group is refused;
a premium module that replaces patching but is not honoured right now is not registered (None, no exception, as for the other rows); an unrelated premium
module and a core module that owns another group are refused; a disabled module, an action id missing from the signed manifest, a missing minimum flag, a
username_param and a different second definition under the same id are refused; registering the identical definition again is idempotent.
"""
from __future__ import annotations

from pathlib import Path

H = Path(__file__).resolve().parent / "system-writes-harness-1.17.70.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input


def reg(module, action_id=None, **kw):
    kw.setdefault("dangerous", True)
    return sa.register_system_action(action_id or f"{module}.setaction", module, "Set update decisions", "winupdate.set_action", kw.pop("permissions", WRITE_FLAGS), **kw)


def refused(call, text=None):
    try:
        call()
    except sa.SystemActionRegistrationError as exc:
        if text:
            must(text in str(exc), str(exc))
        return exc
    raise AssertionError("registered instead of refused")


def world():
    fresh(0)
    sa._clear_for_tests()
    plugin("scriptexecution", system_actions=["scriptexecution.setaction"])
    plugin("rival", category="premium", replaces="", system_actions=["rival.setaction"])
    plugin("scriptsplus", category="premium", replaces="scriptexecution", system_actions=["scriptsplus.setaction"])
    plugin("lapsed", category="premium", replaces="patching", system_actions=["lapsed.setaction"])
    plugin("sidegrade", category="premium", replaces="patching", system_actions=["sidegrade.setaction"])
    plugin("other", category="premium", replaces="", system_actions=["other.setaction"])
    HONOURED["scriptsplus"] = "scriptexecution"  # honoured, but for ANOTHER group
    # "lapsed" replaces patching and is NOT honoured (nothing in HONOURED for it)
    HONOURED["sidegrade"] = "patching"  # a second honoured claim: still its own module, judged on its own


# ---- the honoured replacement registers
world()
got = reg("patchmanagement")
must(got is not None and got.via_replacement is True and got.function == "winupdate.set_action" and got.permissions == WRITE_FLAGS and got.dangerous is True, got)
must(sa.is_registered_system_action("patchmanagement", "patchmanagement.setaction"), "registered")
again = reg("patchmanagement")
must(again == got, "the identical definition is idempotent")
refused(lambda: sa.register_system_action("patchmanagement.setaction", "patchmanagement", "A different label", "winupdate.set_action", WRITE_FLAGS, dangerous=True), "already registered")
print("       the honoured replacement of patching registers it; the identical definition is idempotent; a different one is refused")

# ---- Windows Patching itself is refused
world()
refused(lambda: reg("patching"), "never by 'patching' itself")
must(not sa.registered_system_actions(), "nothing registered")
print("       Windows Patching itself is refused")

# ---- a premium module that replaces nothing, one honoured for another group, an unrelated one, a core module of another group
world()
refused(lambda: reg("rival"), "may register")
refused(lambda: reg("scriptsplus"), "may register")
refused(lambda: reg("other"), "may register")
refused(lambda: reg("scriptexecution"), "may register")
must(not sa.registered_system_actions(), "nothing registered")
print("       a premium module that replaces nothing, one honoured for another group, an unrelated premium module and a core module of another group are refused")

# ---- replaces patching but is not honoured right now: logged, not registered, no exception
world()
HONOURED.pop("patchmanagement")
must(reg("patchmanagement") is None, "a replacement that is not honoured right now is not registered")
must(reg("lapsed") is None, "a module that replaces patching but was never honoured is not registered")
must(not sa.registered_system_actions(), "nothing registered")
print("       a replacement of patching that is not honoured right now is not registered (None, no exception)")

# ---- the common rules still apply
world()
ENABLED["patchmanagement"] = False
refused(lambda: reg("patchmanagement"), "not enabled")
ENABLED["patchmanagement"] = True
PLUGINS["patchmanagement"].system_actions = ()
refused(lambda: reg("patchmanagement"), "signed manifest")
PLUGINS["patchmanagement"].system_actions = ("patchmanagement.setaction",)
refused(lambda: reg("patchmanagement", permissions=("can_run_bulk",)), "minimum flag")
refused(lambda: reg("patchmanagement", username_param="who"), "no username")
refused(lambda: reg("patchmanagement", dangerous=False), "dangerous=True")
refused(lambda: reg("patchmanagement", delegable_to=["maintenance"]), "delegable_to must be empty")
refused(lambda: reg("patchmanagement", action_id="patching.setaction"))
must(not sa.registered_system_actions(), "nothing registered")
extra_flag = reg("patchmanagement", permissions=("can_manage_winupdates", "can_run_bulk"))
must(extra_flag is not None and set(extra_flag.permissions) == {"can_manage_winupdates", "can_run_bulk"}, "a module may add flags, never remove one")
print("       disabled, not in the manifest, a missing flag, a username, dangerous false, delegable_to and another module's prefix are refused; extra flags are allowed")

# ---- a task row is unchanged: patching registers scan, the replacement registers install
world()
must(sa.register_system_action("patching.scan", "patching", "scan", "winupdate.scan", BOTH) is not None, "Windows Patching still registers scan")
plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.install"])
must(sa.register_system_action("patchmanagement.install", "patchmanagement", "install", "winupdate.install", BOTH).via_replacement is True, "the replacement still registers install")
print("       the task rows register exactly as before")
print("PASS system writes registration 1.17.70")
