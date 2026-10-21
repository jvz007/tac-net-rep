#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.68 regression (Johan, 21 October 2026; the former R-36): Tactical's own patch policy is switched off while Advanced Patch Management is honoured.

Johan: "the tactical patch policy must be disabled when APM is installed so that this doesn't happen." The real patch_lockdown.py, system_actions.py and
system_action_confirmation.py on the stub harness of scheduler-completion-harness-1.17.61.py, with a fake Tactical Agent and a fake settings object.

Covered. (1) active() is True only while a replacement of patching is honoured, is cached for 30 seconds, and an unreadable state answers False and logs once
(a fault never switches Tactical's patching off). (2) The two documented switches are set True when active, left alone when not, and an administrator's value
is never lowered or changed. (3) Agent.approve_updates is inert when active (an update set to Ignore is not flipped back) and calls Tactical's own method
unchanged when not; the install is idempotent, keeps the method's name and a failing install fails open (status says so, nothing raises). (4) status() and the
capability core.patch_lockdown 1.0.0. (5) The Scheduler tick step writes one audit row only when the state differs from the newest row, never raises and is
never strict. (6) The re-approve warning goes from an install by the honoured replacement only while the approve is inert in the process; Windows Patching's
own install and every other case keep it; the audit row of a run says which. (7) Nothing in Core writes a Tactical row for this: no model write, no policy
edit, and the declared operations are not touched (read as source). (8) Tactical v1.5.2 still has what the guards rely on (read as source when the reference is here).
"""
from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
logging.disable(logging.NOTSET)
pl = load("tec_tac.patch_lockdown", "patch_lockdown.py")
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"

CLOCK = [1000.0]
PAIRS = {"value": {}}
READS = []


def pairs():
    READS.append(1)
    if isinstance(PAIRS["value"], Exception):
        raise PAIRS["value"]
    return PAIRS["value"]


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


capture = Capture()
logging.getLogger("tec_tac.patch_lockdown").addHandler(capture)
logging.getLogger("tec_tac.patch_lockdown").setLevel(logging.DEBUG)


def fresh_lockdown(value=None):
    pl._clear_for_tests()
    pl._clock = lambda: CLOCK[0]
    pl._honoured_pairs = pairs
    PAIRS["value"] = {"patchmanagement": "patching"} if value is None else value
    del READS[:], capture.records[:]
    CLOCK[0] += 1000.0  # a clean cache window


# ---- (1) when it is active
fresh_lockdown()
must(pl.active() is True and pl.honoured_module() == "patchmanagement", "an honoured replacement of patching")
for other in ({}, {"other": "checks"}, {"patchmanagement": "software"}):
    fresh_lockdown(other)
    must(pl.active() is False and pl.honoured_module() is None, other)
fresh_lockdown()
pl.active()
pl.active()
pl.active()
must(len(READS) == 1, "read once inside the cache window")
CLOCK[0] += 29.0
pl.active()
must(len(READS) == 1, "still cached after 29 seconds")
CLOCK[0] += 2.0
pl.active()
must(len(READS) == 2, "read again after 30 seconds")
PAIRS["value"] = {}
must(pl.active() is True, "the answer of the old window is kept until it ends")
CLOCK[0] += 31.0
must(pl.active() is False, "and the replacement stopping being honoured switches it off")
fresh_lockdown(RuntimeError("module state unreadable"))
must(pl.active() is False and pl.honoured_module() is None, "an unreadable state is inactive: Tactical keeps patching")
CLOCK[0] += 31.0
pl.active()
CLOCK[0] += 31.0
pl.active()
warnings = [r for r in capture.records if r.levelno == logging.WARNING]
must(len(warnings) == 1, f"one log line for repeated faults, not {len(warnings)}")
PAIRS["value"] = {"patchmanagement": "patching"}
CLOCK[0] += 31.0
must(pl.active() is True, "and it recovers once the state can be read")
print("       active only while a replacement of patching is honoured; cached 30 seconds; an unreadable state is inactive, logged once, and recovers")

# ---- (2) the two switches
fresh_lockdown()
target = SimpleNamespace()
got = pl.apply_settings(target)
must(target.TRMM_DISABLE_APPROVE_UPDATES_TASK is True and target.TRMM_DISABLE_WINUPDATES_INSTALL_TASK is True and got == {n: True for n in pl.SETTING_NAMES}, (vars(target), got))
must(pl.tasks_off() is True, "tasks_off")
fresh_lockdown({})
target = SimpleNamespace()
must(pl.apply_settings(target) == {} and not vars(target) and pl.tasks_off() is False, "inactive: nothing is set")
fresh_lockdown()
target = SimpleNamespace(TRMM_DISABLE_APPROVE_UPDATES_TASK=False, TRMM_DISABLE_WINUPDATES_INSTALL_TASK=True)
got = pl.apply_settings(target)
must(target.TRMM_DISABLE_APPROVE_UPDATES_TASK is False and target.TRMM_DISABLE_WINUPDATES_INSTALL_TASK is True, "an administrator's value is never changed, not even to switch Tactical's task off")
must(got == {"TRMM_DISABLE_APPROVE_UPDATES_TASK": False, "TRMM_DISABLE_WINUPDATES_INSTALL_TASK": True} and pl.tasks_off() is False, "and status says the tasks are not all off")


class ReadOnlySettings:
    def __setattr__(self, name, value):
        raise AttributeError("settings are locked")


fresh_lockdown()
got = pl.apply_settings(ReadOnlySettings())
must(got == {n: False for n in pl.SETTING_NAMES} and pl.tasks_off() is False, "a settings object that refuses a write fails open")
src = (APP / "patch_lockdown.py").read_text(encoding="utf-8")
must("= False" not in src.split("def apply_settings", 1)[1].split("def tasks_off", 1)[0].replace("result[name] = False", ""), "the code never sets a switch to False")
print("       both switches are set True when active, never changed when an administrator set them, never set False, and a refusing settings object fails open")


# ---- (3) the guard on Agent.approve_updates
class FakeAgent:
    calls = []

    def approve_updates(self):
        """Tactical's own method."""
        FakeAgent.calls.append(self)
        return "approved"


def install_with(agent_class):
    pl._agent_class = lambda: agent_class
    return pl.install_approve_guard()


fresh_lockdown()
original = FakeAgent.approve_updates
must(install_with(FakeAgent) is True and pl.status()["approve_guard_installed"] is True, "installed")
wrapped = FakeAgent.approve_updates
must(wrapped is not original and wrapped.__name__ == "approve_updates" and wrapped.__doc__ == original.__doc__ and getattr(wrapped, pl.GUARD_MARKER) is True, "wraps and keeps the name")
must(install_with(FakeAgent) is True and FakeAgent.approve_updates is wrapped, "installing twice wraps once")
agent = FakeAgent()
FakeAgent.calls.clear()
must(agent.approve_updates() is None and not FakeAgent.calls, "active: it returns without approving anything, so an update set to Ignore is not flipped back")
PAIRS["value"] = {}
CLOCK[0] += 31.0
must(agent.approve_updates() == "approved" and FakeAgent.calls == [agent], "not active: Tactical's own method runs unchanged and returns its own answer")
PAIRS["value"] = RuntimeError("unreadable")
CLOCK[0] += 31.0
FakeAgent.calls.clear()
must(agent.approve_updates() == "approved" and FakeAgent.calls == [agent], "an unreadable state means Tactical's own approve still runs")
PAIRS["value"] = {"patchmanagement": "patching"}
CLOCK[0] += 31.0


class Broken:
    pass


pl._clear_for_tests()
pl._clock = lambda: CLOCK[0]
must(install_with(Broken) is False and pl.status()["approve_guard_installed"] is False, "no approve_updates on the class: the guard fails open")
pl._agent_class = lambda: (_ for _ in ()).throw(ImportError("agents.models is not available"))
must(pl.install_approve_guard() is False, "an import failure fails open")
must(any(r.levelno == logging.WARNING for r in capture.records), "one log line")
must(pl.apply_at_startup()["approve_guard_installed"] is False, "apply_at_startup never raises")
print("       approve_updates is inert only while active, calls Tactical's own method otherwise (also when the state is unreadable), installs once, and a failed install fails open")

# ---- (4) status and the capability
fresh_lockdown()
install_with(FakeAgent)
pl.apply_settings(SimpleNamespace())
must(pl.status() == {"active": True, "honoured_module": "patchmanagement", "tasks_off": True, "approve_guard_installed": True}, pl.status())
must(pl.approve_neutralised() is True, "active and guarded in this process")
PAIRS["value"] = {}
CLOCK[0] += 31.0
must(pl.status()["active"] is False and pl.approve_neutralised() is False, "no longer honoured: not neutralised")
registered = []
mod("tec_tac.capabilities", register_capability=lambda **kw: registered.append(kw) or kw, capability_status=None, CapabilityDisabled=Exception, CapabilityUnavailable=Exception,
    CapabilityVersionMismatch=Exception, CapabilityUnhealthy=Exception)
pl.register_core_patch_lockdown_capability()
cap = registered[0]
must(cap["id"] == "core.patch_lockdown" and cap["module_id"] == "core" and cap["version"] == "1.0.0" and tuple(cap["operations"]) == ("status",), cap)
must(cap["provider"].status() == pl.status() and cap["metadata"]["writes_tactical_data"] is False and cap["metadata"]["requires_framework"] == ">=1.17.68", cap["metadata"])
must("not_blocked" in cap["metadata"] and "set-update-action" in cap["metadata"]["not_blocked"] and "fails" in cap["metadata"], "the declared operations are named as not blocked")
print("       status and the capability core.patch_lockdown 1.0.0 answer the four keys; it writes no Tactical data")

# ---- (5) the tick step
AUDIT_ROWS = []
ROW_STATE = {"value": None, "fault": False, "write_fault": False}


def last_state():
    if ROW_STATE["fault"]:
        raise RuntimeError("audit store unreadable")
    return ROW_STATE["value"]


def write_row(state, module, previous=None, reason=None, tasks_off_now=None, approve_guard_now=None):
    if ROW_STATE["write_fault"]:
        raise RuntimeError("audit store down")
    AUDIT_ROWS.append((state, module))
    ROW_STATE["value"] = state


pl._last_row_state, pl._write_row = last_state, write_row
fresh_lockdown({})
del AUDIT_ROWS[:]
ROW_STATE.update(value=None, fault=False, write_fault=False)
must(pl.audit_transition() is None and not AUDIT_ROWS, "never switched on and not on now: nothing to say")
ORIGINAL_SWITCH = pl.DECISION_RECORDED
pl.DECISION_RECORDED = True  # the 'on' row needs the lockdown in effect in this process; the 'held' states are in patch-lockdown-held-1.17.68.py
PAIRS["value"] = {"patchmanagement": "patching"}
pl._STATE["settings"] = {n: True for n in pl.SETTING_NAMES}
CLOCK[0] += 31.0
must(pl.audit_transition() == "on" and AUDIT_ROWS == [("on", "patchmanagement")], AUDIT_ROWS)
must(pl.audit_transition() is None and len(AUDIT_ROWS) == 1, "the same state writes nothing again")
PAIRS["value"] = {}
CLOCK[0] += 31.0
must(pl.audit_transition() == "off" and AUDIT_ROWS[-1] == ("off", None), AUDIT_ROWS)
must(pl.audit_transition() is None and len(AUDIT_ROWS) == 2, "and again nothing")
ROW_STATE["fault"] = True
PAIRS["value"] = {"patchmanagement": "patching"}
CLOCK[0] += 31.0
pl._STATE["settings"] = {n: True for n in pl.SETTING_NAMES}
must(pl.audit_transition() is None and len(AUDIT_ROWS) == 2, "a lookup that cannot run writes nothing, so a broken lookup can never repeat a row every tick")
ROW_STATE.update(fault=False, write_fault=True)
must(pl.audit_transition() is None, "a failing write never raises out of the tick")
real_write = pl.__dict__["_write_row"]
audit_calls = []
mod("tec_tac.audit", record=lambda **kw: audit_calls.append(kw) or {"recorded": True}, service_audit_actor=lambda **kw: SimpleNamespace(kind="service", **kw), _auditlog_model=None)
pl.__dict__["_write_row"] = type(pl).__dict__.get("_unused", None) or None
src = (APP / "patch_lockdown.py").read_text(encoding="utf-8")
body = src.split("def _write_row", 1)[1].split("def honoured_module", 1)[0]
must('action=AUDIT_ACTION' in body and 'object_type=AUDIT_OBJECT_TYPE' in body and "strict=False" in body and "service_audit_actor" in body and "metadata=metadata" in body and "\"state\": state" in body, "one non-strict service row with the state and the module id")
must(pl.AUDIT_ACTION == "custom:tactical-patch-lockdown" and pl.AUDIT_OBJECT_TYPE == "tactical_patch_lockdown", "the row names")
tick = (APP / "management" / "commands" / "tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
step = tick.split("from tec_tac.patch_lockdown import audit_transition", 1)
must(len(step) == 2 and "audit_transition()" in step[1].split("except Exception:", 1)[0] and "warning(" in step[1].split("except Exception:", 1)[1].split("\n\n", 1)[0], "a guarded tick step that logs a fault")
must(tick.index("audit_finished_system_updates()") < tick.index("audit_transition()") < tick.index("sweep_state = "), "after the other steps, before the tick's own line")
pl.__dict__["_write_row"] = real_write
pl.DECISION_RECORDED = ORIGINAL_SWITCH
print("       the tick writes one non-strict row only when the state differs from the newest row; a failing lookup or write never raises and never repeats")

# ---- (6) the warning
roots = {}


def setup_world():
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    sched._ACTIONS.clear()
    roots["patching"] = plugin("patching", system_actions=["patching.install", "patching.handler"])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.install", "patchmanagement.handler"])
    HONOURED["patchmanagement"] = "patching"


BOTH = ("can_manage_winupdates", "can_run_bulk")
alice = User("alice")
reset()
setup_world()
sa.register_system_action("patching.install", "patching", "Windows Patching install", "winupdate.install", BOTH)
sa.register_system_action("patchmanagement.install", "patchmanagement", "APM install", "winupdate.install", BOTH)
sa.register_system_action("patching.handler", "patching", "h", "winupdate.install", BOTH)
sa.register_system_action("patchmanagement.handler", "patchmanagement", "h", "winupdate.install", BOTH)
entry = sa.SYSTEM_FUNCTIONS["winupdate.install"]
scan_entry = sa.SYSTEM_FUNCTIONS["winupdate.scan"]
own, repl = sa._ACTIONS["patching.install"], sa._ACTIONS["patchmanagement.install"]
fresh_lockdown({"patchmanagement": "patching"})
pl._agent_class = lambda: FakeAgent
FakeAgent.approve_updates = original
pl.install_approve_guard()
pl.apply_settings(SimpleNamespace())
must(sa._reapprove_warning_applies(repl, entry) is False, "the replacement's install: Tactical's own approve is inert here, so no warning")
must(sa._reapprove_warning_applies(own, entry) is True, "Windows Patching's own install keeps the warning")
must(sa._reapprove_warning_applies(repl, scan_entry) is False, "a scan never had one")
must(sa.get_system_action("patchmanagement.install")["warning"] is None and sa.get_system_action("patching.install")["warning"] == sa.REAPPROVE_WARNING, "list_actions says the same")
pl._STATE["guard"] = False
must(sa._reapprove_warning_applies(repl, entry) is True and sa.get_system_action("patchmanagement.install")["warning"] == sa.REAPPROVE_WARNING, "the guard is not installed in this process: the warning stays")
pl._STATE["guard"] = True
PAIRS["value"] = {}
CLOCK[0] += 31.0
must(sa._reapprove_warning_applies(repl, entry) is True, "the lockdown is not active: the warning stays")
PAIRS["value"] = {"patchmanagement": "patching"}
CLOCK[0] += 31.0
sa._reapprove_warning_applies.__doc__ and None
must(sa._reapprove_warning_applies(None, entry) is True, "no definition: the warning stays")
# the confirmation text
text_with = conf._text({"definition": repl, "entry": entry, "cleaned": {}, "total": 3, "groups": 1, "vanished": 0}, alice, {"schedule_type": "daily", "run_time": "03:00"})
text_own = conf._text({"definition": own, "entry": entry, "cleaned": {}, "total": 3, "groups": 1, "vanished": 0}, alice, {"schedule_type": "daily", "run_time": "03:00"})
must(sa.REAPPROVE_WARNING not in text_with and sa.REAPPROVE_WARNING in text_own, "the confirmation text drops the warning only for the replacement")
# the audit row of a run
IDS = [41, 42]
CFG = {"action_id": "patchmanagement.install"}
HANDLER = "def handler(context):\n    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=IDS)\n"
sched._ACTIONS["patchmanagement.handler"] = sched.ScheduledAction("patchmanagement.handler", "patchmanagement", "h", compile_as(roots["patchmanagement"] / "h.py", HANDLER, sa=sa, CFG=CFG, IDS=IDS)["handler"], "", ("endpoint",), timeout_seconds=600)
sched._ACTIONS["patching.handler"] = sched.ScheduledAction("patching.handler", "patching", "h", compile_as(roots["patching"] / "h.py", HANDLER, sa=sa, CFG=CFG, IDS=IDS)["handler"], "", ("endpoint",), timeout_seconds=600)
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = set(IDS)


def install_run(module):
    CFG["action_id"] = f"{module}.install"
    del AUDITS[:]
    run = make_run(f"{module}.handler", module, user=alice, owner="user", targets={"type": "endpoint", "ids": [str(i) for i in IDS]})
    run.schedule.created_by_username = "alice"
    out = go(run)
    must(isinstance(out, dict) and out["outcome"] == "queued", out)
    return [a for a in AUDITS if a["action"] == "run"][0]["metadata"]


meta = install_run("patchmanagement")
must("warning" not in meta and meta["patch_lockdown"] == "active", meta)
meta = install_run("patching")
must(meta["warning"] == sa.REAPPROVE_WARNING and "patch_lockdown" not in meta, meta)
pl._STATE["guard"] = False
meta = install_run("patchmanagement")
must(meta["warning"] == sa.REAPPROVE_WARNING and "patch_lockdown" not in meta, "without the guard in this process the audit row keeps the warning")
print("       the warning goes from the replacement's install only while the approve is inert here; Windows Patching, an inactive lockdown and a missing guard keep it; the audit row says which")

# ---- (7) no Tactical write, no operation touched
for forbidden in ("WinUpdatePolicy", "objects.update", ".save(", "objects.create", "winupdate.models", "requests.", "tactical_operations.run", "register_tactical_operation", "nats"):
    must(forbidden not in src.split('"""', 2)[2], f"patch_lockdown.py must not contain {forbidden!r}")
apps = (APP / "apps.py").read_text(encoding="utf-8")
must("from .patch_lockdown import apply_at_startup, register_core_patch_lockdown_capability" in apps and apps.index("install_tactical_account_guard()") < apps.index("apply_at_startup()") < apps.index("install_tactical_reporting_bridge()"), "ready() applies it after the account guard, before the reporting bridge")
guard_block = apps.split("apply_at_startup()", 1)[1].split("except Exception:", 1)[1].split("\n", 2)[1]
must("logger.exception" in guard_block, "a fault is logged and never aborts start-up")
tick_ops = (APP / "tactical_operations.py").read_text(encoding="utf-8")
must("patch_lockdown" not in tick_ops, "the declared operations are untouched")
print("       Core writes no Tactical row for this; ready() applies it guarded, and the declared operations are not touched")

# ---- (8) the reference still has what the guards rely on
reference = ROOT.parents[1] / "reference" / "tacticalrmm" / "api" / "tacticalrmm"
if reference.is_dir():
    tasks_src = (reference / "winupdate" / "tasks.py").read_text(encoding="utf-8")
    must('getattr(settings, "TRMM_DISABLE_APPROVE_UPDATES_TASK", False)' in tasks_src and 'getattr(settings, "TRMM_DISABLE_WINUPDATES_INSTALL_TASK", False)' in tasks_src, "Tactical's documented switches")
    must("agent.approve_updates()" in (reference / "winupdate" / "views.py").read_text(encoding="utf-8") and "def approve_updates(self) -> None:" in (reference / "agents" / "models.py").read_text(encoding="utf-8"), "the method the guard wraps")
    print("       Tactical v1.5.2 still has the two switches and the method")
else:
    print("       the Tactical reference is not on this PC: skipped")
print("PASS patch lockdown 1.17.68")
