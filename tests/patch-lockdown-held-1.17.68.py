#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.68 regression (review rounds 1 to 3): the patch lockdown is switched on by AD-41 (Johan, 21 October 2026), with its conditions pinned, and its audit row tells the truth.

Checklist A2 and rule 1.7 allow Core to touch Tactical only for authentication, accounts, AD-13 and AD-19. The lockdown sets two Tactical settings and
wraps Agent.approve_updates. AD-41 in docs/review-accepted-decisions.md records it. Covered. (1) ``DECISION_RECORDED`` is True, and it may be True only
while the accepted-decisions file has a patch lockdown row that names every condition (fail open, never over an administrator's value, only while an
honoured replacement of patching is installed). (2) The switch still works: with the flag False, ``apply_at_startup`` changes nothing in Tactical; with the
module default True and a replacement honoured it sets both settings, wraps the method and leaves an administrator's own value alone. (3) The guards work as before (the 1.17.68 test
pins that). (4) Source: no Core module other than patch_lockdown.py (and the account guards, AD-19) sets a Tactical setting or replaces a Tactical
method, and only apply_at_startup calls the two guards. (5) The audit row says on only when something is in effect (with which part), held when nothing was
switched off, and off when no replacement is honoured; a failing lookup or write never raises.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
pl = load("tec_tac.patch_lockdown", "patch_lockdown.py")
ROOT = Path(__file__).resolve().parents[1]
DECISIONS = ROOT.parents[1] / "docs" / "review-accepted-decisions.md"

# ---- (1) the switch follows the documents
text = DECISIONS.read_text(encoding="utf-8") if DECISIONS.exists() else ""
row = [line for line in text.splitlines() if re.search(r"patch lockdown", line, re.IGNORECASE) and line.lstrip().startswith("|")]
must(pl.DECISION_RECORDED is True, "AD-41 is signed: the lockdown is on by default")
must(bool(row), "DECISION_RECORDED is True but docs/review-accepted-decisions.md has no patch lockdown row")
low = row[0].lower()
must(all(k in low for k in ("fail open", "administrator", "replacement")), "the row must name its conditions: fail open, never over an administrator's value, only for an honoured replacement")
print("       DECISION_RECORDED is True only while the accepted-decisions file records the patch lockdown with its conditions")

# ---- (2) the switch, and the live default
LIVE_SWITCH = pl.DECISION_RECORDED
settings = SimpleNamespace()


class Agent:
    def approve_updates(self):
        return "tactical"


original = Agent.approve_updates
pl._django_settings = lambda: settings
pl._agent_class = lambda: Agent
pl._honoured_pairs = lambda: {"patchmanagement": "patching"}
pl._clear_for_tests()
try:
    pl.DECISION_RECORDED = False
    state = pl.apply_at_startup()
    must(not vars(settings), "no Tactical setting was set")
    must(Agent.approve_updates is original and state["approve_guard_installed"] is False and state["tasks_off"] is False, state)
    print("       switched off in Core: apply_at_startup sets no Tactical setting and wraps no method, even while a replacement is honoured")
finally:
    pl.DECISION_RECORDED = LIVE_SWITCH

# the module default (True) with a replacement honoured, and an administrator's own value
admin = SimpleNamespace(TRMM_DISABLE_APPROVE_UPDATES_TASK=False)
pl._django_settings = lambda: admin
pl._clear_for_tests()
state = pl.apply_at_startup()
must(admin.TRMM_DISABLE_APPROVE_UPDATES_TASK is False, "an administrator's value is never overwritten")
must(admin.TRMM_DISABLE_WINUPDATES_INSTALL_TASK is True, "a switch with no value yet is set")
must(Agent.approve_updates is not original and state["approve_guard_installed"] is True, state)
print("       with the module default and a replacement honoured, the method is wrapped, an unset switch is set and an administrator's value is left alone")
Agent.approve_updates = original
pl._django_settings = lambda: settings
pl._clear_for_tests()

# ---- (3) the guards work, with both settings set from nothing
state = pl.apply_at_startup()
must(settings.TRMM_DISABLE_APPROVE_UPDATES_TASK is True and settings.TRMM_DISABLE_WINUPDATES_INSTALL_TASK is True and Agent.approve_updates is not original and state["approve_guard_installed"] is True, state)
print("       by default, the two settings are set and the method is wrapped")

# ---- (4) source: who touches Tactical's attributes
core = ROOT / "framwork" / "tec_tac"
offenders = []
for path in sorted(core.rglob("*.py")):
    src = path.read_text(encoding="utf-8")
    if path.name != "patch_lockdown.py" and re.search(r"\bsetattr\(\s*(django_)?settings\b|\bsettings\.TRMM_[A-Z_]+\s*=(?!=)", src):
        offenders.append((path.name, "sets a Tactical setting"))
    if path.name not in ("patch_lockdown.py", "tactical_account_guard.py", "tactical_account_guard_fallback.py") and re.search(r"\bAgent\.\w+\s*=(?!=)", src):
        offenders.append((path.name, "replaces an Agent method"))
must(not offenders, offenders)
call_sites = [p.name for p in core.rglob("*.py") if p.name != "patch_lockdown.py" and re.search(r"\b(apply_settings|install_approve_guard)\(", p.read_text(encoding="utf-8"))]
must(not call_sites, call_sites)
guarded = (core / "patch_lockdown.py").read_text(encoding="utf-8")
start = guarded.index("def apply_at_startup")
must(guarded.index("if not DECISION_RECORDED:", start) < guarded.index("apply_settings()", start), "the hold comes before the settings are applied")
print("       no module outside the named exception sets a Tactical setting or replaces a Tactical method; only apply_at_startup calls the two guards, behind the switch")
# ---- (5) the audit row never claims a switch-off that did not happen (review finding: held state)
# The Scheduler tick is a Django management command: AppConfig.ready() runs in that process, so apply_at_startup has filled _STATE there.
tick = (ROOT / "framwork" / "tec_tac" / "management" / "commands" / "tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
must("audit_transition()" in tick, "the tick calls audit_transition")
ROWS = []
PARTS = []
ROW = {"value": None, "fault": False, "write_fault": False}
CLK = [1000.0]
PAIRS = {"value": {}}


def _last():
    if ROW["fault"]:
        raise RuntimeError("audit store unreadable")
    return ROW["value"]


def _write(state, module, previous=None, reason=None, tasks_off_now=None, approve_guard_now=None):
    if ROW["write_fault"]:
        raise RuntimeError("audit store down")
    ROWS.append((state, module, previous, reason))
    PARTS.append((tasks_off_now, approve_guard_now))
    ROW["value"] = state


def reset(recorded=True, tasks=False, pairs=None, guard=False):
    pl._clear_for_tests()
    pl.DECISION_RECORDED = recorded
    pl._STATE["settings"] = {n: True for n in pl.SETTING_NAMES} if tasks else {}
    pl._STATE["guard"] = bool(guard)
    PAIRS["value"] = {"patchmanagement": "patching"} if pairs is None else pairs
    CLK[0] += 31.0
    del ROWS[:]
    del PARTS[:]
    ROW.update(value=None, fault=False, write_fault=False)


pl._clock = lambda: CLK[0]
pl._honoured_pairs = lambda: PAIRS["value"]
pl._last_row_state, pl._write_row = _last, _write
try:
    reset(recorded=False)  # the switch off in Core: held, and the reason says so
    must(pl.in_effect() is False, "switched off: not in effect")
    must(pl.audit_transition() == "held" and ROWS == [("held", "patchmanagement", None, "decision_not_recorded")], ROWS)
    must(pl.audit_transition() is None and len(ROWS) == 1, "the same state again writes nothing")
    PAIRS["value"] = {}
    CLK[0] += 31.0
    must(pl.audit_transition() == "off" and ROWS[-1] == ("off", None, "held", None), ROWS)  # said as 'held had changed nothing', not 'works again'
    must(pl.audit_transition() is None and len(ROWS) == 2, "and nothing again")
    reset(tasks=True)
    must(pl.in_effect() is True and pl.audit_transition() == "on" and ROWS == [("on", "patchmanagement", None, None)] and PARTS == [(True, False)], (ROWS, PARTS))
    PAIRS["value"] = {}
    CLK[0] += 31.0
    must(pl.audit_transition() == "off" and ROWS[-1] == ("off", None, "on", None), ROWS)
    reset(guard=True)  # only the guard is installed: still on, and the row says which part
    must(pl.audit_transition() == "on" and ROWS == [("on", "patchmanagement", None, None)] and PARTS == [(False, True)], (ROWS, PARTS))
    reset(tasks=True, guard=True)
    must(pl.audit_transition() == "on" and PARTS == [(True, True)], PARTS)
    reset()  # flag on, nothing in effect (the method was missing, the settings object refused the write)
    must(pl.in_effect() is False and pl.audit_transition() == "held" and ROWS == [("held", "patchmanagement", None, "not_applied")] and PARTS == [(False, False)], (ROWS, PARTS))
    reset(pairs={})
    must(pl.audit_transition() is None and not ROWS, "never switched on and not honoured: nothing")
    reset()
    ROW["fault"] = True
    must(pl.audit_transition() is None and not ROWS, "a failing lookup writes nothing")
    ROW.update(fault=False, write_fault=True)
    must(pl.audit_transition() is None and not ROWS, "a failing write never raises")
finally:
    pl.DECISION_RECORDED = LIVE_SWITCH
    pl._clear_for_tests()
# the wording, through the real _write_row with a stub audit module
calls = []
src = (ROOT / "framwork" / "tec_tac" / "patch_lockdown.py").read_text(encoding="utf-8")
stub = SimpleNamespace(record=lambda **kw: calls.append(kw), service_audit_actor=lambda **kw: "svc")
import sys as _sys
import types as _types
pkg = _types.ModuleType("wording_pkg")
pkg.audit = stub
_sys.modules["wording_pkg"] = pkg
_sys.modules["wording_pkg.audit"] = stub
src_fn = "def _write_row" + src.split("def _write_row", 1)[1].split("def honoured_module", 1)[0]
ns2 = {"__package__": "wording_pkg", "__name__": "wording_pkg.x", "AUDIT_ACTION": "a", "AUDIT_OBJECT_TYPE": "t", "AUDIT_OBJECT_ID": "w"}
exec(compile(src_fn, "wording", "exec"), ns2)  # noqa: S102 - this repo's own source
ns2["_write_row"]("held", "patchmanagement", None, "decision_not_recorded", False, False)
ns2["_write_row"]("on", "patchmanagement", None, None, True, False)
ns2["_write_row"]("off", None, "held")
ns2["_write_row"]("off", None, "on")
ns2["_write_row"]("held", "patchmanagement", None, "not_applied", False, False)
held_msg, on_msg, off_held_msg, off_on_msg, not_applied_msg = (c["message"] for c in calls)
must("switched off" not in held_msg and "still on" in held_msg and "patchmanagement" in held_msg and calls[0]["metadata"]["state"] == "held" and calls[0]["metadata"]["reason"] == "decision_not_recorded", held_msg)
must("switched off" not in not_applied_msg and "still on" in not_applied_msg and "could not be applied" in not_applied_msg and calls[4]["metadata"]["reason"] == "not_applied", not_applied_msg)
must("is switched off while patchmanagement replaces" in on_msg and "was switched off" not in on_msg, on_msg)
must(calls[1]["metadata"]["tasks_off"] is True and calls[1]["metadata"]["approve_guard"] is False and calls[0]["metadata"]["tasks_off"] is False, "the row says which part is in effect")
must("works again" not in off_held_msg and "changed nothing" in off_held_msg, off_held_msg)
must("works again" in off_on_msg, off_on_msg)
print("       the audit row says held while nothing is switched off, on only when it is (and which part), and works again only after on; a failing lookup or write never raises or repeats")
print("PASS patch lockdown held 1.17.68")
