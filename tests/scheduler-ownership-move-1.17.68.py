#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.68 regression (Johan, 21 October 2026, Q-APM12 option b): the ownership of a schedule moves to the next person who edits it.

Johan: "when a profile is then edited by another engineer the ownership will move to him." The real scheduler.py (reconcile_schedule and its helpers)
on the stub harness of scheduler-completion-harness-1.17.61.py.

Covered. (1) A different person who edits a module-owned schedule through reconcile_schedule becomes the owner: created_by, created_by_username,
confirmed_by_username and updated_by name them, their scope is stored, and ONE strict 'modify' audit row carries owner_changed_from,
owner_changed_to and previous_confirmed_by. (2) The unchanged permission and scope checks still run first. (3) A person whose own Tactical scope
does not cover every target is refused with the plain text from the plan (CQ205 a: never widens): the schedule is exactly as it was, no audit
row of a change is written, one deny row is. A scheduler manager has no bypass here. (4) The same person again moves nothing. (5) A module call
without a request still cannot change a person's schedule, and an installer user or an inactive person cannot take it over. (6) A call that only
switches the schedule off does not move it. (7) A schedule whose creator row is gone (SET_NULL) moves to the next editor. (8) The browser
PATCH follows the same rule (read as source). (9) The schedule keeps every earlier behaviour: a first creation, signatures, the module-owned
schedule with no stored creator.
"""
from __future__ import annotations

import inspect
from datetime import time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True

BOTH = ("can_manage_winupdates", "can_run_bulk")
alice, bob, carol, dave = User("alice"), User("bob"), User("carol"), User("dave", active=False)


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
views = sys.modules["tec_tac.scheduler_views"]
PERMS = {"alice": True, "bob": True, "carol": True, "dave": True}
COVER = {"alice": True, "bob": True, "carol": False, "dave": True}  # carol's own scope does not cover the targets
LIVE = {"alice": True, "bob": True, "carol": True, "dave": True}  # the old rule (a scheduler manager passes): not what a takeover asks
views._can_use_action = lambda user, action: PERMS.get(user.username, False)
views._can_access_target_scope = lambda user, targets, strict=False, **kw: COVER.get(user.username, False) if strict else LIVE.get(user.username, False)

_orig_save = Schedule.save
SAVE_COUNT = []


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    SAVE_COUNT.append(update_fields)
    _orig_save(self, update_fields)


Schedule.save = _save
plugin("patching", system_actions=[])


def handler(context):
    return {"ok": True}


sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=handler, target_types=("none", "endpoint"))
KW = dict(owner_module="patching", owner_key="nightly", action_id="patching.scan", schedule_type="daily", run_time=time(3, 0), targets={"type": "none"})
DESCRIPTORS_BY = {"alice": {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []},
                  "bob": {"mode": "clients", "unrestricted": False, "whole_client_ids": [20], "site_ids": []},
                  "carol": {"mode": "none", "unrestricted": False, "whole_client_ids": [], "site_ids": []}}


def fresh():
    reset()
    del SAVE_COUNT[:]
    for who in PERMS:
        PERMS[who] = True
    COVER.update(alice=True, bob=True, carol=False, dave=True)
    LIVE.update(alice=True, bob=True, carol=True, dave=True)
    DESCRIPTORS.update({k: dict(v) for k, v in DESCRIPTORS_BY.items()})
    for who in ("alice", "bob", "carol", "dave"):
        FLAGS[who] = set(BOTH)


def rows():
    return [r for r in Schedule.objects.rows if r.owner_module == "patching"]


def audit_rows(action=None):
    return [a for a in AUDITS if a["object_type"] == "scheduler_schedule" and (action is None or a["action"] == action)]


def refused(call, kind=sched.SchedulerError):
    try:
        call()
    except kind as exc:
        return exc
    raise AssertionError("the call was accepted")


def state_of(schedule):
    return {k: getattr(schedule, k) for k in ("created_by", "created_by_username", "confirmed_by_username", "updated_by", "creation_scope", "targets", "enabled", "run_time", "schedule_type")}


# ---- (1) the next editor becomes the owner
fresh()
created = sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
must(created.created_by is alice and created.created_by_username == "alice" and created.creation_scope["captured_for"] == "alice", created.__dict__)
del AUDITS[:]
moved = sched.reconcile_schedule(**{**KW, "run_time": time(4, 30)}, confirmed_by_request=RealRequest(bob))
must(moved is created and moved.created_by is bob and moved.created_by_username == "bob" and moved.confirmed_by_username == "bob" and moved.updated_by is bob, moved.__dict__)
must(moved.creation_scope["captured_for"] == "bob" and moved.creation_scope["scope"]["whole_client_ids"] == [20], "bob's scope is stored for the new owner")
log = audit_rows()
must(len(log) == 1 and log[0]["action"] == "modify" and log[0]["strict"] is True and log[0]["actor"] is bob, log)
meta = log[0]["metadata"]
must(meta["owner_changed_from"] == "alice" and meta["owner_changed_to"] == "bob" and meta["previous_confirmed_by"] == "alice" and meta["creator"] == "bob" and meta["confirmed_by"] == "bob", meta)
must("ownership moved" in log[0]["message"], log[0]["message"])
must(not any("endpoint" in str(v) for v in meta.values()), "no endpoint ids in the row")
print("       a different person who edits the schedule becomes the owner, their scope is stored and ONE strict 'modify' row names who it moved from and to")

# ---- (2) the first rights check still runs first
fresh()
sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
before = state_of(rows()[0])
PERMS["bob"] = False
refused(lambda: sched.reconcile_schedule(**{**KW, "run_time": time(5, 0)}, confirmed_by_request=RealRequest(bob)), sched.SchedulerNotAllowed)
must(state_of(rows()[0]) == before, "a person without the action's permission changes nothing")
PERMS["bob"] = True
refused(lambda: sched.reconcile_schedule(**{**KW, "run_time": time(5, 0)}, confirmed_by_request=RealRequest(dave)), sched.SchedulerNotAllowed)  # inactive
installer = User("inst", installer=True)
PERMS["inst"] = True
refused(lambda: sched.reconcile_schedule(**{**KW, "run_time": time(5, 0)}, confirmed_by_request=RealRequest(installer)), sched.SchedulerNotAllowed)
must(state_of(rows()[0]) == before, "an inactive person and an installer user cannot take it over")
print("       the permission, the active-user and the installer-user checks still run first")

# ---- (3) a narrower person is refused and nothing changes
fresh()
sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
before = state_of(rows()[0])
before_runtime = rows()[0].run_time
del AUDITS[:]
exc = refused(lambda: sched.reconcile_schedule(**{**KW, "run_time": time(5, 0)}, confirmed_by_request=RealRequest(carol)), sched.SchedulerNotAllowed)
must(isinstance(exc, sched.TakeoverRefused) and exc.reason == "takeover_out_of_scope", exc)
must(str(exc) == "You cannot take over this schedule: some of its targets are outside your Tactical scope.", str(exc))
must(state_of(rows()[0]) == before and rows()[0].run_time == before_runtime, "the schedule is exactly as it was")
must(not audit_rows("modify") and not audit_rows("add"), "no row of a change")
deny = audit_rows("deny")
must(len(deny) == 1 and deny[0]["metadata"]["reason"] == "takeover_out_of_scope" and deny[0]["actor"] is carol and deny[0]["object_id"] == str(rows()[0].pk), deny)
must(not SAVE_COUNT[1:], "nothing was saved after the refusal: " + str(SAVE_COUNT))
print("       a person whose own scope does not cover every target is refused in plain words; owner, scope and fields stay, and one deny row is written")

# ---- (3b) no bypass for a scheduler manager: the strict check is asked, not the manager shortcut
LIVE["carol"] = True  # the old rule would let carol through (she is a scheduler manager)
refused(lambda: sched.reconcile_schedule(**{**KW, "run_time": time(5, 0)}, confirmed_by_request=RealRequest(carol)), sched.TakeoverRefused)
src = (APP / "scheduler.py").read_text(encoding="utf-8")
must("_can_access_target_scope(person, targets, strict=True)" in src and "_resolver_scope_check(person, action.module_id, targets, strict=True)" in src, "the takeover asks the strict check")
print("       a scheduler manager has no bypass: the strict scope check is the one asked before ownership moves")

# ---- (4) the same person moves nothing
fresh()
sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
del AUDITS[:]
same = sched.reconcile_schedule(**{**KW, "run_time": time(6, 0)}, confirmed_by_request=RealRequest(alice))
must(same.created_by is alice and "owner_changed_from" not in audit_rows("modify")[0]["metadata"] and "ownership moved" not in audit_rows("modify")[0]["message"], audit_rows())
print("       the owner editing their own schedule moves nothing")

# ---- (5) a module without a request still cannot change a person's schedule
fresh()
sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
before = state_of(rows()[0])
refused(lambda: sched.reconcile_schedule(**{**KW, "run_time": time(7, 0)}))
must(state_of(rows()[0]) == before, "a module call with no request changes nothing")
off = sched.reconcile_schedule(**KW, enabled=False)
must(off.enabled is False and off.created_by is alice, "a module may still switch a person's schedule off, and that moves nothing")
print("       a module call without a request still cannot change a person's schedule; it may only switch it off")

# ---- (6) switching off by another person does not move it
fresh()
sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
del AUDITS[:]
disabled = sched.reconcile_schedule(**KW, enabled=False, confirmed_by_request=RealRequest(carol))  # carol could not take it over, but she may switch it off
must(disabled.enabled is False and disabled.created_by is alice and disabled.created_by_username == "alice" and disabled.creation_scope["captured_for"] == "alice", disabled.__dict__)
must("owner_changed_from" not in audit_rows("modify")[0]["metadata"], audit_rows())
print("       switching a schedule off never moves it, even for a person who could not take it over")

# ---- (7) the creator row is gone
fresh()
sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
rows()[0].created_by = None  # SET_NULL: the user row was deleted, the stored name stays
del AUDITS[:]
moved = sched.reconcile_schedule(**{**KW, "run_time": time(8, 0)}, confirmed_by_request=RealRequest(bob))
must(moved.created_by is bob and moved.created_by_username == "bob" and audit_rows("modify")[0]["metadata"]["owner_changed_from"] == "alice", moved.__dict__)
fresh()
sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
rows()[0].created_by = None
again = sched.reconcile_schedule(**{**KW, "run_time": time(8, 0)}, confirmed_by_request=RealRequest(alice))  # same name, row gone: the name decides
must(again.created_by_username == "alice" and "owner_changed_from" not in audit_rows("modify")[0]["metadata"], "the stored name decides when the row is gone")
print("       a schedule whose creator row is gone moves to the next editor; the stored name decides who the owner was")

# ---- (8) the browser PATCH follows the same rule
view_src = (APP / "scheduler_views.py").read_text(encoding="utf-8")
patch = view_src.split("    def patch(self, request, schedule_id):", 1)[1].split("    def delete(self, request, schedule_id):", 1)[0]
for needle in ("takeover = bool(edited and other_person and bool(data.get(\"enabled\", schedule.enabled)))", "strict=True", "TakeoverRefused(TAKEOVER_REFUSED)", "_record_takeover_refusal(exc)",
               "schedule.created_by = request.user", "\"owner_changed_from\": previous_names[0]", "except TakeoverRefused as exc:", "status=403"):
    must(needle in patch, needle)
must("turned_on = " in patch and "edit_fields = _changed_edit_fields(schedule, data)" in patch, "an edit field or switching it on is an edit; a rename or switching it off is not")
must(patch.index("takeover and not _can_access_target_scope") < patch.index("_apply_schedule_fields(schedule, data)"), "the takeover is decided before any field is touched")
must("_audit_system_schedule(request.user, schedule, \"modify\", system_info, owner_move)" in patch and "_audit_schedule_row(request.user, schedule, \"modify\"" in patch, "one audit row in both cases")
print("       the browser PATCH moves ownership only for an edit field or switching on, refuses a narrower editor with 403, and audits the move")

# ---- (9) everything else is as before
sig = sched.reconcile_schedule.__wrapped__ if hasattr(sched.reconcile_schedule, "__wrapped__") else sched.reconcile_schedule
names = list(inspect.signature(sig).parameters)
must(names[:3] == ["owner_module", "owner_key", "action_id"] and names[-2:] == ["confirmed_by_request", "confirmation_id"], names)
fresh()
first = sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(bob))
must(first.created_by is bob and len(audit_rows("add")) == 1 and "owner_changed_from" not in audit_rows("add")[0]["metadata"], "a first creation is not a move")
fresh()
plain = sched.reconcile_schedule(**KW)
must(plain.created_by is None and plain.created_by_username == "" and plain.creation_scope == {}, "a module-owned schedule with no person behaves as before and stores no scope")
print("       the signature, a first creation and a schedule with no person behave as before")
print("PASS scheduler ownership move 1.17.68")
