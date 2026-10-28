#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.63 regression (CQ176): a module-owned schedule that a PERSON creates and the module owns and executes.

The real scheduler.py (reconcile_schedule and its helpers), scheduler_run_context.py, system_actions.py and tasks.py on the stub harness of
scheduler-completion-harness-1.17.61.py. Covered: a verified request (real or DRF request with Core's session proof) creates the schedule, stores
the creator and confirmer by name, and writes an audit row for the creation; a stand-in object with a ``user``, a user id and a request without
the session proof are refused and change nothing; a person without the action permission, without the target scope, or who is inactive is
refused; WITHOUT a request a schedule that has a stored creator can only be switched off or left alone (a changed action, target, parameter,
timing or policy, and switching it back on, are refused; an identical call is a no-op that writes nothing); a second person's confirmation is
audited and, since 1.17.68, moves the ownership to that person (tests/scheduler-ownership-move-1.17.68.py); a module-owned schedule with no creator behaves exactly as before and a system action on it is still
refused as no_owner; a module-owned schedule with a stored creator and an unattended action runs as the creator (run_kind scheduled);
reconcile_schedule called with every old keyword behaves as in 1.17.62; get_owned_schedule gains created_by_username.
"""
from __future__ import annotations

import inspect
from datetime import time
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True  # these tests prove the post-amendment behaviour; scheduler-unattended-gate-1.17.63-1.py proves the gate

BOTH = ("can_manage_winupdates", "can_run_bulk")
IDS = [987654311, 987654312]
alice, bob, carol, dave = User("alice"), User("bob"), User("carol"), User("dave", active=False)
for who in ("alice", "bob", "carol", "dave"):
    FLAGS[who] = set(BOTH)
    SCOPE[who] = set(IDS)
root = plugin("patching", system_actions=["patching.scan", "patching.run"])
# 1.17.66: sections (1) to (5) prove the CQ176 mechanics of an ordinary scheduled action, so nothing is registered with core.system_actions here
# (a declared system action needs a confirmation id at creation; tests/system-actions-creation-1.17.66.py proves that). Section (6) registers them.
plugin("checks", system_actions=[])


# ---- the stand-ins of the one thing this feature needs from Django: what a real, session-checked request looks like
class RealRequest:
    def __init__(self, user, session=True):
        self.user = user
        self.tec_tac_session = object() if session else None


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
PERMS = {"alice": True, "bob": True, "carol": False, "dave": True}
SCOPES = {"alice": True, "bob": True, "carol": True, "dave": True}
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: PERMS.get(user.username, False)
views._can_access_target_scope = lambda user, targets, **kw: SCOPES.get(user.username, False)  # 1.17.68: a takeover asks with strict=True

# the harness model does not add a schedule that is built by hand; the real one saves it. Make save() do the same.
_orig_save = Schedule.save
SAVE_COUNT = []


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    SAVE_COUNT.append(update_fields)
    _orig_save(self, update_fields)


Schedule.save = _save


def handler(context):
    return {"ok": True}


sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=handler, target_types=("none", "endpoint"), unattended=True)
sched.register_scheduled_action(id="patching.plain", module_id="patching", label="plain", handler=handler, target_types=("none", "endpoint"))
KW = dict(owner_module="patching", owner_key="nightly", action_id="patching.scan", schedule_type="daily", run_time=time(3, 0), targets={"type": "none"})


def rows():
    return [r for r in Schedule.objects.rows if r.owner_module == "patching"]


def audit_rows():
    return [a for a in AUDITS if a["object_type"] == "scheduler_schedule"]


def fresh():
    reset()
    del SAVE_COUNT[:]
    for who in PERMS:
        PERMS[who] = who != "carol"
        SCOPES[who] = True


def refused(call, kind=sched.SchedulerError):
    try:
        call()
    except kind as exc:
        return exc
    raise AssertionError("the call was accepted")


# ---- (1) a verified request creates the schedule and names the person
fresh()
created = sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
must(created.owner_type == "module" and created.owner_module == "patching" and created.owner_key == "nightly" and created.module_id == "patching", created.__dict__)
must(created.created_by is alice and created.updated_by is alice and created.created_by_username == "alice" and created.confirmed_by_username == "alice", created.__dict__)
must(created.enabled is True and len(rows()) == 1, rows())
log = audit_rows()
must(len(log) == 1 and log[0]["action"] == "add" and log[0]["actor"] is alice and log[0]["strict"] is True and log[0]["module_id"] == "core", log)
must(log[0]["metadata"]["creator"] == "alice" and log[0]["metadata"]["confirmed_by"] == "alice" and log[0]["metadata"]["owner_module"] == "patching", log[0]["metadata"])
info = sched.get_owned_schedule("patching", "nightly")
must(info is not None and info["created_by_username"] == "alice", info)
print("       a verified request creates the schedule, stores the creator and confirmer by name and writes one 'add' audit row")

# ---- (2) nothing but a real, session-checked request is proof of a person
for label, proof in (("a stand-in object with a user", SimpleNamespace(user=alice, tec_tac_session=object())), ("a user id", alice.pk), ("a user object", alice),
                     ("a request without the session proof", RealRequest(alice, session=False)), ("a dict", {"user": alice})):
    fresh()
    exc = refused(lambda proof=proof: sched.reconcile_schedule(**KW, confirmed_by_request=proof), sched.SchedulerNotAllowed)
    must(not rows() and not audit_rows(), (label, rows(), AUDITS))
fresh()
refused(lambda: sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(dave)), sched.SchedulerNotAllowed)  # inactive
refused(lambda: sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(carol)), sched.SchedulerNotAllowed)  # no permission for the action
SCOPES["alice"] = False
refused(lambda: sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice)), sched.SchedulerNotAllowed)  # targets outside the scope
must(not rows() and not audit_rows(), "a refused call created nothing and wrote nothing")
fresh()
anon = RealRequest(SimpleNamespace(username="x", is_active=True, is_authenticated=False, is_installer_user=False))
refused(lambda: sched.reconcile_schedule(**KW, confirmed_by_request=anon), sched.SchedulerNotAllowed)
installer = User("inst", installer=True)
PERMS["inst"] = True
refused(lambda: sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(installer)), sched.SchedulerNotAllowed)
print("       a stand-in object, a user id, a request with no session proof, an inactive person, an installer user, a person without the action or the scope are all refused")

# ---- (3) without a request a person's schedule can only be switched off or left alone
fresh()
sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
before = {k: getattr(rows()[0], k) for k in ("action_id", "targets", "parameters", "run_time", "schedule_type", "enabled", "weekdays", "retry_count", "timezone")}
del SAVE_COUNT[:], AUDITS[:]
same = sched.reconcile_schedule(**KW)  # identical, no request
must(same is rows()[0] and not SAVE_COUNT and not AUDITS, ("an identical call is a no-op and writes nothing", SAVE_COUNT, AUDITS))
for label, change in (
    ("another action", dict(action_id="patching.plain")),
    ("other targets", dict(targets={"type": "endpoint", "ids": ["1"]})),
    ("parameters", dict(parameters={"x": 1})),
    ("another time", dict(run_time=time(4, 0))),
    ("another type", dict(schedule_type="weekly", weekdays=[1])),
    ("another timezone", dict(timezone_name="Africa/Johannesburg")),
    ("a retry policy", dict(retry_count=3)),
    ("a concurrency policy", dict(concurrency_policy="allow")),
    ("a missed policy", dict(missed_policy="expire")),
):
    call = {**KW, **change}
    exc = refused(lambda call=call: sched.reconcile_schedule(**call))
    must("created by a person" in str(exc), (label, exc))
    must({k: getattr(rows()[0], k) for k in before} == before and not SAVE_COUNT and not AUDITS, (label, "nothing was changed or written"))
off = sched.reconcile_schedule(**{**KW, "enabled": False})
must(off is rows()[0] and off.enabled is False and SAVE_COUNT == [["enabled", "updated_at"]], (off.__dict__, SAVE_COUNT))
must(len(audit_rows()) == 1 and audit_rows()[0]["action"] == "disable" and audit_rows()[0]["metadata"]["creator"] == "alice" and getattr(audit_rows()[0]["actor"], "kind", "") == "service", AUDITS)
must(rows()[0].action_id == "patching.scan" and rows()[0].targets == {"type": "none"} and rows()[0].created_by_username == "alice", "a switch-off changes nothing else")
exc = refused(lambda: sched.reconcile_schedule(**KW))  # switching it back on is a change
must("created by a person" in str(exc) and rows()[0].enabled is False, exc)
del AUDITS[:]
again = sched.reconcile_schedule(**{**KW, "enabled": False})
must(again is rows()[0] and not AUDITS, "switching off an already-off schedule is a no-op")
switched = sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))  # the person can switch it back on with their own request
must(switched.enabled is True and audit_rows()[-1]["action"] == "modify", AUDITS)
print("       with no request: an identical call writes nothing; any change to the action, targets, parameters, timing or policies is refused; only switching off works and re-enabling needs the person")

# ---- (4) a person's later change is audited; since 1.17.68 the next editor becomes the owner (Johan, 21 October 2026)
fresh()
sched.reconcile_schedule(**KW, confirmed_by_request=RealRequest(alice))
del AUDITS[:]
changed = sched.reconcile_schedule(**{**KW, "run_time": time(5, 0)}, confirmed_by_request=RealRequest(bob))
must(changed.created_by is bob and changed.created_by_username == "bob" and changed.updated_by is bob and changed.confirmed_by_username == "bob", changed.__dict__)
log = audit_rows()
must(len(log) == 1 and log[0]["action"] == "modify" and log[0]["actor"] is bob and log[0]["metadata"]["creator"] == "bob" and log[0]["metadata"]["confirmed_by"] == "bob" and log[0]["metadata"]["owner_changed_from"] == "alice", log)
del AUDITS[:]
sched.reconcile_schedule(**{**KW, "run_time": time(5, 0)}, confirmed_by_request=RealRequest(bob))
must(not audit_rows(), "the same person confirming the same thing again writes no new row")
sched.reconcile_schedule(**{**KW, "run_time": time(5, 0)}, confirmed_by_request=RealRequest(alice))
must(len(audit_rows()) == 1 and audit_rows()[0]["metadata"]["confirmed_by"] == "alice", AUDITS)
AUDIT_FAIL["strict"] = True
refused(lambda: sched.reconcile_schedule(**{**KW, "run_time": time(6, 0)}, confirmed_by_request=RealRequest(bob)))
AUDIT_FAIL["strict"] = False
print("       a second person's change is audited and moves the ownership (the earlier creator is named in the row); a repeat writes nothing; a failed strict audit row stops the change")

# ---- (5) as before: no keyword, no creator
fresh()
plain = sched.reconcile_schedule(**KW)
must(plain.created_by is None and plain.created_by_username == "" and plain.confirmed_by_username == "" and not audit_rows(), plain.__dict__)
changed = sched.reconcile_schedule(**{**KW, "run_time": time(7, 0)})
must(changed is plain and plain.run_time == time(7, 0), "a module-owned schedule with no creator is changed as before")
sched.reconcile_schedule(**{**KW, "enabled": False})
must(plain.enabled is False, "and disabled as before")
sched.reconcile_schedule(**KW)
must(plain.enabled is True, "and enabled again as before")
must(sched._is_unattended_scheduled_run(plain) is False, "no creator: never unattended")
exc = refused(lambda: sched.reconcile_schedule(owner_module="patching", owner_key="x", action_id="patching.scan", schedule_type="once", targets={"type": "none"}))
sig = inspect.signature(sched.reconcile_schedule)
names = list(sig.parameters)
must(names[-2:] == ["confirmed_by_request", "confirmation_id"] and all(sig.parameters[n].kind is inspect.Parameter.KEYWORD_ONLY and sig.parameters[n].default is None for n in names[-2:]), names)  # 1.17.66 added confirmation_id
old = ["owner_module", "owner_key", "action_id", "schedule_type", "targets", "parameters", "enabled", "name", "timezone_name", "run_at", "run_time", "weekdays", "day_of_month",
       "interval_seconds", "interval_anchor_at", "target_mode", "missed_policy", "missed_grace_minutes", "concurrency_policy", "retry_count", "retry_delay_seconds"]
must([n for n in names[:-2] if n not in ("month_week", "month_weekday")] == old  # 1.17.88 added the two month fields (keyword-only, optional, after interval_anchor_at)
     and all(sig.parameters[n].kind is inspect.Parameter.KEYWORD_ONLY and sig.parameters[n].default is None for n in ("month_week", "month_weekday"))
     and all(sig.parameters[n].kind is inspect.Parameter.KEYWORD_ONLY for n in old), names)
print("       reconcile_schedule called as before behaves as before; confirmed_by_request (1.17.63) and confirmation_id (1.17.66) are the new, last, keyword-only, optional names")

# ---- (6) the system action on a module-owned schedule: no creator is no_owner, a stored creator runs as the creator
CFG = {"action_id": "patching.scan", "agents": IDS, "parameters": None}
sa._clear_for_tests()
HANDLER_SRC = (
    "def handler(context):\n"
    "    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'], parameters=CFG.get('parameters'))\n"
)
ns = compile_as(root / "handlers.py", HANDLER_SRC, sa=sa, CFG=CFG)
sched.register_scheduled_action(id="patching.run", module_id="patching", label="run", handler=ns["handler"], unattended=True)
sched.register_scheduled_action(id="patching.run-plain", module_id="patching", label="run", handler=ns["handler"])
sa.register_system_action("patching.scan", "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
sa.register_system_action("patching.run", "patching", "Scheduled run", "winupdate.scan", BOTH)
AUTO = {"type": "endpoint", "ids": [str(i) for i in IDS]}


def module_run(action, *, creator_name="", creator=None):
    schedule = Schedule.objects.create(name="s", module_id="patching", action_id=action, owner_type="module", owner_module="patching", owner_key="recurring",
                                       created_by=creator, created_by_username=creator_name, enabled=True)
    run = Run.objects.create(schedule=schedule, schedule_snapshot_id=schedule.id, schedule_name="s", module_id="patching", action_id=action,
                             owner_type="module", owner_module="patching", owner_key="recurring", status="queued", scheduled_for=NOW[0],
                             last_queued_at=NOW[0], targets_snapshot=AUTO)
    return run, go(run)


fresh()
run, out = module_run("patching.run")
rows_ = [a for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]
must(run.status == "skipped" and len(rows_) == 1 and rows_[0]["metadata"]["reason"] == "no_owner" and not TASK_CALLS, (run.__dict__, AUDITS))
print("       a module-owned schedule with no creator still refuses a system action as no_owner")

fresh()
FLAGS["alice"] = set()
alice_scope = SCOPE["alice"]
SCOPE["alice"] = set()
run, out = module_run("patching.run", creator_name="alice", creator=alice)
must(out["outcome"] == "queued" and run.status == "succeeded" and len(TASK_CALLS) == 1, (out, run.__dict__))
sent = [a for a in AUDITS if a["action"] == "run"]
must(len(sent) == 1 and sent[0]["actor"] is alice and sent[0]["metadata"]["run_kind"] == "scheduled" and sent[0]["metadata"]["creator"] == "alice", sent)
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = alice_scope
fresh()
run, out = module_run("patching.run", creator_name="alice", creator=None)  # the creator's user row is gone
must(out["outcome"] == "queued" and getattr([a for a in AUDITS if a["action"] == "run"][0]["actor"], "kind", "") == "service", out)
fresh()
FLAGS["alice"] = set()
run, out = module_run("patching.run-plain", creator_name="alice", creator=alice)  # a creator on an ordinary action is not an exemption
must(run.status == "skipped" and not TASK_CALLS, (run.__dict__, out))
FLAGS["alice"] = set(BOTH)
print("       a module-owned schedule with a stored creator and an unattended action runs as the creator; an ordinary action gets no exemption")

# ---- (7) the source: only the verified-request proof, no user id, and nothing in the module-facing helpers changes
src = (APP / "scheduler.py").read_text(encoding="utf-8")
must("from .tactical_operations import _is_real_request" in src and 'getattr(request, "tec_tac_session", None) is None' in src, "the same proof as run_tactical_operation")
must("def start_one_off_run" in src and "def disable_owned_schedule" in src and "def remove_owned_schedule" in src, "the other helpers are still there")
for name, expected in (("disable_owned_schedule", ["owner_module", "owner_key"]), ("remove_owned_schedule", ["owner_module", "owner_key"])):
    must(list(inspect.signature(getattr(sched, name)).parameters) == expected, name)
must(list(inspect.signature(sched.start_one_off_run).parameters) == ["user", "owner_module", "action_id", "targets", "parameters", "name", "retry_count", "retry_delay_seconds", "confirmation_id"], "start_one_off_run only gained its last optional keyword (1.17.66)")
must(sched.get_owned_schedule("patching", "nobody") is None, "an unknown tuple is still None")
print("       start_one_off_run, disable_owned_schedule and remove_owned_schedule are unchanged; the proof is the one run_tactical_operation asks for")
print("PASS scheduler module-owned creator 1.17.63")
