#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.63 regression (CQ179 b, Johan 20 October 2026): a SCHEDULED run is not re-checked against its creator. Since 1.17.65 (wide rule, CQ184 b / CQ186 / CQ189) that holds for every user-owned scheduled run, flagged or not; the flag has no effect.

The real scheduler.py (its real tick, ``dispatch_due_schedules``), scheduler_run_context.py and tasks.py on the stub harness of
scheduler-completion-harness-1.17.61.py. Covered: ``unattended`` is an optional last field and keyword (equality of every existing action is
unchanged); Core accepts True only for a module whose signed manifest lists a system action; the tick still queues the scheduled run of an
unattended action when its creator was demoted, deactivated or deleted (the name is stored), and (1.17.65) queues an ordinary user-owned schedule too; it still skips a schedule with no stored creator name as
AuthorizationRevoked, and every other tick guard (disabled, bad targets, concurrency, missed);
a person-started run (manual, one-off) of the same action is re-checked as before; verify_run_context exposes the stored names and still reads
the owner fresh for has_tactical_permission and resource_context; the exemption is reached only through the one helper (source read).
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True  # these tests prove the post-amendment behaviour; scheduler-unattended-gate-1.17.63-1.py proves the gate

alice, bob = User("alice"), User("bob")
plugin("patching", system_actions=["patching.scan", "patching.strict"])
for _sid in ("patching.scan", "patching.strict"):
    sa.register_system_action(_sid, "patching", _sid, "winupdate.scan", ("can_manage_winupdates", "can_run_bulk"))
plugin("checks", system_actions=[])
SEEN = []


def handler(context):
    SEEN.append(context)
    try:
        v = rc.verify_run_context(context, expected_module_id="patching", expected_action_id=context["action_id"], require_owner=False)
    except sched.SchedulerRunContextInvalid as exc:
        return {"invalid": str(exc)}
    return {"verified": True, "creator": v.creator_username, "confirmed": v.confirmed_by_username, "unattended": v.unattended, "user": v.user is not None,
            "one_off": v.one_off, "can": v.has_tactical_permission("can_run_bulk")}


def strict_handler(context):  # the default require_owner=True
    v = rc.verify_run_context(context, expected_module_id="patching", expected_action_id=context["action_id"])
    return {"verified": True, "creator": v.creator_username}


# ---- (1) the flag: an optional last field and keyword; accepted only for a module with a signed system action
import dataclasses

names = [f.name for f in dataclasses.fields(sched.ScheduledAction)]
must(names[-1] == "unattended" and names[-2] == "permission_any", names)
must(dataclasses.fields(sched.ScheduledAction)[-1].default is False, "unattended defaults to False")
plain = sched.register_scheduled_action(id="patching.plain", module_id="patching", label="plain", handler=handler)
must(plain.unattended is False, "an action registered as before is not unattended")
must(plain == sched.ScheduledAction("patching.plain", "patching", "plain", handler, "", ("none",), None, False, 3600, ()), "equality of an existing action is unchanged")
unatt = sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=handler, unattended=True)
must(unatt.unattended is True and sched.get_scheduled_action("patching.scan") is unatt, unatt)
must(sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=handler, unattended=True) == unatt, "registering the same action again is idempotent")
try:
    sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=handler)
    raise AssertionError("the same id with a different unattended flag was accepted")
except sched.SchedulerError:
    pass
for bad in ("yes", 1, None):
    try:
        sched.register_scheduled_action(id="patching.bad", module_id="patching", label="b", handler=handler, unattended=bad)
        raise AssertionError(f"unattended={bad!r} was accepted")
    except sched.SchedulerError:
        pass
try:
    sched.register_scheduled_action(id="checks.scan", module_id="checks", label="c", handler=handler, unattended=True)
    raise AssertionError("a module with no system_actions in its manifest was allowed to mark an action unattended")
except sched.SchedulerError as exc:
    must("system_actions" in str(exc), exc)
STATE_FAULT["registry"] = True
try:
    sched.register_scheduled_action(id="patching.scan2", module_id="patching", label="c", handler=handler, unattended=True)
    raise AssertionError("an unreadable manifest list allowed the flag")
except sched.SchedulerError:
    pass
STATE_FAULT["registry"] = False
sched.register_scheduled_action(id="checks.plain", module_id="checks", label="c", handler=handler)  # no flag: no manifest read, nothing changes
sched.register_scheduled_action(id="patching.strict", module_id="patching", label="s", handler=strict_handler, unattended=True)
print("       unattended is an optional last field and keyword; True needs a signed system action; a bad value or an unreadable manifest refuses")

# ---- (2) the real tick
ANCHOR = NOW[0] - timedelta(hours=3)
sched.recover_stale_runs = lambda now: {}
sched._recover_event_jobs_safely = lambda now: {}
sched.cleanup_once_schedules = lambda now: 0
sched.cleanup_run_history = lambda now: 0
FLAGS["alice"] = {"can_run_bulk", "can_manage_winupdates"}


def make_schedule(action_id, *, owner_type="user", creator=alice, name="alice", enabled=True, targets=None, interval=3600, anchor=None, owner_key=""):
    """An interval schedule whose latest occurrence is due right now (the anchor is a whole number of intervals ago)."""
    anchor = anchor or (NOW[0] - timedelta(seconds=interval * 3))
    return Schedule.objects.create(
        name="s", module_id=action_id.split(".")[0], action_id=action_id, owner_type=owner_type,
        owner_module="patching" if owner_type == "module" else "", owner_key=owner_key or ("recurring" if owner_type == "module" else ""),
        created_by=creator, created_by_username=name or "", enabled=enabled, schedule_type="interval", interval_seconds=interval,
        interval_anchor_at=anchor, targets=targets or {"type": "none"}, last_due_key="", updated_at=None,
    )


def tick():
    del QUEUED_IDS[:]
    return sched.dispatch_due_schedules(NOW[0])


def skipped_types(result):
    return sorted(r.error_type for r in Run.objects.rows if str(r.id) in result["skipped"])


# an unattended action: the demoted, deactivated and deleted creator never stops the scheduled run
reset()
s_ok = make_schedule("patching.scan")
r = tick()
must(len(r["queued"]) == 1 and not r["skipped"] and not r["dispatch_failed"], r)
must(sched._is_unattended_scheduled_run(s_ok) is True, "an unattended action on a user schedule with a creator")

reset()
AUTH["deny"] = True  # alice no longer holds the action or the scope (demoted)
s_demoted = make_schedule("patching.scan")
r = tick()
must(len(r["queued"]) == 1 and not r["skipped"], ("a demoted creator's unattended schedule still runs", r))
AUTH["deny"] = False

reset()
alice.is_active = False  # deactivated
s_inactive = make_schedule("patching.scan")
r = tick()
must(len(r["queued"]) == 1 and not r["skipped"], ("a deactivated creator's unattended schedule still runs", r))
alice.is_active = True

reset()
s_deleted = make_schedule("patching.scan", creator=None, name="alice")  # the user row is gone, the stored name is not
r = tick()
must(len(r["queued"]) == 1 and not r["skipped"], ("a deleted creator's name is enough", r))

reset()
s_prefix = make_schedule("patching.scan", creator=alice, name="")  # a row made before migration 0036: the name is read from created_by
must(sched.schedule_creator_names(s_prefix) == ("alice", ""), sched.schedule_creator_names(s_prefix))
r = tick()
must(len(r["queued"]) == 1, ("a row made before 0036 falls back to created_by.username", r))
print("       the tick queues an unattended schedule whose creator was demoted, deactivated or deleted, and one made before migration 0036")

# no stored creator name at all: refused as before
reset()
make_schedule("patching.scan", creator=None, name="")
r = tick()
must(not r["queued"] and skipped_types(r) == ["AuthorizationRevoked"], r)
print("       no creator name at all is refused as before (AuthorizationRevoked)")

# 1.17.65 (wide rule): an ordinary (not flagged) user schedule is not re-checked either, demoted or deactivated
for how in ("deny", "inactive"):
    reset()
    if how == "deny":
        AUTH["deny"] = True
    else:
        alice.is_active = False
    s = make_schedule("patching.plain")
    must(sched._is_unattended_scheduled_run(s) is True, "a scheduled user-owned run is exempt whatever the flag says")
    r = tick()
    must(len(r["queued"]) == 1 and not r["skipped"], (how, r))
    AUTH["deny"] = False
    alice.is_active = True
print("       an ordinary user-owned schedule is queued too: the unattended flag has no effect (1.17.65)")

# a module-owned schedule with a creator name and an ordinary action (not in the signed manifest) gets no exemption
reset()
mo = make_schedule("patching.plain", owner_type="module", creator=None, name="alice")
must(sched._is_unattended_scheduled_run(mo) is False, "module-owned, ordinary action: no exemption")
print("       a module-owned schedule with an action outside the signed manifest system_actions gets no exemption")

# every other guard of the tick still holds for an unattended action
reset()
make_schedule("patching.scan", enabled=False)
r = tick()
must(not r["queued"] and not r["skipped"], "a disabled schedule is not touched")

reset()
bad = make_schedule("patching.scan", targets={"type": "client", "ids": "not-a-list"})
r = tick()
must(not r["queued"] and skipped_types(r) == ["InvalidTargetShape"] and bad.enabled is False, (r, bad.__dict__))

reset()
busy = make_schedule("patching.scan")
Run.objects.create(schedule=busy, status="running", module_id="patching", action_id="patching.scan")
r = tick()
must(not r["queued"] and skipped_types(r) == ["ConcurrencySkip"], r)

reset()
make_schedule("patching.scan", interval=3600, anchor=NOW[0] - timedelta(seconds=3600 * 3 + 1800))  # the occurrence was 30 minutes ago: missed
r = tick()
must(not r["queued"] and skipped_types(r) == ["MissedSkip"], r)

reset()
gone = make_schedule("patching.scan")
del sched._ACTIONS["patching.scan"]
r = tick()
must(not r["queued"] and len(r["skipped"]) == 1, ("an action that is no longer registered is never queued", r))
sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=handler, unattended=True)
print("       a disabled schedule, bad targets, an active run, a missed occurrence and a removed action are all handled as before")

# a module-owned schedule with a stored creator and an unattended action runs under the same rule; with no creator it is as before
reset()
m1 = make_schedule("patching.scan", owner_type="module", creator=None, name="alice")
must(sched._is_unattended_scheduled_run(m1) is True, "module-owned with a stored creator")
m2 = make_schedule("patching.scan", owner_type="module", creator=None, name="", owner_key="nobody")
must(sched._is_unattended_scheduled_run(m2) is False, "module-owned with no creator")
r = tick()
must(len(r["queued"]) == 2, ("module-owned schedules were never re-checked by the tick", r))
one = make_schedule("patching.scan", owner_type="module", creator=alice, name="alice", owner_key="one-off:abc")
must(sched._is_unattended_scheduled_run(one) is False, "a one-off is never unattended")
print("       the helper: module-owned with a creator is unattended, without one is not, a one-off never is")

# ---- (3) the run: scheduled, manual and one-off
def run_for(schedule, *, manual=False):
    return Run.objects.create(
        schedule=schedule, schedule_snapshot_id=schedule.id, schedule_name="s", module_id=schedule.module_id, action_id=schedule.action_id,
        owner_type=schedule.owner_type, owner_module=schedule.owner_module, owner_key=schedule.owner_key, status="queued", manual=manual,
        scheduled_for=NOW[0], last_queued_at=NOW[0],
    )


reset()
FLAGS["alice"] = set()  # the creator lost every Tactical flag
AUTH["deny"] = True
alice.is_active = False
sch = make_schedule("patching.scan")
sch.confirmed_by_username = "bob"
out = go(run_for(sch))
must(out["verified"] is True and out["creator"] == "alice" and out["confirmed"] == "bob" and out["unattended"] is True and out["user"] is True, out)
must(out["can"] is False, "has_tactical_permission is still a fresh read: a creator who lost the flag has none")
FLAGS["alice"] = {"can_run_bulk", "can_manage_winupdates"}
must(go(run_for(sch))["can"] is False, "a deactivated owner reads as no permission (the fresh owner read refuses)")
alice.is_active = True
AUTH["deny"] = False
must(go(run_for(sch))["can"] is True, "an active owner holding the flag reads True")
gone_user = make_schedule("patching.scan", creator=None, name="alice")
out = go(run_for(gone_user))
must(out["verified"] and out["creator"] == "alice" and out["user"] is False and out["unattended"], out)
print("       verify_run_context gives the stored names and unattended, keeps has_tactical_permission a fresh read and verifies with no user row")

# the default require_owner=True still needs a person to read
reset()
alice.is_active = True
sg = make_schedule("patching.strict", creator=None, name="alice")
out = go(run_for(sg))
must(isinstance(out, Exception) and "no person" in str(out), out)
print("       a handler that needs a person (require_owner=True) is still refused when the creator's user row is gone")

# a manual run of the same unattended action is re-checked as before
reset()
AUTH["deny"] = True
sch = make_schedule("patching.scan")
out = go(run_for(sch, manual=True))
must(out == {"invalid": "The person who owns this schedule may no longer run it."}, out)
AUTH["deny"] = False
alice.is_active = False
out = go(run_for(sch, manual=True))
must(out == {"invalid": "The person who owns this schedule may no longer run it."}, out)
alice.is_active = True
out = go(run_for(sch, manual=True))
must(out["verified"] and out["unattended"] is False, ("a manual run verifies as person-started", out))
print("       a manual run of an unattended action is re-checked (owner refused when demoted or deactivated) and is not unattended")

# a one-off run for a person is re-checked as before: the worker skips it before the handler
reset()
alice.is_active = False
one_run = make_run("patching.scan", "patching", user=alice, owner="one-off")
out = go(one_run)
must(one_run.status == "skipped" and one_run.error_type == "AuthorizationRevoked" and not SEEN[len(SEEN):], one_run.__dict__)
alice.is_active = True
reset()
AUTH["deny"] = True
one_run = make_run("patching.scan", "patching", user=alice, owner="one-off")
go(one_run)
must(one_run.status == "skipped" and one_run.error_type == "AuthorizationRevoked", one_run.__dict__)
AUTH["deny"] = False
print("       a one-off run is still re-checked by the worker (AuthorizationRevoked)")

# ---- (4) the exemption is reached only through the one helper
src = (APP / "scheduler.py").read_text(encoding="utf-8")
must(src.count("def _is_unattended_scheduled_run(") == 1, "one helper")
tick_src = src.split("def dispatch_due_schedules", 1)[1].split("def queue_manual_run", 1)[0]
must("None if _is_unattended_scheduled_run(schedule) else _runtime_authorization_error(schedule)" in tick_src and tick_src.count("_runtime_authorization_error(") == 1, "the tick skips the re-check only through the helper")
must(all(line.strip().startswith("#") or "_is_unattended_scheduled_run(schedule)" in line for line in tick_src.splitlines() if "unattended" in line), "the tick holds no other unattended rule")
ctx_src = (APP / "scheduler_run_context.py").read_text(encoding="utf-8")
must(ctx_src.count("= _is_unattended_scheduled_run(run)") == 1 and "from .scheduler import _is_unattended_scheduled_run as decide" in ctx_src, "verify_run_context asks the one helper")
must("not unattended and _authorization_error(schedule)" in ctx_src, "the re-check is skipped only when the helper said unattended")
tasks_src = (APP / "tasks.py").read_text(encoding="utf-8")
tasks_lines = [line for line in tasks_src.splitlines() if "unattended" in line]
must(all("_is_unattended_scheduled_run" in line for line in tasks_lines), "tasks.py holds no exemption of its own: it only names the one helper (1.17.68)")
must(sum(1 for line in tasks_lines if line.strip().startswith(("from .scheduler import _is_unattended_scheduled_run", "if _is_unattended_scheduled_run(run):"))) == 2 and tasks_src.count("_is_unattended_scheduled_run(run)") == 1, "the one-off re-check skips only through the helper, only for a run whose signed marker verifies (scheduler._delegated_run_is_valid)")
sa_src = (APP / "system_actions.py").read_text(encoding="utf-8")
must("getattr(verified, \"unattended\", False)" in sa_src and "_is_unattended_scheduled_run" not in sa_src, "system actions read the verified answer and never decide it again")
body = src.split("def _is_unattended_scheduled_run", 1)[1].split("def _runtime_authorization_error", 1)[0]
for needle in ("manual", "is_one_off_key", "_action_declared_as_system_action", "schedule_creator_names", "except Exception:\n        return False"):
    must(needle in body, f"the helper lacks {needle}")
print("       the tick, verify_run_context and the system-action code reach the exemption only through the one helper (source read)")
print("PASS scheduler unattended owner 1.17.63")
