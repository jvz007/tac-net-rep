#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.66 regression (AD-13 as amended, CQ175, CQ197): the permission, scope and the one plain Yes or No are checked when a person creates or
edits a schedule for a declared system action.

The real system_action_confirmation.py, system_actions.py, scheduler.py (reconcile_schedule and start_one_off_run) and scheduler_run_context.py
on the stub harness. Covered: the confirmation text names what, the total, the groups and the timing, and carries the fixed install warning; a
create or edit with no confirmation id, or with an id made for another person, action, endpoints, parameters or timing, or an expired, tampered
or malformed id, is refused; the owning module's permission, each Tactical flag (with no bypass for a scheduler manager), the person's scope over
every target, a target type Core cannot read as endpoints, a count above the ceiling, a module that is disabled, a replacement that is not
honoured and bad parameters are each refused at creation, with one deny row that names a reason and no endpoint; an allowed creation or edit
writes one strict audit row naming creator, confirmer, schedule, total, groups and timing; a one-off run needs the id too; the capability
operation takes only a real request; an action that is not a declared system action is not touched.
"""
from __future__ import annotations

from datetime import time
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"
CLOCK = [1_000_000.0]
conf._clock = lambda: CLOCK[0]

PATCH_FLAGS = ("can_manage_winupdates", "can_run_bulk")
SCRIPT_FLAGS = ("can_run_bulk", "can_run_scripts")
BASE = 1000
alice, bob, carol = User("alice"), User("bob"), User("carol")
PERMS = {"alice": True, "bob": True, "carol": False}
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: PERMS.get(user.username, False)
views._can_access_target_scope = lambda user, targets: True


class RealRequest:
    def __init__(self, user, session=True):
        self.user = user
        self.tec_tac_session = object() if session else None


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
_orig_save = Schedule.save
SAVES2 = []


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    SAVES2.append(update_fields)
    _orig_save(self, update_fields)


Schedule.save = _save


def handler(context):
    return {"ok": True}


def endpoints(count, start=BASE):
    return {"type": "endpoint", "ids": [str(start + i) for i in range(count)]}


SCAN, INSTALL, RUN, PLAIN = "patching.scan", "patchmanagement.install", "scriptexecution.run", "checks.plain"
SCRIPT_PARAMS = {"system_action_parameters": {"script_pk": 7, "args": ["-Quiet"], "timeout": 120}}
DAILY = {"schedule_type": "daily", "run_time": "03:00", "timezone": "UTC"}
KW = dict(schedule_type="daily", run_time=time(3, 0))


def fresh():
    reset()
    del SAVES2[:]
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    mod("scripts")
    sys.modules["scripts"].__path__ = []
    mod("scripts.tasks", bulk_script_task=FakeTacticalTask("script"))
    plugin("patching", system_actions=[SCAN])
    plugin("patchmanagement", category="premium", replaces="patching", system_actions=[INSTALL])
    plugin("scriptexecution", system_actions=[RUN])
    plugin("checks", system_actions=[])
    HONOURED["patchmanagement"] = "patching"
    sa.register_system_action(SCAN, "patching", "Scheduled patch scan", "winupdate.scan", PATCH_FLAGS)
    sa.register_system_action(INSTALL, "patchmanagement", "Advanced Patch Management install", "winupdate.install", PATCH_FLAGS)
    sa.register_system_action(RUN, "scriptexecution", "Scheduled script run", "scripts.run", SCRIPT_FLAGS)
    for aid, module in ((SCAN, "patching"), (INSTALL, "patchmanagement"), (RUN, "scriptexecution"), (PLAIN, "checks")):
        if aid not in sched._ACTIONS:
            sched.register_scheduled_action(id=aid, module_id=module, label=aid, handler=handler, target_types=("none", "endpoint", "profile"), timeout_seconds=600)
    for who in ("alice", "bob", "carol"):
        FLAGS[who] = set(PATCH_FLAGS) | set(SCRIPT_FLAGS)
        SCOPE[who] = set(range(BASE, BASE + 41000))
        PERMS[who] = who != "carol"
    CLOCK[0] = 1_000_000.0


def rows():
    return [r for r in Schedule.objects.rows if r.owner_module == "patching"]


def deny_rows():
    return [a for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def schedule_rows():
    return [a for a in AUDITS if a["object_type"] == "scheduler_schedule"]


def describe(user=alice, action=SCAN, targets=None, parameters=None, when=DAILY):
    return conf.describe_confirmation(user, action, targets if targets is not None else endpoints(3), parameters, when)


def create(confirmation_id, user=alice, action=SCAN, targets=None, parameters=None, key="nightly", **extra):
    module = action.split(".")[0]
    kw = dict(owner_module=module, owner_key=key, action_id=action, targets=targets if targets is not None else endpoints(3), parameters=parameters, **KW)
    kw.update(extra)
    return sched.reconcile_schedule(**kw, confirmed_by_request=RealRequest(user), confirmation_id=confirmation_id)


def refused(call, reason):
    try:
        call()
    except conf.SystemActionCreationRefused as exc:
        must(exc.reason == reason and isinstance(exc, sched.SchedulerNotAllowed), (reason, exc.reason, str(exc)))
        return exc
    raise AssertionError(f"accepted instead of {reason}")


def one_deny(reason):
    found = deny_rows()
    must(len(found) == 1 and found[0]["metadata"]["reason"] == reason, (reason, AUDITS))
    row = found[0]
    must(row["metadata"]["requested_by"] == "person" and row["metadata"]["phase"] == "creation" and row["module_id"] == "core", row)
    must(not any(str(BASE + i) in repr(row) for i in range(5)), "no endpoint id in the deny row")
    must(not Schedule.objects.rows, "nothing was created")


# ---- the confirmation text
fresh()
result = describe(targets=endpoints(4500))
must(result["required"] is True and result["total"] == 4500 and result["groups"] == 3 and result["expires_in"] == 600 and isinstance(result["confirmation_id"], str), result)
text = result["text"]
must("Scheduled patch scan" in text and "4500 endpoint(s)" in text and "3 group(s)" in text and "every day at 03:00 (UTC)" in text and "alice" in text and text.endswith("Do you want to continue?"), text)
must("does not check your rights again" in text, "the plain cost of an unattended schedule")
must(not any(str(BASE + i) in text for i in range(5)), "no endpoint id in the text")
install = describe(action=INSTALL)
must(sa.REAPPROVE_WARNING in install["text"] and sa.REAPPROVE_WARNING not in text, "the install text carries the fixed warning, the scan text does not")
script = describe(action=RUN, parameters=SCRIPT_PARAMS)
must("Script number 7, 1 argument(s), time limit 120 seconds." in script["text"] and "-Quiet" not in script["text"], script["text"])
once = describe(when={"schedule_type": "once", "run_at": "now"})
must("once, now" in once["text"], once["text"])
weekly = describe(when={"schedule_type": "weekly", "weekdays": [0, 4], "run_time": "02:30", "timezone": "Africa/Johannesburg"})
must("every week on Monday, Friday at 02:30 (Africa/Johannesburg)" in weekly["text"], weekly["text"])
must(not deny_rows() and not schedule_rows(), "a text writes no audit row")
print("       the text names what, the total, the groups, the timing and the person; install carries the fixed warning; no endpoint or argument value is shown")

# ---- an action that is not a declared system action is not touched
fresh()
plain = describe(action=PLAIN)
must(plain == {"required": False, "text": None, "confirmation_id": None, "total": None, "groups": None, "expires_in": None}, plain)
schedule = sched.reconcile_schedule(owner_module="checks", owner_key="x", action_id=PLAIN, schedule_type="daily", run_time=time(3, 0), targets={"type": "none"}, confirmed_by_request=RealRequest(alice))
must(schedule.created_by_username == "alice" and not deny_rows(), "no confirmation id is asked for an ordinary action")
print("       an action that is not a declared system action needs no id and is created as before")

# ---- no id, wrong id, expired, tampered
fresh()
refused(lambda: create(None), "confirmation_required")
one_deny("confirmation_required")
fresh()
refused(lambda: create(""), "confirmation_required")
good = describe()["confirmation_id"]
del AUDITS[:]
for label, call in (
    ("another person", lambda: create(good, user=bob)),
    ("another action", lambda: create(describe(action=RUN, parameters=SCRIPT_PARAMS)["confirmation_id"], action=SCAN)),
    ("other endpoints", lambda: create(good, targets=endpoints(3, BASE + 1))),
    ("one more endpoint", lambda: create(good, targets=endpoints(4))),
    ("other parameters", lambda: create(good, parameters={"system_action_parameters": {}})),
    ("another time", lambda: create(good, run_time=time(4, 0))),
    ("another type", lambda: create(good, schedule_type="interval", interval_seconds=3600)),
    ("a garbage id", lambda: create("not-an-id")),
    ("a tampered id", lambda: create(good[:-1] + ("0" if good[-1] != "0" else "1"))),
    ("a shortened id", lambda: create(good.split(".")[0])),
    ("a number", lambda: create(12345)),
):
    del AUDITS[:]
    refused(call, "confirmation_invalid")
    must(len(deny_rows()) == 1 and deny_rows()[0]["metadata"]["reason"] == "confirmation_invalid" and not rows(), (label, AUDITS))
CLOCK[0] += 601
del AUDITS[:]
refused(lambda: create(good), "confirmation_invalid")
CLOCK[0] -= 601
must(len(deny_rows()) == 1, "an expired id is one deny row")
del AUDITS[:]
created = create(good)  # the same request, in time, is accepted
must(created.created_by is alice and created.confirmed_by_username == "alice" and len(rows()) == 1, created.__dict__)
print("       no id, an id for another person, action, endpoints, parameters or timing, a tampered, shortened or expired id are each one deny row and nothing is created")

# ---- the audit row of an allowed creation and edit
fresh()
cid = describe(targets=endpoints(4500))["confirmation_id"]
created = create(cid, targets=endpoints(4500))
log = schedule_rows()
must(len(log) == 1 and log[0]["action"] == "add" and log[0]["strict"] is True and log[0]["actor"] is alice, log)
meta = log[0]["metadata"]
must(meta["creator"] == "alice" and meta["confirmed_by"] == "alice" and meta["total_agents"] == 4500 and meta["groups"] == 3 and meta["when"] == "every day at 03:00 (UTC)", meta)
must(log[0]["object_id"] == str(created.pk) and meta["action_id"] == SCAN and not any(str(BASE + i) in repr(log) for i in range(5)), log)
del AUDITS[:]
edit_id = conf.describe_confirmation(bob, SCAN, endpoints(4500), None, {"schedule_type": "daily", "run_time": "05:00", "timezone": "UTC"})["confirmation_id"]
changed = create(edit_id, user=bob, targets=endpoints(4500), run_time=time(5, 0))
must(changed is created and changed.created_by is alice and changed.updated_by is bob and changed.confirmed_by_username == "bob", changed.__dict__)
log = schedule_rows()
must(len(log) == 1 and log[0]["action"] == "modify" and log[0]["actor"] is bob and log[0]["metadata"]["creator"] == "alice" and log[0]["metadata"]["confirmed_by"] == "bob", log)
refused(lambda: create(edit_id, user=bob, targets=endpoints(4500), run_time=time(6, 0)), "confirmation_invalid")
must(created.run_time == time(5, 0), "a refused edit changes nothing")
print("       an allowed creation and edit write one strict audit row with creator, confirmer, schedule, total, groups and timing")

# ---- the controls
fresh()
PERMS["alice"] = False
refused(lambda: describe(), "not_permitted")
one_deny("not_permitted")
fresh()
PERMS["alice"] = False
try:  # reconcile_schedule asks the Scheduler's own permission first (the 1.17.63 check), before the system-action controls
    create("x")
    raise AssertionError("accepted")
except sched.SchedulerNotAllowed as exc:
    must(not isinstance(exc, conf.SystemActionCreationRefused) and not rows(), exc)
fresh()
FLAGS["alice"].discard("can_run_scripts")
refused(lambda: describe(action=RUN, parameters=SCRIPT_PARAMS), "not_permitted")
one_deny("not_permitted")
fresh()
FLAGS["alice"].discard("can_manage_winupdates")
refused(lambda: describe(), "not_permitted")
fresh()
real_native = views._can_use_action
views._can_use_action = lambda user, action: True  # a scheduler manager passes the Scheduler's own permission, but has no Tactical flag
FLAGS["alice"].discard("can_run_bulk")
refused(lambda: describe(), "not_permitted")
views._can_use_action = real_native
fresh()
SCOPE["alice"].discard(BASE + 2)
refused(lambda: describe(), "out_of_scope")
one_deny("out_of_scope")
fresh()
SCOPE["alice"] = set()
refused(lambda: create("x"), "out_of_scope")
fresh()
refused(lambda: describe(targets={"type": "profile", "profile_id": 5}), "targets_unresolved")
one_deny("targets_unresolved")
fresh()
refused(lambda: describe(targets={"type": "none"}), "agent_count")
fresh()
refused(lambda: describe(targets=endpoints(40001)), "agent_count")
one_deny("agent_count")
fresh()
big = describe(targets=endpoints(40000))
must(big["total"] == 40000 and big["groups"] == 20, big)
fresh()
real_enabled = sa._enabled_now
sa._enabled_now = lambda module_id: False
refused(lambda: describe(), "module_disabled")
sa._enabled_now = real_enabled
fresh()
HONOURED.clear()
refused(lambda: describe(action=INSTALL), "replacement_not_honoured")
fresh()
for bad in ({"script_pk": "7"}, {}, {"script_pk": 7, "command": "x"}, {"script_pk": 7, "timeout": 0}):
    del AUDITS[:]
    refused(lambda bad=bad: describe(action=RUN, parameters={"system_action_parameters": bad}), "bad_parameters")
fresh()
refused(lambda: describe(parameters={"system_action_parameters": {"script_pk": 7}}), "bad_parameters")  # a scan takes no parameters
fresh()
inactive = User("inactive", active=False)
FLAGS["inactive"] = set(PATCH_FLAGS)
SCOPE["inactive"] = set(range(BASE, BASE + 10))
PERMS["inactive"] = True
refused(lambda: describe(user=inactive), "owner_inactive")
fresh()
secret = {"system_action_parameters": {"script_pk": 7, "args": ["TOP-SECRET-ARG"], "env_vars": ["K=TOP-SECRET-ENV"], "timeout": 0}}
refused(lambda: describe(action=RUN, parameters=secret), "bad_parameters")
must("TOP-SECRET" not in repr(AUDITS), "a refused parameter value is never written to the audit trail")
print("       permission, each Tactical flag (no manager bypass), scope, unreadable targets, the ceiling, a disabled module, a replacement not honoured and bad parameters are each refused with one deny row")

# ---- one-off run: the id is needed and works
fresh()
once_when = {"schedule_type": "once", "run_at": "now"}
try:
    sched.start_one_off_run(user=alice, owner_module="patching", action_id=SCAN, targets=endpoints(3))
    raise AssertionError("a one-off run of a system action started without an id")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "confirmation_required", exc.reason)
must(not Schedule.objects.rows and not QUEUED_IDS, "nothing was created or queued")
cid = conf.describe_confirmation(alice, SCAN, endpoints(3), None, once_when)["confirmation_id"]
run = sched.start_one_off_run(user=alice, owner_module="patching", action_id=SCAN, targets=endpoints(3), confirmation_id=cid)
must(run is not None and len(QUEUED_IDS) == 1, "the one-off run with the id is queued")
try:
    sched.start_one_off_run(user=bob, owner_module="patching", action_id=SCAN, targets=endpoints(3), confirmation_id=cid)
    raise AssertionError("another person used the id")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "confirmation_invalid", exc.reason)
one_off = [a for a in AUDITS if a["object_type"] == "scheduler_run" and a["action"] == "add"]
must(len(one_off) == 1 and one_off[0]["metadata"]["total_agents"] == 3 and one_off[0]["metadata"]["groups"] == 1, one_off)
print("       a one-off run of a system action needs the id; an id for another person is refused; the audit row names total and groups")

# ---- reconcile_schedule works in one transaction that a refusal rolls back: the deny row is written after it, so it is kept
fresh()
EVENTS = []


class RecordingAtomic:
    def __enter__(self):
        EVENTS.append(("enter", len(AUDITS)))

    def __exit__(self, *exc):
        EVENTS.append(("exit", len(AUDITS)))
        return False


real_transaction = sched.transaction
sched.transaction = SimpleNamespace(atomic=lambda *a, **k: RecordingAtomic())
try:
    refused(lambda: create(None), "confirmation_required")
finally:
    sched.transaction = real_transaction
must(EVENTS == [("enter", 0), ("exit", 0)], EVENTS)
must(len(deny_rows()) == 1 and deny_rows()[0]["metadata"]["reason"] == "confirmation_required", "the row was written after the transaction ended, and once")
fresh()
try:
    describe(user=carol)
except conf.SystemActionCreationRefused as exc:
    must(exc.pending is None and len(deny_rows()) == 1, "outside a transaction the row is written at once")
conf.record_refusal(ValueError("any other exception"))  # does nothing and never raises
print("       a refusal inside reconcile_schedule writes its deny row after the transaction that it rolls back, once; elsewhere at once")

# ---- the capability operation takes only a real request
fresh()
provider = sa._PROVIDER
shown = provider.describe_confirmation(RealRequest(alice), action_id=SCAN, targets=endpoints(3), when=DAILY)
must(shown["required"] is True and shown["total"] == 3, shown)
for proof in (alice, SimpleNamespace(user=alice, tec_tac_session=object()), RealRequest(alice, session=False), alice.pk):
    try:
        provider.describe_confirmation(proof, action_id=SCAN, targets=endpoints(3), when=DAILY)
        raise AssertionError("a stand-in was accepted")
    except sched.SchedulerNotAllowed:
        pass
must("describe_confirmation" in sa.system_actions_contract_metadata()["operations"], "the operation is in the capability")
print("       the capability operation takes the person's own signed-in request: a user, a stand-in or a user id is refused")

# ---- the source: one place for the controls, the id is signed and never stored
src = (APP / "system_action_confirmation.py").read_text(encoding="utf-8")
must("hmac.compare_digest" in src and "settings.SECRET_KEY" in src and ".objects." not in src and "objects.create" not in src, "signed, compared in constant time, never stored")
must(src.count("def _controls(") == 1 and "has_tactical_permission" in src and "is_superuser" not in src and "_native_scheduler_manager" not in src, "the Tactical flags have no manager bypass")
print("PASS system actions creation 1.17.66")
