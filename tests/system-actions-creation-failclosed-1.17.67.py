#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.67 regression (held Medium of the 1.17.66 review): the system-action creation gate fails closed when it cannot read.

The real system_action_confirmation.py, system_actions.py and scheduler.py on the stub harness. ``scheduler.system_action_state`` answers
declared, not_declared or unknown. A definite no from EITHER fact (the memory registry, the signed manifest) is not_declared, so an ordinary
action never needs the manifest and is never refused for a read fault. When a read fails and the other fact did not settle it, the answer is
unknown and a creation, an edit, a switch-on, a one-off start and the confirmation text are refused with ``declaration_unreadable``: one deny
row (also for reconcile_schedule, after its transaction), nothing saved, nothing queued, no run row, no confirmation id. The run-time
exemption ``_action_declared_as_system_action`` still answers False (every re-check kept) when a read fails.
"""
from __future__ import annotations

import ast
from datetime import time
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"

PATCH_FLAGS = ("can_manage_winupdates", "can_run_bulk")
BASE = 1000
alice = User("alice")
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: True
views._can_access_target_scope = lambda user, targets: True
SCAN, PLAIN, LISTED_ONLY = "patching.scan", "checks.plain", "checks.listed"
DAILY = {"schedule_type": "daily", "run_time": "03:00", "timezone": "UTC"}
ENDPOINTS = {"type": "endpoint", "ids": [str(BASE + i) for i in range(3)]}


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
_orig_save = Schedule.save
SAVES2 = []


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    SAVES2.append(update_fields)
    _orig_save(self, update_fields)


Schedule.save = _save
REAL_MANIFEST, REAL_REGISTERED = sched._manifest_system_actions, sa.is_registered_system_action


def handler(context):
    return {"ok": True}


def fresh():
    reset()
    del SAVES2[:]
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    sched._manifest_system_actions = REAL_MANIFEST
    sa.is_registered_system_action = REAL_REGISTERED
    plugin("patching", system_actions=[SCAN])
    plugin("checks", system_actions=[LISTED_ONLY])  # listed in a manifest, never registered with core.system_actions
    sa.register_system_action(SCAN, "patching", "Scheduled patch scan", "winupdate.scan", PATCH_FLAGS)
    for aid, module in ((SCAN, "patching"), (PLAIN, "checks"), (LISTED_ONLY, "checks")):
        if aid not in sched._ACTIONS:
            sched.register_scheduled_action(id=aid, module_id=module, label=aid, handler=handler, target_types=("none", "endpoint"), timeout_seconds=600)
    FLAGS["alice"] = set(PATCH_FLAGS)
    SCOPE["alice"] = set(range(BASE, BASE + 100))


def boom(*args, **kwargs):
    raise RuntimeError("read failed")


def break_manifest():
    sched._manifest_system_actions = boom


def break_registry():
    sa.is_registered_system_action = boom


def denies():
    return [a for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def refused_unreadable(call):
    try:
        call()
    except conf.SystemActionCreationRefused as exc:
        must(exc.reason == "declaration_unreadable" and isinstance(exc, sched.SchedulerNotAllowed), exc.reason)
        must("try again" in str(exc).lower() and "signed manifest" in str(exc), str(exc))
        return exc
    raise AssertionError("accepted although the declaration could not be read")


def nothing_changed():
    must(not Schedule.objects.rows and not Run.objects.rows and not QUEUED_IDS and not SAVES2, ("saved or queued", Schedule.objects.rows, QUEUED_IDS))
    must(not [a for a in AUDITS if a["object_type"] in ("scheduler_schedule", "scheduler_run")], AUDITS)
    must(len(denies()) == 1 and denies()[0]["metadata"]["reason"] == "declaration_unreadable", AUDITS)
    must(not any(str(BASE + i) in repr(AUDITS) for i in range(3)), "no endpoint id in the deny row")


def reconcile(**extra):
    return sched.reconcile_schedule(owner_module="patching", owner_key="nightly", action_id=SCAN, schedule_type="daily", run_time=time(3, 0), targets=ENDPOINTS,
                                    confirmed_by_request=RealRequest(alice), confirmation_id="anything", **extra)


# ---- the state itself
fresh()
must(sched.system_action_state("patching", SCAN) == "declared", "listed and registered")
must(sched.system_action_state("patching", "patching.other") == "not_declared", "neither")
must(sched.system_action_state("checks", PLAIN) == "not_declared", "an ordinary action")
must(sched.system_action_state("checks", LISTED_ONLY) == "not_declared", "listed, not registered")
must(sched.system_action_state(None, SCAN) == "not_declared" and sched.system_action_state("patching", 5) == "not_declared", "bad input")
break_manifest()
must(sched.system_action_state("patching", SCAN) == "unknown", "registered, manifest unreadable")
must(sched.system_action_state("checks", PLAIN) == "not_declared", "an ordinary action never reads the manifest: the memory check settles it")
must(sched.system_action_state("checks", LISTED_ONLY) == "not_declared", "not registered: settled by the memory check, the manifest is not read")
fresh()
break_registry()
must(sched.system_action_state("patching", SCAN) == "unknown", "manifest lists it, registry unreadable")
must(sched.system_action_state("checks", PLAIN) == "not_declared", "the manifest says it is not listed: settled")
sched._manifest_system_actions = boom
must(sched.system_action_state("checks", PLAIN) == "unknown", "both reads fail: unknown")
fresh()
break_manifest()
break_registry()
must(sched.system_action_state("patching", SCAN) == "unknown", "both unreadable")
print("       system_action_state: declared, not_declared (a definite no from either fact) or unknown (a failed read nothing else settles)")

# ---- the view's own helper (POST and PATCH use it), taken from the source
tree = ast.parse((APP / "scheduler_views.py").read_text(encoding="utf-8"))
helper_names = {"_TIMING_FIELDS", "_EDIT_FIELDS"}
nodes = [n for n in tree.body if (isinstance(n, ast.Assign) and any(getattr(t, "id", "") in helper_names for t in n.targets)) or (isinstance(n, ast.FunctionDef) and n.name == "_system_action_creation")]
space = {"__package__": "tec_tac", "__name__": "tec_tac.scheduler_views", "require_creation": conf.require_creation}
exec(compile(ast.Module(body=nodes, type_ignores=[]), "scheduler_views_helper", "exec"), space)  # noqa: S102 - the helper's own source
helper = space["_system_action_creation"]
body = {"enabled": True, "targets": ENDPOINTS, "parameters": None, **DAILY}
stored_off = SimpleNamespace(enabled=False, action_id=SCAN, targets=ENDPOINTS, parameters={}, schedule_type="daily", timezone="UTC", run_at=None, run_time=time(3, 0),
                             weekdays=[], day_of_month=None, interval_seconds=None, target_mode="snapshot")

# ---- every way in is refused when a read fails: nothing saved, nothing queued, one deny row, no confirmation id
for label, breaker in (("manifest", break_manifest), ("registry", break_registry)):
    fresh()
    breaker()
    exc = refused_unreadable(lambda: reconcile())
    must(exc.pending is None, "the row was written after the transaction")
    nothing_changed()
    fresh()
    breaker()
    refused_unreadable(lambda: reconcile(enabled=True))
    nothing_changed()
    fresh()
    breaker()
    refused_unreadable(lambda: sched.start_one_off_run(user=alice, owner_module="patching", action_id=SCAN, targets=ENDPOINTS, confirmation_id="anything"))
    nothing_changed()
    fresh()
    breaker()
    result = []
    refused_unreadable(lambda result=result: result.append(conf.describe_confirmation(alice, SCAN, ENDPOINTS, None, DAILY)))
    must(not result and len(denies()) == 1, "no confirmation id was issued")
    fresh()
    breaker()
    refused_unreadable(lambda: sa._PROVIDER.describe_confirmation(RealRequest(alice), action_id=SCAN, targets=ENDPOINTS, when=DAILY))
    must(len(denies()) == 1, AUDITS)
    fresh()
    breaker()
    action = sched.get_scheduled_action(SCAN)
    exc = refused_unreadable(lambda action=action: conf.require_creation(alice, action, ENDPOINTS, None, DAILY, "x"))
    must(exc.pending is None and len(denies()) == 1, "written at once outside a transaction")
    fresh()
    breaker()
    del AUDITS[:]
    exc = refused_unreadable(lambda action=action: conf.require_creation(alice, action, ENDPOINTS, None, DAILY, "x", defer=True))
    must(exc.pending is not None and not denies(), "deferred: the row waits for the caller")
    conf.record_refusal(exc)
    must(len(denies()) == 1 and denies()[0]["metadata"]["reason"] == "declaration_unreadable" and not getattr(conf._STATE, "deferred", False), AUDITS)
    fresh()
    breaker()
    refused_unreadable(lambda action=action: helper(alice, action, body, "x"))  # POST
    fresh()
    breaker()
    refused_unreadable(lambda action=action: helper(alice, action, body, "x", schedule=stored_off))  # PATCH that switches it on
    fresh()
    breaker()
    must(helper(alice, action, {**body, "enabled": False}, None) is None and not denies(), "a schedule that stays off is not checked, as before")
    print(f"       {label} unreadable: POST, PATCH-on, reconcile_schedule, start_one_off_run, describe_confirmation and the capability are refused; nothing saved or queued; one deny row")

# the view maps the refusal to 403 with its reason, and the reason is in the table and the docs
vsrc = (APP / "scheduler_views.py").read_text(encoding="utf-8")
must(vsrc.count("except SystemActionCreationRefused as exc:") >= 3 and '"reason": exc.reason' in vsrc and "status=403" in vsrc, "403 with the reason")
must("declaration_unreadable" in sa.REASONS and "declaration_unreadable" in sa.system_actions_contract_metadata()["refusal_reasons"], "the reason code")
must("declaration_unreadable" in (APP.parent.parent / "docs" / "system-actions.md").read_text(encoding="utf-8"), "documented")
print("       the view answers 403 with the reason; the reason is in REASONS, the contract metadata and docs/system-actions.md")

# ---- the healthy read: nothing weaker
fresh()
good = conf.describe_confirmation(alice, SCAN, ENDPOINTS, None, DAILY)
must(good["required"] is True and good["confirmation_id"], good)
try:
    reconcile()
    raise AssertionError("created with a wrong id")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "confirmation_invalid", exc.reason)
fresh()
FLAGS["alice"].discard("can_run_bulk")
try:
    conf.describe_confirmation(alice, SCAN, ENDPOINTS, None, DAILY)
    raise AssertionError("no flag")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "not_permitted", exc.reason)
print("       with a healthy read a declared action still needs the permission, flags, scope and the confirmation id")

# ---- an ordinary action is NOT refused when a read fails
for label, aid, module in (("not registered", PLAIN, "checks"), ("listed in a manifest but not registered", LISTED_ONLY, "checks")):
    fresh()
    break_manifest()
    schedule = sched.reconcile_schedule(owner_module=module, owner_key=f"k-{aid}", action_id=aid, schedule_type="daily", run_time=time(3, 0), targets=ENDPOINTS,
                                        confirmed_by_request=RealRequest(alice))
    must(schedule.created_by is alice and not denies(), (label, schedule.__dict__))
    run = sched.start_one_off_run(user=alice, owner_module=module, action_id=aid, targets=ENDPOINTS)
    must(run is not None and not denies(), label)
    must(conf.describe_confirmation(alice, aid, ENDPOINTS, None, DAILY)["required"] is False, label)
    must(conf.require_creation(alice, sched.get_scheduled_action(aid), ENDPOINTS, None, DAILY, None) is None, label)
fresh()
break_registry()  # the registry unreadable, the manifest says an ordinary action is not listed: settled, not refused
schedule = sched.reconcile_schedule(owner_module="checks", owner_key="plain-2", action_id=PLAIN, schedule_type="daily", run_time=time(3, 0), targets=ENDPOINTS, confirmed_by_request=RealRequest(alice))
must(schedule is not None and not denies(), "the manifest settles it")
print("       an ordinary action (not registered, or listed but not registered) is created, started and described as before while a read fails")

# ---- the run-time exemption keeps its answer: False on a failed read, so every re-check stays
fresh()
break_manifest()
must(sched._action_declared_as_system_action("patching", SCAN) is False, "run time: a failed read keeps every re-check")
fresh()
break_registry()
must(sched._action_declared_as_system_action("patching", SCAN) is False, "run time: a failed registry read keeps every re-check")
fresh()
must(sched._action_declared_as_system_action("patching", SCAN) is True, "healthy read")
src = (APP / "scheduler.py").read_text(encoding="utf-8")
body_src = src.split("def _action_declared_as_system_action")[1].split("\ndef ")[0]
must("except Exception:" in body_src and "return False" in body_src and "system_action_state" not in body_src, "the run-time function still swallows to False")
must("_action_declared_as_system_action(registered.module_id, action_id)" in src, "the run-time exemption still uses it")
print("       the run-time exemption still answers False (every re-check kept) when the read fails")
print("PASS system actions creation fail-closed 1.17.67")
