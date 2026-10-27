#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.80 regression: a module's own Scheduler action that is not a Tactical function gets the schedule's stored creator as its person.

The real scheduler.py (reconcile_schedule, the tick), scheduler_run_context.py and tasks.py on the stub harness of scheduler-completion-harness-1.17.61.py,
with APM's real manifest shape (``scheduler_person_actions`` lists patchmanagement.notice and patchmanagement.reboot; neither is a system action).
Covered: (1) a declared action on a schedule made through reconcile_schedule(confirmed_by_request=...) verifies with the creator as user, unattended False,
and the run writes one audit row (run, run_as creator); (2) an undeclared action, a listing the manifest no longer has, a manual run, a schedule with no stored
creator and another module's action all get no person; (3) the creator is re-checked on every run: deactivated or without the permission or the scope, the tick
skips the run and verify refuses; (4) the expected ids stay strict; (5) the manifest key is parsed with the same shape rules as system_actions;
(6) the AD-13 exemption is not widened: the helper stays False for a declared action; (7) contract text, docs and notes carry the new wording.
"""
from __future__ import annotations

import ast
import re
from datetime import timedelta
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
sched.recover_stale_runs = lambda now: {}
sched._recover_event_jobs_safely = lambda now: {}
sched.cleanup_once_schedules = lambda now: 0
sched.cleanup_run_history = lambda now: 0

# 1.17.81: the manifest answer is cached by a fingerprint of the manifest files; here the fingerprint is the stub registry state
sched._manifest_signature = lambda: (STATE_FAULT["registry"], tuple((k, tuple(getattr(p, "scheduler_person_actions", ()))) for k, p in PLUGINS.items()))
alice, bob = User("alice"), User("bob")
PERMS = {"alice": True, "bob": True}
SCOPES = {"alice": True, "bob": True}


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: PERMS.get(user.username, False)
views._can_access_target_scope = lambda user, targets, **kw: SCOPES.get(user.username, False)
_orig_save = Schedule.save


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    _orig_save(self, update_fields)


Schedule.save = _save
SEEN = []


def verifying_handler(action_id):
    def handler(context):
        try:
            v = rc.verify_run_context(context, expected_module_id="patchmanagement", expected_action_id=action_id, require_owner=True)
        except sched.SchedulerRunContextInvalid as exc:
            return {"invalid": str(exc)}
        SEEN.append(v)
        return {"user": v.user.username, "unattended": v.unattended, "creator": v.creator_username}
    return handler


def fresh(declared=("patchmanagement.notice", "patchmanagement.reboot")):
    reset()
    PLUGINS.clear()
    plugin("patchmanagement", category="premium")
    PLUGINS["patchmanagement"].scheduler_person_actions = tuple(declared)
    plugin("other")
    del SEEN[:]
    sched._ACTIONS.clear()
    for who in PERMS:
        PERMS[who] = SCOPES[who] = True
    for user in (alice, bob):
        user.is_active = True
    for name in ("notice", "reboot", "plain"):
        sched.register_scheduled_action(id=f"patchmanagement.{name}", module_id="patchmanagement", label=name, handler=verifying_handler(f"patchmanagement.{name}"))
    sched.register_scheduled_action(id="other.notice", module_id="other", label="n", handler=verifying_handler("other.notice"))


def create(action="patchmanagement.notice", key="profile:1", person=alice, module="patchmanagement"):
    kw = dict(owner_module=module, owner_key=key, action_id=action, schedule_type="interval", interval_seconds=3600, interval_anchor_at=NOW[0] - timedelta(hours=3), targets={"type": "none"})
    return sched.reconcile_schedule(**kw, confirmed_by_request=RealRequest(person) if person else None)


def run_for(schedule, *, manual=False):
    return Run.objects.create(
        schedule=schedule, schedule_snapshot_id=schedule.id, schedule_name="s", module_id=schedule.module_id, action_id=schedule.action_id,
        owner_type=schedule.owner_type, owner_module=schedule.owner_module, owner_key=schedule.owner_key, status="queued", manual=manual,
        scheduled_for=NOW[0], last_queued_at=NOW[0], targets_snapshot={"type": "none"},
    )


def person_rows():
    return [a for a in AUDITS if a["action"] == "run" and (a.get("metadata") or {}).get("run_as") == "creator"]


NO_PERSON = "This run has no person behind it."
REFUSED = "The person who owns this schedule may no longer run it."

# ---- (1) declared: the creator is the person, nothing is exempt, one audit row per run
for action in ("patchmanagement.notice", "patchmanagement.reboot"):
    fresh()
    s = create(action)
    must(s.created_by is alice and s.created_by_username == "alice" and s.owner_type == "module", s.__dict__)
    created_rows = len(AUDITS)
    must(sched.scheduled_person_action(s) is True and sched._is_unattended_scheduled_run(s) is False, "declared, and NOT the AD-13 exemption")
    out = go(run_for(s))
    must(out == {"user": "alice", "unattended": False, "creator": "alice"}, out)
    must(len(person_rows()) == 1 and len(AUDITS) == created_rows + 1 and person_rows()[0]["metadata"]["owner_module"] == "patchmanagement", AUDITS)
    must(person_rows()[0]["metadata"]["creator"] == "alice" and person_rows()[0]["strict"] is False, person_rows())
print("       a declared module action verifies with the creator as person, unattended False, and one audit row per run")

# ---- (2) everything else gets no person
fresh()
out = go(run_for(create("patchmanagement.plain")))
must(out == {"invalid": NO_PERSON} and not person_rows(), out)  # registered by the module, creator stored, but not declared
fresh(declared=())
out = go(run_for(create("patchmanagement.notice")))
must(out == {"invalid": NO_PERSON} and not person_rows(), out)  # a manifest that no longer lists it
fresh()
out = go(run_for(create(), manual=True))
must(out == {"invalid": NO_PERSON} and not person_rows(), out)  # a manual run is not the creator's
fresh()
s = create(person=None)  # no confirmed_by_request: no stored creator
must(sched.schedule_creator_names(s)[0] == "", s.__dict__)
out = go(run_for(s))
must(out == {"invalid": NO_PERSON} and not person_rows(), out)
fresh()
PLUGINS["patchmanagement"].scheduler_person_actions = ("patchmanagement.notice", "other.notice")  # another module's action in the list: never honoured
s = create("other.notice", key="x", module="other")
must(sched.scheduled_person_action(s) is False, "an action registered by another module is not honoured through this manifest")
print("       undeclared, delisted, manual, no stored creator and another module's action get no person (no_owner) and write no audit row")

# ---- (3) the creator is re-checked on every run
for how in ("inactive", "permission", "scope"):
    fresh()
    s = create()
    {"inactive": lambda: setattr(alice, "is_active", False), "permission": lambda: PERMS.update(alice=False), "scope": lambda: SCOPES.update(alice=False)}[how]()
    must(sched.scheduled_person_action(s) is True, how)
    tick_result = sched.dispatch_due_schedules(NOW[0])
    must(not tick_result["queued"] and [r.error_type for r in Run.objects.rows if str(r.id) in tick_result["skipped"]] == ["AuthorizationRevoked"], (how, tick_result))
    out = go(run_for(s))
    must(out == {"invalid": REFUSED} and not person_rows(), (how, out))
fresh()
s = create()
tick_result = sched.dispatch_due_schedules(NOW[0])
must(len(tick_result["queued"]) == 1 and not tick_result["skipped"], (tick_result, [(r.error_type, r.error) for r in Run.objects.rows]))
print("       a deactivated creator, one without the permission and one without the scope: the tick skips the run and verify refuses; an intact creator is queued")

# ---- (4) the expected ids stay exact
fresh()
s = create("patchmanagement.notice")
run = run_for(s)
sched._ACTIONS["patchmanagement.notice"] = sched.ScheduledAction("patchmanagement.notice", "patchmanagement", "n", verifying_handler("patchmanagement.reboot"))
out = go(run)
must(out == {"invalid": "This run belongs to another module or action."}, out)
print("       a handler that names another action id is refused")

# ---- (5) the manifest key has the shape rules of system_actions (the real parser, read from registry.py)
tree = ast.parse((APP / "registry.py").read_text(encoding="utf-8"))
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_scheduler_person_actions")
ns = {"RegistryError": type("RegistryError", (Exception,), {}), "SYSTEM_ACTIONS_MAX": 20, "_PERSON_ACTIONS_MIN_FRAMEWORK": (1, 17, 80), "_requires_framework_floor": lambda payload: (1, 17, 80), "_SYSTEM_ACTION_NAME_RE": re.compile(r"[a-z0-9][a-z0-9_-]*")}
exec(compile(ast.Module(body=[fn], type_ignores=[]), "registry.py", "exec"), ns)  # noqa: S102 - Core's own source
parse = ns["_scheduler_person_actions"]
must(parse({}, "extension", "patchmanagement") == () and parse({"scheduler_person_actions": ["patchmanagement.notice"]}, "extension", "patchmanagement") == ("patchmanagement.notice",))
for bad in ("patchmanagement.notice", ["other.notice"], ["patchmanagement.A"], ["patchmanagement.n", "patchmanagement.n"], [1], [f"patchmanagement.a{i}" for i in range(21)]):
    try:
        parse({"scheduler_person_actions": bad}, "extension", "patchmanagement")
    except ns["RegistryError"]:
        continue
    raise AssertionError(("accepted", bad))
try:
    parse({"scheduler_person_actions": []}, "reportset", "x")
    raise AssertionError("a reportset may not declare it")
except ns["RegistryError"]:
    pass
reg = (APP / "registry.py").read_text(encoding="utf-8")
must('"scheduler_person_actions",\n})' in reg and "scheduler_person_actions=scheduler_person_actions" in reg, "supported key, carried by the PluginSpec")
print("       the manifest key is parsed with the same shape rules as system_actions; reportsets may not declare it")

# ---- (6)/(7) text
con = (APP / "contracts.py").read_text(encoding="utf-8")
must("Since 1.17.80 (module-facing, additive, framework >=1.17.80; fail closed)" in con and "scheduler_person_actions" in con)
must("scheduler_person_actions" in (ROOT / "docs" / "module-scheduling.md").read_text(encoding="utf-8"))
must(any((ROOT / d / "RELEASE_NOTES_1.17.80.md").is_file() for d in (".", "docs/releases")))  # 1.17.81: earlier notes move to docs/releases
print("PASS scheduler person actions 1.17.80")
