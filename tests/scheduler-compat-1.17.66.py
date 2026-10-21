#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.66 compatibility: the creation-time controls reach only a declared system action; every other scheduled action behaves as in 1.17.65.

The real scheduler.py, system_action_confirmation.py, scheduler_run_context.py and system_actions.py on the stub harness, plus a read of
scheduler_views.py as source (it needs Django). Covered: reconcile_schedule and start_one_off_run for an ordinary action (no system action
registered, an action registered with core.system_actions but not in the signed manifest, and an action in the manifest but not registered) are
created and started with no confirmation id, write no deny row and write the audit rows they wrote in 1.17.65; a confirmation id passed for such
an action is ignored; the signatures only gained one last optional keyword; a person-started run of a system action is still re-checked at
run time and a scheduled one is not (1.17.65); the HTTP views call the same single check before the targets are canonicalised, drop the id from
the payload, keep the original order of their other checks, save an ordinary schedule exactly as before and write the strict audit row inside
one transaction only for a system action; the route is registered once; no module in modules/ calls the new names.
"""
from __future__ import annotations

import ast
import inspect
import re
from datetime import time
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"

BOTH = ("can_manage_winupdates", "can_run_bulk")
IDS = [987654311, 987654312]
alice = User("alice")
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = set(IDS)


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: True
views._can_access_target_scope = lambda user, targets, **kw: True  # 1.17.68: a takeover asks with strict=True
_orig_save = Schedule.save


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    _orig_save(self, update_fields)


Schedule.save = _save
root = plugin("patching", system_actions=["patching.sys"])  # in the signed manifest
plugin("checks", system_actions=[])


def handler(context):
    return {"ok": True}


for aid, module in (("patching.plain", "patching"), ("patching.sys", "patching"), ("patching.registered-only", "patching"), ("checks.plain", "checks")):
    sched.register_scheduled_action(id=aid, module_id=module, label=aid, handler=handler, target_types=("none", "endpoint"), timeout_seconds=600)
sa.register_system_action("patching.sys", "patching", "Scheduled scan", "winupdate.scan", BOTH)
PLUGINS["patching"].system_actions = ("patching.sys", "patching.registered-only")  # listed AND registered below, then one is withdrawn
sa.register_system_action("patching.registered-only", "patching", "Registered only", "winupdate.scan", BOTH)
PLUGINS["patching"].system_actions = ("patching.sys",)  # registered with core.system_actions but no longer in the signed manifest
ENDPOINTS = {"type": "endpoint", "ids": [str(i) for i in IDS]}


def denies():
    return [a for a in AUDITS if a["action"] == "deny"]


# ---- an ordinary action: created and started exactly as in 1.17.65, with or without an id
for aid in ("patching.plain", "patching.registered-only", "checks.plain"):
    reset()
    module = aid.split(".")[0]
    for extra in ({}, {"confirmation_id": "ignored"}):
        schedule = sched.reconcile_schedule(owner_module=module, owner_key=f"k-{len(extra)}", action_id=aid, schedule_type="daily", run_time=time(3, 0), targets=ENDPOINTS,
                                            confirmed_by_request=RealRequest(alice), **extra)
        must(schedule.created_by is alice and schedule.created_by_username == "alice" and schedule.enabled is True, schedule.__dict__)
    log = [a for a in AUDITS if a["object_type"] == "scheduler_schedule"]
    must(len(log) == 2 and all(a["action"] == "add" and a["strict"] is True for a in log) and not denies(), AUDITS)
    for row in log:
        must(set(row["metadata"]) == {"owner_module", "owner_key", "action_id", "requested_by", "creator", "confirmed_by", "enabled"}, row["metadata"])  # exactly the 1.17.63 keys
        must(row["metadata"]["requested_by"] == "module", row["metadata"])
    run = sched.start_one_off_run(user=alice, owner_module=module, action_id=aid, targets=ENDPOINTS)
    must(run is not None and not denies(), "a one-off run of an ordinary action starts with no id")
    one_off = [a for a in AUDITS if a["object_type"] == "scheduler_run"]
    must(len(one_off) == 1 and one_off[0]["metadata"] == {"owner_module": module, "action_id": aid, "requested_by": "scheduler"}, one_off)
print("       an ordinary action (no system action, registered but not in the manifest) is created and started with no id; the audit rows keep their 1.17.65 keys")

# ---- no confirmed_by_request: the module-owned path is untouched, with an action that is a system action too
reset()
plain = sched.reconcile_schedule(owner_module="patching", owner_key="nightly", action_id="patching.sys", schedule_type="daily", run_time=time(3, 0), targets=ENDPOINTS)
must(plain.created_by is None and not denies() and not [a for a in AUDITS if a["object_type"] == "scheduler_schedule"], "no person, no check, as before")
print("       reconcile_schedule with no confirmed_by_request is unchanged, even for a system action")

# ---- the signatures
sig = inspect.signature(sched.reconcile_schedule)
must(list(sig.parameters)[-2:] == ["confirmed_by_request", "confirmation_id"] and sig.parameters["confirmation_id"].default is None and sig.parameters["confirmation_id"].kind is inspect.Parameter.KEYWORD_ONLY, sig)
sig = inspect.signature(sched.start_one_off_run)
must(list(sig.parameters)[-1] == "confirmation_id" and sig.parameters["confirmation_id"].default is None and sig.parameters["confirmation_id"].kind is inspect.Parameter.KEYWORD_ONLY, sig)
must(list(sig.parameters)[:-1] == ["user", "owner_module", "action_id", "targets", "parameters", "name", "retry_count", "retry_delay_seconds"], "the earlier keywords are untouched")
print("       each signature gained exactly one last, keyword-only, optional name")

# ---- run time: a person-started run is still re-checked, a scheduled one is not (1.17.65)
BODY = ("def handler(context):\n    return sa.run_system_action(context, action_id='patching.sys', agent_ids=%r)\n" % IDS)
ns = compile_as(root / "handlers.py", BODY, sa=sa)
sched.register_scheduled_action(id="patching.sys-run", module_id="patching", label="r", handler=ns["handler"], target_types=("none",), timeout_seconds=600)
PLUGINS["patching"].system_actions = ("patching.sys",)
sa._clear_for_tests()
sa.register_system_action("patching.sys", "patching", "Scheduled scan", "winupdate.scan", BOTH)
AUTO_TARGETS = lambda: {"type": "endpoint", "ids": [str(i) for i in IDS]}  # noqa: E731
reset()
FLAGS["alice"] = set()  # the person was demoted after creating the schedule
run = make_run("patching.sys-run", "patching", user=alice, owner="user", manual=True)
out = go(run)
must(not TASK_CALLS and (isinstance(out, sa.SystemActionRefused) or run.status == "skipped"), (out, run.__dict__))
reset()
FLAGS["alice"] = set()
run = make_run("patching.sys-run", "patching", user=alice, owner="user", manual=False)
out = go(run)
must(isinstance(out, dict) and out["outcome"] == "queued" and len(TASK_CALLS) == 1, (out, run.__dict__))
FLAGS["alice"] = set(BOTH)
print("       a person-started run of a system action is still re-checked at run time; a scheduled run is not (1.17.65)")

# ---- the views: read as source (they need Django); the helper is run with a spy
text = (APP / "scheduler_views.py").read_text(encoding="utf-8")
tree = ast.parse(text)
post = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "SchedulerListView")
patch = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "SchedulerDetailView")
post_src = ast.get_source_segment(text, next(n for n in post.body if isinstance(n, ast.FunctionDef) and n.name == "post"))
patch_src = ast.get_source_segment(text, next(n for n in patch.body if isinstance(n, ast.FunctionDef) and n.name == "patch"))
for label, src in (("post", post_src), ("patch", patch_src)):
    order = [src.index(needle) for needle in ('incoming.pop("confirmation_id", None)', "_normalize_targets(", "_system_action_creation(", "_canonicalize_endpoint_targets_for_user(", "_validate_shape(", "_require_target_scope(")]
    must(order == sorted(order), f"{label}: the id leaves the payload, the check runs on the normalised targets before they are canonicalised, and the old order of the other checks stays")
    must("if system_info is None:" in src and "transaction.atomic()" in src and "_audit_system_schedule(" in src, f"{label}: an ordinary schedule is saved as before; a system action is saved with its audit row in one transaction")
    must("except SystemActionCreationRefused as exc:" in src and 'status=403' in src and src.index("except SystemActionCreationRefused") < src.index("except SchedulerError"), f"{label}: a refusal is a 403 with its reason")
helper_names = {"_TIMING_FIELDS", "_EDIT_FIELDS"}
nodes = [n for n in tree.body if (isinstance(n, ast.Assign) and any(getattr(t, "id", "") in helper_names for t in n.targets)) or (isinstance(n, ast.FunctionDef) and n.name == "_system_action_creation")]
spy = []
space = {"__package__": "tec_tac", "__name__": "tec_tac.scheduler_views", "require_creation": lambda *a: spy.append(a) or {"total": 1}}
exec(compile(ast.Module(body=nodes, type_ignores=[]), "scheduler_views_helper", "exec"), space)  # noqa: S102 - the helper's own source, under a spy
helper = space["_system_action_creation"]
stored = SimpleNamespace(enabled=True, action_id="patching.sys", targets=ENDPOINTS, parameters={}, schedule_type="daily", timezone="UTC", run_at=None, run_time=time(3, 0), weekdays=[], day_of_month=None, interval_seconds=None, target_mode="snapshot")
same = {"enabled": True, "action_id": "patching.sys", "targets": ENDPOINTS, "parameters": {}, "schedule_type": "daily", "timezone": "UTC", "run_at": None, "run_time": time(3, 0), "weekdays": [], "day_of_month": None, "interval_seconds": None, "target_mode": "snapshot", "name": "renamed", "retry_count": 5}
must(helper(alice, object(), {**same, "enabled": False}, None) is None and not spy, "a schedule that stays off is not checked")
must(helper(alice, object(), same, None, schedule=stored) is None and not spy, "an edit of the name or the policies of a schedule that is already on is not checked")
for label, change in (("targets", {"targets": {"type": "endpoint", "ids": ["1"]}}), ("time", {"run_time": time(4, 0)}), ("parameters", {"parameters": {"x": 1}}), ("action", {"action_id": "patching.other"}), ("type", {"schedule_type": "weekly"})):
    del spy[:]
    helper(alice, object(), {**same, **change}, "cid", schedule=stored)
    must(len(spy) == 1, f"a change of the {label} is checked")
del spy[:]
helper(alice, object(), same, "cid", schedule=SimpleNamespace(**{**stored.__dict__, "enabled": False}))
must(len(spy) == 1, "switching a schedule on is checked")
del spy[:]
helper(alice, object(), same, "cid")
must(len(spy) == 1 and spy[0][5] == "cid", "a new schedule is checked with the id from the body")
urls = (APP / "urls.py").read_text(encoding="utf-8")
must(urls.count("SchedulerSystemActionConfirmationView.as_view()") == 1 and 'path("scheduler/system-actions/confirmation/"' in urls, "the route is registered once")
must("class SchedulerSystemActionConfirmationView(APIView):" in text and "permission_classes = [SessionAuthenticated]" in text.split("class SchedulerSystemActionConfirmationView", 1)[1].split("def post", 1)[0], "a signed-in session is required")
print("       the HTTP views keep their order and save an ordinary schedule as before; only a system action is checked, in one place; the route is registered once")

# ---- no module uses the new names
MODULES = ROOT.parents[1] / "modules"
if MODULES.is_dir():
    names = re.compile(r"\b(describe_confirmation|confirmation_id|system_action_confirmation|SystemActionCreationRefused|run_system_action|register_system_action)\b")
    hits = []
    for path in MODULES.rglob("*.py"):
        if any(part in {"node_modules", "__pycache__", "tests"} for part in path.parts):
            continue
        if names.search(path.read_text(encoding="utf-8", errors="replace")):
            hits.append(str(path.relative_to(MODULES)))
    must(not hits, f"modules that already use the new names: {hits}")
    print("       no module in modules/ uses the new names")
else:
    print("       modules/ is not on this PC: the module search was skipped")
print("PASS scheduler compat 1.17.66")
