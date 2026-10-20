#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.62 regression (held Low from the 1.17.61 review): run_system_action ties agent_ids to the schedule's targets. A run never widens the set.

Before 1.17.62 a handler could name any endpoint inside its owner's role scope, whatever the schedule targeted, because the call did not
read the run's targets snapshot. Now every endpoint must be one of the snapshotted targets, after the count and shape checks and after the
owner's scope check (which is unchanged).

The real system_actions.py, scheduler.py, scheduler_run_context.py, caller_identity.py and tasks.py on the stub harness; the stub of
resources_adapter.agent_pks_for_scheduler_targets resolves endpoint, client, site and dynamic snapshots like the real helper (read as source
in the last section). Covered: ids inside an endpoint, client, site and dynamic-scope snapshot run; one id outside refuses the whole call with
one deny row, no send and a skipped run; a vanished target is reported as a count and never silently dropped; an empty snapshot and ``none``
refuse; a module-owned target type and a resolver that fails answer targets_unresolved (nothing is guessed); the count (0 and 2001) and shape
checks run before any lookup, the owner's scope check still comes first, and the 2000 cap is unchanged; the deny row and the run carry no
endpoint id; the real resolver reads Tactical through resources_adapter only.
"""
from __future__ import annotations

import re
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

BOTH = ("can_manage_winupdates", "can_run_bulk")
IDS = [987654311, 987654312, 987654313]
OUTSIDE = 987654399
alice = User("alice")
CFG = {"agents": list(IDS)}
SNAPSHOT = {"value": {"type": "endpoint", "ids": [str(i) for i in IDS]}}
AUTO_TARGETS = lambda: SNAPSHOT["value"]  # the snapshot of every run make_run builds
root = plugin("patching", system_actions=["patching.scan"])
sa._clear_for_tests()
sa.register_system_action("patching.scan", "patching", "Scan", "winupdate.scan", BOTH)
ns = compile_as(root / "h.py", "def h(context):\n    return sa.run_system_action(context, action_id='patching.scan', agent_ids=CFG['agents'])\n", sa=sa, CFG=CFG)
sched.register_scheduled_action(id="patching.h", module_id="patching", label="h", handler=ns["h"], target_types=("none",), timeout_seconds=600)


UNSET = object()


def start(snapshot, agents=UNSET, owner="user"):
    reset()
    FLAGS["alice"] = set(BOTH)
    SCOPE["alice"] = set(IDS) | {OUTSIDE} | set(range(5000, 7100))
    CFG["agents"] = list(IDS) if agents is UNSET else agents
    SNAPSHOT["value"] = snapshot
    run = make_run("patching.h", "patching", user=alice, owner=owner)
    return run, go(run)


def deny_rows():
    return [a for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def refused(run, out, reason):
    rows = deny_rows()
    ok = len(rows) == 1 and rows[0]["metadata"]["reason"] == reason and not TASK_CALLS and run.status == "skipped" and run.error_type == "SystemActionRefused"
    must(ok, (reason, out, AUDITS, run.__dict__))
    must(not [a for a in AUDITS if a["action"] == "run"], "no strict run row")
    text = repr(AUDITS) + repr({k: v for k, v in run.__dict__.items() if k != "targets_snapshot"})
    must(not any(str(i) in text for i in (*IDS, OUTSIDE)), "no endpoint id in the audit trail or the run")
    return rows[0]


# ---- ids inside the snapshot run, whatever the snapshot's kind
run, out = start({"type": "endpoint", "ids": [str(i) for i in IDS]})
must(out["outcome"] == "queued" and TASK_CALLS == [("scan", (IDS,), {})], out)
run, out = start({"type": "endpoint", "ids": [str(i) for i in IDS] + [str(OUTSIDE)]}, agents=IDS[:2])
must(out["outcome"] == "queued" and TASK_CALLS == [("scan", (IDS[:2],), {})], "a subset of the targets runs")
CLIENT_AGENTS[7] = set(IDS)
reset()
CLIENT_AGENTS[7] = set(IDS)
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = set(IDS)
SNAPSHOT["value"] = {"type": "client", "ids": [7]}
CFG["agents"] = list(IDS)
run = make_run("patching.h", "patching", user=alice, owner="user")
out = go(run)
must(out["outcome"] == "queued", out)
SITE_AGENTS[3] = set(IDS)
reset()
SITE_AGENTS[3] = set(IDS)
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = set(IDS)
SNAPSHOT["value"] = {"type": "sites", "ids": [3]}
run = make_run("patching.h", "patching", user=alice, owner="user")
must(go(run)["outcome"] == "queued", "a site snapshot")
reset()
CLIENT_AGENTS[7] = set(IDS)
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = set(IDS)
SNAPSHOT["value"] = {"type": "dynamic", "scope": {"type": "client", "ids": [7]}, "filter": {"os": "windows"}}
run = make_run("patching.h", "patching", user=alice, owner="user")
must(go(run)["outcome"] == "queued", "a dynamic snapshot is bounded by its Tactical scope; the module's filter only narrows it")
print("       ids inside an endpoint, client, site or dynamic-scope snapshot run")

# ---- one id outside refuses the whole call
run, out = start({"type": "endpoint", "ids": [str(i) for i in IDS]}, agents=[*IDS, OUTSIDE])
row = refused(run, out, "outside_targets")
must(row["metadata"] == {"reason": "outside_targets", "requested_by": "scheduler", "owner_module": "patching", "run_id": str(run.id)}, row["metadata"])
must(row["actor"] is alice and "never widens" in run.error and "no longer exist" not in run.error, run.error)
run, out = start({"type": "endpoint", "ids": [str(IDS[0])]})  # the handler names three; the schedule targets one
refused(run, out, "outside_targets")
run, out = start({"type": "none"})
refused(run, out, "outside_targets")
run, out = start({})
refused(run, out, "outside_targets")
run, out = start({"type": "client", "ids": [7]}, agents=[OUTSIDE])
refused(run, out, "outside_targets")
print("       one endpoint outside the snapshot refuses the whole call with one deny row, no send and a skipped run; none and an empty snapshot refuse")

# ---- a target that no longer exists is reported as a count
reset()
EXISTING_AGENTS = {IDS[0], IDS[1]}
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = set(IDS)
SNAPSHOT["value"] = {"type": "endpoint", "ids": [str(i) for i in IDS]}
CFG["agents"] = list(IDS)
run = make_run("patching.h", "patching", user=alice, owner="user")
out = go(run)
refused(run, out, "outside_targets")
must("1 target(s) of this schedule no longer exist." in run.error, run.error)
reset()
EXISTING_AGENTS = {IDS[0]}
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = set(IDS)
CFG["agents"] = list(IDS)
run = make_run("patching.h", "patching", user=alice, owner="user")
out = go(run)
must("2 target(s) of this schedule no longer exist." in run.error, run.error)
EXISTING_AGENTS = None
print("       a vanished target is counted in the refusal text and never silently dropped")

# ---- unresolvable snapshots: nothing is guessed
run, out = start({"type": "profile", "profile_id": 5})
refused(run, out, "targets_unresolved")
real_target_pks = sa._target_pks
sa._target_pks = lambda snapshot: (_ for _ in ()).throw(RuntimeError("ambiguous identifier"))
run, out = start({"type": "endpoint", "ids": [str(i) for i in IDS]})
sa._target_pks = real_target_pks
refused(run, out, "targets_unresolved")
print("       a module-owned target type and a failing resolver answer targets_unresolved; nothing is guessed")

# ---- order: count and shape first, then the owner's scope, then the targets
for bad in ([], None, "abc", [True], list(range(5000, 7001))):
    run, out = start({"type": "endpoint", "ids": [str(i) for i in IDS]}, agents=bad)
    must(not TARGET_CALLS and len(deny_rows()) == 1 and deny_rows()[0]["metadata"]["reason"] in ("agent_count", "bad_agents"), (bad if not isinstance(bad, list) or len(bad) < 5 else "2001", AUDITS))
run, out = start({"type": "endpoint", "ids": [str(i) for i in IDS]}, agents=[IDS[0], 4])  # 4 is outside the owner's role scope
refused(run, out, "out_of_scope")
must(not TARGET_CALLS, "the owner's scope is judged before the snapshot is read")
run, out = start({"type": "endpoint", "ids": [str(i) for i in range(5000, 7000)]}, agents=list(range(5000, 7000)))
must(out["outcome"] == "queued" and out["agents"] == 2000, "exactly 2000 still runs when the schedule targets them all")
run, out = start({"type": "endpoint", "ids": [str(i) for i in range(5000, 6999)]}, agents=list(range(5000, 7000)))
refused(run, out, "outside_targets")
print("       the count and shape come first, the owner's role scope second, the targets third; the 2000 cap is unchanged")

# ---- the owner's scope still applies to a target in the snapshot
run, out = start({"type": "endpoint", "ids": [str(OUTSIDE)]}, agents=[OUTSIDE])
must(out["outcome"] == "queued", "in scope and in the snapshot")
reset()
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = set(IDS)
SNAPSHOT["value"] = {"type": "endpoint", "ids": [str(OUTSIDE)]}
CFG["agents"] = [OUTSIDE]
run = make_run("patching.h", "patching", user=alice, owner="user")
out = go(run)
refused(run, out, "out_of_scope")
print("       an endpoint in the snapshot but outside the owner's role scope is still refused as out_of_scope")

# ---- a one-off run is bound the same way; a module-owned run is refused earlier (no owner)
run, out = start({"type": "endpoint", "ids": [str(IDS[0])]}, owner="one-off")
refused(run, out, "outside_targets")
print("       a one-off run is bound by its snapshot too")

# ---- the real resolver reads Tactical through resources_adapter only
adapter = (APP / "resources_adapter.py").read_text(encoding="utf-8")
body = adapter.split("def agent_pks_for_scheduler_targets", 1)[1].split("\ndef ", 1)[0]
for needle in ("tactical_scope_ref", "_models()", "Client.objects.filter(pk__in=values)", "Site.objects.filter(pk__in=values)", "agent_id__in", 'kind == "module"', "return None"):
    must(needle in body, f"the resolver lacks {needle}")
must("trusted" not in body and "filter_by_role" not in body, "the resolver is a bound, not an authorization decision: the owner's scope is checked separately")
src = (APP / "system_actions.py").read_text(encoding="utf-8")
must(re.search(r"_refuse\(\"out_of_scope\", \*\*common\)\n    # \(6b\).*\n    try:\n        resolved = _target_pks\(run.targets_snapshot or \{\}\)", src), "the targets check follows the scope check")
must('"outside_targets"' in src and '"targets_unresolved"' in src and 'REASONS' in src, "the new reasons exist")
docs = (ROOT / "docs" / "system-actions.md").read_text(encoding="utf-8")
must("outside_targets" in docs and "targets_unresolved" in docs, "the docs name the reasons")
meta = sa.system_actions_contract_metadata()
must({"outside_targets", "targets_unresolved"} <= set(meta["refusal_reasons"]) and meta["requires_framework"] == ">=1.17.61", "the capability's reasons list grows; its version stays (additive)")
print("       the real resolver uses resources_adapter only and is a bound; the reasons are in the capability metadata and the docs")

print("PASS system actions targets 1.17.62")
