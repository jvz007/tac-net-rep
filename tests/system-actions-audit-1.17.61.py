#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.61 regression: the shape of every audit row this release writes is pinned (rule A8: no secrets, no ids, no result text).

Covered: the strict 'run' row of a system action (action run, object system_action, object id the action id, actor the owner, exactly
the metadata keys the plan names, no endpoint number or hostname); the single 'deny' row of a refusal; the 'custom:outcome-unknown' row;
the custom rows (custom:scheduler-completion, custom:scheduler-completion-refused, custom:outcome-unknown)
use action names the audit module accepts and Core alone writes; only the 'run' row is strict; audit.py itself is unchanged in the rules
this release relies on (the Core-only action stays custom:operation-failed; module 'core' accepts any authenticated user as actor).
"""
from __future__ import annotations

import re
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

BOTH = ["can_manage_winupdates", "can_run_bulk"]
IDS = [987654311, 987654312]
alice = User("alice")
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = set(IDS)
root = plugin("patching", system_actions=["patching.scan"])
sa._clear_for_tests()
sa.register_system_action("patching.scan", "patching", "Scan", "winupdate.scan", BOTH)
CFG = {"agents": IDS}
AUTO_TARGETS = lambda: {"type": "endpoint", "ids": [str(i) for i in CFG["agents"]]}  # 1.17.62: the schedule targets what the handler sends
ns = compile_as(root / "h.py", "def h(context):\n    return sa.run_system_action(context, action_id='patching.scan', agent_ids=CFG['agents'])\n", sa=sa, CFG=CFG)
sched.register_scheduled_action(id="patching.h", module_id="patching", label="h", handler=ns["h"], target_types=("none",), timeout_seconds=600)

reset()
run = make_run("patching.h", "patching", user=alice, owner="user")
must(go(run)["outcome"] == "queued")
must([a["action"] for a in AUDITS] == ["run"], AUDITS)
row = AUDITS[0]
must(set(row) == {"actor", "module_id", "action", "object_type", "object_id", "message", "metadata", "strict"}, set(row))
must(row["strict"] is True and row["actor"] is alice and row["module_id"] == "core" and row["object_type"] == "system_action" and row["object_id"] == "patching.scan", row)
must(set(row["metadata"]) == {"requested_by", "run_id", "schedule_id", "owner_module", "function", "agent_count", "targets_digest", "run_kind", "creator", "confirmed_by"}, row["metadata"])  # 1.17.63 added the last three: who is behind the run
must(row["metadata"]["requested_by"] == "scheduler" and row["metadata"]["agent_count"] == 2, row["metadata"])
must(not any(str(i) in repr(row) for i in IDS), "no endpoint number")
must(re.fullmatch(r"[0-9a-f]{32}", row["metadata"]["targets_digest"]), row["metadata"]["targets_digest"])
digest = row["metadata"]["targets_digest"]
reset()
run2 = make_run("patching.h", "patching", user=alice, owner="user")
go(run2)
must(AUDITS[0]["metadata"]["targets_digest"] != digest, "the digest is bound to the run: the same endpoints in another run differ")
print("       the strict 'run' row: action run, object system_action, actor the owner, only the pinned metadata, no endpoint number")

reset()
FLAGS["alice"] = set()
run = make_run("patching.h", "patching", user=alice, owner="user")
go(run)
must(len(AUDITS) == 1, AUDITS)
row = AUDITS[0]
must(set(row) == {"actor", "module_id", "action", "object_type", "object_id", "message", "metadata"} and "strict" not in row, set(row))
must(row["action"] == "deny" and row["actor"] is alice and row["module_id"] == "core" and row["object_type"] == "system_action" and row["object_id"] == "patching.scan", row)
must(row["metadata"] == {"reason": "permission_lost", "requested_by": "scheduler", "owner_module": "patching", "run_id": str(run.id), "run_kind": "scheduled", "creator": "alice", "confirmed_by": None}, row["metadata"])  # 1.17.63: run_kind, creator, confirmed_by
must(row["message"].startswith("A scheduled system action was refused:") and not any(str(i) in repr(row) for i in IDS), row["message"])
FLAGS["alice"] = set(BOTH)
print("       the deny row: reason code, requested_by scheduler, owner module and run id; not strict; no ids")

reset()
run = make_run("patching.h", "patching", user=alice, owner="user")
run.system_action_marks = [{"action_id": "patching.scan", "targets_digest": sa._digest(run.id, "patching.scan", IDS), "state": "claiming", "agents": 2}]
go(run)
row = AUDITS[0]
must([a["action"] for a in AUDITS] == ["custom:outcome-unknown"] and row["actor"] is alice and row["object_type"] == "system_action", AUDITS)
must(row["metadata"] == {"requested_by": "scheduler", "run_id": str(run.id), "owner_module": "patching", "reason": "outcome_unknown", "run_kind": "scheduled", "creator": "alice", "confirmed_by": None}, row["metadata"])  # 1.17.63: run_kind, creator, confirmed_by
print("       the outcome-unknown row: the owner as actor, reason and run id only")

# every custom action this release writes is a valid audit action name and none is the Core-only failed action
audit_src = (APP / "audit.py").read_text(encoding="utf-8")
pattern = re.compile(r"^custom:[a-z0-9][a-z0-9_-]{0,63}$")
written = set(re.findall(r'"(custom:[a-z0-9_-]+)"', (APP / "scheduler_completion.py").read_text(encoding="utf-8") + (APP / "system_actions.py").read_text(encoding="utf-8")))
must(written == {"custom:scheduler-completion", "custom:scheduler-completion-refused", "custom:outcome-unknown"}, written)
must(all(pattern.fullmatch(name) for name in written) and "custom:operation-failed" not in written)
must('_CUSTOM_ACTION_RE = re.compile(r"^custom:[a-z0-9][a-z0-9_-]{0,63}$")' in audit_src and 'CORE_ONLY_FAILED_ACTION = "custom:operation-failed"' in audit_src, "audit.py rules unchanged")
must('if not permissions or module.get("id") == "core":' in audit_src, "module core accepts any authenticated actor, so the owner can be the actor")
records = re.findall(r"record\(", (APP / "system_actions.py").read_text(encoding="utf-8"))
must(len(records) == 3, "three audit writers in system_actions.py: run, deny, outcome-unknown")
must((APP / "system_actions.py").read_text(encoding="utf-8").count("strict=True") == 1, "only the 'run' row is strict")
must("strict=True" not in (APP / "scheduler_completion.py").read_text(encoding="utf-8"), "the scheduler completion rows are best effort")
print("       the custom action names are valid, Core-written and not the Core-only failed action; audit.py is unchanged")

print("PASS system actions audit 1.17.61")
