#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.66 regression: every public name of this release has a row in the contract catalog (framwork/tec_tac/contracts.py).

contracts.py needs Django, so it is read as source (ast.literal_eval of CORE_CONTRACTS, RULES and HTTP_CONTRACT_DETAILS). Covered: a row for
describe_confirmation and SystemActionCreationRefused, each naming 1.17.66 and resolving to a real attribute; the rows of register_system_action,
run_system_action, reconcile_schedule, start_one_off_run and SystemActionRefused say what 1.17.66 changed (groups, parameters, the ceiling,
parameters_changed, confirmation_id, the new reasons, the install warning); the HTTP route of the confirmation has its entry; the rule text names
capability 1.1.0 and scripts.run; the capability metadata names every function-table row, every refusal reason and the new operation; the docs
name each new public name; no (import_path, name) pair repeats.
"""
from __future__ import annotations

import ast
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")

tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
values = {}
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("CORE_CONTRACTS", "RULES", "HTTP_CONTRACT_DETAILS"):
        values[node.targets[0].id] = ast.literal_eval(node.value)
rows, rules, http = values["CORE_CONTRACTS"], values["RULES"], values["HTTP_CONTRACT_DETAILS"]
index = {(r["import_path"], r["name"]): r for r in rows}
must(len(index) == len(rows), "no (import_path, name) pair repeats")

NEW = (("tec_tac.system_action_confirmation", "describe_confirmation"), ("tec_tac.system_action_confirmation", "SystemActionCreationRefused"))
for key in NEW:
    must(key in index, f"no catalog row for {key}")
    row = index[key]
    must(row["kind"] == "python" and row["audience"] == "provider/backend" and row["area"] == "system-actions", row)
    must("1.17.66" in row["purpose"] and ">=1.17.66" in row["purpose"], f"{key} does not say which release added it")
    must(hasattr(conf, key[1]), f"{key} does not exist in the module")
must(callable(conf.describe_confirmation) and issubclass(conf.SystemActionCreationRefused, sched.SchedulerNotAllowed), "the names are real")
print("       a catalog row for each of the two new public names, each naming 1.17.66 and resolving to a real attribute")

purpose = index[("tec_tac.system_action_confirmation", "describe_confirmation")]["purpose"]
for text in ("600 seconds", "does not prove the person pressed Yes", "required false", "POST /api/tfd/scheduler/system-actions/confirmation/", "reconcile_schedule(confirmation_id=)",
             "start_one_off_run(confirmation_id=)", "no bypass for a scheduler manager", "SystemActionCreationRefused", "describe_confirmation(request"):
    must(text in purpose, f"describe_confirmation row lacks {text!r}")
for reason in ("not_permitted", "confirmation_required", "confirmation_invalid", "out_of_scope", "targets_unresolved", "agent_count", "bad_parameters"):
    must(reason in index[("tec_tac.system_action_confirmation", "SystemActionCreationRefused")]["purpose"], f"reason {reason} is not described")
for reason in sa.REASONS:
    must(reason in index[("tec_tac.system_actions", "SystemActionRefused")]["purpose"], f"reason {reason} is not described")
print("       the new rows state the 600-second id, its limit, the three ways in and every reason; SystemActionRefused names every reason")

run_row = index[("tec_tac.system_actions", "run_system_action")]["purpose"]
for text in ("groups: {total, sent, failed, not_started}", "summary", "40000", "groups of at most 2000", "its own STRICT audit row", "parameters_changed", "system_action_parameters",
             "scripts.run", "never an argument or an environment value", "1.17.66", "CQ178", "OutcomeUnknown"):
    must(text in run_row, f"run_system_action row lacks {text!r}")
reg_row = index[("tec_tac.system_actions", "register_system_action")]["purpose"]
for text in ("1.1.0", "scripts.run", "scriptexecution", "can_run_scripts", "CQ173", "Tactical installs what its own patch policy approves, including updates set to Ignore elsewhere.", "patch lockdown"):  # 1.17.68: R-36 is built (core.patch_lockdown)
    must(text in reg_row, f"register_system_action row lacks {text!r}")
must("R-36 is open" not in reg_row and "inactive until" not in reg_row, "the old install refusal is gone from the row")
rec_row = index[("tec_tac.scheduler", "reconcile_schedule")]["purpose"]
must("confirmation_id=None" in rec_row and ">=1.17.66" in rec_row and "SystemActionCreationRefused" in rec_row and "Any other action behaves exactly as before" in rec_row, "reconcile_schedule row")
one_row = index[("tec_tac.scheduler", "start_one_off_run")]["purpose"]
must("confirmation_id=None) -> TecTacScheduleRun" in one_row and "run_at: now" in one_row and ">=1.17.66" in one_row, "start_one_off_run row")
must("Since 1.17.65 (module-facing, framework >=1.17.65; AD-13 condition 2 amended and signed 20 October 2026)" in run_row, "the 1.17.65 text stays in the run_system_action row")
print("       the rows of register_system_action, run_system_action, reconcile_schedule and start_one_off_run say what 1.17.66 changed")

route = http["/api/tfd/scheduler/system-actions/confirmation/"]["POST"]
must(set(route["body"]) == {"action_id", "targets", "parameters", "when"} and set(route["response"]) == {"required", "text", "confirmation_id", "total", "groups", "expires_in"}, route)
must(set(route["errors"]) == {"400", "401", "403"} and "1.17.66" in " ".join(route["notes"]) and "confirmation_id" in " ".join(route["notes"]), route)
rule = next(r for r in rules if r.startswith("System actions (core.system_actions 1.2.0"))  # 1.17.68: 1.2.0 (additive)
for text in ("scripts.run", "groups of at most 2000", "CQ178", "CQ173", "Yes or No", "POST /api/tfd/scheduler/system-actions/confirmation/", "requires.framework >=1.17.61"):
    must(text in rule, f"the rule lacks {text!r}")
print("       the HTTP route has its entry (body, response, errors, notes) and the rule names capability 1.1.0, scripts.run and the groups")

meta = sa.system_actions_contract_metadata()
must(meta["version"] == "1.2.0" and meta["operations"] == ["list_actions", "get_action", "run", "describe_confirmation", "describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket", "start_delegated_run"], meta)  # 1.17.68: the five delegation operations are appended, none of the four earlier ones changed
must(set(meta["functions"]) == {"winupdate.scan", "winupdate.install", "scripts.run"} and set(meta["refusal_reasons"]) == set(sa.REASONS), meta)
must(meta["functions"]["scripts.run"]["takes_username"] is True and meta["functions"]["scripts.run"]["min_flags"] == ["can_run_bulk", "can_run_scripts"], meta["functions"]["scripts.run"])
must(meta["http"] == {"confirmation": "POST /api/tfd/scheduler/system-actions/confirmation/"} and meta["requires_framework"].startswith(">=1.17.61") and "1.17.66" in meta["requires_framework"], meta)
must(meta["unattended"].startswith("A scheduled run of a user-owned schedule skips owner_inactive, permission_lost and out_of_scope (>=1.17.65"), "the unattended text stays as in 1.17.65")
print("       the capability metadata is 1.1.0 and names every row, reason and operation; the unattended text is unchanged")

for name, needles in (("system-actions.md", ("describe_confirmation", "scripts.run", "groups", "CQ178", "CQ173", "confirmation", "40000", "parameters_changed")),
                      ("module-scheduling.md", ("confirmation_id", "system action")),
                      ("scheduler.md", ("groups", "confirmation"))):
    text = (ROOT / "docs" / name).read_text(encoding="utf-8")
    for needle in needles:
        must(needle in text, f"docs/{name} does not mention {needle}")
print("       the docs exist and name each new public name")
print("PASS contract catalog 1.17.66")
