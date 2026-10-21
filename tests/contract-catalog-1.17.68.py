#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.68 regression: the contract catalog (framwork/tec_tac/contracts.py), the docs and the release notes carry every new public name and every changed behaviour.

contracts.py needs Django, so it is read as source (ast.literal_eval). Covered: a row for each new function, class and capability (describe_delegation, register_delegation_grant,
remove_delegation_grant, issue_delegation_ticket, start_delegated_run, DelegationRefused, register_target_resolver, CreationScopeUnavailable, TakeoverRefused, the patch lockdown
status); the changed rows (register_system_action, reconcile_schedule, verify_run_context, VerifiedSchedulerRun, the confirmation route notes, the system-actions rule) say what
changed and which release; the capability metadata is 1.2.0 with the four earlier operations first; core.patch_lockdown is 1.0.0 with one operation; the docs exist and name each new
public name; the release notes carry the headings, the module-facing changes and the dev-server checklist; one root release note; the earlier notes are kept; VERSION and the package
say 1.17.68; the questions and requests are written.
"""
from __future__ import annotations

import ast
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
pl = load("tec_tac.patch_lockdown", "patch_lockdown.py")
deleg = load("tec_tac.delegation", "delegation.py")

tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
values = {}
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("CORE_CONTRACTS", "RULES", "HTTP_CONTRACT_DETAILS"):
        values[node.targets[0].id] = ast.literal_eval(node.value)
rows, rules, http = values["CORE_CONTRACTS"], values["RULES"], values["HTTP_CONTRACT_DETAILS"]
index = {(r["import_path"], r["name"]): r for r in rows}
must(len(index) == len(rows), "no row is listed twice")

# ---- the new rows
NEW = {
    ("tec_tac.system_actions", "describe_delegation"): ("owner_module", "confirmation_id", "600 seconds", "own prefix", "scheduler manager", "40000"),
    ("tec_tac.system_actions", "register_delegation_grant"): ("grant_key", "20 grants", "takeover_out_of_scope", "owner_changed_from", "digest"),
    ("tec_tac.system_actions", "remove_delegation_grant"): ("strict audit row", "stops working"),
    ("tec_tac.system_actions", "issue_delegation_ticket"): ("LIVE Scheduler run", "24 hours", "digest"),
    ("tec_tac.system_actions", "start_delegated_run"): ("outside_grant", "marker", "never starts a second install", "run_system_action", "grant_changed", "get_one_off_run", "every other one-off keeps every re-check"),
    ("tec_tac.delegation", "DelegationRefused"): ("SchedulerNotAllowed", "SchedulerPermanentError", "takeover_out_of_scope"),
    ("tec_tac.scheduler_target_resolvers", "register_target_resolver"): ("AppConfig.ready()", "target_types", "unresolved", "40000", "TargetResolverRegistrationError", "targets_unresolved", "decides no right"),
    ("tec_tac.scheduler", "CreationScopeUnavailable"): ("Edit it and save it once", "creation_scope_unavailable", "never invents"),
    ("tec_tac.scheduler", "TakeoverRefused"): ("takeover_out_of_scope", "You cannot take over this schedule", "never widens"),
    ("tec_tac.patch_lockdown", "status"): ("core.patch_lockdown 1.0.0", "TRMM_DISABLE_APPROVE_UPDATES_TASK", "TRMM_DISABLE_WINUPDATES_INSTALL_TASK", "approve_updates", "tasks_off", "approve_guard_installed",
                                           "fails open", "custom:tactical-patch-lockdown", "not blocked", "writes no Tactical data"),
}
for key, needles in NEW.items():
    must(key in index, f"missing row {key}")
    purpose = index[key]["purpose"]
    must("1.17.68" in purpose, f"{key} does not say which release added it")
    for needle in needles:
        must(needle in purpose, f"{key} row lacks {needle!r}")
    must(index[key]["kind"] == "python" and index[key]["audience"] and index[key]["area"], f"{key} keeps the row shape")
print("       a row for each new function, class and capability says what it does, who may call it and which release added it")

# ---- the changed rows
reg = index[("tec_tac.system_actions", "register_system_action")]["purpose"]
for needle in ("delegable_to", "patch lockdown", "core.patch_lockdown", "patch_lockdown: active", "Since 1.17.68"):
    must(needle in reg, f"register_system_action lacks {needle!r}")
must("R-36 is not built" not in reg and "(R-36" not in reg, "the stale R-36 wording is gone")
rec = index[("tec_tac.scheduler", "reconcile_schedule")]["purpose"]
for needle in ("Since 1.17.68", "IS an edit", "creation_scope", "owner_changed_from", "owner_changed_to", "previous_confirmed_by", "TakeoverRefused", "no bypass for a scheduler manager", "only switches the schedule off moves nothing",
               "register_target_resolver", "The signature is unchanged"):
    must(needle in rec, f"reconcile_schedule lacks {needle!r}")
must("confirmation_id=None" not in rec or "Any other action behaves exactly as before" in rec, "the older text stays")
verify = index[("tec_tac.scheduler", "verify_run_context")]["purpose"]
must("Since 1.17.68" in verify and "held_at_creation" in verify and "delegation.start" in verify and "Every other one-off keeps every re-check" in verify, "verify_run_context")
vsr = index[("tec_tac.scheduler", "VerifiedSchedulerRun")]["purpose"]
for needle in ("has_creation_scope", "creation_scope_info()", "held_at_creation(flag)", "resolved_endpoints(*, whole_scope=False, limit=MAX_AGENTS)", "CreationScopeUnavailable", "Q-APM12", "never wider than the targets AND the scope",
               "has_tactical_permission and resource_context are unchanged", "40000", "creator_username"):
    must(needle in vsr, f"VerifiedSchedulerRun lacks {needle!r}")
route = http["/api/tfd/scheduler/system-actions/confirmation/"]["POST"]["notes"]
must(any("Since 1.17.68" in note and "takeover_out_of_scope" in note for note in route), "the confirmation route notes name the scope and the takeover")
rule = next(r for r in rules if r.startswith("System actions (core.system_actions 1.2.0 since Core 1.17.68"))
for needle in ("Since 1.17.68", "creation scope", "held_at_creation", "register_target_resolver", "describe_delegation", "start_delegated_run", "core.patch_lockdown", "run_system_action unchanged"):
    must(needle in rule or needle.replace("creation scope", "created or last edited") in rule, f"the system actions rule lacks {needle!r}")
print("       the changed rows, the route notes and the system-actions rule say what changed and since which release")

# ---- the capabilities
meta = sa.system_actions_contract_metadata()
must(meta["version"] == "1.2.0" and meta["operations"][:4] == ["list_actions", "get_action", "run", "describe_confirmation"] and meta["operations"][4:] == [
    "describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket", "start_delegated_run"], meta["operations"])
must(">=1.17.68" in meta["requires_framework"] and ">=1.17.61" in meta["requires_framework"] and "delegation" in meta, meta["requires_framework"])
for name in ("describe_delegation(", "register_delegation_grant(", "remove_delegation_grant(", "issue_delegation_ticket(", "start_delegated_run(", "delegable_to=()"):
    must(name in meta["python"], name)
cap_meta = pl.patch_lockdown_contract_metadata()
must(cap_meta["id"] == "core.patch_lockdown" and cap_meta["version"] == "1.0.0" and cap_meta["operations"] == ["status"] and cap_meta["writes_tactical_data"] is False and cap_meta["requires_framework"] == ">=1.17.68", cap_meta)
for reason in deleg.REASONS:
    must(reason in index[("tec_tac.system_actions", "start_delegated_run")]["purpose"] or reason in index[("tec_tac.delegation", "DelegationRefused")]["purpose"] or reason in ("queue_failed", "context_invalid", "bad_module"), f"reason {reason} is not described")
print("       core.system_actions is 1.2.0 with the four earlier operations first and five appended; core.patch_lockdown is 1.0.0 with one operation and writes no Tactical data")

# ---- the docs
sys_doc = (ROOT / "docs" / "system-actions.md").read_text(encoding="utf-8")
for needle in ("core.system_actions 1.2.0", "## Creation-time scope and ownership", "## Delegation", "## A module-owned target type", "register_target_resolver", "describe_delegation", "register_delegation_grant",
               "remove_delegation_grant", "issue_delegation_ticket", "start_delegated_run", "delegable_to", "TakeoverRefused", "CreationScopeUnavailable", "held_at_creation", "resolved_endpoints", "CQ205",
               "grant_changed", "outside_grant", "patch_lockdown: active", "docs/patch-lockdown.md", "CQ203", "wrong_module"):
    must(needle in sys_doc, f"docs/system-actions.md lacks {needle!r}")
must("(R-36 is not built)" not in sys_doc, "the stale wording is gone")
lock = (ROOT / "docs" / "patch-lockdown.md").read_text(encoding="utf-8")
for needle in ("TRMM_DISABLE_APPROVE_UPDATES_TASK", "TRMM_DISABLE_WINUPDATES_INSTALL_TASK", "approve_updates", "core.patch_lockdown", "status()", "approve_guard_installed", "How it fails", "Fails open", "30 seconds",
               "custom:tactical-patch-lockdown", "checklist A2", "CQ203", "What is not built"):
    must(needle in lock, f"docs/patch-lockdown.md lacks {needle!r}")
sched_doc = (ROOT / "docs" / "scheduler.md").read_text(encoding="utf-8")
must("The scope a schedule keeps, and ownership (Core 1.17.68" in sched_doc and "TakeoverRefused" in sched_doc and "resolved_endpoints" in sched_doc and "CreationScopeUnavailable" in sched_doc, "docs/scheduler.md")
msched = (ROOT / "docs" / "module-scheduling.md").read_text(encoding="utf-8")
must("a `reconcile_schedule` call with a person's request IS an edit" in msched and "register_target_resolver" in msched and "start_delegated_run" in msched and "core.patch_lockdown" in msched, "docs/module-scheduling.md")
caps = (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8")
must("`core.system_actions` 1.2.0" in caps and "`core.patch_lockdown` 1.0.0" in caps, "docs/capabilities.md")
must("1.2.0" in (ROOT / "docs" / "developer-contracts.md").read_text(encoding="utf-8") and "core.patch_lockdown" in (ROOT / "docs" / "developer-contracts.md").read_text(encoding="utf-8"), "docs/developer-contracts.md")
print("       the docs name each new public name; docs/patch-lockdown.md is new")

# ---- the release notes and the version
VERSION_NOW = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
roots = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
must(roots == [f"RELEASE_NOTES_{VERSION_NOW}.md"], f"exactly one root release note: {roots}")
must((ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.67.md").is_file() and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.66.md").is_file(), "the earlier notes are kept")
body = (ROOT / f"RELEASE_NOTES_{VERSION_NOW}.md").read_text(encoding="utf-8")
for needle in ("# Tec-Tac Framework 1.17.68", "## What changed and why", "## Module-facing", "## What I checked in modules/", "## What was left out, and what ends each wait", "## What I could not do", "## Questions I filed",
               "## Not run here", "## Dev-server checklist", "## Tests", "PASS", "FAIL", "Behaviour change 1", "Behaviour change 2", "CQ203", "CQ204", "CQ205", "tec_tac_check_contract_export", "migration 0037", "makemigrations --check",
               "patch-lockdown-runtime-1.17.68.py", "scheduler-creation-scope-runtime-1.17.68.py", "delegation-runtime-1.17.68.py", "delegation part (S4)", "checklist A2",
               "It never widens", "Closes", "R-36"):
    must(needle in body, f"the release notes lack {needle!r}")
must(VERSION_NOW.split("-")[0] == "1.17.68" and f'"version": "{VERSION_NOW}"' in (ROOT / "tec_tac_package.json").read_text(encoding="utf-8"), "version 1.17.68")
print("       one root release note, the earlier ones kept, VERSION and the package say 1.17.68")

# ---- the questions and the requests
reviews = ROOT.parents[1] / "reviews"
if reviews.is_dir():
    questions = (reviews / "questions" / "core.md").read_text(encoding="utf-8")
    for needle in ("### CQ203 (21 October 2026)", "### CQ204 (21 October 2026)", "### CQ205 (21 October 2026)", "## Core 1.17.68 (21 October 2026)", "Dev server update (21 October 2026), Core 1.17.68"):
        must(needle in questions, f"reviews/questions/core.md lacks {needle!r}")
    must(questions.count("### CQ203 ") == 1 and questions.count("### CQ204 ") == 1 and questions.count("### CQ205 ") == 1, "each question once")
    requests = (reviews / "requests" / "core.md").read_text(encoding="utf-8")
    for gone in ("### core (framework): say how Maintenance's unattended patch step may start", "### core: while a replacement for patching is honoured, disable Tactical's native patching paths",
                 "### core: a way to read a module-owned target type as endpoints", "### core: confirm that an honoured replacement's Tactical operations", "### core (framework): creation-time scope read for a module-owned schedule"):
        must(gone not in requests, f"the shipped entry {gone!r} is removed")
    must("a progress call for a Scheduler handler" in requests and "Core 1.17.68" in requests, "the progress-call entry stays; 1.17.68 is named")
    premium = (reviews / "requests" / "premium-modules.md").read_text(encoding="utf-8")
    must("## From Core 1.17.68 (21 October 2026)" in premium and "resolved_endpoints()" in premium and "delegable_to" in premium and "release-manager" in premium and "Q-APM12" in premium, "premium-modules.md")
    modules_req = (reviews / "requests" / "core-modules.md").read_text(encoding="utf-8")
    must("## From Core 1.17.68 (21 October 2026)" in modules_req and "### maintenance" in modules_req.split("## From Core 1.17.68 (21 October 2026)", 1)[1] and "issue_delegation_ticket" in modules_req, "core-modules.md")
    print("       the three questions and the requests are written; the shipped entries are removed")
else:
    print("       reviews/ is not on this PC: the question and request checks were skipped")
print("PASS contract catalog 1.17.68")
