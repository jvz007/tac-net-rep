#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.61 regression: every new public name of this release has a row in the contract catalog (framwork/tec_tac/contracts.py).

contracts.py needs Django, so it is read as source (ast.literal_eval of CORE_CONTRACTS and RULES). Covered: a row for PendingCompletion,
pending_completion, complete_pending_run, SchedulerCompletionRefused, serialize_run (the additive completion key and the new error types),
register_system_action, run_system_action and SystemActionRefused; every row's import_path and name resolve to a real attribute of the real
module (the harness loads them); no (import_path, name) pair repeats; every new row states the framework version it needs; the manifest
key and the capability are described in the rules; the capability metadata names every function-table row and refusal reason; the diagnostic
action is registered and described; the module docs exist and name each public name.
"""
from __future__ import annotations

import ast
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
values = {}
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("CORE_CONTRACTS", "RULES"):
        values[node.targets[0].id] = ast.literal_eval(node.value)
rows, rules = values["CORE_CONTRACTS"], values["RULES"]
index = {(r["import_path"], r["name"]): r for r in rows}
must(len(index) == len(rows), "no (import_path, name) pair repeats")

NEW = {
    ("tec_tac.scheduler", "PendingCompletion"), ("tec_tac.scheduler", "pending_completion"), ("tec_tac.scheduler", "complete_pending_run"),
    ("tec_tac.scheduler", "SchedulerCompletionRefused"), ("tec_tac.scheduler", "serialize_run"),
    ("tec_tac.system_actions", "register_system_action"), ("tec_tac.system_actions", "run_system_action"), ("tec_tac.system_actions", "SystemActionRefused"),
}
modules = {"tec_tac.scheduler": sched, "tec_tac.system_actions": sa}
for key in sorted(NEW):
    must(key in index, f"no catalog row for {key}")
    row = index[key]
    must(row["kind"] == "python" and row["audience"] == "provider/backend" and row["area"] in ("scheduler", "system-actions"), row)
    must("1.17.61" in row["purpose"], f"{key} does not say which release added it")
    must(hasattr(modules[key[0]], key[1]), f"{key} does not exist in the module")
print("       a catalog row for each of the eight new public names, each naming 1.17.61 and resolving to a real attribute")

# the public names of this release that exist in the modules are all catalogued
public_new = {"PendingCompletion", "pending_completion", "complete_pending_run", "SchedulerCompletionRefused"}
must(all(("tec_tac.scheduler", name) in index for name in public_new))
must(all(callable(getattr(sched, name)) for name in public_new))
must({"register_system_action", "run_system_action", "SystemActionRefused", "SystemActionRegistrationError", "SYSTEM_FUNCTIONS"} <= set(dir(sa)))

row = index[("tec_tac.scheduler", "serialize_run")]["purpose"]
for text in ("completion", "pending", "completed", "expired", "CompletionTimeout", "ExternalFailed", "ExternalCancelled", "ExternalTimedOut", "PendingRefused",
             "SystemActionRefused", "tec-tac.scheduler-test-pending"):
    must(text in row, f"the serialize_run row does not mention {text}")
must("tec-tac.scheduler-test-pending" in sched._ACTIONS, "the diagnostic action is registered (so it is listed in the export)")
print("       the serialize_run row names the additive completion key, every new error type and the diagnostic action")

purpose = index[("tec_tac.scheduler", "complete_pending_run")]["purpose"]
for text in ("core.caller_identity", "plain re-export", "idempotent", "conflict", "late", "wrong_job", "custom:scheduler-completion-refused", "16 KiB", "500 characters"):
    must(text in purpose, text)
purpose = index[("tec_tac.system_actions", "run_system_action")]["purpose"]
for text in ("2000", "STRICT audit", ".delay", "at most once", "OutcomeUnknown", "no bypass", "function_unavailable", "Queued in Tactical"):
    must(text in purpose, text)
for reason in sa.REASONS:
    must(reason in index[("tec_tac.system_actions", "SystemActionRefused")]["purpose"], f"reason {reason} is not described")
for reason in completion.REFUSAL_TEXT:
    must(reason in index[("tec_tac.scheduler", "SchedulerCompletionRefused")]["purpose"], f"reason {reason} is not described")
print("       the purposes state the caller rule, the idempotency, the limits, the at-most-once rule and every refusal reason")

must(any("system_actions" in rule and "1.17.61" in rule and "requires.framework" in rule for rule in rules), "the manifest key is described in the rules")
meta = sa.system_actions_contract_metadata()
must(meta["id"] == "core.system_actions" and meta["version"] == "1.0.0" and meta["requires_framework"] == ">=1.17.61", meta)
must(set(meta["functions"]) == set(sa.SYSTEM_FUNCTIONS) and set(meta["refusal_reasons"]) == set(sa.REASONS), meta)
print("       the manifest key and the capability metadata are documented")

for name, needles in (("system-actions.md", ("run_system_action", "register_system_action", "winupdate.scan", "winupdate.install", "CQ173", "at most once")),
                      ("scheduler.md", ("PendingCompletion", "complete_pending_run", "CompletionTimeout", "settle_server_job_runs")),
                      ("module-scheduling.md", ("pending_completion", "complete_pending_run", "server_maintenance_job")),
                      ("server-maintenance-capability.md", ("source_run_id", "pending_completion"))):
    text = (ROOT / "docs" / name).read_text(encoding="utf-8")
    for needle in needles:
        must(needle in text, f"docs/{name} does not mention {needle}")
print("       the docs exist and name each public name")

# the release notes: the module-facing heading, the questions, the requests and a PASS or FAIL checklist
notes = (ROOT / "RELEASE_NOTES_1.17.61.md").read_text(encoding="utf-8")
must("## Module-facing" in notes and "What I checked in `modules/`" in notes and "## What was left out, and what ends each wait" in notes, "the notes carry the headings the plan names")
for question in ("CQ172", "CQ173", "CQ174", "CQ175", "CQ176", "CQ177", "CQ178", "CQ50"):
    must(question in notes, f"the notes name {question}")
steps = notes[notes.index("## Dev-server checklist"):]
must(steps.count("**Step ") == 8 and steps.count("**FAIL**") >= 7 and "Expect" in steps, "eight checklist steps, each with its FAIL line")
must((ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.60.md").is_file() and not (ROOT / "RELEASE_NOTES_1.17.60.md").exists(), "the earlier notes moved to docs/releases")
must(ROOT.joinpath("VERSION").read_text(encoding="utf-8").strip() == "1.17.61" and '"version": "1.17.61"' in ROOT.joinpath("tec_tac_package.json").read_text(encoding="utf-8"), "version 1.17.61")
reviews = ROOT.parents[1] / "reviews"
if reviews.is_dir():
    questions = (reviews / "questions" / "core.md").read_text(encoding="utf-8")
    for question in ("CQ172", "CQ173", "CQ174", "CQ175", "CQ176", "CQ177", "CQ178"):
        must(questions.count(f"### {question} (20 October 2026), Core 1.17.61") == 1, f"{question} is in the questions file once")
    for area in ("premium-modules", "core-modules", "ui"):
        must("From Core 1.17.61 (20 October 2026)" in (reviews / "requests" / f"{area}.md").read_text(encoding="utf-8"), f"{area} has the 1.17.61 request section")
    own = (reviews / "requests" / "core.md").read_text(encoding="utf-8")
    must("- Core 1.17.61 (20 October 2026" in own and "async completion for a Scheduler action" not in own.replace("'core: async completion for a Scheduler action' (patchmanagement 0.11.0)", ""), "the shipped line is there and the async request is gone")
print("       the release notes, the questions and the requests are written")

print("PASS contract catalog 1.17.61")
