#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.74 regression (Q-APM21 b): the public contract of resolve_delegated_targets.

Covered: capability core.system_actions is at least 1.4.0 (additive; the pins use >= so a -N rebuild passes), its operations keep the ten earlier ones first and in order and
append resolve_delegated_targets, and the provider object really has it; the metadata keeps every earlier key (write.kinds included), names no command kind or reboot row, gains the
delegation caller and requires_framework '>=1.17.74'; every refusal reason is still sorted and listed once; the capability route gives the same answer as a direct call;
contracts.py has a resolve_delegated_targets row and the system-actions rule says what it does and that polling is the supported way to resume after a reboot; docs/system-actions.md
has the 'Durable runs with a reboot' section and says no event is published (so a later release that adds an event must change this test and the text together), and names no
reboot row as built; the contract-export gate fails on an export made for 1.17.73.
"""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path

H = Path(__file__).resolve().parent / "delegated-targets-harness-1.17.74.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input


def at_least(version, wanted):
    return tuple(int(x) for x in version.split("-")[0].split(".")) >= tuple(int(x) for x in wanted.split("."))


meta = sa.system_actions_contract_metadata()
EARLIER = ["list_actions", "get_action", "run", "describe_confirmation", "describe_delegation", "register_delegation_grant", "remove_delegation_grant",
           "issue_delegation_ticket", "start_delegated_run", "run_write"]
must(at_least(meta["version"], "1.4.0") and meta["version"] == sa.CAPABILITY_VERSION, meta["version"])
must(meta["operations"] == EARLIER + ["resolve_delegated_targets"] and list(sa.OPERATIONS) == EARLIER + ["resolve_delegated_targets"], meta["operations"])
must(all(callable(getattr(sa._PROVIDER, name, None)) for name in meta["operations"]), "the provider has every operation, resolve_delegated_targets included")
print("       core.system_actions is 1.4.0 or later; the ten earlier operations stay first and in order; resolve_delegated_targets is appended and exists on the provider")

# ---- the route and the direct import give the same answer
fresh(3)
route_src = '''
def resolve(sa, ticket, **kw):
    return sa._PROVIDER.resolve_delegated_targets(ticket, **kw)
'''
ns = compile_as(roots["patchmanagement"] / "route2.py", route_src, sa=sa)
mods["patchmanagement"]["resolve"] = ns["resolve"]
save_grant()
must(resolve(ticket(), [BASE, BASE + 2])["covered"] == 1, "the capability route resolve_delegated_targets gives the same answer as the direct call")
print("       the capability route gives the same answer as the direct call")

# ---- the metadata
for key in ("id", "version", "operations", "python", "delegation", "functions", "manifest_key", "max_agents", "max_agents_per_group", "max_groups", "parameters_key",
            "refusal_reasons", "http", "delivery", "audit_actions", "requires_framework", "unattended", "write"):
    must(key in meta, key)
must("kinds" not in meta and "command" not in meta and "delegable_kinds" not in meta["delegation"], "the metadata names no command kind (CQ213, CQ215 are open)")
must(meta["write"]["kinds"] == ["task", "write"] and meta["write"]["function"] == "winupdate.set_action" and meta["write"]["max_changes"] == 40000, "a 1.3.0 reader of the write block still finds what it read")
rows = meta["functions"]
must(set(rows) == {"winupdate.scan", "winupdate.install", "scripts.run", "winupdate.set_action"}, sorted(rows))
for key in ("winupdate.scan", "winupdate.install", "scripts.run"):
    must(rows[key]["kind"] == "task" and rows[key]["replacement_only"] is False, key)
must(rows["winupdate.set_action"]["kind"] == "write" and rows["winupdate.set_action"]["replacement_only"] is True, "the write row is unchanged")
must(meta["delegation"]["callers"]["resolve_delegated_targets"] == "provider module named by the grant", meta["delegation"])
must({"describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket", "start_delegated_run"} <= set(meta["delegation"]["callers"]), "the earlier callers stay")
must(">=1.17.74" in meta["requires_framework"] and ">=1.17.70" in meta["requires_framework"] and ">=1.17.68" in meta["requires_framework"] and meta["requires_framework"].startswith(">=1.17.61"), meta["requires_framework"])
must("agents.reboot" not in meta["python"] and "resolve_delegated_targets(ticket, *, action_id, endpoint_ids)" in meta["python"] and "run_system_write(context, *, action_id, changes)" in meta["python"], "the python signatures")
must("wrong_kind" in meta["refusal_reasons"] and "use run_system_action for a task and run_system_write for a write" in sa.REASONS["wrong_kind"], sa.REASONS["wrong_kind"])
must(len(meta["refusal_reasons"]) == len(set(meta["refusal_reasons"])) and meta["refusal_reasons"] == sorted(sa.REASONS), "sorted, no duplicates")
json.dumps(meta, sort_keys=True)  # the export writes it as JSON
print("       the metadata keeps every earlier key, names no command kind and gains the new caller")

# ---- contracts.py
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
ROWS = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CORE_CONTRACTS")
RULES = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "RULES")
by = {(r["import_path"], r["name"]): r for r in ROWS}
resolve_row = by[("tec_tac.system_actions", "resolve_delegated_targets")]
must(resolve_row["area"] == "system-actions" and resolve_row["kind"] == "python" and resolve_row["audience"] == "provider/backend", resolve_row)
text = resolve_row["purpose"]
for needle in ("resolve_delegated_targets(ticket, *, action_id, endpoint_ids)", "1.17.74", "Q-APM21", "1 to 40000", "agent id texts", "never named", "ticket_invalid", "generic refusal", "one deny audit row",
               "creates no run and no schedule", "call stack", "stored creation-time scope", "start_delegated_run", "not_covered"):
    must(needle in text, f"the resolve_delegated_targets row lacks {needle!r}")
register_text = by[("tec_tac.system_actions", "register_system_action")]["purpose"]
must("agents.reboot" not in register_text and "nats_cmd" not in register_text, "the register_system_action row names no reboot row")
run_text = by[("tec_tac.system_actions", "run_system_action")]["purpose"]
must("agents.reboot" not in run_text and "not_accepted" not in run_text, "the run_system_action row names no command result")
must("or a task row by run_system_write" in by[("tec_tac.system_actions", "SystemActionRefused")]["purpose"], "wrong_kind is described for the task and write kinds")
rule = next(r for r in RULES if r.startswith("System actions (core.system_actions"))
must(rule.startswith("System actions (core.system_actions 1.2.0 since Core 1.17.68, 1.1.0 since Core 1.17.66;") and "core.system_actions is 1.3.0 from this release" in rule, rule[:140])  # the earlier text is kept, so the pins on it hold
for needle in ("Since 1.17.74", "resolve_delegated_targets", "Core publishes no 'endpoint is back' event", "polling Agents' get_reboot_status is the supported way", "Durable runs with a reboot"):
    must(needle in rule, f"the system-actions rule lacks {needle!r}")
must("agents.reboot" not in rule and "nats_cmd" not in rule and "third kind of row" not in rule, "the rule names no reboot row")
print("       contracts.py: the resolve_delegated_targets row, the system-actions rule describe the new function and polling")

# ---- the docs
doc = (ROOT / "docs" / "system-actions.md").read_text(encoding="utf-8")
must(doc.startswith("# System actions (core.system_actions 1.4.0, Core 1.17.74)"), doc[:80])
for needle in ("Durable runs with a reboot (Core 1.17.74)", "CQ213", "CQ215", "get_reboot_status", "resolve_delegated_targets", "Q-APM21", "ticket_invalid", "start_one_off_run", "register_target_resolver"):
    must(needle in doc, f"docs/system-actions.md lacks {needle!r}")
durable = doc.split("## Durable runs with a reboot (Core 1.17.74)")[1].split("\n## ")[0]
must("Core publishes no \"agent is back\" event" in durable and "Polling is the supported path" in durable and "An \"accepted\" answer is not a restart" in durable, "polling is the supported path and no event is published")
must("A release that adds one must change this section and its test together." in durable, "the section says who must change it")
must("The third kind: a command" not in doc and "custom:command-closed" not in doc and "Reboot (AD-46, CQ213, CQ215): not built" in doc, "the docs say the reboot row is not built")
print("       docs/system-actions.md: the durable-run section (polling is the supported path, no event) and the reboot row named as not built")

# ---- the contract-export gate: an export made for 1.17.73 fails, a matching one passes
spec = importlib.util.spec_from_file_location("contract_export_check", APP / "contract_export_check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
VERSION = ROOT.joinpath("VERSION").read_text(encoding="utf-8").strip()
SAMPLE = [by[("tec_tac.system_actions", name)] for name in ("register_system_action", "run_system_action", "resolve_delegated_targets", "SystemActionRefused")]


def fake_export(version, metadata, rows):
    lines = ["# Tec-Tac Public Contracts", "", f"Framework: **{version}**  ", "Generated: `2026-10-22T10:00:00+00:00`", "", "## Core Python contracts", "",
             "| Import | Function / signature | Audience | Purpose |", "| --- | --- | --- | --- |"]
    for row in rows:
        lines.append(f"| `{row['import_path']}` | `{row['name']}()` | {row['audience']} | {row['purpose']} |")
    lines += ["", "## Registered capabilities", "", "### `core.system_actions`", "", "- Provider module: `core`", "- Published metadata:", "", "```json", json.dumps(metadata, indent=2, sort_keys=True), "```", ""]
    return "\n".join(lines)


must(check.check_export_text(fake_export(VERSION, meta, SAMPLE), rows=SAMPLE, metadata=meta, version=VERSION) == [], "a matching export passes")
old_meta = dict(meta, version="1.3.0", operations=EARLIER)
found = check.check_export_text(fake_export("1.17.73", old_meta, [r for r in SAMPLE if r["name"] != "resolve_delegated_targets"]), rows=SAMPLE, metadata=meta, version=VERSION)
must(any("the export is for Core 1.17.73" in line for line in found), found)
for key in ("version", "operations"):
    must(f"core.system_actions metadata field '{key}' differs from the code" in found, (key, found))
must(any("resolve_delegated_targets is missing from the export" in line for line in found), found)
print("       the contract-export gate fails on an export made for 1.17.73 (version, operations, the new contract row) and passes on a matching one")
print("delegated-targets-contract-1.17.74: ok")
