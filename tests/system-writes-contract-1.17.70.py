#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.70 regression (CQ203, AD-45): the public contract of the second kind of system action.

Covered: capability core.system_actions is 1.3.0 (additive), its operations keep the nine earlier ones first and in order and append run_write, and the
provider object really has run_write; the metadata keeps every earlier key and gains the write block, kind and replacement_only on every function row and
the four new refusal reasons; contracts.py has a run_system_write row and names the new reasons, the new registration rules and the second kind in the
register_system_action row, the SystemActionRefused row and the system-actions rule; docs/system-actions.md describes the second kind, AD-45 and the plain
limit that Tactical's own audit log does not show Core's write; the contract-export gate (the pure checker on fixture files) fails on an export made
before this release, and passes on one that matches.
"""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path

H = Path(__file__).resolve().parent / "system-writes-harness-1.17.70.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

meta = sa.system_actions_contract_metadata()
EARLIER = ["list_actions", "get_action", "run", "describe_confirmation", "describe_delegation", "register_delegation_grant", "remove_delegation_grant",
           "issue_delegation_ticket", "start_delegated_run"]
must(meta["version"] == "1.3.0" and sa.CAPABILITY_VERSION == "1.3.0", meta["version"])
must(meta["operations"] == EARLIER + ["run_write"] and list(sa.OPERATIONS) == EARLIER + ["run_write"], meta["operations"])
must(all(callable(getattr(sa._PROVIDER, name, None)) for name in meta["operations"]), "the provider has every operation, run_write included")
print("       core.system_actions is 1.3.0; the nine earlier operations stay first and in order; run_write is appended and exists on the provider")

# ---- the route and the direct import give the same answer (the provider calls the public function, which reads the caller from the stack)
fresh(3)
route_src = '''
def handler(context):
    return sa._PROVIDER.run_write(context, action_id=CFG["action_id"], changes=CFG["changes"])
'''
ns = compile_as(roots["patchmanagement"] / "route.py", route_src, sa=sa, CFG=CFG)
sched.register_scheduled_action(id="patchmanagement.route", module_id="patchmanagement", label="r", handler=ns["handler"], target_types=("none", "endpoint"), timeout_seconds=600)
run, out = start(decide(sorted(UPD)), handler="patchmanagement.route")
must(out["outcome"] == "written" and out["written"] == 3, out)
print("       the capability route run_write gives the same answer as the direct call")

# ---- the metadata
for key in ("id", "version", "operations", "python", "delegation", "functions", "manifest_key", "max_agents", "max_agents_per_group", "max_groups", "parameters_key",
            "refusal_reasons", "http", "delivery", "audit_actions", "requires_framework", "unattended"):
    must(key in meta, key)
must(meta["write"]["kinds"] == ["task", "write"] and meta["write"]["function"] == "winupdate.set_action" and meta["write"]["max_changes"] == 40000, meta["write"])
must(meta["write"]["max_changes_per_group"] == 2000 and meta["write"]["audit_chunk"] == 500 and "audit log does not show" in meta["write"]["limit"], meta["write"])
rows = meta["functions"]
must(set(rows) == {"winupdate.scan", "winupdate.install", "scripts.run", "winupdate.set_action"}, sorted(rows))
must(rows["winupdate.set_action"] == {"tactical": "winupdate.serializers.WinUpdateSerializer", "owner_module": "patching", "min_flags": ["can_manage_winupdates"], "takes_username": False,
                                      "reapproves_by_policy": False, "parameters": ["allowed_actions"], "kind": "write", "replacement_only": True}, rows["winupdate.set_action"])
for key in ("winupdate.scan", "winupdate.install", "scripts.run"):
    must(rows[key]["kind"] == "task" and rows[key]["replacement_only"] is False, key)
    must({"tactical", "owner_module", "min_flags", "takes_username", "reapproves_by_policy", "parameters"} <= set(rows[key]), key)
for reason in ("wrong_kind", "bad_changes", "unknown_update", "action_not_allowed"):
    must(reason in meta["refusal_reasons"] and sa.REASONS[reason], reason)
    must(reason in meta["write"]["refusal_reasons"], reason)
must(len(meta["refusal_reasons"]) == len(set(meta["refusal_reasons"])) and meta["refusal_reasons"] == sorted(sa.REASONS), "sorted, no duplicates")
must(">=1.17.70" in meta["requires_framework"] and ">=1.17.68" in meta["requires_framework"] and ">=1.17.61" in meta["requires_framework"], meta["requires_framework"])
must("run_system_write(context, *, action_id, changes)" in meta["python"] and "run_system_action(context, *, action_id, agent_ids, parameters=None)" in meta["python"], "the python signatures")
json.dumps(meta, sort_keys=True)  # the export writes it as JSON
print("       the metadata keeps every earlier key and gains the write block, kind and replacement_only on every row and the four new reasons")

# ---- contracts.py
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
ROWS = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CORE_CONTRACTS")
RULES = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "RULES")
by = {(r["import_path"], r["name"]): r for r in ROWS}
write_row = by[("tec_tac.system_actions", "run_system_write")]
must(write_row["area"] == "system-actions" and write_row["kind"] == "python" and write_row["audience"] == "provider/backend", write_row)
text = write_row["purpose"]
for needle in ("run_system_write(context, *, action_id, changes)", "1.17.70", "CQ203", "AD-45", "winupdate.set_action", "honoured replacement", "exactly those two keys", "inherit is refused",
               "reads each update's endpoint itself", "BEFORE the write", "[update_id, before, after]", "not overwritten", "changed_meanwhile", "outcome-unknown", "wrong_kind",
               "bad_changes", "unknown_update", "action_not_allowed", "not_delegable", "Tactical's own audit log does not show this write", "40000", "2000", "500"):
    must(needle in text, f"the run_system_write row lacks {needle!r}")
register_text = by[("tec_tac.system_actions", "register_system_action")]["purpose"]
for needle in ("1.17.70", "winupdate.set_action", "replacement_only", "dangerous=True", "empty delegable_to", "Windows Patching itself is refused", "allowed_actions"):
    must(needle in register_text, f"the register_system_action row lacks {needle!r}")
refused_text = by[("tec_tac.system_actions", "SystemActionRefused")]["purpose"]
for reason in ("wrong_kind", "bad_changes", "unknown_update", "action_not_allowed"):
    must(reason in refused_text, reason)
rule = next(r for r in RULES if r.startswith("System actions (core.system_actions"))
must(rule.startswith("System actions (core.system_actions 1.2.0 since Core 1.17.68, 1.1.0 since Core 1.17.66;") and "core.system_actions is 1.3.0 from this release" in rule, rule[:140])  # the earlier opening is kept, so the pins on it hold
for needle in ("run_system_write", "second kind", "winupdate.set_action", "honoured replacement of Windows Patching", "Windows Patching does not register it", "Tactical keeps the decisions",
               "audit log does not show Core's write"):
    must(needle in rule, f"the system-actions rule lacks {needle!r}")
print("       contracts.py: the run_system_write row, the register and refusal rows and the system-actions rule describe the second kind")

# ---- the docs
doc = (ROOT / "docs" / "system-actions.md").read_text(encoding="utf-8")
must(doc.startswith("# System actions (core.system_actions 1.3.0, Core 1.17.70)"), doc[:80])
for needle in ("The second kind: a write", "AD-45", "CQ203", "winupdate.set_action", "run_system_write", "replacement_only", "honoured replacement", "changed_meanwhile", "custom:write-closed",
               "Tactical's own audit log does not show", "Reboot with a result", "Communicator", "wrong_kind", "bad_changes", "unknown_update", "action_not_allowed"):
    must(needle in doc, f"docs/system-actions.md lacks {needle!r}")
must("Pushing rule decisions (CQ203): built in 1.17.70" in doc, "the 'not in this release' list names what shipped")
print("       docs/system-actions.md describes the second kind, AD-45 and the plain limit")

# ---- the contract-export gate: an export made before this release fails, a matching one passes
spec = importlib.util.spec_from_file_location("contract_export_check", APP / "contract_export_check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
VERSION = ROOT.joinpath("VERSION").read_text(encoding="utf-8").strip()
SAMPLE = [by[("tec_tac.system_actions", name)] for name in ("register_system_action", "run_system_action", "run_system_write", "SystemActionRefused")]


def fake_export(version, metadata, rows):
    lines = ["# Tec-Tac Public Contracts", "", f"Framework: **{version}**  ", "Generated: `2026-10-21T10:00:00+00:00`", "", "## Core Python contracts", "",
             "| Import | Function / signature | Audience | Purpose |", "| --- | --- | --- | --- |"]
    for row in rows:
        lines.append(f"| `{row['import_path']}` | `{row['name']}()` | {row['audience']} | {row['purpose']} |")
    lines += ["", "## Registered capabilities", "", "### `core.system_actions`", "", "- Provider module: `core`", "- Published metadata:", "", "```json", json.dumps(metadata, indent=2, sort_keys=True), "```", ""]
    return "\n".join(lines)


must(check.check_export_text(fake_export(VERSION, meta, SAMPLE), rows=SAMPLE, metadata=meta, version=VERSION) == [], "a matching export passes")
old_meta = dict(meta, version="1.2.0", operations=EARLIER, functions={k: v for k, v in meta["functions"].items() if k != "winupdate.set_action"})
old_meta.pop("write")
found = check.check_export_text(fake_export("1.17.69", old_meta, [r for r in SAMPLE if r["name"] != "run_system_write"]), rows=SAMPLE, metadata=meta, version=VERSION)
must(any("the export is for Core 1.17.69" in line for line in found), found)
for key in ("version", "operations", "functions", "write"):
    must(f"core.system_actions metadata field '{key}' differs from the code" in found, (key, found))
must(any("run_system_write is missing from the export" in line for line in found), found)
print("       the contract-export gate fails on an export made before this release (version, operations, the new row, the write block, the new contract row) and passes on a matching one")
print("PASS system writes contract 1.17.70")
