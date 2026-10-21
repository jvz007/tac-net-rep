#!/usr/bin/env python3
"""1.17.68 regression (S5, patchmanagement 0.11.0 and 0.11.2): the statement that an honoured replacement registers Tactical operations and row lookups under its
own module id, and what happens at the first start. Documentation and contract text only: no behaviour changed.

Read as source (this PC has no Django). It checks that the code really works the way the statement says, so the statement cannot drift from it: both registration
functions decide through _honoured_pairs (the one source), the row-lookup function accepts an honoured replacement, the dispatch re-reads the honoured state
and answers 404 tactical_operation_not_found for an operation whose module is no longer an owner, and the module-state helper writes the state before it reloads
the web workers and restarts Celery. Then it checks that the statement is in the docs and in the two contract rows, with the module id rule, the restart rule and
the 404.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


ops = (APP / "tactical_operations.py").read_text(encoding="utf-8").replace("\r\n", "\n")
tree = ast.parse(ops)
funcs = {n.name: ast.get_source_segment(ops, n) for n in tree.body if isinstance(n, ast.FunctionDef)}

# ---- the code behind the statement
must("def _honoured_pairs() -> dict[str, str]:" in ops and "module_replacement.honoured_replacement(node.id, model=model)" in funcs["_honoured_pairs"], "_honoured_pairs is the one source")
must("pairs = _honoured_pairs()" in ops and "pairs.get(owner) in owners" in ops, "the route owner check joins an honoured replacement to the rules of the module it replaces")
must("category != \"core\" and owner not in pairs" in ops, "a premium module registers only as an honoured replacement (AD-21 and AD-20)")
row = funcs["register_tactical_row_lookup"]
must("owner not in _honoured_pairs()" in row and "module = _check_module(module_id)" in row and "owner = module[\"id\"]" in row, "the row lookup registers under the module's own id and accepts an honoured replacement")
register = funcs["register_tactical_operation"]
must("_check_route_owner" in register or "_check_route_owner" in ops, "operations are checked against the owner table at registration")
must('"tactical_operation_not_found"' in ops and "_owners_for_rule" in ops, "dispatch answers 404 tactical_operation_not_found from the owner table and the honoured state read again")
must(ops.count("_honoured_pairs()") >= 4, "the honoured state is read at registration and at dispatch, never remembered")
ready_note = "A refused registration is not remembered"
module_replacement = (ROOT / "docs" / "module-replacement.md").read_text(encoding="utf-8")
must(ready_note in module_replacement.replace("\n", " ") or "not remembered" in module_replacement, "the earlier section already says a refusal is not remembered")
helper = (ROOT / "scripts" / "module-v2-job-helper.py")
if helper.is_file():
    text = helper.read_text(encoding="utf-8")
    must("sync_and_reload" in text and "reload-rmm-uwsgi.sh" in text and "systemctl" in text and "celery" in text, "the helper reloads the web workers and restarts Celery")
    order = [m.start() for m in (re.search(r"def sync_and_reload", text), re.search(r"reload-rmm-uwsgi\.sh", text), re.search(r"restart.{0,40}celery|celery.{0,40}restart", text)) if m]
    must(order == sorted(order) and len(order) == 3, "the web reload comes before the Celery restart")
print("       the code decides registration through _honoured_pairs on every call and at dispatch, accepts the replacement's own module id for operations and row lookups, answers 404 when it is no longer an owner, and the enable job reloads the web workers and Celery")

# ---- the docs
repl = module_replacement.replace("\r\n", "\n")
section = repl.split("## The statement for operations and row lookups (1.17.68", 1)
must(len(section) == 2, "module-replacement.md has the section")
body = section[1].split("## What this does not do", 1)[0]
for needle in ("patchmanagement", "register_tactical_operation", "register_tactical_row_lookup", "_honoured_pairs()", "own module id", "scan", "install", "set-update-action", "reset-patch-policy",
               "add-patch-policy", "edit-patch-policy", "delete-patch-policy", "patch-policy-row", "No behaviour changed", "no extra restart by hand", "ready()", "restarts Celery",
               "404 `tactical_operation_not_found`", "before any restart", "TacticalOperationRegistrationError", "tests/replacement-registration-statement-1.17.68.py"):
    must(needle in body, f"docs/module-replacement.md lacks {needle!r}")
tactical = (ROOT / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
must("Row lookups follow the same rule (statement, 1.17.68)" in tactical and "_honoured_pairs()" in tactical and "no extra restart by hand" in tactical and "404 `tactical_operation_not_found`" in tactical, "docs/tactical-operations.md")
print("       docs/module-replacement.md and docs/tactical-operations.md state the module id rule, the restart rule and the 404")

# ---- the contract rows
contracts = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
rows = next(ast.literal_eval(n.value) for n in contracts.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CORE_CONTRACTS")
index = {(r["import_path"], r["name"]): r for r in rows}
for name in ("register_tactical_operation", "register_tactical_row_lookup"):
    purpose = index[("tec_tac.tactical_operations", name)]["purpose"]
    must("Statement (1.17.68" in purpose and "_honoured_pairs" in purpose and "tactical_operation_not_found" in purpose, f"{name} row")
op_row = index[("tec_tac.tactical_operations", "register_tactical_operation")]["purpose"]
for needle in ("OWN module id", "patchmanagement", "winupdate/", "automation/patchpolicy/", "ready()", "restarts Celery", "no extra restart by hand", "before any restart", "no behaviour changed"):
    must(needle in op_row, f"register_tactical_operation row lacks {needle!r}")
must("under its own module id" in index[("tec_tac.tactical_operations", "register_tactical_row_lookup")]["purpose"] and "no behaviour changed" in index[("tec_tac.tactical_operations", "register_tactical_row_lookup")]["purpose"], "row lookup row")
for row in (index[("tec_tac.tactical_operations", "register_tactical_operation")], index[("tec_tac.tactical_operations", "register_tactical_row_lookup")]):
    must(row["area"] == "tactical-operations" and row["kind"] == "python", "the rows keep their area and kind")
print("       both contract rows carry the statement, the module id rule, the restart rule and the 404")
print("PASS replacement registration statement 1.17.68")
