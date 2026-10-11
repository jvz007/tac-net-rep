#!/usr/bin/env python3
"""1.17.18: what the exported public contract says about the new module-facing surfaces.

contracts.py needs Django, so the literal tables are read with ``ast`` and the real ``render_markdown`` is run on a catalogue built
from them (the way tests/contract-export-1.17.16.py does it). Covered: the three browser rows for UI 0.12.93 (resource-views with
the grid column operations, runtime-context with the tactical_scope fields, and the new tacticalScope row), checked against the UI
source when workspace/ui is beside this repository; the 1.17.18 Python contract text for start_one_off_run, register_tactical_operation
and register_tactical_row_lookup; the inspect endpoint note for several signed packages; and unique ids and JSON-serialisable output.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork/tec_tac"
PATH = APP / "contracts.py"
tree = ast.parse(PATH.read_text(encoding="utf-8"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def literal(name):
    node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


CORE = literal("CORE_CONTRACTS")
RULES = literal("RULES")
BROWSER = literal("BROWSER_CONTRACTS")
HTTP = literal("HTTP_CONTRACT_DETAILS")
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)
catalog = {"framework_version": "1.17.18", "generated_at": "2026-10-11T00:00:00+00:00", "rules": list(RULES), "core": [dict(r, signature="()") for r in CORE],
           "browser": [dict(r) for r in BROWSER], "resource_directory": {}, "capabilities": [], "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)
json.dumps(catalog)

ids = [r["id"] for r in BROWSER]
must(len(ids) == len(set(ids)), "browser row ids are unique")


def browser(row_id):
    found = [r for r in BROWSER if r["id"] == row_id]
    must(len(found) == 1, f"one browser row {row_id}")
    return found[0]


# ---- (1) resource views
views = browser("ui.authenticated.resource-views")
must(views["service"] == "resourceViews" and views["operations"] == ["register", "list", "clear", "gridColumns", "loadGridColumns"], views["operations"])
text = " ".join(views["details"])
for needle in ("endpoint.grid-columns", "module-resource-views.md", "Grid columns", "100 ids", "failed", "timeout", "UI 0.12.93", "AD-12"):
    must(needle in text or needle in views["docs"], f"resource-views lacks {needle!r}")
must(views["docs"] == "tec-tac-ui/docs/module-resource-views.md", views["docs"])

# ---- (2) runtime context
context = browser("ui.authenticated.runtime-context")
for op in ("tactical_scope.mode", "tactical_scope.unrestricted", "tactical_scope.whole_client_count", "tactical_scope.site_count"):
    must(op in context["operations"], op)
must("tactical_permissions.<flag>" in context["operations"], "the earlier operation stays")
scope_text = next(d for d in context["details"] if d.startswith("tactical_scope:"))
for needle in ("counts only", "no id lists", "tacticalScope()", "AD-12", "UI 0.12.93", "Core 1.17.17", "mode: 'none'"):
    must(needle in scope_text, f"runtime-context tactical_scope lacks {needle!r}")

# ---- (3) the new tacticalScope row, modelled on hasTacticalPermission
row = browser("ui.authenticated.tactical-scope")
must(row["phase"] == "authenticated" and row["service"] == "tacticalScope" and row["operations"] == ["tacticalScope"] and row["audience"] == "module/browser", row)
must(row["docs"] == "tec-tac-ui/docs/module-runtime-api.md" and "tacticalScope()" in row["details"][0], (row["docs"], row["details"][0]))  # 1.17.19: a plain path, the section sits in details
must("Core 1.17.17" in row["purpose"] and "UI 0.12.93" in row["purpose"], row["purpose"])
text = " ".join(row["details"])
for needle in ("mode, unrestricted, whole_client_count, site_count", "unrestricted, clients, sites, mixed or none", "no id lists", "AD-12", "scope_unrestricted_required", "Public modules"):
    must(needle in text, f"tacticalScope row lacks {needle!r}")
permissions = browser("ui.authenticated.tactical-permissions")
must(set(row) == set(permissions), "same shape as the hasTacticalPermission row")
for row_id in ("ui.authenticated.tactical-scope", "ui.authenticated.resource-views"):
    must(row_id in md, f"the export renders {row_id}")

# ---- the UI really does this (read only; skipped when workspace/ui is not beside this repository)
UI = ROOT.parent / "ui"
if (UI / "src" / "resource-views.js").is_file():
    rv = (UI / "src/resource-views.js").read_text(encoding="utf-8")
    main = (UI / "src/main.js").read_text(encoding="utf-8")
    rc = (UI / "src/runtime-context.js").read_text(encoding="utf-8")
    must("export const GRID_COLUMN_PLACEMENT = 'endpoint.grid-columns'" in rv and "GRID_COLUMN_MAX_IDS = 100" in rv, "placement and the 100 id limit")
    must("gridColumns(query = {})" in rv and "loadGridColumns(query = {})" in rv, "the two module-scoped methods")
    must("'timeout'" in rv and "'failed'" in rv and "status: 'ready'" in rv, "the three load states")
    must(re.search(r"const tacticalScope = \(\) =>", main) and "        tacticalScope,\n" in main, "tacticalScope is passed to authenticated modules")
    keys = re.search(r"return \{\s*mode,\s*unrestricted:.*?whole_client_count:.*?site_count:", rc, re.S)
    must(keys, "normalizeTacticalScope returns mode, unrestricted, whole_client_count and site_count")
    must("{ mode: 'none', unrestricted: false, whole_client_count: 0, site_count: 0 }" in rc, "the fail-closed default")
else:
    print("       UI cross-check skipped: workspace/ui is not beside this repository")

# ---- the Python rows and the inspect note
def core(area, name):
    found = [r for r in CORE if r["area"] == area and r["name"] == name]
    must(len(found) == 1, f"one entry {area}/{name}, got {len(found)}")
    return found[0]


one_off = core("scheduler", "start_one_off_run")["purpose"]
for needle in ("retry_count=0, retry_delay_seconds=60", "0 to 10", "1 to 86400", "SchedulerTransientError", "re-check", "framework >=1.18.0".replace("1.18.0", "1.17.18")):
    must(needle in one_off, f"start_one_off_run lacks {needle!r}")
register = core("tactical-operations", "register_tactical_operation")["purpose"]
for needle in ("Since 1.17.18", "core.tactical_operations 1.4.0", "caller_scope='unrestricted'", "scope_unrestricted_required", "optional: true", "agent_pk", "row_lookup",
               "object_not_found", "CQ57", "count_fields", "select", "up to 1000", "body_selector", "body_selector_mismatch", "audit.params", "32 fields"):
    must(needle in register or needle.replace("up to 1000", "first 1000 rows") in register, f"register_tactical_operation lacks {needle!r}")
lookup = core("tactical-operations", "register_tactical_row_lookup")
source = (APP / "tactical_operations.py").read_text(encoding="utf-8")
must(re.search(r"^def register_tactical_row_lookup\b", source, re.M) and lookup["import_path"] == "tec_tac.tactical_operations", "defined where it says")
must("1.17.18" in lookup["purpose"] and "None" in lookup["purpose"] and "agent_id" in lookup["purpose"] and lookup["audience"] == "core module/backend", lookup)
must("register_tactical_row_lookup" in md, "the export renders the lookup")
http = HTTP["/api/tfd/tactical-operations/{module_id}/{operation_id}/"]["POST"] if "/api/tfd/tactical-operations/{module_id}/{operation_id}/" in HTTP else None
if http is None:
    key = next(k for k in HTTP if "tactical-operations" in k)
    http = HTTP[key]["POST"]
must(any("1.17.18" in note and "caller_scope" in note for note in http["notes"]), "the HTTP notes name 1.17.18")
must("scope_unrestricted_required" in http["errors"]["403"] and "body_selector_mismatch" in http["errors"]["400"], http["errors"])
inspect = HTTP["/api/tfd/modules/v2/packages/inspect/"]["POST"]["notes"]
note = next(n for n in inspect if "Since 1.17.18" in n)
for needle in ("signatures", "metadata_files", "metadata.filename", "metadata.signature", "name (1).zip", "Nothing stays staged"):
    must(needle in note, f"the inspect note lacks {needle!r}")

print("[TEST] PASS contract export 1.17.18")
