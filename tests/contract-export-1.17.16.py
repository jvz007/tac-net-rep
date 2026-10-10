#!/usr/bin/env python3
"""1.17.16: what the exported public contract says about the new module-facing surfaces.

contracts.py needs Django, so the literal tables (CORE_CONTRACTS, RULES) are read with ``ast`` and the real ``render_markdown`` is run
on a catalogue built from them, the way tests/contract-export-1.17.14.py does it. Each new entry must point at a real name in its
module (checked as text), and the texts must state what modules rely on: the 1.3.0 capability, the request check, the Python-only
keywords, the claimed module id of a notice, the one-off run re-check, and the manifest keys.
"""
from __future__ import annotations

import ast
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
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)
catalog = {"framework_version": "1.17.16", "generated_at": "2026-10-10T00:00:00+00:00", "rules": list(RULES), "core": [dict(r, signature="()") for r in CORE],
           "browser": [], "resource_directory": {}, "capabilities": [], "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)


def row(area, name):
    found = [r for r in CORE if r["area"] == area and r["name"] == name]
    must(len(found) == 1, f"one contract entry for {area}/{name}, got {len(found)}")
    return found[0]


# every new entry names something that exists in the module it points at
NEW = (("module-routes", "mounted_routes", "route_mounting"), ("notices", "publish", "notices"), ("audit", "request_correlation_id", "audit"),
       ("scheduler", "start_one_off_run", "scheduler"), ("scheduler", "get_one_off_run", "scheduler"), ("scheduler", "get_owned_schedule", "scheduler"),
       ("scheduler", "SchedulerNotAllowed", "scheduler"))
for area, name, module_file in NEW:
    entry = row(area, name)
    must(entry["import_path"] == f"tec_tac.{module_file}" and entry["kind"] == "python" and entry["purpose"] and entry["audience"], entry)
    source = (APP / f"{module_file}.py").read_text(encoding="utf-8")
    must(re.search(rf"^(def|class) {name}\b", source, re.M), f"{name} is defined in {module_file}.py")
    must("1.17.16" in entry["purpose"], f"{name} says which release added it")
    must(name in md, f"the export renders {name}")

routes = row("module-routes", "mounted_routes")["purpose"]
for needle in ("\"routes\": {\"prefix\"", "/api/tfd/<prefix>/", "defaults to the module id", "own django_apps", "after every AppConfig.ready()",
               "Core's own routes", "first by sorted module id", "Compatibility path, no end date", "state is mounted, compat or refused", "framework >=1.17.16"):
    must(needle in routes, f"routes entry lacks {needle!r}")

notice = row("notices", "publish")["purpose"]
for needle in ("never core or tec-tac", "CLAIMED id", "verified caller identity", "1000 characters", "internal Tec-Tac route", "dedupe key", "never reset", "Not exposed over HTTP"):
    must(needle in notice, f"notices entry lacks {needle!r}")

corr = row("audit", "request_correlation_id")["purpose"]
for needle in ("tec_tac_request_id", "a browser header", "never read", "explicit correlation_id", "wins over the request id"):
    must(needle in corr, f"correlation entry lacks {needle!r}")

one_off = row("scheduler", "start_one_off_run")["purpose"]
for needle in ("only its own actions", "SchedulerNotAllowed", "one-off:<uuid>", "ticker never dispatches", "re-checks", "skipped", "owner_user_id", "one_off",
               "not the system-action contract", "framework >=1.17.16"):
    must(needle in one_off, f"one-off entry lacks {needle!r}")
must("a module reads only its own" in row("scheduler", "get_owned_schedule")["purpose"].replace("A module", "a module").replace("a module reads only its own tuple", "a module reads only its own"), "owned schedule")

# the Tactical operation entry says what 1.3.0 added, and that a browser cannot use it
run_text = row("tactical-operations", "run_tactical_operation")["purpose"]
for needle in ("core.tactical_operations 1.3.0", "still major 1", "correlation_id=None", "invalid_correlation_id", "audit_before=None", "invalid_audit_before",
               "before_source caller", "Neither keyword is available over HTTP", "a browser can never send a correlation id", "authenticated_request_required",
               "no audit row", "tec_tac_session", "stub tests"):
    must(needle in run_text, f"run entry lacks {needle!r}")
# the older text is kept
must("Also available as capability core.tactical_operations 1.1.0 (1.0.0 until 1.17.12; ask for >=1,<2) operation run." in run_text, "older text kept")

# the manifest-key rule
rule = next(r for r in RULES if r.startswith("Manifest keys added in 1.17.16"))
for needle in ("routes {prefix, urlconf}", "description", "1 to 500 characters", "no control characters", "null when absent", "framework >=1.17.16"):
    must(needle in rule, f"the manifest key rule lacks {needle!r}")
must("Manifest keys added in 1.17.16" in md, "the export renders the rule")

# the capability version in code and in the docs agree
ops = (APP / "tactical_operations.py").read_text(encoding="utf-8")
must('CAPABILITY_VERSION = "1.3.0"' in ops and "declaration_keys_added_in_1_3_0" in ops, "capability 1.3.0 in code")
docs = (ROOT / "docs/tactical-operations.md").read_text(encoding="utf-8")
must("`core.tactical_operations` 1.3.0" in docs.split("\n", 12)[4] or "`core.tactical_operations` 1.3.0" in docs[:600], "the docs header names 1.3.0, not 1.0.0")
must("`core.tactical_operations` 1.0.0, owner" not in docs, "the stale 1.0.0 header is gone")

print("[TEST] PASS contract export 1.17.16")
