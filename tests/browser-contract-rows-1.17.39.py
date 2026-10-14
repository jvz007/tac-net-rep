#!/usr/bin/env python3
"""1.17.39: contract rows, documentation only, plus the three repository HTTP rows.

1. ui.authenticated.runtime-context lists user.superuser once, right after user.id, with a details line that names the effective
   superuser, the Tactical flag as a different thing (user.tactical_superuser), the display-hint rule and the fail-closed rule. Core
   already sends it (views.py _user_payload), and that line is checked in the source.
2. ui.authenticated.modulePreferences lists get, getAll, set, remove and flush; its details carry the 400 ms and 2 second debounce,
   flush(), module_not_allowed with hideControl, audit_failed with the old-value wording, and UI 0.12.108 with Core 1.17.38. The
   numbers are checked against workspace/ui/docs/module-preferences.md when that repository sits beside this one.
3. HTTP_CONTRACT_DETAILS has the three repository routes (sync all, sync one, online catalog) with the skipped fields and the five
   informational release fields, all marked added 1.17.39, additive, informational.

contracts.py needs Django, so the tables are read with ast and the two render functions are exec'd from the same tree (as in
tests/browser-contract-rows-1.17.37.py). The Python keys of the renderers are checked by ast.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "framwork/tec_tac/contracts.py"
VIEWS = ROOT / "framwork/tec_tac/views.py"
tree = ast.parse(PATH.read_text(encoding="utf-8"))
PATTERN = re.compile(r"^tec-tac-ui/docs/[A-Za-z0-9._-]+\.md$")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def literal(name):
    node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


BROWSER = literal("BROWSER_CONTRACTS")
HTTP = literal("HTTP_CONTRACT_DETAILS")
RULES = literal("RULES")
CORE = literal("CORE_CONTRACTS")
by_id = {r["id"]: r for r in BROWSER}
ids = [r["id"] for r in BROWSER]
must(len(by_id) == len(BROWSER), "ids are unique")
for row in BROWSER:
    must(PATTERN.match(str(row.get("docs", ""))), f"{row['id']}: docs is not a plain path: {row.get('docs')!r}")


def text_of(row):
    return " ".join(row.get("details", [])) + " " + row.get("purpose", "") + " " + " ".join(row.get("operations", []))


# ------------------------------------------------------------------------------------------------ 1. runtime-context: user.superuser
runtime = by_id["ui.authenticated.runtime-context"]
ops = runtime["operations"]
must(ops.count("user.superuser") == 1, "user.superuser is listed exactly once")
must(ops.index("user.superuser") == ops.index("user.id") + 1, "user.superuser follows user.id")
must(ops.index("tactical_permissions.<flag>") > ops.index("user.superuser"), "the rest of the list is unchanged in order")
line = next((d for d in runtime["details"] if d.startswith("user.superuser")), "")
must(line, "a details line starts with user.superuser")
for needle in ("effective superuser", "is_superuser", "strict boolean", "user.tactical_superuser", "display hint", "AD-12", "AD-35",
               "fail closed", "since before 1.17.38", "from 1.17.39"):
    must(needle in line, f"user.superuser details lack {needle!r}")

views_text = VIEWS.read_text(encoding="utf-8")
must('"superuser": user_superuser or role_superuser' in views_text, "views.py sends the effective superuser the row describes")
must('"tactical_superuser": user_superuser' in views_text, "views.py sends the Tactical flag under its own key")
must(runtime.get("docs") == "tec-tac-ui/docs/module-runtime-api.md", "runtime-context docs path is unchanged")

# ------------------------------------------------------------------------------------------------ 2. modulePreferences
ids_prefs = ids.index("ui.authenticated.modulePreferences")
must(ids.index("ui.authenticated.terminal") + 1 == ids_prefs, "the row still follows ui.authenticated.terminal")
prefs = by_id["ui.authenticated.modulePreferences"]
must(prefs["operations"] == ["get", "getAll", "set", "remove", "flush"], "five operations in order")
must(prefs["docs"] == "tec-tac-ui/docs/module-preferences.md", "docs path")
must(prefs.get("phase") == "authenticated" and prefs.get("service") == "modulePreferences", "phase and service")
must("Needs Core 1.17.35 or later and UI 0.12.106 or later" in prefs["purpose"], "the 1.17.35 line is kept")
must("UI 0.12.108" in prefs["purpose"] and "Core 1.17.38" in prefs["purpose"], "the purpose names UI 0.12.108 and Core 1.17.38")
text = text_of(prefs)
for needle in ("400 ms", "2 seconds", "flush()", "module_not_allowed", "status 403", "hideControl", "audit_failed", "status 503",
               "old value stays", "UI 0.12.108", "Core 1.17.38", "registerPublic", "localStorage"):
    must(needle in text, f"modulePreferences text lacks {needle!r}")
must("does not reject when a write failed" in text, "flush does not reject for a failed write")
must("[a-z0-9][a-z0-9._-]{0,63}" in text and "4 KiB" in text and "50 names" in text, "the limits are kept")

ui_doc = ROOT.parent / "ui" / "docs" / "module-preferences.md"
if ui_doc.is_file():
    doc = ui_doc.read_text(encoding="utf-8")
    for needle in ("400 ms", "2 seconds", "`flush()`", "hideControl", "UI 0.12.108", "Core 1.17.38", "old value stays"):
        must(needle in doc, f"the UI doc lacks {needle!r}; the row must copy the UI doc exactly")
    print("       UI cross-check: module-preferences.md has the same numbers and names")
else:
    print("       UI cross-check skipped: workspace/ui is not beside this repository")

must("ui.authenticated.terminal" in ids and by_id["ui.authenticated.terminal"]["docs"] == "tec-tac-ui/docs/module-terminal.md",
     "the terminal row is still present")

# ------------------------------------------------------------------------------------------------ 3. the three repository HTTP rows
routes = {
    "/api/tfd/modules/repositories/sync/": "POST",
    "/api/tfd/modules/repositories/<str:repository_id>/sync/": "POST",
    "/api/tfd/modules/catalog/online/": "GET",
}
for route, method in routes.items():
    must(route in HTTP, f"{route} has a contract detail row")
    must(method in HTTP[route], f"{route} documents {method}")
    detail = repr(HTTP[route])
    must("added 1.17.39" in detail or "Added 1.17.39" in detail, f"{route} is marked added 1.17.39")
    must("additive" in detail and "informational" in detail, f"{route} is marked additive and informational")
sync_all = repr(HTTP["/api/tfd/modules/repositories/sync/"])
sync_one = repr(HTTP["/api/tfd/modules/repositories/<str:repository_id>/sync/"])
online = repr(HTTP["/api/tfd/modules/catalog/online/"])
for needle in ("skipped_count", "skipped[]", "{index, id, version, reason}", "100 characters", "300 characters", "'duplicate'",
               "generic sentence", "stays 'ok'"):
    must(needle in sync_all, f"sync routes lack {needle!r}")
must("skipped_count" in sync_one and "skipped[]" in sync_one, "the one-repository sync names the skipped fields")
for needle in ("channel", "lifecycle", "downgrade_policy", "signing_environment", "recommended", "modules[]", "releases[]", "64 characters",
               "never acts on them", "not gated on any entitlement"):
    must(needle in online, f"online catalog row lacks {needle!r}")

# ------------------------------------------------------------------------------------------------ the renderers
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
catalog = {"framework_version": "1.17.39", "generated_at": "2026-10-14T00:00:00+00:00", "rules": list(RULES),
           "core": [dict(r, signature="()") for r in CORE], "browser": [dict(r) for r in BROWSER], "resource_directory": {},
           "capabilities": [], "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)
text_export = ns["render_text"](catalog)
must("`ui.authenticated.modulePreferences`" in md and "ui.authenticated.modulePreferences" in text_export, "the row is rendered")
must("user.superuser" in md and "user.superuser" in text_export, "runtime-context renders user.superuser")
must("flush" in md and "flush" in text_export, "modulePreferences renders flush")
cells = [line for line in md.splitlines() if line.startswith("| `ui.")]
must(len(cells) == len(BROWSER), (len(cells), len(BROWSER)))
docs_cells = re.findall(r"\| docs=(.*?) - ", text_export)
must(len(docs_cells) == len(BROWSER), (len(docs_cells), len(BROWSER)))
for cell in docs_cells:
    must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", cell), f"text export docs cell: {cell!r}")

print("[TEST] PASS browser contract rows and repository HTTP rows 1.17.39")
