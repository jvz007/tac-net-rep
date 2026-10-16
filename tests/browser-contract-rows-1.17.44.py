#!/usr/bin/env python3
"""1.17.44: three browser contract rows from UI 0.12.112 (dialogs, signInLanding, rowMenu), the SearchSelect server mode on
ui.authenticated.components, and the response fields of GET /api/tfd/modules/repositories/ in the Markdown and text exports.

Documentation only: no endpoint, capability or version moves. contracts.py needs Django, so the tables are read with ast and the
render functions are exec'd from the same tree, as in tests/browser-contract-rows-1.17.42.py. The exports used to print the HTTP
boundary as a bare route table, so sync_schedule (in the JSON catalog since 1.17.42) never reached the exported file.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "framwork/tec_tac/contracts.py"
VIEWS = ROOT / "framwork/tec_tac/module_repository_views.py"
SCHEDULE = ROOT / "framwork/tec_tac/module_repository.py"
tree = ast.parse(PATH.read_text(encoding="utf-8"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def literal(name):
    node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


BROWSER = literal("BROWSER_CONTRACTS")
RULES = literal("RULES")
CORE = literal("CORE_CONTRACTS")
DETAILS = literal("HTTP_CONTRACT_DETAILS")
ids = [r["id"] for r in BROWSER]

# (1) order: after components, before services; the 1.17.42 order stays true
NEW = ["ui.authenticated.dialogs", "ui.authenticated.signInLanding", "ui.authenticated.rowMenu"]
must(len(ids) == len(set(ids)), "no browser row id is duplicated")
for row_id in NEW:
    must(ids.count(row_id) == 1, f"{row_id} is there once")
start = ids.index("ui.authenticated.components")
must(ids[start + 1: start + 4] == NEW, ids[start: start + 5])
must(ids[start + 4] == "ui.authenticated.services", "services follows the three new rows")
must(ids.index("ui.authenticated.components") == ids.index("ui.authenticated.modulePreferences") + 1, "components still follows modulePreferences")
rows = {r["id"]: r for r in BROWSER}

# (2) shape
SHAPE = {
    "ui.authenticated.dialogs": ("dialogs", ["register", "open"], "tec-tac-ui/docs/module-dialogs.md"),
    "ui.authenticated.signInLanding": ("signInLanding", ["register"], "tec-tac-ui/docs/module-sign-in-landing.md"),
    "ui.authenticated.rowMenu": ("rowMenu", ["open", "shouldHandle"], "tec-tac-ui/docs/module-row-menu.md"),
}
for row_id, (service, operations, docs) in SHAPE.items():
    row = rows[row_id]
    must(row["phase"] == "authenticated" and row["service"] == service, (row_id, row["phase"], row["service"]))
    must(row["operations"] == operations, (row_id, row["operations"]))
    must(row["audience"] == "module/browser", row["audience"])
    must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", row["docs"]) and row["docs"] == docs, row["docs"])
    must(row["purpose"].strip() and row["details"], row_id)
    must("UI 0.12.112" in row["purpose"], f"{row_id}: the purpose names UI 0.12.112")
    text_all = " ".join(row["details"]) + " " + row["purpose"]
    must("Documentation only" in text_all and "no endpoint, capability or version moves" in text_all, f"{row_id}: documentation only")
    must("registerPublic" in text_all, f"{row_id}: the public-page rule is stated")

NEEDLES = {
    "ui.authenticated.dialogs": (
        "register(descriptor)", "open(id or descriptor)", "<module id>.<id>", "letters, digits, _ and -", "at most 64", "no dot", "title", "200 characters",
        "'default' is 520px", "'wide' is 760px", "mount(element, {close})", "may be async", "cleanup function", "{unmount}", "beforeClose()",
        "false or a rejected Promise keeps the dialog open", "One dialog at a time", "status 0 and no code", "1100", "1300", "1400", "1200",
        "popup window", "signed out", "backend-supplied context", "register() failed or timed out", "unloaded", "names another module",
        "context.module_register_timeout_seconds", "registerPublic gets no dialogs",
    ),
    "ui.authenticated.signInLanding": (
        "register({id, permission, check})", "One registration per module", "a second register replaces the first",
        "check({reason: 'landing', signal, context})", "a route path", "{dialog: '<module id>.<dialog id>'}",
        "/ or /dashboards", "no address", "popup window", "public page", "/sso/callback", "signed out", "Unsaved changes win",
        "ignored", "one warning", "context.module_register_timeout_seconds", "own page", "Core's named pages", "/popup/", "/public/", "/sso/",
        "must start with the module's id", "registered", "once", "Disabled, failed or unloaded modules are never called",
        "registerPublic gets no signInLanding", "as built in UI 0.12.112", "not as a Core promise", "Q66", "Q67",
    ),
    "ui.authenticated.rowMenu": (
        "open({event, element, label, items})", "returns true when the menu is shown", "shouldHandle(event)", "right-click on a text field",
        "id (required; letters, digits and _ - . :", "at most 64 characters", "unique in the menu", "label (required, 80 characters)", "hint (120)",
        "danger", "disabled", "reason (120, default 'Unavailable for this selection.')", "run (required unless disabled)",
        "1 to 40 items", "TypeError", "plain text", "1150", "1100", "1200", "1300", "1400", "caught and logged as one warning",
        "popup window", "signed out", "registerPublic gets no rowMenu",
    ),
}
for row_id, needles in NEEDLES.items():
    row = rows[row_id]
    text_all = " ".join(row["details"]) + " " + row["purpose"]
    for needle in needles:
        must(needle in text_all, f"{row_id} names {needle!r}")
# the two open UI questions are stated as built, never as a Core promise
must("Core will" not in " ".join(rows["ui.authenticated.signInLanding"]["details"]), "no Core promise about Q66 or Q67")

# (3) SearchSelect server mode, added to the existing row; every 1.17.42 needle still holds
comp = rows["ui.authenticated.components"]
comp_text = " ".join(comp["details"]) + " " + comp["purpose"]
for needle in (
    "300", "Showing the first 300", "Documentation only", "no endpoint, capability or version moves", "Needs UI 0.12.111 and Core 1.17.41 or later",
    "serverSearch", "loading", "hasMore", "selectedLabel", "not in the loaded rows", "search (the typed text, empty when the list opens",
    "the module debounces", "more (no payload", "fires once", "last row or the list is scrolled to its end", "loading returns to false",
    "skips its own filter", "1000", "Showing the first 1000 loaded", "Keep typing to narrow it", "aria-busy", "No matches",
    "Typing never changes modelValue", "static list keeps the local filter and the 300 cap", "UI 0.12.112",
):
    must(needle in comp_text, f"the components row names {needle!r}")

# (4) the repositories route: the opt-in flag and the full response text
repo = DETAILS["/api/tfd/modules/repositories/"]["GET"]
must(repo.get("export_details") is True, "the repositories GET opts in to the export details")
for route, methods in DETAILS.items():
    for method, block in methods.items():
        if isinstance(block, dict) and (route, method) != ("/api/tfd/modules/repositories/", "GET"):
            must(not block.get("export_details"), f"{method} {route} is not flagged, so the export stays short")
response = repo["response"]
must(set(response) == {"schema", "repositories", "count", "manage", "sync_schedule"}, sorted(response))
must("whole number 1" in response["schema"], response["schema"])
sched = response["sync_schedule"]
for needle in ("enabled", "time ('03:00', or null)", "timezone", "Django TIME_ZONE", "next_run_at", "last_run_at", "last_run_status",
               "Null for the whole object when the schedule does not exist", "no address"):
    must(needle in sched, f"sync_schedule names {needle!r}")
rows_text = response["repositories"]
for needle in ("auth_token", "last_attempt_at", "synced_at", "module_count", "skipped_count", "skipped", "status", "error", "_url", "generic"):
    must(needle in rows_text, f"the repository row text names {needle!r}")

# (5) the view returns exactly the documented keys, and sync_schedule_status the six documented ones
views_tree = ast.parse(VIEWS.read_text(encoding="utf-8"))
cls = next(n for n in ast.walk(views_tree) if isinstance(n, ast.ClassDef) and n.name == "ModuleRepositoryListView")
get = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "get")
returns = [n for n in ast.walk(get) if isinstance(n, ast.Return) and isinstance(n.value, ast.Call)]
must(len(returns) == 1, "the GET has one return")
payload = returns[0].value.args[0]
must(isinstance(payload, ast.Dict), "the GET answers with a dict literal")
keys = [k.value for k in payload.keys if isinstance(k, ast.Constant)]
must(keys == ["schema", "repositories", "count", "manage", "sync_schedule"], keys)
must(isinstance(payload.values[0], ast.Constant) and payload.values[0].value == 1, "schema is the whole number 1")
sched_tree = ast.parse(SCHEDULE.read_text(encoding="utf-8"))
fn = next(n for n in sched_tree.body if isinstance(n, ast.FunctionDef) and n.name == "sync_schedule_status")
dicts = [n for n in ast.walk(fn) if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict)]
must(len(dicts) == 1, "sync_schedule_status returns one dict")
status_keys = [k.value for k in dicts[0].value.keys]
must(status_keys == ["enabled", "time", "timezone", "next_run_at", "last_run_at", "last_run_status"], status_keys)

# (6) the exports carry the rows, the SearchSelect text and the response details
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
http_rows = [
    {"route": "/api/tfd/modules/repositories/", "name": "tfd-module-repositories", "methods": ["GET", "POST"], "kind": "http",
     "audience": "browser/external", "contract": DETAILS["/api/tfd/modules/repositories/"]},
    {"route": "/api/tfd/modules/repositories/sync/", "name": "tfd-module-repositories-sync", "methods": ["POST"], "kind": "http",
     "audience": "browser/external", "contract": DETAILS["/api/tfd/modules/repositories/sync/"]},  # a contract that is not flagged
    {"route": "/api/tfd/no-contract/", "name": "plain", "methods": ["GET"], "kind": "http", "audience": "browser/external"},  # no contract key
]
catalog = {"framework_version": "1.17.44", "generated_at": "2026-10-16T00:00:00+00:00", "rules": list(RULES),
           "core": [dict(r, signature="()") for r in CORE], "browser": [dict(r) for r in BROWSER], "resource_directory": {}, "capabilities": [],
           "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": http_rows}
md = ns["render_markdown"](catalog)
text = ns["render_text"](catalog)
for row_id in NEW:
    must(row_id in md and row_id in text, f"{row_id} is rendered in both exports")
    must(f"### `{row_id}` details" in md, f"{row_id} has its details section")
for needle in ("Showing the first 1000 loaded", "serverSearch", "selectedLabel", "hasMore", "aria-busy"):
    must(needle in md and needle in text, f"both exports carry {needle!r}")
must("### HTTP response details" in md and "HTTP RESPONSE DETAILS" in text, "both exports have the response details")
for needle in ("`GET /api/tfd/modules/repositories/`", "sync_schedule", "enabled", "timezone", "next_run_at", "last_run_at", "last_run_status",
               "03:00", "schema", "count", "manage", "auth_token", "skipped_count", "Added 1.17.42"):
    must(needle in md, f"the Markdown export carries {needle!r}")
for needle in ("GET /api/tfd/modules/repositories/", "response sync_schedule", "response schema", "response count", "response manage", "note: Added 1.17.42"):
    must(needle in text, f"the text export carries {needle!r}")
must(md.count("#### `") == 1 and text.count("    authorization:") == 1, "only the flagged route is described")
must("/api/tfd/modules/repositories/sync/" in md and "response `repositories`: one row per enabled" not in md, "the unflagged route stays a table row only")
must("/api/tfd/no-contract/" in md and "/api/tfd/no-contract/" in text, "a row with no contract still prints in the table")
# no flagged route, no section
bare = dict(catalog, http=[http_rows[1], http_rows[2]])
must("HTTP response details" not in ns["render_markdown"](bare) and "HTTP RESPONSE DETAILS" not in ns["render_text"](bare), "no section without a flagged route")
empty = dict(catalog, http=[])
ns["render_markdown"](empty)
ns["render_text"](empty)

# (7) the UI docs, when they sit beside this repository, carry the same facts
UI_DOCS = ROOT.parent / "ui" / "docs"
if (UI_DOCS / "module-dialogs.md").is_file():
    def doc(name):
        return (UI_DOCS / name).read_text(encoding="utf-8")
    d = doc("module-dialogs.md")
    for needle in ("520px", "760px", "1100", "1300", "1400", "1200", "200 characters", "at most 64", "beforeClose", "status` 0", "module_register_timeout_seconds"):
        must(needle in d, f"module-dialogs.md has {needle!r}")
    d = doc("module-sign-in-landing.md")
    for needle in ("/dashboards", "/sso/callback", "/popup/", "/public/", "Q66", "Q67", "module_register_timeout_seconds", "one registration per module".capitalize()):
        must(needle in d, f"module-sign-in-landing.md has {needle!r}")
    d = doc("module-row-menu.md")
    for needle in ("1150", "1100", "1200", "1300", "1400", "40 items", "80 characters", "120 characters", "Unavailable for this selection.", "TypeError"):
        must(needle in d, f"module-row-menu.md has {needle!r}")
    d = doc("module-components.md")
    for needle in ("Server search and paging", "1000 loaded rows", "Showing the first 1000 loaded. Keep typing to narrow it.", "serverSearch", "selectedLabel", "hasMore", "aria-busy"):
        must(needle in d, f"module-components.md has {needle!r}")
    print("       UI doc cross-check passed")
else:
    print("       UI cross-check skipped: workspace/ui is not beside this repository")

print("[TEST] PASS browser contract rows 1.17.44")
