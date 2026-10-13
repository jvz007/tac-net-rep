#!/usr/bin/env python3
"""1.17.23: browser contract rows for popup mode, the shell confirm dialog and the modules.json ``dependencies`` field.

Covered: the rows ui.authenticated.popup, ui.authenticated.confirm and ui.authenticated.module-descriptor exist; every docs value is a
plain path; the popup details name popupHref, meta.popup, meta.permission and meta.permissions, the URL form and both refusal texts; the
confirm details name every option with its limit; the router row names the /popup/ prefix and the taken-alias refusal; the descriptor row
names ``dependencies`` and sync-modules.sh; the real render_markdown and render_text carry every row and no docs cell holds a space or a
parenthesis. contracts.py needs Django, so the tables are read with ``ast``. The test fails on 1.17.22.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "framwork/tec_tac/contracts.py"
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
RULES = literal("RULES")
CORE = literal("CORE_CONTRACTS")
by_id = {r["id"]: r for r in BROWSER}
must(len(by_id) == len(BROWSER), "ids are unique")


def details(row_id):
    must(row_id in by_id, f"row {row_id} exists")
    return " ".join(by_id[row_id].get("details", []))


for row in BROWSER:
    must(PATTERN.match(str(row.get("docs", ""))), f"{row['id']}: docs is not a plain path: {row.get('docs')!r}")

popup = details("ui.authenticated.popup")
for needle in ("popupHref", "meta.popup", "meta.permission", "meta.permissions", "https://<host>/tec-tac/#/popup/<module id><path>",
               "This page is not available to you.", "This page cannot open in its own window.", "query string", "..",
               "zero-width", "/popup", "opens nothing", "registerPublic", "failed or timed-out register()", "hard dependencies",
               "superuser", "every code is required"):
    must(needle in popup, f"popup details name {needle!r}")
must(by_id["ui.authenticated.popup"]["docs"] == "tec-tac-ui/docs/module-runtime-api.md", "popup docs path")
must("Popup mode" in popup and "Popup mode" not in by_id["ui.authenticated.popup"]["docs"], "section name is in details")
must("0.12.95" in by_id["ui.authenticated.popup"]["purpose"], "popup needs UI 0.12.95")

confirm = details("ui.authenticated.confirm")
for needle in ("question (required", "300", "target (at most 200", "count (a whole number of 1 or more", "noun (at most 30",
               "detail (at most 400", "danger", "yesLabel and noLabel (at most 24", "no input field", "Asked by <module id>",
               "failed or timed-out register()", "shell's value wins", "Display only", "one dialog shows at a time", ):
    must(needle.lower() in confirm.lower(), f"confirm details name {needle!r}")
must("0.12.96" in by_id["ui.authenticated.confirm"]["purpose"], "confirm needs UI 0.12.96")

router = details("ui.authenticated.router")
must("/popup/" in router and "0.12.96" in router and "alias that another owner already holds" in router, "router row names /popup/ and the taken alias")

descriptor = details("ui.authenticated.module-descriptor")
for needle in ("dependencies", "sync-modules.sh", "sorted", "Older shells ignore", "loads the module alone", "optional_dependencies", "tec_tac.json"):
    must(needle in descriptor, f"descriptor details name {needle!r}")

functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)
catalog = {"framework_version": "1.17.23", "generated_at": "2026-10-13T00:00:00+00:00", "rules": list(RULES),
           "core": [dict(r, signature="()") for r in CORE], "browser": [dict(r) for r in BROWSER], "resource_directory": {}, "capabilities": [],
           "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)
text = ns["render_text"](catalog)
cells = []
for line in md.splitlines():
    if line.startswith("| `ui.") and line.count("|") >= 8:
        parts = [p.strip() for p in line.strip().strip("|").split(" | ")]
        cells.append(parts[5])
must(len(cells) == len(BROWSER), (len(cells), len(BROWSER)))
for cell in cells:
    must(re.fullmatch(r"`tec-tac-ui/docs/[A-Za-z0-9._-]+\.md`", cell), f"markdown docs cell: {cell!r}")
for row_id in ("ui.authenticated.popup", "ui.authenticated.confirm", "ui.authenticated.module-descriptor"):
    must(f"`{row_id}`" in md and row_id in text, f"{row_id} is rendered")
docs_cells = re.findall(r"\| docs=(.*?) - ", text)
must(len(docs_cells) == len(BROWSER), (len(docs_cells), len(BROWSER)))
for cell in docs_cells:
    must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", cell), f"text export docs cell: {cell!r}")
print("[TEST] PASS browser contract popup confirm 1.17.23")
