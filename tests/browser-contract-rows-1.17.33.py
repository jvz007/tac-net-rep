#!/usr/bin/env python3
"""1.17.33: browser contract rows owed to the UI (reviews/requests/core.md, UI 0.12.103), documentation only.

Adds ui.authenticated.jobs (background job follow, UI 0.12.103), gives ui.authenticated.notifications a details list with the signed-out
line, and adds the signed-out line to ui.authenticated.transport (the row that lists api, apiRaw, apiBlob and apiText). The wording is
taken from workspace/ui/docs (module-job-follow.md, module-notifications.md, module-runtime-api.md). No row changes a value that a module
consumes, and no capability or contract version moves.

Covered: ids are unique; every docs value is a plain tec-tac-ui/docs/*.md path; the jobs row names follow, every descriptor key, the
clamps, the defaults, the stop rules, the limits 10 and 50, the refusals, dedupeKey and UI 0.12.103; the notifications details carry the
signed-out line and the null return; the transport details carry status 401 and code signed_out; the real render_markdown and
render_text carry every row and no docs cell holds a space or a parenthesis. contracts.py needs Django, so the tables are read with ast
and the two render functions are exec'd from the same tree. tests/browser-contract-rows-1.17.32.py and the other contract tests run
unchanged.
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


def check(row_id, needles):
    text = details(row_id) + " " + by_id[row_id].get("purpose", "") + " " + " ".join(by_id[row_id].get("operations", []))
    for needle in needles:
        must(needle in text, f"{row_id} names {needle!r}")


for row in BROWSER:
    must(PATTERN.match(str(row.get("docs", ""))), f"{row['id']}: docs is not a plain path: {row.get('docs')!r}")

# ------------------------------------------------------------------------------------------------ the jobs row
jobs = by_id.get("ui.authenticated.jobs", {})
must(jobs.get("phase") == "authenticated" and jobs.get("service") == "jobs", "jobs row is authenticated jobs")
must(jobs.get("operations") == ["follow"], "jobs row lists follow")
must(jobs.get("audience") == "module/browser", "jobs row audience")
must(jobs.get("docs") == "tec-tac-ui/docs/module-job-follow.md", "jobs docs path")
must(jobs.get("purpose") == "Follow a background job through a read route after the person leaves the page.", "jobs purpose")
check("ui.authenticated.jobs", [
    "follow(descriptor)", "{id, cancel()}", "AD-12", "UI 0.12.103",
    "id", "title", "path", "check(payload)", "'success'", "'error'", "successMessage", "errorMessage", "timeoutMessage",
    "intervalMs", "timeLimitMs", "default 5000", "2000", "60000", "10000", "1800000", "required",
    "second follow with the same id replaces the first", "GET read route", "guarded api",
    "first finish", "one success or error notice", "time limit", "one timeout notice", "cancel()", "pagehide", "end of the session",
    "status 401", "silently", "Three failed reads in a row", "one error notice",
    "dedupeKey job-follow:<id>", "10 live follows per module", "50 in all", "throws a plain error",
    "outside a context Core supplied", "while signed out", "abandoned or unloaded module", "bound by the shell",
    "tactical-operations",
])

# ------------------------------------------------------------------------------------------------ notifications and transport
check("ui.authenticated.notifications", [
    "Nothing shows and nothing is sent while the person is signed out; a module treats status 401 as signed out and stays silent.",
    "show, info, success, warning and error return null", "UI 0.12.103",
])
must(by_id["ui.authenticated.notifications"]["docs"] == "tec-tac-ui/docs/module-notifications.md", "notifications docs path")
check("ui.authenticated.transport", [
    "While signed out the shell refuses the call with status 401 and code signed_out, with no request.",
    "api", "apiRaw", "apiBlob", "apiText", "Error shape",
])
must(by_id["ui.authenticated.transport"]["docs"] == "tec-tac-ui/docs/module-runtime-api.md", "transport docs path")

# ------------------------------------------------------------------------------------------------ the renderers
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
catalog = {"framework_version": "1.17.33", "generated_at": "2026-10-14T00:00:00+00:00", "rules": list(RULES),
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
for needle in ("ui.authenticated.jobs", "job-follow:<id>", "signed_out"):
    must(needle in md and needle in text, f"{needle} is rendered")
for row in BROWSER:
    must(f"`{row['id']}`" in md and row["id"] in text, f"{row['id']} is rendered")
docs_cells = re.findall(r"\| docs=(.*?) - ", text)
must(len(docs_cells) == len(BROWSER), (len(docs_cells), len(BROWSER)))
for cell in docs_cells:
    must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", cell), f"text export docs cell: {cell!r}")
print("[TEST] PASS browser contract rows 1.17.33")
