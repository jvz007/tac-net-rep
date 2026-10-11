#!/usr/bin/env python3
"""1.17.19: a browser contract row's ``docs`` cell is a plain path, so the module validator can read it as a file.

The 1.17.18 export wrote ``tec-tac-ui/docs/module-runtime-api.md (section tacticalScope())`` and the validator reported
``reference.ui-doc-missing`` on every module build. Covered: every BROWSER_CONTRACTS row's docs value matches
``^tec-tac-ui/docs/[A-Za-z0-9._-]+\\.md$``; the tactical-scope row keeps the section name in details, not in docs; the rendered
markdown and the text export carry no docs cell with a space or a parenthesis; when the UI docs tree is beside this repository, each
named file exists (skipped with a note when it is not). contracts.py needs Django, so the tables are read with ``ast`` and the real
``render_markdown`` and ``render_text`` run on a catalogue built from them. The test fails on the 1.17.18 text.
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

must(len(BROWSER) >= 10, "the browser table is read")
for row in BROWSER:
    must(PATTERN.match(str(row.get("docs", ""))), f"{row.get('id')}: docs is not a plain path: {row.get('docs')!r}")

scope = next(r for r in BROWSER if r["id"] == "ui.authenticated.tactical-scope")
must(scope["docs"] == "tec-tac-ui/docs/module-runtime-api.md", scope["docs"])
must("section tacticalScope()" in " ".join(scope["details"]) and "tacticalScope" not in scope["docs"], "the section name is in details")

# the real renderers, on a catalogue built from the literal tables
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)
catalog = {"framework_version": "1.17.19", "generated_at": "2026-10-11T00:00:00+00:00", "rules": list(RULES),
           "core": [dict(r, signature="()") for r in CORE], "browser": [dict(r) for r in BROWSER], "resource_directory": {}, "capabilities": [],
           "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)
cells = []
for line in md.splitlines():
    if line.startswith("| `ui.") and line.count("|") >= 8:
        parts = [p.strip() for p in line.strip().strip("|").split(" | ")]
        cells.append(parts[5])  # Contract | Phase | Service | Operations | Audience | Canonical docs | Purpose
must(len(cells) == len(BROWSER), (len(cells), len(BROWSER)))
for cell in cells:
    must(re.fullmatch(r"`tec-tac-ui/docs/[A-Za-z0-9._-]+\.md`", cell), f"markdown docs cell: {cell!r}")
text = ns["render_text"](catalog)
for row in BROWSER:
    must(row["docs"] in text, row["docs"])
docs_cells = re.findall(r"\| docs=(.*?) - ", text)
must(len(docs_cells) == len(BROWSER), (len(docs_cells), len(BROWSER)))
for cell in docs_cells:
    must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", cell), f"text export docs cell: {cell!r}")

# the UI docs exist, when the UI tree is beside this repository
candidates = [ROOT.parent / "ui" / "docs", ROOT.parent.parent / "repos" / "ui" / "docs"]
docs_dir = next((p for p in candidates if p.is_dir()), None)
if docs_dir is None:
    print("       UI docs tree not found beside this repository: file existence not checked")
else:
    for row in BROWSER:
        name = row["docs"].split("/")[-1]
        must((docs_dir / name).is_file(), f"{row['id']}: {name} is not in {docs_dir}")
    print(f"       every browser docs path exists in {docs_dir}")
print("[TEST] PASS contract browser doc cells 1.17.19")
