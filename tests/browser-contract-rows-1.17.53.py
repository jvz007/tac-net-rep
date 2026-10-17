#!/usr/bin/env python3
"""1.17.53: FilterEditor joins the browser contract row ui.authenticated.components. Documentation only.

No endpoint, capability or version moves. contracts.py needs Django, so the tables are read with ast and the real render functions are
exec'd from the same tree, as in tests/browser-contract-rows-1.17.42.py.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "framwork/tec_tac/contracts.py"
tree = ast.parse(PATH.read_text(encoding="utf-8"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def literal(name, source=tree):
    node = next(n for n in source.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


BROWSER = literal("BROWSER_CONTRACTS")
RULES = literal("RULES")
CORE = literal("CORE_CONTRACTS")
ids = [r["id"] for r in BROWSER]

# (a) the operations list and the row's place
must(ids.count("ui.authenticated.components") == 1 and len(ids) == len(set(ids)), "the row is there once")
must(ids.index("ui.authenticated.components") == ids.index("ui.authenticated.modulePreferences") + 1, "the row follows modulePreferences")
comp = BROWSER[ids.index("ui.authenticated.components")]
must(comp["operations"] == ["SearchSelect", "TagEditor", "DataTable", "FormRow", "EditorWindow", "Stepper", "FilterEditor"], comp["operations"])
must(comp["docs"] == "tec-tac-ui/docs/module-components.md" and isinstance(comp["docs"], str), comp["docs"])

# (b) every FilterEditor fact
text = " ".join(comp["details"]) + " " + comp["purpose"]
must("Since UI 0.12.116 FilterEditor, the shared filter editor, bound per module." in comp["purpose"], "purpose names FilterEditor")
for needle in (
    "viewKey (required", "^[a-z0-9][a-z0-9_-]{0,60}$", "modelValue (the current definition", "disabled", "update:modelValue", "apply",
    "{ definition, filterSetId }", "both null means no filter", "never sends an empty definition", "no module id prop",
    "no AD-20 replacement exception", "not a sandbox", "GET /api/tfd/filter-sets/fields/", "GET /api/tfd/filter-values/", "/api/tfd/filter-sets/",
    "POST, PUT and DELETE for Only me sets", "UI 0.12.116", "Core 1.17.50", "core.filter_sets 1.0.0", "registerPublic gets no components",
    "tec-tac-ui/docs/module-filters.md", "UI 0.12.117", "Core 1.17.52", "core.filter_sets 1.1.0", "YYYY-MM-DD", "between", "in_the_last",
    "not_in_the_last", "relative_units", "integer", "minimum", "maximum", "max_amount", "UTC days", "never matches a positive operator",
    "{ amount, unit }", "{ from, to }", "10**15", "The first six members are unchanged",
    "Documentation only: no endpoint, capability or version moves",
):
    must(needle in text, f"the components row names {needle!r}")

# (c) the six earlier members keep their text: their tests still pass
for earlier in ("1.17.42", "1.17.44", "1.17.50", "1.17.51"):
    done = subprocess.run([sys.executable, str(ROOT / "tests" / f"browser-contract-rows-{earlier}.py")], capture_output=True, text=True, check=False)
    must(done.returncode == 0, f"{earlier}: {done.stdout}{done.stderr}")

# (d) both exports carry the member
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
catalog = {"framework_version": "1.17.53", "generated_at": "2026-10-17T00:00:00+00:00", "rules": list(RULES),
           "core": [dict(r, signature="()") for r in CORE], "browser": [dict(r) for r in BROWSER], "resource_directory": {}, "capabilities": [],
           "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)
txt = ns["render_text"](catalog)
for name, out in (("markdown", md), ("text", txt)):
    must("FilterEditor" in out, f"{name} export lists FilterEditor")
    must("FilterEditor (UI 0.12.116, added to this row in Core 1.17.53)" in out, f"{name} export carries the details section")
    must("YYYY-MM-DD" in out and "UTC days" in out, f"{name} export carries the date and number entry")
must(re.search(r"ui\.authenticated\.components.*FilterEditor", md), "the markdown table row lists FilterEditor")

# (e) the capabilities the row relies on are still declared
fs = ast.parse((ROOT / "framwork/tec_tac/filter_sets.py").read_text(encoding="utf-8"))
to = ast.parse((ROOT / "framwork/tec_tac/tactical_operations.py").read_text(encoding="utf-8"))
must(literal("CAPABILITY_VERSION", fs) == "1.1.0", "core.filter_sets is still 1.1.0")
must(literal("CAPABILITY_VERSION", to) == "1.15.0", "core.tactical_operations is still 1.15.0")

# (f) the UI docs, when they sit beside this repository, agree
UI = ROOT.parent / "ui" / "docs"
if (UI / "module-filters.md").is_file():
    filters = (UI / "module-filters.md").read_text(encoding="utf-8")
    components = (UI / "module-components.md").read_text(encoding="utf-8")
    runtime = (UI / "module-runtime-api.md").read_text(encoding="utf-8")
    for needle in ("^[a-z0-9][a-z0-9_-]{0,60}$", "update:modelValue", "{ definition, filterSetId }", "GET /api/tfd/filter-sets/fields/",
                   "GET /api/tfd/filter-values/", "/api/tfd/filter-sets/", "no module id prop", "not a sandbox", "UI 0.12.117", "Core 1.17.52",
                   "relative_units", "max_amount", "YYYY-MM-DD", "UTC days", "10**15"):
        must(needle.lower() in filters.lower(), f"module-filters.md has {needle!r}")
    for needle in ("viewKey", "modelValue", "disabled", "update:modelValue", "apply", "filterSetId", "registerPublic", "Core 1.17.50"):
        must(needle in components, f"module-components.md has {needle!r}")
    for needle in ("viewKey", "/api/tfd/filter-sets/", "/api/tfd/filter-values/", "UI 0.12.116", "no module id prop", "no replacement exception"):
        must(needle in runtime, f"module-runtime-api.md has {needle!r}")
    print("       UI doc cross-check passed")
else:
    print("       UI cross-check skipped: workspace/ui is not beside this repository")

# (g) the version (a -N retry suffix is stripped)
raw = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
version = tuple(int(x) for x in re.sub(r"-\d+$", "", raw).split("."))
must(version >= (1, 17, 53), raw)
print("browser contract rows 1.17.53 ok")
