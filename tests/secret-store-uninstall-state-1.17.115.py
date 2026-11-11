#!/usr/bin/env python3
"""1.17.115 regression: Core keeps a module's secrets when the module is uninstalled, and says so.

Request: certificatemanagement 0.5.0 asked whether Core deletes a module's secrets at uninstall. The answer is no, and this test pins that answer so
the docs stay true. Covered: docs/secret-store.md has the section 'When a module is uninstalled' naming kept rows, a later install of the same id
and delete-before-uninstall; a source scan shows module_manager.py, module_manager_v2.py, scripts/remove-extension.sh and
scripts/module-job-helper.py never mention secret_store or core_secret (if a purge is ever added, update the docs section and this test); the
contract text of the core.secrets rows and the module-secrets guidance carry the sentence; and the put, get, delete signatures are unchanged.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


docs = (ROOT / "docs" / "secret-store.md").read_text(encoding="utf-8")
must("## When a module is uninstalled" in docs, "docs section")
section = docs.split("## When a module is uninstalled", 1)[1].split("\n## ", 1)[0]
low = section.lower()
must("keeps a module's secrets" in low, "kept")
must("same id" in low and "reads the old values again" in low, "same-id reinstall")
must("delete(name)" in section and "before they uninstall" in section, "delete before uninstall")
must("remove connection" in low, "remove connection advice")
must("not installed and enabled" in low, "unreadable while not installed")

for rel in ("framwork/tec_tac/module_manager.py", "framwork/tec_tac/module_manager_v2.py", "scripts/remove-extension.sh", "scripts/module-job-helper.py"):
    path = ROOT / rel
    must(path.is_file(), f"{rel} exists")
    text = path.read_text(encoding="utf-8", errors="replace").lower()
    for word in ("secret_store", "core_secret"):
        must(word not in text, f"{rel} mentions {word}: Core would then purge secrets, so update docs/secret-store.md and this test")

contracts = (APP / "contracts.py").read_text(encoding="utf-8")
sentence = "When a module is uninstalled Core keeps its secret rows"
must(contracts.count("Core keeps a module's secrets when it is uninstalled") == 1, "module-secrets guidance")
must(contracts.count(sentence) == 5, "the five core.secrets rows carry the sentence")
must("delete(name) before uninstall" in contracts, "delete before uninstall")

tree = ast.parse((APP / "secret_store.py").read_text(encoding="utf-8"))


def args(name):
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.unparse(node.args)


must(args("put").split(",")[0].strip() == "name: str" or args("put").startswith("name"), args("put"))
must(args("get").startswith("name"), args("get"))
must(args("delete").startswith("name"), args("delete"))
print("secret-store-uninstall-state-1.17.115: ok")
