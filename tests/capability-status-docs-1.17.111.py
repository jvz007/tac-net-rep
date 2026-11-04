#!/usr/bin/env python3
"""1.17.111 regression: every key tec_tac.capabilities.capability_status returns is documented in its contract row and in docs/capabilities.md (request of Automation Manager 0.11.1).

Runs the real registry.py, module_state.py and capabilities.py against a temporary folder of manifests; contracts.py is read as source (it needs Django). Covered. (1) The keys of the
answer for a registered capability (checked and unchecked), a missing one, a disabled one, a version mismatch and a replacement are the same set, and every one appears in the contract row and
in the documents; module_id is named explicitly. (2) The keys are also read from the source of capability_status (the base dict and every key set on it later), so a key added without a line in
the row and in the document fails here. (3) The row says it is documented since Core 1.17.111 and additive.
"""
from __future__ import annotations

import ast
import json
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


fcntl = types.ModuleType("fcntl")
fcntl.__dict__.update(LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
sys.modules.setdefault("fcntl", fcntl)

from tec_tac import capabilities as caps, module_state, registry  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="tectac-capstatus-docs-"))
EXT, REP = TMP / "extensions", TMP / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE
for module_id, enabled in (("stubmod", True), ("offmod", False)):
    folder = EXT / module_id
    folder.mkdir()
    (folder / "tec_tac.json").write_text(json.dumps({"id": module_id, "type": "extension", "version": "1.2.3"}), encoding="utf-8")
    STATE["modules"][module_id] = {"enabled": enabled}

caps._clear_capabilities_for_tests()
caps.register_capability(id="stubmod.cap", module_id="stubmod", version="1.0.0", provider=object(), description="A stub", operations=("read",), metadata={"k": "v"}, health=lambda: {"healthy": True, "n": 1})
caps.register_capability(id="offmod.cap", module_id="offmod", version="1.0.0", provider=object())

answers = {
    "available": caps.capability_status("stubmod.cap"),
    "unchecked": caps.capability_status("stubmod.cap", check_health=False),
    "missing": caps.capability_status("nothere.cap"),
    "disabled": caps.capability_status("offmod.cap"),
    "version": caps.capability_status("stubmod.cap", version=">=2.0.0"),
}
must(answers["available"]["available"] is True and answers["available"]["module_id"] == "stubmod", answers["available"])
must(answers["missing"]["state"] == "missing" and answers["missing"]["module_id"] == "nothere", answers["missing"])
must(answers["disabled"]["state"] == "disabled" and answers["version"]["state"] == "version-incompatible" and answers["unchecked"]["state"] == "health-unchecked", {k: v["state"] for k, v in answers.items()})
keysets = {tuple(sorted(row)) for row in answers.values()}
must(len(keysets) == 1, keysets)  # the same keys in every state
KEYS = set(next(iter(keysets)))
must(KEYS == {"id", "module_id", "available", "state", "required_version", "installed_version", "capability_version", "description", "operations", "metadata", "reason", "health", "health_checked", "replaces"}, sorted(KEYS))

# the contract row
row_text = None
for node in ast.walk(ast.parse((ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8"))):
    if isinstance(node, ast.Dict):
        pairs = {k.value: v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant)}
        if "name" in pairs and isinstance(pairs["name"], ast.Constant) and pairs["name"].value == "capability_status" and "purpose" in pairs:
            row_text = ast.literal_eval(pairs["purpose"])
must(row_text, "the capability_status contract row")
missing = sorted(key for key in KEYS if key not in row_text)
must(not missing, f"keys returned by capability_status but not named in the contract row: {missing}")
must("module_id (the module that provides the capability" in row_text, "module_id is named explicitly, with what it means")
must("1.17.111" in row_text and "additive" in row_text, "the row says since when and that it is additive")
for state in ("available", "missing", "disabled", "capability-unavailable", "version-incompatible", "unhealthy", "health-reentrant", "health-unchecked"):
    must(state in row_text, f"the row lists the state {state}")

# the document
doc = (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8")
missing_doc = sorted(key for key in KEYS if f"| `{key}` |" not in doc)
must(not missing_doc, f"keys returned by capability_status but not in docs/capabilities.md: {missing_doc}")
must("1.17.111" in doc and "module_id" in doc, "the document names the release and module_id")

# the source: every key set on the answer is one of the documented keys (a key added later fails here until it is documented)
source = ast.parse((ROOT / "framwork" / "tec_tac" / "capabilities.py").read_text(encoding="utf-8"))
function = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == "capability_status")
found = set()
for node in ast.walk(function):
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "base" and isinstance(node.value, ast.Dict):
        found |= {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "update" and isinstance(node.func.value, ast.Name) and node.func.value.id == "base":
        found |= {kw.arg for kw in node.keywords if kw.arg}
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript) and isinstance(node.targets[0].value, ast.Name) and node.targets[0].value.id == "base":
        key = node.targets[0].slice
        if isinstance(key, ast.Constant):
            found.add(key.value)
must(found == KEYS, f"the source sets {sorted(found - KEYS)} that is not documented, or leaves out {sorted(KEYS - found)}")
print("       every key capability_status returns is in the contract row and in docs/capabilities.md, module_id is named, and a new key without a line fails here")
print("PASS capability status docs 1.17.111")
