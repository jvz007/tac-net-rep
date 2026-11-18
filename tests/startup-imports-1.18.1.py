#!/usr/bin/env python3
"""Regression: Core 1.18.1 start-up imports are lighter and every public name is unchanged."""
import ast
import importlib
import re
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "framwork" / "tec_tac"

PUBLIC_NAMES = [
    "MAX_RESPONSE_BYTES", "ROUTE_OWNERS", "EXACT_RULES", "TacticalOperation", "TacticalOperationResult",
    "register_tactical_operation", "run_tactical_operation", "list_operations", "get_operation",
    "upload_ceiling_bytes", "tactical_operations_contract_metadata",
    "_ID_RE", "_LITERAL_RE", "_PARAM_RE", "_FIELD_RE", "_OBJECT_ID_RE", "_CORRELATION_RE", "_SECRET_NAME_RE",
    "_PARAM_NAME_RE", "_SCOPE_SOURCE_RE", "_SCOPE_TYPE_BODY_RE", "_EXTENSION_RE", "_CONTENT_TYPE_RE",
    "_PARAM_VALUE_RE", "_LIST_CONTROL", "_ITEM_NAME_RE", "_ITEM_SWITCH_RE", "_PERCENT_RE",
]

# Original pattern text and flags (Core 1.18.0): the lazy patterns must answer the same.
ORIGINAL = {
    "_ID_RE": (r"^[a-z][a-z0-9_-]{0,63}$", 0),
    "_LITERAL_RE": (r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$", 0),
    "_PARAM_RE": (r"^\{([a-z][a-z0-9_]{0,31})(?::(str|int|agent|service))?\}$", 0),
    "_FIELD_RE": (r"^[A-Za-z_][A-Za-z0-9_]{0,63}$", 0),
    "_OBJECT_ID_RE": (r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$", 0),
    "_CORRELATION_RE": (r"^[A-Za-z0-9._:-]{1,128}$", 0),
    "_SECRET_NAME_RE": (r"(pass|secret|token|key|credential|auth|cookie|signature)", re.IGNORECASE),
    "_PARAM_NAME_RE": (r"^[a-z][a-z0-9_]{0,31}$", 0),
    "_SCOPE_SOURCE_RE": (r"^(path|body):([A-Za-z_][A-Za-z0-9_]{0,63})(?:\.([A-Za-z_][A-Za-z0-9_]{0,63}))?$", 0),
    "_SCOPE_TYPE_BODY_RE": (r"^body:([A-Za-z_][A-Za-z0-9_]{0,63})$", 0),
    "_EXTENSION_RE": (r"^[a-z0-9]{1,10}$", 0),
    "_CONTENT_TYPE_RE": (r"^[A-Za-z0-9!#$&^_.+-]{1,60}/[A-Za-z0-9!#$&^_.+-]{1,60}$", 0),
    "_LIST_CONTROL": (r"[\x00-\x08\x0b-\x1f\x7f]", 0),
    "_ITEM_NAME_RE": (r"^-{0,2}[A-Za-z_][A-Za-z0-9_.\-]{0,63}$", 0),
    "_ITEM_SWITCH_RE": (r"^(?:-{1,2}|/)[A-Za-z0-9_?][A-Za-z0-9_.\-]{0,63}$", 0),
    "_PERCENT_RE": (r"%([0-9A-Fa-f]{2})", 0),
}
ORIGINAL_KINDS = {
    "str": r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$",
    "agent": r"^[A-Za-z0-9_][A-Za-z0-9_.-]{20,254}$",
    "int": r"^[0-9]{1,12}$",
    "service": r"^[A-Za-z0-9_][A-Za-z0-9 $#().,_-]{0,255}$",
}

SAMPLES = [
    "", "a", "agents", "get-agent", "Agents", "9abc", "_x", "a_b.c-d", "can_edit", "{agent_id}", "{agent_id:agent}",
    "{id:int}", "{id:other}", "{Id}", "path:agent_id", "body:name.key", "body:name", "body:", "path:a.b.c",
    "application/json", "text/plain; x", "a/b/c", "password", "API_TOKEN", "Cookie", "signature_hex", "name",
    "tactical-server", "abc:def.1", "x" * 64, "x" * 65, "x" * 200, "12345678901234", "123", "-flag", "--flag",
    "/switch", "-", "name=value", "a b", "svc name$", "..", "%41%zz%7E", "line\x00ctl\x1f\x7f tab\t nl\n",
    "https://x/y",
]

package_stub = types.ModuleType("tec_tac")
package_stub.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package_stub
ops = importlib.import_module("tec_tac.tactical_operations")

# (a) every public name is still there, and each lazy pattern answers like the original
missing = [name for name in PUBLIC_NAMES if not hasattr(ops, name)]
assert not missing, missing

for name, (text, flags) in ORIGINAL.items():
    lazy = getattr(ops, name)
    ref = re.compile(text, flags)
    for sample in SAMPLES:
        for method in ("match", "fullmatch", "search"):
            a, b = getattr(lazy, method)(sample), getattr(ref, method)(sample)
            assert (a is None) == (b is None), (name, method, sample)
            if a is not None:
                assert a.group(0) == b.group(0) and a.groups() == b.groups(), (name, method, sample)
        assert lazy.findall(sample) == ref.findall(sample), (name, sample)
        assert lazy.sub("", sample) == ref.sub("", sample), (name, sample)
    assert lazy.pattern == text and lazy.flags & flags == flags, name

assert set(ops._PARAM_VALUE_RE) == set(ORIGINAL_KINDS)
for kind, text in ORIGINAL_KINDS.items():
    ref = re.compile(text)
    for sample in SAMPLES:
        assert (ops._PARAM_VALUE_RE[kind].match(sample) is None) == (ref.match(sample) is None), (kind, sample)

# (b) diagnostics.py: no module-level import of the heavy names, detector text still present
diag_text = (PKG_DIR / "diagnostics.py").read_text(encoding="utf-8")
assert "MigrationAutodetector" in diag_text
heavy = ("django.db.migrations", "subprocess", "shutil")
for node in ast.parse(diag_text).body:
    if isinstance(node, ast.Import):
        for alias in node.names:
            assert not alias.name.startswith(heavy), (alias.name, node.lineno)
    if isinstance(node, ast.ImportFrom):
        assert not (node.module or "").startswith(heavy), (node.module, node.lineno)

# system_actions.py keeps its public table and no longer compiles patterns at import
sa_tree = ast.parse((PKG_DIR / "system_actions.py").read_text(encoding="utf-8"))
sa_names = set()
for node in sa_tree.body:
    if isinstance(node, ast.Assign):
        sa_names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        sa_names.add(node.target.id)
assert "SYSTEM_FUNCTIONS" in sa_names, "SYSTEM_FUNCTIONS must stay a module-level name"
for node in ast.walk(sa_tree):
    if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "compile":
        raise AssertionError("system_actions.py still calls re.compile")

# (c) fresh interpreter: patterns compile on first use, not at import
PROBE = """
import json, re, sys, types
count = {"n": 0}
seen = []
real = re.compile
def counting(*a, **k):
    count["n"] += 1
    seen.append(a[0] if isinstance(a[0], str) else repr(a[0]))
    return real(*a, **k)
re.compile = counting
pkg = types.ModuleType("tec_tac"); pkg.__path__ = [sys.argv[1]]; sys.modules["tec_tac"] = pkg
import tec_tac.tactical_operations as ops
at_import = count["n"]
assert not ops._ID_RE.compiled and not ops._SECRET_NAME_RE.compiled
assert ops._ID_RE.match("agents") and ops._ID_RE.compiled
assert count["n"] == at_import + 1, (count["n"], at_import)
ops._ID_RE.match("again")
assert count["n"] == at_import + 1, "compiled twice"
print(json.dumps(seen[:at_import]))
"""
result = subprocess.run([sys.executable, "-B", "-c", PROBE, str(PKG_DIR)], capture_output=True, text=True)
assert result.returncode == 0, result.stderr
import json
compiled_at_import = set(json.loads(result.stdout.strip().splitlines()[-1]))
ours = {text for text, _ in ORIGINAL.values()} | set(ORIGINAL_KINDS.values())
assert not (compiled_at_import & ours), sorted(compiled_at_import & ours)

print("start-up imports 1.18.1 regression: PASS")
