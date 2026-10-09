#!/usr/bin/env python3
"""1.17.13 regression: the two dev-server runtime scripts declare probe manifests that Core's own rules accept.

The 1.17.11 and 1.17.12 scripts declared the capability ``patching.windows`` on a probe core module called ``tectac-probe-replaced``. Core
refuses that (a core module's capability must begin with its own id), so most of their steps failed with RegistryError before they tested
anything (debug/test results 1.17.11.log, debug/command results 18-06.log). This test reads both corrected scripts without running them and
checks every ``manifest(...)`` call for a probe against Core's real registry rules:

* a core probe declares only capabilities that begin with its own id;
* the replacement probe is ``category: premium`` (AD-21) and declares the same capability names as the module it replaces (AD-20);
* neither script still declares ``patching.windows`` as a capability.

The scripts themselves need Django and Tactical's AuditLog, so Johan runs them on the dev server (manage.py shell). They could not run on
the development PC, and a pass there is not a condition of the release.
"""
from __future__ import annotations

import ast
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules.setdefault(name, module)


_stub("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
from tec_tac import registry  # noqa: E402

SCRIPTS = ("module-replacement-reconcile-runtime-1.17.13.py", "module-replacement-handback-runtime-1.17.13.py")
must(not (ROOT / "tests" / "module-replacement-reconcile-runtime-1.17.11.py").exists(), "the 1.17.11 script was renamed, not copied")
must(not (ROOT / "tests" / "module-replacement-handback-runtime-1.17.12.py").exists(), "the 1.17.12 script was renamed, not copied")

checked = 0
for name in SCRIPTS:
    source = (ROOT / "tests" / name).read_text(encoding="utf-8")
    must('"patching.windows"' not in source, f"{name} still declares patching.windows")
    must("1.17.13" in source.split('"""')[1], f"{name} does not say which release carries it")
    tree = ast.parse(source)
    names: dict[str, object] = {}
    for node in tree.body:  # the module-level constants the manifest calls use
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in ("OLD", "CAP"):
                names[target.id] = eval(compile(ast.Expression(node.value), name, "eval"), {}, dict(names))
            elif isinstance(target, ast.Tuple) and [elt.id for elt in target.elts if isinstance(elt, ast.Name)] == ["REPL", "OLD"]:
                names["REPL"], names["OLD"] = ast.literal_eval(node.value)
    must({"OLD", "REPL", "CAP"} <= set(names), (name, sorted(names)))
    must(names["CAP"].startswith(names["OLD"] + "."), f"{name}: CAP must begin with the replaced module's id")
    probes = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "manifest" and node.args and isinstance(node.args[0], ast.Name):
            module_id = names.get(node.args[0].id)
            if module_id is None:
                continue
            kwargs = {kw.arg: eval(compile(ast.Expression(kw.value), name, "eval"), {}, dict(names)) for kw in node.keywords if kw.arg}
            probes.setdefault(module_id, []).append(kwargs)
    must(names["OLD"] in probes and names["REPL"] in probes, (name, sorted(probes)))
    for module_id, calls in probes.items():
        for kwargs in calls:
            payload = {"id": module_id, **kwargs}
            category = str(payload.get("category") or "")
            if module_id == names["OLD"]:
                must(category == "core", f"{name}: the replaced probe is a core module")
                must(payload["capabilities"] and all(cap.startswith(module_id + ".") for cap in payload["capabilities"]), (name, payload))
            if "replaces" in payload:
                must(category == "premium", f"{name}: a probe replacement must be category premium (AD-21): {payload}")
                replaced = next(call for call in probes[names["OLD"]])
                must(sorted(payload["capabilities"]) == sorted(replaced["capabilities"]), f"{name}: the replacement publishes the same names (AD-20)")
            # Core's own parser accepts it
            registry._replacement_keys(payload, "extension", module_id, category)
            checked += 1
must(checked >= 4, checked)

# the 1.17.13 scripts also exercise the new behaviour
reconcile = (ROOT / "tests" / SCRIPTS[0]).read_text(encoding="utf-8")
handback = (ROOT / "tests" / SCRIPTS[1]).read_text(encoding="utf-8")
for needle in ("category_refused", "replacement-category", "is_development_server", "_server_environment", "category_missing"):
    must(needle in reconcile, f"reconcile script lacks {needle}")
for needle in ("module-replacement:switch-failed:job-long", "The outcome is not confirmed", "_audit_already_written", "rolled_back"):
    must(needle in handback, f"hand-back script lacks {needle}")
for source in (reconcile, handback):
    must("sys.exit(1)" in source and "steps passed" in source, "the script prints PASS or FAIL per step and exits 1 on a failure")

print("[TEST] PASS module replacement runtime probes 1.17.13")
