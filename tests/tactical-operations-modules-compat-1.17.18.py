#!/usr/bin/env python3
"""1.17.18 backwards compatibility: every Tactical operation that a module under modules/ declares today still registers.

Each modules/<id>/package/**/operations.py that holds an OPERATIONS table (id -> keyword arguments of
register_tactical_operation) is loaded as data and registered, module by module, against the stubs of
tests/tactical-operations-1.17.7.py with the real tactical_operations.py of this release. A declaration that only the module's
apps.py builds (alerts, licensing, globalsettings) is covered by the route check of tests/tactical-operation-route-owners-1.17.18.py.
Skipped when modules/ is not beside this repository. Declarations that need a Tec-Tac permission codename the stubs do not know
are registered without ``module_permission`` (that key is untouched by 1.17.18).
"""
from __future__ import annotations

import importlib.util
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index("fresh()\nmust(ops.list_operations() == []")
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, PLUGINS, fresh, must = (G[k] for k in ("ops", "PLUGINS", "fresh", "must"))

MODULES = Path(__file__).resolve().parents[3] / "modules"
if not (MODULES / "catalog.toml").is_file():
    print("[TEST] SKIP tactical operations modules compat 1.17.18 (modules/ is not beside this repository)")
    raise SystemExit(0)

catalog = tomllib.loads((MODULES / "catalog.toml").read_text(encoding="utf-8"))
entries = catalog.get("modules") or {}
category = {key: str(value.get("category", "")) for key, value in entries.items()}

fresh()
import inspect

ALLOWED = set(inspect.signature(ops.register_tactical_operation).parameters) - {"id"}
registered = {}
skipped = []
for folder in sorted(p for p in MODULES.iterdir() if (p / "package").is_dir()):
    module_id = folder.name
    for file in sorted((folder / "package").rglob("operations.py")):
        if "tests" in file.parts:
            continue
        spec = importlib.util.spec_from_file_location(f"compat_{module_id.replace('-', '_')}_ops", file)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # a module whose operations.py imports Django or Tec-Tac cannot be read as data
            skipped.append((module_id, f"import: {type(exc).__name__}"))
            continue
        table = getattr(module, "OPERATIONS", None)
        if not isinstance(table, dict) or not table:
            skipped.append((module_id, "no OPERATIONS table"))
            continue
        PLUGINS[module_id] = SimpleNamespace(plugin_id=module_id, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False,
                                             audit_events=(), category=category.get(module_id, "core"))
        count = 0
        for op_id, kwargs in table.items():
            # a module's table may carry its own page hints; its apps.py passes only the keys the call takes
            kwargs = {key: value for key, value in kwargs.items() if key in ALLOWED}
            kwargs.pop("module_id", None)
            kwargs.pop("module_permission", None)
            for flag in kwargs.get("permissions") or ():
                G["Role"].FIELDS.setdefault(flag, "BooleanField")  # the stub Role knows only a few of Tactical's flags
            # The same call as the module's apps.py makes.
            ops.register_tactical_operation(id=op_id, module_id=module_id, **kwargs)
            count += 1
        registered[module_id] = count

must(registered, f"no operations table could be read: {skipped}")
total = sum(registered.values())
must(total >= 50, f"only {total} declarations registered: {registered} (skipped {skipped})")
# every registered operation describes and serialises
import json
for row in ops.list_operations():
    json.dumps(row)
    # Modules adopt the 1.17.18 keys over time (agent-management bulk-recovery uses caller_scope), so the row is only held to
    # describing every key; a declaration that names none of the new keys keeps the defaults. 1.17.22: server_only is a bool, since
    # Agents now declares server_only true on some operations (it was pinned False for every module before).
    must({"caller_scope", "body_selector", "server_only"} <= set(row) and "params" in row["audit"] and isinstance(row["server_only"], bool), row)
print(f"       registered {total} declarations of {len(registered)} modules: {registered}")
if skipped:
    print(f"       not read as data: {skipped}")
print("[TEST] PASS tactical operations modules compat 1.17.18")
