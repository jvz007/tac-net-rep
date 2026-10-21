"""Runtime check for Core 1.17.71 (PluginSpec dependencies and core.module_dependants). It did NOT run on the development PC (Django is not installed there).

It writes nothing: it reads the registry, the module state and the capability list.

One command, on the dev server:
    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/module-dependants-runtime-1.17.71.py

Each line prints PASS or FAIL (or SKIP with its reason); the file ends with PASS only when every line passed.
    1 every installed module has dependencies and optional_dependencies as sorted (id, constraint) pairs
    2 the capability core.module_dependants 1.0.0 is registered with the operation dependants and answers get_capability('>=1.0.0,<2.0.0')
    3 a shell is not a module: Core refuses it with a plain sentence that names no module
    4 for each enabled module that something depends on, code that runs inside that module's folder gets a well-formed answer about itself only
       (SKIP when no installed module names another in its dependencies)
    5 when Groups and a module that names it (Advanced Patch Management 0.13.0 or later) are both installed, that module shows up for the Groups caller
"""
import sys

from tec_tac import module_dependants as md
from tec_tac import registry
from tec_tac.capabilities import get_capability, has_capability

RESULTS = []


def check(label, ok):
    RESULTS.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + label)


plugins = [p for p in registry.get_plugins() if p.plugin_type == "extension"]
well_formed = all(
    isinstance(p.dependencies, tuple) and isinstance(p.optional_dependencies, tuple)
    and list(p.dependencies) == sorted(p.dependencies) and list(p.optional_dependencies) == sorted(p.optional_dependencies)
    and all(isinstance(i, tuple) and len(i) == 2 and all(isinstance(x, str) for x in i) for i in (*p.dependencies, *p.optional_dependencies))
    for p in plugins
)
check(f"{len(plugins)} installed module(s) carry dependencies as sorted (id, constraint) pairs", well_formed)

check("the capability core.module_dependants 1.0.0 is registered", has_capability("core.module_dependants", version=">=1.0.0,<2.0.0"))
provider = get_capability("core.module_dependants", version=">=1.0.0,<2.0.0", required=False)
check("get_capability returns a provider with the operation dependants", provider is not None and callable(getattr(provider, "dependants", None)))

try:
    md.dependants()
    check("a shell is refused", False)
except md.DependantsRefused as exc:
    check("a shell is refused with a plain sentence that names no module (" + str(exc)[:60] + "...)", not any(p.plugin_id in str(exc) for p in plugins))
except Exception as exc:  # noqa: BLE001 - a probe
    check(f"a shell is refused (unexpected {type(exc).__name__})", False)

from tec_tac import module_state  # noqa: E402

named = {}
for p in plugins:
    for dep_id, _constraint in (*p.dependencies, *p.optional_dependencies):
        named.setdefault(dep_id, []).append(p.plugin_id)
by_id = {p.plugin_id: p for p in plugins}
probed = 0
for dep_id, users in sorted(named.items()):
    target = by_id.get(dep_id)
    if target is None or target.legacy or not module_state.is_enabled(dep_id):
        continue
    namespace = {"md": md}
    exec(compile("def ask():\n    return md.dependants()\n", str(target.root / "runtime_probe.py"), "exec"), namespace)  # noqa: S102 - a probe compiled under the module's own folder
    try:
        answer = namespace["ask"]()
    except Exception as exc:  # noqa: BLE001 - a probe
        check(f"{dep_id}: the caller inside the module folder gets an answer (got {type(exc).__name__})", False)
        continue
    probed += 1
    ids = [r["id"] for r in answer["dependants"]]
    listed_ok = answer["module"] == dep_id and set(answer) == {"module", "dependants", "complete"} and ids == sorted(ids)
    listed_ok = listed_ok and all(set(r) == set(md.ROW_KEYS) for r in answer["dependants"])
    listed_ok = listed_ok and set(ids) == {u for u in users if not by_id[u].legacy}
    check(f"{dep_id}: lists {len(ids)} dependant(s), about itself only", listed_ok)
if not probed:
    print("SKIP no enabled module is named by another module's dependencies on this server")

if "groups" in by_id and "patchmanagement" in by_id and any(i[0] == "groups" for i in (*by_id["patchmanagement"].dependencies, *by_id["patchmanagement"].optional_dependencies)):
    namespace = {"md": md}
    exec(compile("def ask():\n    return md.dependants()\n", str(by_id["groups"].root / "runtime_probe.py"), "exec"), namespace)  # noqa: S102 - a probe
    ids = [r["id"] for r in namespace["ask"]()["dependants"]]
    check("Advanced Patch Management shows up for the Groups caller", "patchmanagement" in ids)
else:
    print("SKIP Groups and a module that names it are not both installed")

print("PASS module dependants runtime 1.17.71" if all(RESULTS) else "FAIL module dependants runtime 1.17.71")
if not all(RESULTS):
    sys.exit(1)
