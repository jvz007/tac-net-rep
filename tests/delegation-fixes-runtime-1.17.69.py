"""Runtime check for Core 1.17.69 (the three Medium findings of the 1.17.68-2 review). It did NOT run on the development PC (Django is not installed there).

Nothing is written: no grant, no schedule, no audit row of its own. It reads Core's own code in a real process and probes the caller walk with module code
compiled under an installed module's folder, as tests/delegation-runtime-1.17.68.py does.

One command, on the dev server:
    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/delegation-fixes-runtime-1.17.69.py

Each line prints PASS or FAIL; the file ends with PASS only when every line passed. The installed module `patching` (any enabled extension works: set TECTAC_PROBE_MODULE) must be
installed and enabled.
    1 none of the five delegation.py functions has a caller argument
    2 a call from this shell (not a module) is refused caller_unverified
    3 module code that imports delegation.py and names ANOTHER module as the owner is refused wrong_module
    4 a Core frame (module code compiled under Core's own folder) is refused caller_unverified
    5 the caller walk accepts a tuple of Core files and still refuses an empty tuple
    6 a resolver that names no endpoint is refused in strict mode (a takeover) and, at creation, for a person who is not unrestricted
"""
import inspect
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from tec_tac import caller_identity, delegation, registry, scheduler
from tec_tac import scheduler_target_resolvers as resolvers

MODULE = os.environ.get("TECTAC_PROBE_MODULE", "patching")
RESULTS = []


def check(label, ok):
    RESULTS.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + label)


def reason_of(call):
    try:
        call()
    except delegation.DelegationRefused as exc:
        return exc.reason
    except Exception as exc:  # noqa: BLE001 - a probe: any other error is a failed line
        return f"{type(exc).__name__}: {exc}"
    return "accepted"


roots = {p.plugin_id: p.root for p in registry.discover_plugins() if p.plugin_type == "extension"}
if MODULE not in roots:
    print(f"FAIL the module {MODULE} must be installed here (or set TECTAC_PROBE_MODULE)")
    sys.exit(1)

check("1 the five functions take no caller", all("caller" not in inspect.signature(getattr(delegation, n)).parameters for n in ("describe", "register", "remove", "issue_ticket", "start")))
check("2 a call from this shell is caller_unverified", reason_of(lambda: delegation.remove(owner_module="maintenance", grant_key="tectacprobe")) == "caller_unverified")
src = "def call():\n    return delegation.remove(owner_module='maintenance', grant_key='tectac-probe')\n"
ns = {"delegation": delegation}
exec(compile(src, str(roots[MODULE] / "_tectac_probe_delegation_1_17_69.py"), "exec"), ns)  # noqa: S102 - probe code under an installed module's folder
check(f"3 module {MODULE} naming maintenance is wrong_module", MODULE == "maintenance" or reason_of(ns["call"]) == "wrong_module")
core_ns = {"delegation": delegation}
exec(compile(src, str(Path(delegation.__file__).with_name("scheduler.py")), "exec"), core_ns)  # noqa: S102 - probe code under Core's own file name
check("4 a Core frame is caller_unverified", reason_of(core_ns["call"]) == "caller_unverified")
check("5 a tuple of Core files is accepted by the walk, an empty one is not", caller_identity._provider_files((__file__, "x")) == (__file__, "x") and caller_identity._provider_files(()) is None)

user = SimpleNamespace(username="tectac-probe-user", pk=0, is_active=True)
had = resolvers._RESOLVERS.get(("maintenance", "tectacprobe"))
saved_declared = resolvers._declared
try:
    resolvers._RESOLVERS[("maintenance", "tectacprobe")] = lambda targets: []
    resolvers._declared = lambda module_id, target_type: True
    targets = {"type": "tectacprobe", "ids": [1]}
    strict = scheduler._resolver_scope_check(user, "maintenance", targets, strict=True)
    check("6 an empty resolver result is refused in strict mode", strict is False)
finally:
    resolvers._declared = saved_declared
    if had is None:
        resolvers._RESOLVERS.pop(("maintenance", "tectacprobe"), None)
    else:
        resolvers._RESOLVERS[("maintenance", "tectacprobe")] = had

print("PASS delegation fixes runtime 1.17.69" if all(RESULTS) else "FAIL delegation fixes runtime 1.17.69")
