#!/usr/bin/env python3
"""1.17.95 regression (AD-34 amendment, Johan 29 October 2026: denied entries are audited): a core module may write a deny row too.

Extends the harness of tests/audit-server-module-deny-1.17.30.py (fake verified-caller helper, no Django).
Accepted: a core-category module whose verified caller is that same module, action deny, a signed-in person with none of its permissions; the row
carries actor_kind human, the username and debug_info.actor_authority server-module-deny (the constant is kept so exports stay valid).
Refused (AuditContractError, nothing written): add, modify, run, view and custom:* from a core module; premium, test and empty categories and module
core itself; a verified caller that is another module or None; an installer user and an unauthenticated actor; a disabled and a legacy module.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "audit-declared-browser-events-1.17.0.py"
source = HARNESS.read_text(encoding="utf-8")
marker_line = "# === Q34: denials reach the audit log as Core-owned rows"
H = {"__name__": "audit_harness", "__file__": str(HARNESS)}
exec(compile(source.split(marker_line)[0], "audit-declared-browser-events-1.17.0.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse
audit, ROWS, reset, registry, ROOT, GRANTED = H["audit"], H["ROWS"], H["reset"], H["registry"], H["ROOT"], H["GRANTED"]
ENABLED = H["ENABLED"]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


CALLER = {"value": None}
CALLS = []


def fake_caller(*, provider_file):
    CALLS.append(provider_file)
    return CALLER["value"]


_caller_module = types.ModuleType("tec_tac.caller_identity")
_caller_module.calling_module_for_core_provider = fake_caller
sys.modules["tec_tac.caller_identity"] = _caller_module


def who(module_id):
    return SimpleNamespace(module_id=module_id, kind="module", module_version="1.0.0")


def spec(plugin_id, category, **kwargs):
    return registry.PluginSpec(
        plugin_id=plugin_id, plugin_type=kwargs.pop("plugin_type", "extension"), root=ROOT, version="2.0.0", category=category,
        permission_groups=((("Use", (f"{plugin_id}.use",)),)), **kwargs,
    )


core_mod = spec("coremod-demo", "core")
core_other = spec("coremod-other", "core")
premium = spec("premium-demo", "premium")
test_mod = spec("test-demo", "test")
no_cat = spec("nocat-demo", "")
disabled = spec("coredis-demo", "core")
legacy = spec("coreleg-demo", "core", plugin_type="legacy", legacy=True)
ENABLED["coredis-demo"] = False
registry.get_plugins = lambda: (core_mod, core_other, premium, test_mod, no_cat, disabled, legacy)


class Role:
    is_superuser = False


class User:
    is_authenticated = True
    is_superuser = False

    def __init__(self, username, installer=False):
        self.username, self.is_installer_user, self.role = username, installer, Role()

    def get_and_set_role_cache(self):
        return self.role


class Anonymous:
    is_authenticated = False
    username = ""


person, installer = User("nobody"), User("installer", installer=True)


def write(actor, module="coremod-demo", action="deny", **extra):
    return audit.record(actor=actor, module_id=module, action=action, object_type="endpoint-message", object_id="m-1", message="x", **extra)


def refused(actor, module="coremod-demo", action="deny", caller="same"):
    reset()
    CALLER["value"] = who(module) if caller == "same" else caller
    try:
        write(actor, module, action)
    except audit.AuditContractError:
        must(not ROWS, "a refused row writes nothing")
        return
    raise AssertionError(f"accepted {actor!r} {module} {action} caller={caller!r}")


# accepted
reset()
CALLS.clear()
CALLER["value"] = who("coremod-demo")
result = write(person)
must(result["recorded"] is True and len(ROWS) == 1, result)
info = ROWS[0]["debug_info"]
must(info["actor_authority"] == "server-module-deny" and info["actor_kind"] == "human" and info["actor_identity"] == "nobody", info)
must(ROWS[0]["action"] == "deny" and ROWS[0]["username"] == "nobody" and info["module_id"] == "coremod-demo", ROWS[0])
must(CALLS and all(Path(c).name == "audit.py" for c in CALLS), CALLS)
reset()
CALLER["value"] = who("coremod-other")
write(person, module="coremod-other", action="DENY")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", ROWS)

# other actions from a core module
for action in ("add", "modify", "run", "view", "delete", "export", "custom:made-up", "custom:deny", "custom:operation-failed"):
    refused(person, action=action)

# other categories and module core
for module in ("premium-demo", "test-demo", "nocat-demo", "coredis-demo", "coreleg-demo", "unknown-demo"):
    refused(person, module=module)
reset()
CALLER["value"] = who("core")
try:
    write(person, module="core")
    must(len(ROWS) == 1 and "actor_authority" not in ROWS[0]["debug_info"], ROWS)  # module core keeps its old behaviour
except audit.AuditContractError:
    raise AssertionError("module core keeps its old behaviour") from None

# the verified caller
refused(person, caller=who("coremod-other"))
refused(person, caller=who("premium-demo"))
refused(person, caller=None)
refused(person, caller=who("core"))

# the person
refused(installer)
refused(Anonymous())

# service and device actors are unchanged, a person with a grant gets the normal row without asking the helper
reset()
CALLER["value"] = None
write(audit.service_audit_actor(module_id="coremod-demo", service="worker"), action="view")
must(len(ROWS) == 1 and "actor_authority" not in ROWS[0]["debug_info"], ROWS)
reset()
CALLS.clear()
GRANTED.add("coremod-demo.use")
write(person)
must(len(ROWS) == 1 and "actor_authority" not in ROWS[0]["debug_info"] and not CALLS, ROWS)
GRANTED.clear()

# the old private name stays an alias, and the helper never raises
must(audit._server_module_deny_allowed is audit._module_deny_allowed, "alias kept")
CALLER["value"] = who("coremod-demo")
must(audit._module_deny_allowed(None, {"id": "coremod-demo", "category": "core"}, "deny") is False, "no actor")
must(audit._module_deny_allowed(person, {"id": "coremod-demo", "category": "core"}, "deny") is True, "the accepted case")
must(audit._module_deny_allowed(person, {"id": "coremod-demo", "category": "premium"}, "deny") is False, "category")

docs = " ".join((ROOT / "docs/module-audit.md").read_text(encoding="utf-8").split())
section = docs.split("## Deny rows from a server module", 1)[1].split("## Verified module caller", 1)[0]
for word in ("AD-34", "`core`", "1.17.95", "server-module-deny"):
    must(word in section, f"docs mention {word}")
print("[TEST] PASS audit core module deny 1.17.95")
