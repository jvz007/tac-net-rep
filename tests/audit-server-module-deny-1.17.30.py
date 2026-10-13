#!/usr/bin/env python3
"""1.17.30 regression (AD-34 condition 2): a server module may write a deny row for a person who holds none of its permissions.

Reuses the stub harness of tests/audit-declared-browser-events-1.17.0.py, as tests/audit-declared-owner-rows-1.17.20.py does, with a fake
Tactical operation registry and a fake verified-caller helper (the real helper is pinned by tests/caller-identity-core-provider-1.17.27.py).
Django is not installed on the development PC.

Accepted: action deny from a module whose category is server, with the verified caller being that same module, for a signed-in person
with none of its permissions; the row carries actor_kind human, actor_identity the username and debug_info.actor_authority server-module-deny.
Refused (AuditContractError, nothing written): any other action (add, modify, view, custom:*), category core, premium, test or empty, a
verified caller that is another module, no verified caller, a Core caller, an installer user, an unauthenticated actor, a disabled module and
a legacy module. Service and device actors are unchanged; custom:operation-failed is still refused by record(); a person who holds a module
permission gets the normal row with no actor_authority; the browser paths never take the new path; a caller cannot supply the marker; the
helper is asked with audit.py's own file; docs and contract text name AD-34.
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
assert marker_line in source
H = {"__name__": "audit_harness", "__file__": str(HARNESS)}
exec(compile(source.split(marker_line)[0], "audit-declared-browser-events-1.17.0.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse
audit, ROWS, reset, registry, ROOT, GRANTED = H["audit"], H["ROWS"], H["reset"], H["registry"], H["ROOT"], H["GRANTED"]
ENABLED = H["ENABLED"]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ---- the verified caller, faked: what calling_module_for_core_provider would answer for the code that called audit.record
CALLER = {"value": None}
CALLS = []


def fake_caller(*, provider_file):
    CALLS.append(provider_file)
    return CALLER["value"]


# audit.py imports the helper inside the function (1.17.30 precheck fix), so the fake goes in as the tec_tac.caller_identity module
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


server = spec("server-demo", "server")
other_server = spec("server-other", "server")
core_mod = spec("coremod-demo", "core")
premium = spec("premium-demo", "premium")
test_mod = spec("test-demo", "test")
no_cat = spec("nocat-demo", "")
disabled = spec("serverdis-demo", "server")
legacy = spec("serverleg-demo", "server", plugin_type="legacy", legacy=True)
ENABLED["serverdis-demo"] = False
registry.get_plugins = lambda: (server, other_server, core_mod, premium, test_mod, no_cat, disabled, legacy)


class Role:
    is_superuser = False


class User:
    is_authenticated = True
    is_superuser = False

    def __init__(self, username, installer=False):
        self.username = username
        self.is_installer_user = installer
        self.role = Role()

    def get_and_set_role_cache(self):
        return self.role


class Anonymous:
    is_authenticated = False
    username = ""


person = User("nobody")
installer = User("installer", installer=True)


def write(actor, module="server-demo", action="deny", **extra):
    return audit.record(actor=actor, module_id=module, action=action, object_type="invitation", object_id="i-1", message="x", **extra)


def refused(actor, module="server-demo", action="deny", caller="same", **extra):
    reset()
    CALLER["value"] = who(module) if caller == "same" else caller
    try:
        write(actor, module, action, **extra)
    except audit.AuditContractError as exc:
        must(str(exc), "a plain contract error")
        must(not ROWS, "a refused row writes nothing")
        return
    raise AssertionError(f"accepted {actor!r} {module} {action} caller={caller!r}")


# ---- accepted
reset()
CALLS.clear()
CALLER["value"] = who("server-demo")
result = write(person)
must(result["recorded"] is True and len(ROWS) == 1, result)
info = ROWS[0]["debug_info"]
must(info["actor_authority"] == "server-module-deny" and info["actor_kind"] == "human" and info["actor_identity"] == "nobody", info)
must(ROWS[0]["username"] == "nobody" and ROWS[0]["action"] == "deny", ROWS[0])
must(CALLS and all(Path(c).name == "audit.py" for c in CALLS), CALLS)  # the helper gets audit.py's own file
must(audit.ACTOR_AUTHORITY_SERVER_MODULE_DENY == "server-module-deny", "constant")
reset()
CALLER["value"] = who("server-other")
write(person, module="server-other", action="DENY")  # the action is normalised
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and ROWS[0]["debug_info"]["actor_authority"] == "server-module-deny", ROWS)

# ---- other actions
for action in ("add", "modify", "view", "delete", "run", "custom:made-up", "custom:deny", "approve", "export"):
    refused(person, action=action)
refused(person, action="custom:operation-failed")
try:
    write(person, action="not a valid action")
    raise AssertionError("accepted an invalid action")
except audit.AuditContractError:
    pass

# ---- other categories, and modules that cannot take the path
for module in ("coremod-demo", "premium-demo", "test-demo", "nocat-demo", "serverdis-demo", "serverleg-demo", "unknown-demo"):
    refused(person, module=module)
reset()
CALLER["value"] = who("core")
try:
    write(person, module="core", action="deny")  # module core has no permission surface, so the normal rule applies, never the new path
    must(len(ROWS) == 1 and "actor_authority" not in ROWS[0]["debug_info"], ROWS)
except audit.AuditContractError:
    raise AssertionError("module core keeps its old behaviour") from None

# ---- the verified caller
refused(person, caller=who("server-other"))  # another module's code calls
refused(person, caller=who("premium-demo"))
refused(person, caller=who("coremod-demo"))
refused(person, caller=None)  # no verified caller: a Core frame, a library, a generated frame or an error all answer None
refused(person, caller=who("core"))  # Core is never a module caller
refused(person, caller=SimpleNamespace(module_id="", kind="module", module_version="1"))


def broken(*, provider_file):
    raise RuntimeError("registry down")


_caller_module.calling_module_for_core_provider = broken
refused(person, caller=None)  # a failing helper is a refusal and never raises past the audit contract error
_caller_module.calling_module_for_core_provider = fake_caller

# ---- the person
refused(installer)
refused(Anonymous())

# ---- unchanged paths
reset()
CALLER["value"] = None
svc = audit.service_audit_actor(module_id="server-demo", service="worker")
dev = audit.device_audit_actor(module_id="server-demo", device_id="d-1")
write(svc, action="view")
write(dev, action="view")
must(len(ROWS) == 2 and all("actor_authority" not in row["debug_info"] for row in ROWS), ROWS)
try:
    write(audit.service_audit_actor(module_id="server-other", service="worker"), module="server-demo", action="deny")
    raise AssertionError("a service actor of another module was accepted")
except audit.AuditContractError:
    pass

# a person who holds a module permission gets the normal row, and the new helper is not even asked
reset()
CALLS.clear()
GRANTED.add("server-demo.use")
write(person, action="deny")
write(person, action="view")
must(len(ROWS) == 2 and all("actor_authority" not in row["debug_info"] for row in ROWS), ROWS)
must(not CALLS, "a person with a grant never reaches the caller check")
GRANTED.clear()

# a caller cannot supply the marker
reset()
CALLER["value"] = who("server-demo")
write(person, metadata={"actor_authority": "forged"}, operation_context={"actor_authority": "forged"})
must(ROWS[0]["debug_info"]["actor_authority"] == "server-module-deny", ROWS[0]["debug_info"])
refused(person, action="modify", metadata={"actor_authority": "server-module-deny"})

# ---- the browser paths never take it
reset()
CALLER["value"] = who("server-demo")
for writer, kwargs in (
    (audit.record_browser_declared, {"action": "deny", "object_type": "invitation"}),
):
    try:
        writer(actor=person, module_id="server-demo", **kwargs)
        raise AssertionError("the browser writer accepted a person with no grant")
    except audit.AuditContractError:
        pass
try:
    audit.record_core_refusal(actor=person, module_id="server-demo", object_type="invitation", object_id="i-1", message="x", metadata={})
    raise AssertionError("record_core_refusal accepted a person with no grant")
except audit.AuditContractError:
    pass
must(not ROWS, "the browser writers wrote nothing")
must(audit.can_record_from_browser(person, "server-demo") is False and audit.can_record(person, "server-demo") is False, "browser needs a grant")

# the helper itself never raises
must(audit._server_module_deny_allowed(None, {"id": "server-demo", "category": "server"}, "deny") is False, "no actor")
must(audit._server_module_deny_allowed(person, {"id": "server-demo", "category": "server"}, object()) is False, "an action that is not text")
CALLER["value"] = who("server-demo")
must(audit._server_module_deny_allowed(person, {"id": "server-demo", "category": "server"}, "deny") is True, "the one accepted case")
must(audit._server_module_deny_allowed(person, {"id": "server-demo", "category": "premium"}, "deny") is False, "category")
must(audit._server_module_deny_allowed(person, {"id": "server-demo", "category": "server", "legacy": True}, "deny") is False, "legacy")

# ---- docs and contract text
docs = " ".join((ROOT / "docs/module-audit.md").read_text(encoding="utf-8").split())
section = docs.split("## Deny rows from a server module", 1)[1].split("## Standard action vocabulary", 1)[0]
for word in ("AD-34", "server-module-deny", "category is `server`", "exactly `deny`", "same module", "Core-private", "1.17.30"):
    must(word in section, f"docs section mentions {word}")
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
row = [line for line in contracts.splitlines() if '"purpose": "Record a Tec-Tac module event' in line]
must(len(row) == 1 and "AD-34" in row[0] and "server-module-deny" in row[0] and "category is server" in row[0] and "1.17.30" in row[0], "audit.record purpose")
caller_doc = (ROOT / "docs/caller-identity.md").read_text(encoding="utf-8")
must("AD-34" in caller_doc and "core.audit" in caller_doc and "core.resources" in caller_doc and "AD-31 condition 2" in caller_doc, "docs/caller-identity.md")
must("calling_module_for_core_provider" not in contracts, "the helper is not a contract row")
print("[TEST] PASS audit server module deny 1.17.30")
