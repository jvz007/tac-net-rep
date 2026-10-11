#!/usr/bin/env python3
"""1.17.20 regression: a module's backend audit row is accepted for a person who holds none of its permissions, when the module is the
declaring owner of the action (requests/core.md "Core 1.17.20"; globalsettings 0.3.0, scriptmanager 0.4.2).

Reuses the stub harness of tests/audit-declared-browser-events-1.17.0.py (as tests/audit-private-operation-writer-1.17.8.py does) with a
fake Tactical operation registry and a fake ``tactical_permission_flags``. Django is not installed on the development PC.

Covered: a person with only can_run_scripts gets a ``run`` row accepted for a module that declared a ``run`` operation needing that flag,
and the row carries actor_authority; a ``deny`` row is accepted for a person with no flags when the module owns an operation; refused: an
outcome row for a person without the operation's flag, an action no operation declares, an operation that has a module_permission, an
operation with no Tactical flag, a module with no operation, an installer user, an unauthenticated actor, module ``core``, a legacy
module, a disabled module, a failing registry; a caller cannot supply actor_authority through metadata or operation_context; a row for a
person who holds a module grant is unchanged; service and device actors are unchanged; the browser path still refuses.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "audit-declared-browser-events-1.17.0.py"
source = HARNESS.read_text(encoding="utf-8")
marker_line = "# === Q34: denials reach the audit log as Core-owned rows"
assert marker_line in source
H = {"__name__": "audit_harness", "__file__": str(HARNESS)}
exec(compile(source.split(marker_line)[0], "audit-declared-browser-events-1.17.0.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse
audit, ROWS, reset, registry, ROOT, GRANTED = H["audit"], H["ROWS"], H["reset"], H["registry"], H["ROOT"], H["GRANTED"]
ENABLED, rbac_stub = H["ENABLED"], H["rbac_stub"]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ---- a fake operation registry and Tactical flag check
OPS = {}
REGISTRY_BOOM = {"on": False}


def op(op_id, action, flags=("can_run_scripts",), module_permission=None):
    return {"id": op_id, "audit": {"action": action, "object_type": "script"}, "permissions": list(flags), "module_permission": module_permission}


def list_operations(module_id=None):
    if REGISTRY_BOOM["on"]:
        raise RuntimeError("registry down")
    return [dict(row) for row in OPS.get(module_id, [])]


fake_ops = types.ModuleType("tec_tac.tactical_operations")
fake_ops.list_operations = list_operations
sys.modules["tec_tac.tactical_operations"] = fake_ops
FLAG_CALLS = []


def tactical_permission_flags(user, flags):
    FLAG_CALLS.append((getattr(user, "username", None), tuple(flags)))
    names = list(flags)
    denied = {name: False for name in names}
    if not getattr(user, "is_authenticated", False) or getattr(user, "is_installer_user", False):
        return denied
    role = getattr(user, "role", None)
    if role is None:
        return denied
    return {name: bool(getattr(role, name, False)) for name in names}


rbac_stub.tactical_permission_flags = tactical_permission_flags


def spec(plugin_id, **kwargs):
    return registry.PluginSpec(plugin_id=plugin_id, plugin_type=kwargs.pop("plugin_type", "extension"), root=ROOT, version="2.0.0", **kwargs)


def perm(plugin_id):
    return (("Use", (f"{plugin_id}.use",)),)


owner = spec("owner-demo", permission_groups=perm("owner-demo"))
no_ops = spec("noops-demo", permission_groups=perm("noops-demo"))
perm_op = spec("permop-demo", permission_groups=perm("permop-demo"))
no_flag_op = spec("noflag-demo", permission_groups=perm("noflag-demo"))
legacy_owner = spec("legacyowner-demo", plugin_type="legacy", legacy=True, permission_groups=perm("legacyowner-demo"))
disabled_owner = spec("disabledowner-demo", permission_groups=perm("disabledowner-demo"))
ENABLED["disabledowner-demo"] = False
registry.get_plugins = lambda: (owner, no_ops, perm_op, no_flag_op, legacy_owner, disabled_owner)
OPS["owner-demo"] = [op("run-script", "run"), op("export-csv", "export", flags=("can_list_scripts", "can_view_scripts")), op("noop", "view", flags=())]
OPS["permop-demo"] = [op("edit", "modify", module_permission="permop-demo.edit")]
OPS["noflag-demo"] = [op("view-thing", "view", flags=())]
OPS["legacyowner-demo"] = [op("run-script", "run")]
OPS["disabledowner-demo"] = [op("run-script", "run")]
OPS["core"] = [op("run-script", "run")]


class Role:
    def __init__(self, **flags):
        self.is_superuser = False
        for name, value in flags.items():
            setattr(self, name, value)


class User:
    is_authenticated = True
    is_superuser = False

    def __init__(self, username, installer=False, **flags):
        self.username = username
        self.is_installer_user = installer
        self.role = Role(**flags)

    def get_and_set_role_cache(self):
        return self.role


class Anonymous:
    is_authenticated = False
    username = ""


runner = User("runner", can_run_scripts=True)
bare = User("bare")
lister = User("lister", can_list_scripts=True)  # only one of the two export flags
both = User("both", can_list_scripts=True, can_view_scripts=True)
installer = User("installer", installer=True, can_run_scripts=True)


def write(actor, module="owner-demo", action="run", **extra):
    return audit.record(actor=actor, module_id=module, action=action, object_type="script", object_id="s-1", message="x", **extra)


def refused(actor, module="owner-demo", action="run", **extra):
    reset()
    try:
        write(actor, module, action, **extra)
    except audit.AuditContractError as exc:
        must(str(exc), "a plain contract error")
        must(not ROWS, "a refused row writes nothing")
        return
    raise AssertionError(f"accepted {actor!r} {module} {action}")


# ---- (b) an outcome row on the operation's own audit action and Tactical flags
reset()
result = write(runner)
must(result["recorded"] is True and len(ROWS) == 1, result)
info = ROWS[0]["debug_info"]
must(info["actor_authority"] == "declared-operation-owner" and info["actor_kind"] == "human" and info["actor_identity"] == "runner", info)
must(ROWS[0]["username"] == "runner" and ROWS[0]["action"] == "run", ROWS[0])
reset()
write(both, action="export")  # an operation with two flags, the person holds both
must(len(ROWS) == 1 and ROWS[0]["debug_info"]["actor_authority"] == "declared-operation-owner", ROWS)
refused(lister, action="export")  # holds only one of the two flags
refused(bare)  # no flag at all
refused(runner, action="export")  # holds a flag, but not that operation's flags
refused(runner, action="delete")  # an action no operation declares
refused(runner, action="custom:made-up")
refused(runner, action="view")  # declared, but the operation has no Tactical flag to rest on

# ---- (a) deny
reset()
write(bare, action="deny")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and ROWS[0]["debug_info"]["actor_authority"] == "declared-operation-owner", ROWS)
reset()
write(lister, action="DENY")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", ROWS)

# ---- (c) everything else stays refused
refused(bare, module="noops-demo", action="deny")  # a module with no declared operation
refused(runner, module="noops-demo", action="run")
refused(bare, module="permop-demo", action="modify")  # the operation needs a module permission
refused(runner, module="permop-demo", action="modify")
reset()
write(bare, module="permop-demo", action="deny")  # deny still follows the owner rule
must(len(ROWS) == 1, ROWS)
refused(runner, module="noflag-demo", action="view")
refused(installer, action="run")
refused(installer, action="deny")
refused(Anonymous(), action="run")
refused(Anonymous(), action="deny")
refused(runner, module="legacyowner-demo", action="run")
refused(bare, module="legacyowner-demo", action="deny")
refused(runner, module="disabledowner-demo", action="run")
refused(bare, module="disabledowner-demo", action="deny")
refused(runner, module="unknown-demo", action="run")

# module core: Core's own writer path keeps working (no permission surface), and the new rule never widens it for a non-person
reset()
write(bare, module="core", action="view")  # core has no permission groups, so this was always accepted
must(len(ROWS) == 1 and "actor_authority" not in ROWS[0]["debug_info"], ROWS)
must(audit._declared_owner_row_allowed(runner, {"id": "core", "legacy": False}, "run") is False, "core is never a declaring owner")

# a failing registry or flag check fails closed
REGISTRY_BOOM["on"] = True
refused(runner)
refused(bare, action="deny")
REGISTRY_BOOM["on"] = False
real_flags = rbac_stub.tactical_permission_flags
rbac_stub.tactical_permission_flags = lambda user, flags: (_ for _ in ()).throw(RuntimeError("down"))
refused(runner)
rbac_stub.tactical_permission_flags = real_flags

# an invalid action keeps its own refusal
reset()
try:
    write(runner, action="not a valid action")
    raise AssertionError("accepted an invalid action")
except audit.AuditContractError:
    pass

# ---- a caller cannot supply or fake actor_authority
reset()
write(runner, metadata={"actor_authority": "declared-operation-owner"})
must(ROWS[0]["debug_info"]["metadata"] == {"actor_authority": "declared-operation-owner"}, "kept as metadata only")
must(ROWS[0]["debug_info"]["actor_authority"] == "declared-operation-owner", "Core's own marker is present")
refused(bare, metadata={"actor_authority": "declared-operation-owner"})
refused(bare, action="modify", operation_context={"actor_authority": "declared-operation-owner"})
reset()
write(runner, operation_context={"actor_authority": "forged"})
must(ROWS[0]["debug_info"]["actor_authority"] == "declared-operation-owner", "an operation_context key cannot replace Core's marker")
# a person who holds a module grant is unchanged: no actor_authority, even for a metadata key of that name
reset()
GRANTED.add("owner-demo.use")
write(runner, metadata={"actor_authority": "forged"})
must("actor_authority" not in ROWS[0]["debug_info"], ROWS[0]["debug_info"])
write(bare, action="view")
must("actor_authority" not in ROWS[1]["debug_info"], "a grant holder needs no declared-owner rule")
GRANTED.clear()

# ---- service and device actors are unchanged
reset()
svc = audit.service_audit_actor(module_id="owner-demo", service="worker")
dev = audit.device_audit_actor(module_id="owner-demo", device_id="d-1")
write(svc, action="view")
write(dev, action="view")
must(len(ROWS) == 2 and all("actor_authority" not in row["debug_info"] for row in ROWS), ROWS)
try:
    write(audit.service_audit_actor(module_id="noops-demo", service="worker"), action="view")
    raise AssertionError("a service actor of another module was accepted")
except audit.AuditContractError:
    pass

# ---- the browser path is unchanged
must(audit.can_record_from_browser(runner, "owner-demo") is False and audit.can_record(runner, "owner-demo") is False, "browser needs a grant")
must(audit.declared_browser_event(runner, "owner-demo", "run", "script") is False, "no declared browser event for a permissioned module")
reset()
for writer in (audit.record_browser_declared,):
    try:
        writer(actor=runner, module_id="owner-demo", action="run", object_type="script")
        raise AssertionError("the browser writer accepted a person with no grant")
    except audit.AuditContractError:
        pass
try:
    audit.record_core_refusal(actor=bare, module_id="owner-demo", object_type="script", object_id="s-1", message="x", metadata={})
    raise AssertionError("record_core_refusal accepted a person with no grant")
except audit.AuditContractError:
    pass
must(not ROWS, "the browser writers wrote nothing")

# ---- docs and contract text
docs = " ".join((ROOT / "docs/module-audit.md").read_text(encoding="utf-8").split())
must("declaring owner" in docs and "declared-operation-owner" in docs and "browser path" in docs and "1.17.20" in docs, "docs section")
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
row = [line for line in contracts.splitlines() if '"purpose": "Record a Tec-Tac module event' in line]
must(len(row) == 1 and "declaring owner" in row[0] and "declared-operation-owner" in row[0], "audit.record purpose")
print("[TEST] PASS audit declared owner rows 1.17.20")
