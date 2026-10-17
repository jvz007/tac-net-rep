#!/usr/bin/env python3
"""1.17.51 pinning test: the audit row for an event-log export by a person who holds only List checks (request 'From checks 0.15.0 review round 0').

No behaviour changed. Core has accepted this row since 1.17.20 (_declared_owner_row_allowed, actor_authority 'declared-operation-owner'): a
signed-in person with none of the module's permissions is accepted when the module declared a Tactical operation whose audit action equals
the row's action, the operation needs no module_permission, and the person holds every Tactical flag of that operation. Checks therefore
declares its event-log read as a GET operation with audit action 'export' and permissions ['can_list_checks'], and writes its export row
from its backend. This test pins exactly that case, and the documentation of it (docs/module-audit.md, the audit.record contract row, the
release notes).

Reuses the stub harness of tests/audit-declared-owner-rows-1.17.20.py. Django is not installed on the development PC.

Accepted: a person with only can_list_checks and no module grant, a module that declared a GET operation with audit action export and no
module_permission: audit.record(action='export', object_type='agent') is marked declared-operation-owner.
Refused (AuditContractError): the same person without the flag, a module that declared no such operation, an operation with module_permission
set, an installer user, and any action other than the declared one.
"""
from __future__ import annotations

import re
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT_DIR = HERE.parent
HARNESS = HERE / "audit-declared-browser-events-1.17.0.py"
source = HARNESS.read_text(encoding="utf-8")
marker_line = "# === Q34: denials reach the audit log as Core-owned rows"
H = {"__name__": "audit_harness", "__file__": str(HARNESS)}
exec(compile(source.split(marker_line)[0], "audit-declared-browser-events-1.17.0.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse
audit, ROWS, reset, registry, ROOT, ENABLED, rbac_stub = H["audit"], H["ROWS"], H["reset"], H["registry"], H["ROOT"], H["ENABLED"], H["rbac_stub"]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


OPS = {}


def operation(op_id, action, flags, module_permission=None, method="GET"):
    return {"id": op_id, "method": method, "audit": {"action": action, "object_type": "agent"}, "permissions": list(flags),
            "module_permission": module_permission}


fake_ops = types.ModuleType("tec_tac.tactical_operations")
fake_ops.list_operations = lambda module_id=None: [dict(row) for row in OPS.get(module_id, [])]
sys.modules["tec_tac.tactical_operations"] = fake_ops


def tactical_permission_flags(user, flags):
    names = list(flags)
    denied = {name: False for name in names}
    if not getattr(user, "is_authenticated", False) or getattr(user, "is_installer_user", False):
        return denied
    role = getattr(user, "role", None)
    return denied if role is None else {name: bool(getattr(role, name, False)) for name in names}


rbac_stub.tactical_permission_flags = tactical_permission_flags


def spec(plugin_id, **kwargs):
    return registry.PluginSpec(plugin_id=plugin_id, plugin_type="extension", root=ROOT, version="0.15.0", **kwargs)


def perm(plugin_id):
    return (("Use", (f"{plugin_id}.use", f"{plugin_id}.edit")),)


checks = spec("checks-demo", permission_groups=perm("checks-demo"))
no_declaration = spec("nodecl-demo", permission_groups=perm("nodecl-demo"))
gated = spec("gated-demo", permission_groups=perm("gated-demo"))
registry.get_plugins = lambda: (checks, no_declaration, gated)
ENABLED.clear()
OPS["checks-demo"] = [operation("event-log", "export", ["can_list_checks"])]
OPS["nodecl-demo"] = [operation("event-log", "view", ["can_list_checks"])]  # declares a read, but not an export action
OPS["gated-demo"] = [operation("event-log", "export", ["can_list_checks"], module_permission="gated-demo.export")]


class Role:
    is_superuser = False

    def __init__(self, **flags):
        for name, value in flags.items():
            setattr(self, name, value)


class User:
    is_authenticated = True
    is_superuser = False

    def __init__(self, username, installer=False, **flags):
        self.username, self.is_installer_user, self.role = username, installer, Role(**flags)

    def get_and_set_role_cache(self):
        return self.role


lister = User("lister", can_list_checks=True)   # only List checks, no grant of the module
bare = User("bare")
installer = User("installer", installer=True, can_list_checks=True)


def write(actor, module="checks-demo", action="export"):
    return audit.record(actor=actor, module_id=module, action=action, object_type="agent", object_id="a-1", message="Event log exported.")


def refused(actor, module="checks-demo", action="export"):
    reset()
    try:
        write(actor, module, action)
    except audit.AuditContractError as exc:
        must(str(exc), "a plain contract error")
        must(not ROWS, "a refused row writes nothing")
        return
    raise AssertionError(f"accepted {actor.username} {module} {action}")


# accepted
reset()
result = write(lister)
must(result["recorded"] is True and len(ROWS) == 1 and ROWS[0]["action"] == "export", result)
info = ROWS[0]["debug_info"]
must(info["actor_authority"] == "declared-operation-owner" and info["actor_kind"] == "human" and info["actor_identity"] == "lister", info)
must(ROWS[0]["object_type"] == "agent" and ROWS[0]["username"] == "lister", ROWS[0])
reset()
write(lister, action="EXPORT")
must(len(ROWS) == 1 and ROWS[0]["action"] == "export", "the action is normalised")

# refused
refused(bare)                                    # the same person without the flag
refused(lister, module="nodecl-demo")            # a module that declared no export operation
refused(lister, module="gated-demo")             # an operation with a module_permission
refused(installer)                               # an installer user
for other in ("view", "run", "delete", "modify", "custom:event-log-export"):
    refused(lister, action=other)                # any action other than the declared one

# Core does not loosen the rule: a module cannot claim a flag it never declared
OPS["checks-demo"] = [operation("event-log", "export", ["can_list_checks"])]
refused(User("scripter", can_run_scripts=True))
must(audit._declared_owner_row_allowed(lister, {"id": "checks-demo", "legacy": False}, "export") is True)
must(audit._declared_owner_row_allowed(lister, {"id": "nodecl-demo", "legacy": False}, "export") is False)

# the documentation names the case
doc = " ".join((ROOT_DIR / "docs" / "module-audit.md").read_text(encoding="utf-8").split())
for needle in ("Worked example: an export by a person who holds only List checks", "can_list_checks", "audit action `export`", "declared-operation-owner",
               "no module_permission", "requires.framework", ">=1.17.51"):
    must(needle in doc, f"docs/module-audit.md names {needle!r}")
contracts = " ".join((ROOT_DIR / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8").split())
must("Worked example (1.17.51, no behaviour change)" in contracts and "can_list_checks" in contracts, "the audit.record row has the worked example")
notes = " ".join((ROOT_DIR / "RELEASE_NOTES_1.17.51-1.md").read_text(encoding="utf-8").split())
must("event-log export" in notes and "requires.framework >=1.17.51" in notes and "No Core behaviour changed" in notes, "the release notes name it")
print("audit declared owner export 1.17.51 ok")
