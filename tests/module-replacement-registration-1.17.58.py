#!/usr/bin/env python3
"""1.17.58 regression: Advanced Patch Management's four operations register under its own id while its replacement is honoured (AD-20).

Request of patchmanagement 0.11.0, answered with a test and a statement in docs/module-replacement.md. Covered:
- a premium module with replaces = "patching" registers scan, install, set-update-action and reset-patch-policy on the winupdate/ and
  automation/patchpolicy/ routes while Core honours the replacement;
- the same four registrations are refused with TacticalOperationRegistrationError, never another exception, and leave nothing registered,
  while Windows Patching is enabled (and while the replacement is disabled);
- a refused registration is never retried: Core decides at the moment register_tactical_operation is called, from the owner table and the
  live module state, so a later change of state does not register what ready() was refused;
- the run is under the replacement's own module id, and a registration after the state changes works again.

Uses the stubs of tests/tactical-operations-1.17.7.py, as tests/module-replacement-owner-1.17.9.py does. Django is not installed.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)  # noqa: S102 - test-only reuse of the 1.17.7 stubs
ops, PLUGINS, ENABLED, declare, fresh, must = (G[k] for k in ("ops", "PLUGINS", "ENABLED", "declare", "fresh", "must"))
run, route, CALLS, ROWS, AGENT = (G[k] for k in ("run", "route", "CALLS", "ROWS", "AGENT"))


def plugin(name, category, **extra):
    base = dict(plugin_id=name, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False, audit_events=(),
                category=category, replaces="", capabilities=(), capabilities_declared=False)
    base.update(extra)
    PLUGINS[name] = SimpleNamespace(**base)


plugin("patching", "core", capabilities_declared=True)
plugin("patchmanagement", "premium", replaces="patching", capabilities_declared=True)


def state(patching, patchmanagement):
    ENABLED.update(patching=patching, patchmanagement=patchmanagement)


FLAG = ["can_reboot_agents"]
AGENT_SCOPE = [{"type": "agent", "source": "path:agent_id"}]
OPERATIONS = {
    "scan": dict(method="POST", route="winupdate/{agent_id:agent}/scan/", scope=AGENT_SCOPE, body_fields=[],
                 audit={"action": "run", "object_type": "agent", "audit_fields": []}),
    "install": dict(method="POST", route="winupdate/{agent_id:agent}/install/", scope=AGENT_SCOPE, body_fields=[],
                    audit={"action": "run", "object_type": "agent", "audit_fields": []}),
    "set-update-action": dict(method="PUT", route="winupdate/{update_id:int}/", scope=[], body_fields=["action"],
                              audit={"action": "modify", "object_type": "windows_update", "object_param": "update_id", "audit_fields": ["action"]}),
    "reset-patch-policy": dict(method="POST", route="automation/patchpolicy/reset/", scope=[], body_fields=["client", "site"],
                               audit={"action": "modify", "object_type": "patch_policy", "audit_fields": []}),
}


def register_all():
    return {name: declare(id=name, module_id="patchmanagement", permissions=FLAG, **spec) for name, spec in OPERATIONS.items()}


def refused_all(label):
    for name, spec in OPERATIONS.items():
        try:
            declare(id=name, module_id="patchmanagement", permissions=FLAG, **spec)
        except ops.TacticalOperationRegistrationError as exc:
            must(isinstance(exc, ValueError), "a ValueError subclass, as every registration refusal is")
            continue
        raise AssertionError(f"{name} was accepted ({label})")
    must(ops.list_operations("patchmanagement") == [], f"nothing left registered ({label})")


# (1) honoured: Windows Patching disabled, the replacement enabled
fresh()
state(patching=False, patchmanagement=True)
made = register_all()
must(set(made) == set(OPERATIONS) and all(op.module_id == "patchmanagement" for op in made.values()), made)
must(sorted(row["id"] for row in ops.list_operations("patchmanagement")) == sorted(OPERATIONS), ops.list_operations("patchmanagement"))
must(register_all() == made, "registering the same declaration again is idempotent")
print("       honoured: scan, install, set-update-action and reset-patch-policy register under patchmanagement")

# (2) Windows Patching is enabled: a clean refusal, nothing left behind
for flags, label in (((True, True), "both enabled"), ((True, False), "only Windows Patching enabled"), ((False, False), "both disabled")):
    fresh()
    state(*flags)
    refused_all(label)
print("       not honoured: each of the four is refused with TacticalOperationRegistrationError and nothing stays registered")

# (3) a refused registration is not retried; Core decides at the moment of the call from the live state
fresh()
state(patching=True, patchmanagement=True)  # the first start: the enable job has not finished switching
refused_all("first start")
state(patching=False, patchmanagement=True)  # the switch completes afterwards
must(ops.list_operations("patchmanagement") == [], "Core does not retry a refused registration when the state changes")
must(sorted(made_again := register_all()) == sorted(OPERATIONS), made_again)  # the next ready() (a reloaded worker) registers them
print("       a refused registration is not retried; the next ready() after the switch registers them")

# (4) the registered operation runs under the replacement's id while honoured, and stops running when it is not
fresh()
state(patching=False, patchmanagement=True)
register_all()
route(f"/winupdate/{AGENT}/scan/")
must(run(module="patchmanagement", operation="scan", params={"agent_id": AGENT}).status == 200 and len(CALLS) == 1, "runs")
must(ROWS and ROWS[-1]["debug_info"]["module_id"] == "patchmanagement", ROWS[-1:])
print("       the run is recorded under patchmanagement's own module id")
print("[TEST] PASS module replacement registration 1.17.58")
