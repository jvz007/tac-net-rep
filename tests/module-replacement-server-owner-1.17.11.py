#!/usr/bin/env python3
"""1.17.11 regression: a server module has no Tactical routes, so an honoured server-module replacement joins no owner rule (AD-20 amendment 4).

Builds on the stubs of tests/tactical-operations-1.17.7.py, the way tests/module-replacement-owner-1.17.9.py does. The real
tactical_operations.py and module_replacement.py run against them. Django and Tactical are not installed.

Licensing is a server module that owns Tactical's core/codesign/ route through a named exception. A premium module that replaces
Licensing is honoured as a module replacement, but it does not join that rule.
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
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, PLUGINS, ENABLED, declare, refused, fresh, must = (G[k] for k in ("ops", "PLUGINS", "ENABLED", "declare", "refused", "fresh", "must"))


def plugin(name, category, **extra):
    base = dict(plugin_id=name, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False, audit_events=(),
                category=category, replaces="", capabilities=(), capabilities_declared=False)
    base.update(extra)
    PLUGINS[name] = SimpleNamespace(**base)


for name in ("agent-management", "remote-background", "take-control", "scriptexecution", "audit", "debug", "globalsettings",
             "scriptmanager", "automation", "alerts", "checks"):
    plugin(name, "core")
plugin("patching", "core", capabilities_declared=True)
plugin("patchmanagement", "premium", replaces="patching", capabilities_declared=True)
PLUGINS["licensing"].category = "server"
PLUGINS["licensing"].capabilities_declared = True
plugin("altlicense", "premium", replaces="licensing", capabilities_declared=True)

FLAG = ["can_code_sign"]
NOSCOPE = dict(scope=[], body_fields=[], audit={"action": "view", "object_type": "agent", "audit_fields": []})


def spec(module, op, route_text, method, over):
    out = dict(id=op, module_id=module, method=method, route=route_text, permissions=FLAG, **NOSCOPE)
    out.update(over)
    return out


def ok(module, op, route_text, method="GET", **over):
    return declare(**spec(module, op, route_text, method, over))


def no(module, op, route_text, method="GET", **over):
    return refused(**spec(module, op, route_text, method, over))


mr = sys.modules["tec_tac.module_replacement"]

# ------------------------------------------------------------------------------------------ honoured, but no owner rule
fresh()
ENABLED.update(licensing=False, altlicense=True, patching=False, patchmanagement=True)
must(mr.honoured_replacement("altlicense") == "licensing", "honoured as a module replacement (capabilities, hard dependencies)")
must(ops._honoured_pairs() == {"patchmanagement": "patching"}, ops._honoured_pairs())  # the core pair is there, the server pair is not
must("altlicense" not in ops._honoured_pairs(), "a server module's replacement joins no owner rule")
must(ops._owners_for_rule(("core", "codesign")) == {"licensing"}, "Licensing's named exception is unchanged")
msg = no("altlicense", "cs", "core/codesign/", "PUT")
must("not a core module" in msg or "does not own" in msg, msg)
must(no("altlicense", "agents", "agents/{agent_id:agent}/reboot/", "POST", permissions=["can_reboot_agents"]), "and no other rule")
# the core replacement next to it keeps working
ok("patchmanagement", "wu", "winupdate/", "GET", permissions=["can_list_agents"])
# Licensing itself, enabled, keeps its route
fresh()
ENABLED.update(licensing=True, altlicense=False)
ok("licensing", "cs", "core/codesign/", "PUT", module_permission="licensing.manage")
# a server module replaced and then both enabled: nobody is honoured
fresh()
ENABLED.update(licensing=True, altlicense=True)
must(mr.honoured_replacement("altlicense") is None and "altlicense" not in ops._honoured_pairs(), "both enabled: not honoured")
no("altlicense", "cs2", "core/codesign/", "PUT")

print("[TEST] PASS server module replacement owner table 1.17.11")
