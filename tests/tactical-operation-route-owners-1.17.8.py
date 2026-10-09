#!/usr/bin/env python3
"""1.17.8 regression: Core's route-level owner table for Tactical operations (held Medium from the 1.17.7 review).

Builds on the stubs of tests/tactical-operations-1.17.7.py (the stub section is executed from that file, so the two
cannot drift). The real tactical_operations.py runs against them. Django and Tactical are not installed on the PC.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index("fresh()\nmust(ops.list_operations() == []")
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, PLUGINS, declare, refused, fresh, must = (G[k] for k in ("ops", "PLUGINS", "declare", "refused", "fresh", "must"))

for name in ("agent-management", "remote-background", "take-control", "scriptexecution", "endpoints", "audit", "debug", "globalsettings",
             "scriptmanager", "automation", "patching", "alerts"):
    PLUGINS[name] = SimpleNamespace(plugin_id=name, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False,
                                    audit_events=(), category="core")
PLUGINS["licensing"].category = "server"  # a server module, as in modules/catalog.toml

FLAG = ["can_reboot_agents"]
NOSCOPE = dict(scope=[], body_fields=[], audit={"action": "view", "object_type": "agent", "audit_fields": []})


def spec(module, op, route, method, over):
    out = dict(id=op, module_id=module, method=method, route=route, permissions=FLAG, **NOSCOPE)
    out.update(over)
    return out


def ok(module, op, route, method="GET", **over):
    return declare(**spec(module, op, route, method, over))


def no(module, op, route, method="GET", **over):
    return refused(**spec(module, op, route, method, over))


fresh()
# ---- clients/ is Core's (AD-11), bar the Agent Management deployments
for route in ("clients/{id:int}/", "clients/sites/", "clients/", "clients/sites/{id:int}/"):
    for method in ("GET", "POST"):
        msg = no("agent-management", "cl", route, method)
        must("Core's own" in msg, msg)
    no("agents", "cl", route)
no("endpoints", "cl", "clients/")
ok("agent-management", "dep-list", "clients/deployments/")
ok("agent-management", "dep-one", "clients/deployments/{id:int}/")
ok("agent-management", "dep-del", "clients/deployments/{id:int}/", "DELETE")
ok("agent-management", "dep-deploy", "clients/{uid}/deploy/")
no("agents", "dep-agents", "clients/deployments/{id:int}/", "PUT")
no("agent-management", "dep-sub", "clients/{uid}/other/")  # only deploy is homed there

# ---- core/codesign is Licensing's alone (AD-16); the rest of core/ is explicit per prefix
fresh()
cs = dict(permissions=["can_code_sign"])
for mod in ("reportmanager", "globalsettings", "scriptmanager", "premiumdemo", "agents"):
    no(mod, "cs", "core/codesign/", "PUT", **cs)
ok("licensing", "cs", "core/codesign/", "PUT", **cs)
no("licensing", "set", "core/settings/")
ok("globalsettings", "ver", "core/version/")
for prefix in ("settings", "customfields", "keystore", "urlaction", "emailtest", "smstest", "clearcache", "servermaintenance", "webtermperms"):
    ok("globalsettings", prefix, f"core/{prefix}/")
    no("reportmanager", "x" + prefix, f"core/{prefix}/x/")
ok("reportmanager", "sch", "core/schedules/")
no("globalsettings", "sch", "core/schedules/", "POST")
ok("scriptmanager", "ssv", "core/serverscript/test/", "POST")
no("globalsettings", "ssv", "core/serverscript/test/", "POST")
for route in ("core/openai/generate/", "core/dashinfo/", "core/unlisted/", "core/"):
    for mod in ("globalsettings", "reportmanager", "scriptmanager"):
        no(mod, "u", route)

# ---- agents/ sub-routes
fresh()
ok("take-control", "vnc", "agents/{agent_id:agent}/{port}/webvnc/")
no("take-control", "vnc-reboot", "agents/{agent_id:agent}/reboot/", "POST")
no("take-control", "vnc-cmd", "agents/{agent_id:agent}/cmd/", "POST")
for mod in ("agents", "remote-background", "endpoints", "agent-management"):
    no(mod, "vnc-" + mod, "agents/{agent_id:agent}/{port}/webvnc/")
ok("remote-background", "cmd", "agents/{agent_id:agent}/cmd/", "POST")
no("remote-background", "rb-reboot", "agents/{agent_id:agent}/reboot/", "POST")
no("remote-background", "rb-vnc", "agents/{agent_id:agent}/{port}/webvnc/")
ok("scriptexecution", "run", "agents/{agent_id:agent}/runscript/", "POST")
no("scriptexecution", "se-reboot", "agents/{agent_id:agent}/reboot/", "POST")
no("scriptexecution", "se-cmd", "agents/{agent_id:agent}/cmd/", "POST")
ok("agents", "reboot", "agents/{agent_id:agent}/reboot/", "POST")
ok("agents", "wol", "agents/{agent_id:agent}/wol/", "POST")
ok("agents", "pend", "logs/pendingactions/{id:int}/", "DELETE")
ok("agents", "pend-list", "logs/pendingactions/")
no("agents", "a-cmd", "agents/{agent_id:agent}/cmd/", "POST")
no("agents", "a-vnc", "agents/{agent_id:agent}/{port}/webvnc/")
no("agents", "a-run", "agents/{agent_id:agent}/runscript/", "POST")
no("endpoints", "e-reboot", "agents/{agent_id:agent}/reboot/", "POST")  # Endpoints composes contracts, owns no route
ROUTED = (
    ("agents/{agent_id:agent}/meshcentral/", "take-control"), ("agents/{agent_id:agent}/meshcentral/recover/", "take-control"),
    ("agents/{agent_id:agent}/processes/", "remote-background"), ("agents/{agent_id:agent}/registry/create-key/", "remote-background"),
    ("agents/{agent_id:agent}/eventlog/{logtype}/{days:int}/", "remote-background"), ("agents/{agent_id:agent}/terminal-defaults/", "remote-background"),
    ("agents/update/", "agent-management"), ("agents/versions/", "agent-management"), ("agents/bulkrecovery/", "agent-management"),
    ("agents/{agent_id:agent}/recover/", "agent-management"),
)
for route, owner in ROUTED:
    fresh()
    for other in sorted({"take-control", "remote-background", "agent-management", "agents", "scriptexecution", "endpoints"} - {owner}):
        no(other, "o-" + other, route)
    ok(owner, "own", route)

# ---- logs/
fresh()
for mod in ("endpoints", "debug", "audit"):
    no(mod, "pa-" + mod, "logs/pendingactions/")
ok("audit", "aud", "logs/audit/", "PATCH")
ok("debug", "dbg", "logs/debug/", "PATCH")
no("debug", "dbg2", "logs/audit/", "PATCH")
for mod in ("agents", "audit", "debug", "endpoints"):
    no(mod, "unl-" + mod, "logs/unlisted/")

# ---- automation/ and the single-owner groups
fresh()
ok("patching", "pp", "automation/patchpolicy/", "POST")
no("automation", "pp-a", "automation/patchpolicy/{id:int}/", "PUT")
ok("automation", "pol", "automation/policies/", "POST")
no("patching", "pol-p", "automation/policies/", "POST")
for group, mod in (("reporting", "reportmanager"), ("alerts", "alerts"), ("scripts", "scriptmanager"), ("winupdate", "patching")):
    ok(mod, "g-" + group, f"{group}/x/")
    no("agents", "ga-" + group, f"{group}/x/")

# ---- longest prefix wins, and a non-owner registering first does not block the owner later
fresh()
no("agents", "lp", "agents/{agent_id:agent}/cmd/", "POST")  # group owner, reserved sub-route
must(ops.list_operations() == [], "a refusal left no trace")
no("agents", "first", "agents/{agent_id:agent}/{port}/webvnc/")
ok("take-control", "later", "agents/{agent_id:agent}/{port}/webvnc/")  # the first caller was refused, so the route is free
must([row["module_id"] for row in ops.list_operations()] == ["take-control"], ops.list_operations())
msg = no("globalsettings", "named", "core/schedules/")
must("reportmanager" in msg and "core/schedules" in msg, msg)  # the message names the route and the owner

# ---- the group map is gone and Endpoints owns no route
must(not hasattr(ops, "GROUP_OWNERS"), "GROUP_OWNERS is gone")
must("endpoints" not in set().union(*ops.ROUTE_OWNERS.values()), "Endpoints owns no route")

# ---- 1.17.7 cases still hold
fresh()
must("not a core module" in no("premiumdemo", "p", "agents/{agent_id:agent}/reboot/", "POST"), "premium refused")
no("oldmod", "o", "agents/{agent_id:agent}/reboot/", "POST")
no("offmod", "d", "agents/{agent_id:agent}/reboot/", "POST")
first = declare()
must(declare() is first and first.module_id == "agents", "idempotent re-register")
no("reportmanager", "dup", "agents/{agent_id:agent}/reboot/", "POST")
print("[TEST] PASS tactical operation route owners 1.17.8")

# ---- 1.17.8-1: a parameter segment is a wildcard, so it cannot reach a reserved sub-route through the group rule
fresh()
for route in ("agents/{agent_id:agent}/{op}/", "agents/{x}/", "agents/{a}/{b}/webvnc/", "agents/{agent_id:agent}/{port}/{x}/", "agents/{x}/{y}/"):
    for mod in ("agents", "endpoints"):
        no(mod, "wc-" + mod, route, "POST")
must(ops.list_operations() == [], "wildcard refusals left no trace")
ok("remote-background", "wc-rb", "agents/{agent_id:agent}/cmd/", "POST")
ok("take-control", "wc-tc", "agents/{agent_id:agent}/{port}/webvnc/")
ok("agent-management", "wc-am", "agents/{agent_id:agent}/recover/", "POST")
ok("agents", "wc-ok", "agents/{agent_id:agent}/reboot/", "POST")
no("agents", "wc-ok2", "agents/{agent_id:agent}/{x}/wol/", "POST")  # 1.17.9: x can be cmd, so the longest rule is Remote Background's
