#!/usr/bin/env python3
"""1.17.9 regression: an honoured replacement joins the replaced module's owner-table rules (AD-20 condition 2),
and the route-owner dispatch recheck (held Medium from the 1.17.8 review).

Builds on the stubs of tests/tactical-operations-1.17.7.py (the helper section is executed from that file, so the two cannot
drift). The real tactical_operations.py and module_replacement.py run against them. Django and Tactical are not installed.
"""
from __future__ import annotations

import dataclasses
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
run, route, refusal, CALLS, ROWS, AGENT, tech = (G[k] for k in ("run", "route", "refusal", "CALLS", "ROWS", "AGENT", "tech"))


def plugin(name, category, **extra):
    base = dict(plugin_id=name, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False, audit_events=(),
                category=category, replaces="", capabilities=(), capabilities_declared=False)
    base.update(extra)
    PLUGINS[name] = SimpleNamespace(**base)


for name in ("agent-management", "remote-background", "take-control", "scriptexecution", "audit", "debug", "globalsettings",
             "scriptmanager", "automation", "alerts", "checks"):
    plugin(name, "core")
plugin("patching", "core", capabilities_declared=True)
plugin("patchmanagement", "", replaces="patching", capabilities_declared=True)
plugin("rival", "", replaces="patching", capabilities_declared=True)
plugin("premiumtwo", "", replaces="premiumdemo", capabilities_declared=True)  # names a module that is not a core module
plugin("nocaps", "core")  # a core module that never declared capabilities
plugin("wannabe", "", replaces="nocaps", capabilities_declared=True)
PLUGINS["licensing"].category = "server"


def state(patching=False, patchmanagement=True, rival=False):
    ENABLED.update(patching=patching, patchmanagement=patchmanagement, rival=rival)


FLAG = ["can_reboot_agents"]
NOSCOPE = dict(scope=[], body_fields=[], audit={"action": "view", "object_type": "agent", "audit_fields": []})


def spec(module, op, route_text, method, over):
    out = dict(id=op, module_id=module, method=method, route=route_text, permissions=FLAG, **NOSCOPE)
    out.update(over)
    return out


def ok(module, op, route_text, method="GET", **over):
    return declare(**spec(module, op, route_text, method, over))


def no(module, op, route_text, method="GET", **over):
    return refused(**spec(module, op, route_text, method, over))


# ------------------------------------------------------------------------------------------ owner table
fresh()
state()
must(ops._honoured_pairs() == {"patchmanagement": "patching"}, ops._honoured_pairs())
must(ops._owners_for_rule(("winupdate",)) == {"patching", "patchmanagement"}, "the replacement joins winupdate/")
must(ops._owners_for_rule(("automation", "patchpolicy")) == {"patching", "patchmanagement"}, "and automation/patchpolicy/")
must(ops._owners_for_rule(("automation",)) == {"automation"} and ops._owners_for_rule(("agents",)) == {"agents"}, "and no other rule")
must(ops._owners_for_rule(("clients",)) == frozenset() and ops._owners_for_rule(("core", "openai")) == frozenset(), "Core's own rules stay empty")
must(ops.ROUTE_OWNERS[("winupdate",)] == {"patching"}, "the static table is not changed")

ok("patchmanagement", "wu-scan", "winupdate/{agent_id:agent}/scan/", "POST", scope=[{"type": "agent", "source": "path:agent_id"}])
ok("patchmanagement", "wu-list", "winupdate/")
ok("patchmanagement", "pp", "automation/patchpolicy/", "POST")
ok("patchmanagement", "pp-one", "automation/patchpolicy/{id:int}/", "PUT")
for route_text in ("agents/{agent_id:agent}/reboot/", "agents/{agent_id:agent}/cmd/", "clients/", "clients/sites/", "core/settings/", "core/openai/x/",
                   "automation/policies/", "automation/", "logs/audit/", "logs/pendingactions/", "alerts/x/", "scripts/", "reporting/x/",
                   "checks/", "core/codesign/"):
    msg = no("patchmanagement", "x", route_text, "POST", permissions=["can_code_sign"] if "codesign" in route_text else FLAG)
    must("does not own route" in msg or "Core's own" in msg, (route_text, msg))
for route_text in ("agents/{x}/", "agents/{agent_id:agent}/{p}/create-key/"):
    no("patchmanagement", "wild", route_text)
must(sorted(row["id"] for row in ops.list_operations("patchmanagement")) == ["pp", "pp-one", "wu-list", "wu-scan"], "refusals left no trace")
state(patching=True, patchmanagement=False)
ok("patching", "p-wu", "winupdate/{agent_id:agent}/install/", "POST")  # the core module itself is unchanged
no("patching", "p-agents", "agents/{agent_id:agent}/reboot/", "POST")
state()
# a rule the replaced module does not own is refused even where another core module's name sits in the owner set
no("patchmanagement", "alerts-like", "alerts/x/")
# the replacement keeps Licensing's named exception unchanged
ok("licensing", "cs", "core/codesign/", "PUT", permissions=["can_code_sign"])
no("patchmanagement", "cs2", "core/codesign/", "PUT", permissions=["can_code_sign"])

# the moment the target is enabled again, or the replacement is disabled, the replacement is refused
for flip in ({"patching": True}, {"patchmanagement": False}):
    fresh()
    state()
    state(**{"patching": False, "patchmanagement": True, **flip})
    msg = no("patchmanagement", "gone", "winupdate/{agent_id:agent}/scan/", "POST", scope=[{"type": "agent", "source": "path:agent_id"}])
    must("not a core module" in msg or "disabled" in msg, msg)
fresh()
state(patching=True, patchmanagement=True)
must(ops._honoured_pairs() == {}, "both enabled: nobody is honoured")
no("patchmanagement", "both", "winupdate/")
ok("patching", "core-wu", "winupdate/")  # the core module keeps its routes

# premium modules without a declared and honoured replaces stay refused
fresh()
state()
must("not a core module" in no("premiumdemo", "p", "winupdate/"), "no replaces")
must("not a core module" in no("premiumtwo", "p2", "winupdate/"), "replaces a module that is not a core module")
ENABLED["premiumdemo"] = True
no("premiumtwo", "p3", "agents/{agent_id:agent}/reboot/", "POST")
state(patching=False, patchmanagement=True, rival=True)
must(ops._honoured_pairs() == {}, "two enabled replacements of one module: neither is honoured")
no("patchmanagement", "competing", "winupdate/")
no("rival", "competing2", "winupdate/")
state()
must("not a core module" in no("wannabe", "w", "automation/patchpolicy/"), "replaces a core module that declares no capabilities")
ENABLED["nocaps"] = False
ENABLED["wannabe"] = True
no("wannabe", "w2", "automation/patchpolicy/")
must(ops._honoured_pairs() == {"patchmanagement": "patching"}, "wannabe is not honoured, patchmanagement still is")

# ------------------------------------------------------------------------------------------ dispatch
fresh()
state()
SCAN = f"/winupdate/{AGENT}/scan/"
ok("patchmanagement", "scan", "winupdate/{agent_id:agent}/scan/", "POST", scope=[{"type": "agent", "source": "path:agent_id"}])
route(SCAN)
result = run(module="patchmanagement", operation="scan", params={"agent_id": AGENT})
must(result.status == 200 and len(CALLS) == 1, "an honoured replacement's operation runs")
state(patching=True, patchmanagement=True)  # the core module is enabled again before the worker restarts
del ROWS[:]
refusal(lambda: run(module="patchmanagement", operation="scan", params={"agent_id": AGENT}), 404, "tactical_operation_not_found")
must(not CALLS and not ROWS, "a replacement that is no longer honoured reaches nothing and writes nothing")
state(patching=False, patchmanagement=False)
refusal(lambda: run(module="patchmanagement", operation="scan", params={"agent_id": AGENT}), 404, "tactical_operation_not_found")
state()
must(run(module="patchmanagement", operation="scan", params={"agent_id": AGENT}).status == 200, "honoured again")
# a core module's operation is not affected by any of this
state(patching=True, patchmanagement=False)
ok("patching", "pscan", "winupdate/{agent_id:agent}/install/", "POST", scope=[{"type": "agent", "source": "path:agent_id"}])
route(f"/winupdate/{AGENT}/install/")
must(run(module="patching", operation="pscan", params={"agent_id": AGENT}).status == 200, "the core module runs its own operation")
state()
refusal(lambda: run(module="patching", operation="pscan", params={"agent_id": AGENT}), 404, "tactical_operation_not_found")  # disabled core module

# Licensing's operation (a server module) still runs
fresh()
state()
ok("licensing", "cs", "core/codesign/", "PUT", permissions=["can_code_sign"], body_fields=["token"],
   audit={"action": "modify", "object_type": "code_signing_token", "audit_fields": []})
route("/core/codesign/")
codesigner = G["User"]("signer", G["Roleish"]("can_code_sign"))
must(run(user=codesigner, module="licensing", operation="cs", body={"token": "t"}).status == 200, "Licensing's exception runs")

# ------------------------------------------------------------------------------------------ dispatch recheck (1.17.8 held Medium)
fresh()
state()
real = ops.register_tactical_operation
base = ok("patchmanagement", "scan", "winupdate/{agent_id:agent}/scan/", "POST", scope=[{"type": "agent", "source": "path:agent_id"}])
# an operation injected into the registry for a module that does not own the concrete path
ops._OPERATIONS[("agents", "evil")] = dataclasses.replace(base, id="evil", module_id="agents")
route(SCAN)
refusal(lambda: run(module="agents", operation="evil", params={"agent_id": AGENT}), 404, "tactical_operation_not_found")
must(not CALLS, "an operation that does not own its concrete path never reaches Tactical")
# a str parameter value of 'registry' lands on Remote Background's rule
owner_check = ops._check_route_owner
ops._check_route_owner = lambda *args, **kwargs: None  # register past the owner check to prove the dispatch check on its own
ok("agents", "slip", "agents/{agent_id:agent}/{p}/create-key/", "POST", scope=[{"type": "agent", "source": "path:agent_id"}])
ops._check_route_owner = owner_check
route(f"/agents/{AGENT}/registry/create-key/")
route(f"/agents/{AGENT}/other/create-key/")
refusal(lambda: run(module="agents", operation="slip", params={"agent_id": AGENT, "p": "registry"}), 404, "tactical_operation_not_found")
refusal(lambda: run(module="agents", operation="slip", params={"agent_id": AGENT, "p": "Registry"}), 404, "tactical_operation_not_found")
must(not CALLS, "'registry' is refused at dispatch")
must(run(module="agents", operation="slip", params={"agent_id": AGENT, "p": "other"}).status == 200, "an ordinary value passes the recheck")
# the recheck on its own, for the rule's owner, the replacement, Licensing and an unlisted route
op = ops._OPERATIONS[("agents", "slip")]
ops._recheck_route_owner(op, f"/agents/{AGENT}/other/create-key/")
for path in ("/agents/update/", "/agents/x/registry/", f"/agents/{AGENT}/cmd/", f"/agents/{AGENT}/5900/webvnc/", "/clients/", "/core/settings/", "/beta/x/"):
    try:
        ops._recheck_route_owner(op, path)
        raise AssertionError(path)
    except ops.TacticalOperationError as exc:
        must(exc.status == 404 and exc.code == "tactical_operation_not_found", path)
pm = ops._OPERATIONS[("patchmanagement", "scan")]
ops._recheck_route_owner(pm, SCAN)
state(patching=True, patchmanagement=True)
try:
    ops._recheck_route_owner(pm, SCAN)
    raise AssertionError("not honoured")
except ops.TacticalOperationError:
    pass
state()

print("[TEST] PASS module replacement owner table and dispatch recheck 1.17.9")
