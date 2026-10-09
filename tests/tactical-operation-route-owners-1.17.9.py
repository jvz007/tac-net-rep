#!/usr/bin/env python3
"""1.17.9 regression: the wildcard owner check uses the parameter kind (held Medium from the 1.17.8 review).

A parameter of kind agent (21 or more characters) or int can never hold a route word. A plain str parameter can, so every
expansion counts, including ones that run on past the matched rule: agents/{agent_id:agent}/{p}/create-key/ lands on Remote
Background's registry rule and is refused to Agents. The stub section is executed from tests/tactical-operations-1.17.7.py.
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

for name in ("agent-management", "remote-background", "take-control", "scriptexecution", "endpoints", "checks"):
    PLUGINS[name] = SimpleNamespace(plugin_id=name, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False,
                                    audit_events=(), category="core")
PLUGINS["licensing"].category = "server"

FLAG = ["can_reboot_agents"]
NOSCOPE = dict(scope=[], body_fields=[], audit={"action": "view", "object_type": "agent", "audit_fields": []})


def spec(module, op, route, method, over):
    out = dict(id=op, module_id=module, method=method, route=route, permissions=FLAG, body_fields=[], **{k: v for k, v in NOSCOPE.items() if k != "body_fields"})
    out.update(over)
    return out


def ok(module, op, route, method="GET", **over):
    return declare(**spec(module, op, route, method, over))


def no(module, op, route, method="GET", **over):
    return refused(**spec(module, op, route, method, over))


fresh()
# ---- the seven registry routes Remote Background owns, reached through an untyped parameter
REGISTRY = ("create-key", "delete-key", "rename-key", "create-value", "edit-value", "delete-value", "")
for tail in REGISTRY:
    route = "agents/{agent_id:agent}/{p}/" + (tail + "/" if tail else "")
    msg = no("agents", "reg-" + (tail or "browse"), route, "POST")
    must("does not own route" in msg, msg)
must(ops.list_operations() == [], "refusals left no trace")
no("agents", "recover-p", "agents/{agent_id:agent}/{p}/recover/", "POST")  # p=meshcentral is Take Control's
no("agents", "eventlog-w", "agents/{a:agent}/{t}/{l}/{d:int}/")  # t=eventlog (Remote Background), t=x l=webvnc (Take Control)
for route in ("agents/{x}/", "agents/{x}/reboot/", "agents/{x}/notes/", "agents/{x}/{y}/"):
    for method in ("GET", "POST"):
        no("agents", "str-" + method, route, method)
must(ops.list_operations() == [], "an untyped agents parameter reaches update, versions and bulkrecovery")
msg = no("agents", "rb-name", "agents/{agent_id:agent}/{p}/create-key/", "POST")
must("does not own route" in msg and "owner:" in msg, msg)  # the message names the rule and its owner

# ---- what stays accepted
ok("agents", "reboot", "agents/{agent_id:agent}/reboot/", "POST")
ok("agents", "notes", "agents/{agent_id:agent}/notes/")
ok("agents", "pend", "logs/pendingactions/")
ok("agents", "pend-one", "logs/pendingactions/{id:int}/", "DELETE")
ok("agents", "wol", "agents/{agent_id:agent}/wol/", "POST")
ok("agents", "agent-int", "agents/{agent_id:agent}/notes/{id:int}/", "DELETE")
ok("agents", "plain", "agents/notes/{id:int}/", "DELETE")  # a literal sub-path and an int parameter

# ---- Remote Background accepts the routes it owns, by literal and through an untyped parameter that cannot leave its rules
fresh()
for tail in REGISTRY:
    ok("remote-background", "rb-" + (tail or "browse"), "agents/{agent_id:agent}/registry/" + (tail + "/" if tail else ""), "POST")
ok("remote-background", "rb-eventlog", "agents/{agent_id:agent}/eventlog/{logtype}/{days:int}/")
ok("remote-background", "rb-proc", "agents/{agent_id:agent}/processes/{pid:int}/", "DELETE")
ok("remote-background", "rb-cmd", "agents/{agent_id:agent}/cmd/", "POST")
no("remote-background", "rb-reg-p", "agents/{agent_id:agent}/{p}/create-key/", "POST")  # p could be meshcentral or eventlog
ok("take-control", "tc-vnc", "agents/{agent_id:agent}/{port}/webvnc/")
ok("take-control", "tc-mesh", "agents/{agent_id:agent}/meshcentral/recover/", "POST")
ok("agent-management", "am-upd", "agents/update/", "POST")
ok("agent-management", "am-rec", "agents/{agent_id:agent}/recover/", "POST")
ok("scriptexecution", "se-run", "agents/{agent_id:agent}/runscript/", "POST")

# ---- the kinds decide: int can never be a route word, and a str parameter at a position no rule names is fine
fresh()
ok("agents", "int-pos", "agents/{n:int}/notes/")  # digits only, so never 'update' or 'registry'
no("agents", "str-late", "agents/{agent_id:agent}/notes/{name}/", "GET")  # name=webvnc is Take Control's route (agents/<id>/<port>/webvnc/)
ok("agents", "str-ok", "logs/pendingactions/{name}/", "GET")  # no rule names a word at that position
no("agents", "str-early", "agents/{name}/notes/")
no("agents", "str-mid", "agents/{agent_id:agent}/{name}/notes/")  # name=registry, cmd, eventlog ... run past their rule

# ---- the length-based skip is gone
must("len(rule) < len(combo)" not in Path(ops.__file__).read_text(encoding="utf-8"), "the length heuristic was deleted")

# ---- checks' eight real routes (modules/checks) still register
fresh()
CHECKS = (  # the routes modules/checks/.../operations.py declares today
    ("POST", "checks/"), ("PUT", "checks/{check_id:int}/"), ("DELETE", "checks/{check_id:int}/"), ("POST", "checks/{result_id:int}/reset/"),
    ("POST", "checks/{agent_id:agent}/resetall/"), ("POST", "checks/{agent_id:agent}/run/"),
    ("POST", "checks/client/{client_id:int}/csbulkrun/"), ("POST", "checks/site/{site_id:int}/csbulkrun/"),
)
for index, (method, route) in enumerate(CHECKS):
    ok("checks", f"check-{index}", route, method)
no("agents", "checks-agents", "checks/{agent_id:agent}/run/", "POST")
must(len(ops.list_operations()) == 8, ops.list_operations())

print("[TEST] PASS tactical operation route owners 1.17.9")
