#!/usr/bin/env python3
"""1.17.41 regression: query_params on any method, and the route parameter kind service (Remote Background request items a and b,
15 October 2026: registry delete-key and delete-value read request.query_params on a DELETE; services/{agent_id}/{svcname}/ carries a
Windows service name).

Covered: a DELETE operation declaring query_params registers; the forwarded request carries the query string and request.GET; an
unlisted query name is refused query_field_not_allowed; a secret-looking name is still refused at registration; a registry-style value
with backslashes passes and a '..' segment is refused; an audit field naming a query parameter lands in the success row's after value;
a GET declaration is unchanged. The service kind: registration by remote-background succeeds and by another module is refused by the
owner table; MSSQL$SQLEXPRESS, 'Print Spooler', 'Foo (bar).svc' and 'a,b' are accepted; '../x', 'a/b', '..', a leading dot, a
257-character name and an empty value are refused invalid_params (a value is stripped first, so a leading space is not a case); the concrete path is /services/<agent>/MSSQL$SQLEXPRESS/; the str
kind still refuses '$'; a service parameter named in audit.params appears in the row's after value.
Uses the stubs of tests/tactical-operations-1.17.7.py.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)  # noqa: S102 - test-only reuse of the 1.17.7 stubs
ops, fresh, must = (G[k] for k in ("ops", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, User, Roleish, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "User", "Roleish", "Request"))
FakeResponse, refusal, tactical_view = G["FakeResponse"], G["refusal"], G["tactical_view"]
PLUGINS, ENABLED = G["PLUGINS"], G["ENABLED"]
PLUGINS["remote-background"] = SimpleNamespace(plugin_id="remote-background", plugin_type="extension", version="0.8.0", permission_groups=(),
                                               legacy=False, audit_events=(), category="core")


class QueryDict(dict):
    def __init__(self, qs=""):
        super().__init__({key: values[0] for key, values in parse_qs(qs, keep_blank_values=True).items()})
        self.qs = qs


sys.modules["django.http"].QueryDict = QueryDict
FLAG = "can_manage_notes"
tech = User("rb", Roleish(FLAG))
tech.sees = {"agents": {AGENT}, "clients": {1}, "sites": {10}}

SEEN: list = []


def seeing(response=None):
    def view(request, *args, **kwargs):
        SEEN.append(request)
        return response if response is not None else FakeResponse(200, b'{"ok": true}')
    return view


def register(**over):
    spec = dict(id="reg-delete-key", module_id="remote-background", method="DELETE", route="agents/{agent_id:agent}/registry/",
                permissions=[FLAG], scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=[],
                audit={"action": "delete", "object_type": "registry_key", "audit_fields": ["path", "name"]}, query_params=["path", "name"])
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def refused(**over):
    try:
        register(**over)
    except ops.TacticalOperationRegistrationError as exc:
        return str(exc)
    raise AssertionError(f"registration was accepted: {over}")


def run(module, operation, params=None, body=None, query=None):
    del CALLS[:], SEEN[:], ROWS[:]
    return ops.run_tactical_operation(Request(tech), module, operation, params, body, query=query)


REG_PATH = f"/agents/{AGENT}/registry/"

# ---- query_params on a DELETE
fresh()
op = register()
must(op.method == "DELETE" and op.query_params == ("path", "name"), op)
ROUTES[REG_PATH] = (seeing(), (), {})
result = run("remote-background", "reg-delete-key", {"agent_id": AGENT}, query={"path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme", "name": "Value 1"})
must(result.status == 200, result)
request = SEEN[0]
must(request.method == "DELETE", request.method)
must(request.META["QUERY_STRING"] == "path=HKEY_LOCAL_MACHINE%5CSOFTWARE%5CAcme&name=Value%201", request.META["QUERY_STRING"])
must(isinstance(request.GET, QueryDict) and request.GET["path"] == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme", "request.GET carries the query")
must(ROWS[0]["action"] == "delete" and ROWS[0]["after_value"] == {"path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme", "name": "Value 1"}, ROWS[0])
print("       DELETE with query_params: registered, query string and request.GET forwarded, after value carries the fields")

# an unlisted name, a bad value
refusal(lambda: run("remote-background", "reg-delete-key", {"agent_id": AGENT}, query={"other": "x"}), 400, "query_field_not_allowed")
for bad in ("a/../b", "..", "a\\..\\b", "%2e%2e", "a\nb", "", "x" * 513):
    refusal(lambda bad=bad: run("remote-background", "reg-delete-key", {"agent_id": AGENT}, query={"path": bad}), 400, "invalid_query")
must(not CALLS and not SEEN, "Tactical is never reached by a refused query")
print("       unlisted name and bad values refused")

# a secret-looking name is still refused at registration, on any method
for verb in ("DELETE", "POST", "GET"):
    for secretive in ("token", "api_key", "password"):
        fresh()
        text = refused(method=verb, query_params=[secretive], audit={"action": "delete", "object_type": "registry_key"})
        must("looks like a secret" in text, text)
# the old GET-only refusal is gone, and a POST declares one too
fresh()
register(id="post-query", method="POST", route="agents/{agent_id:agent}/registry/create-key/", query_params=["path"],
         audit={"action": "add", "object_type": "registry_key", "audit_fields": ["path"]})
register(id="get-query", method="GET", route="agents/{agent_id:agent}/registry/list/", query_params=["path"],
         audit={"action": "view", "object_type": "registry_key"})
must(ops.get_operation("remote-background", "get-query")["query_params"] == ["path"], "a GET declaration is unchanged")
print("       secret names refused; POST and GET declarations accepted")

# ---- the service kind
SVC = "services/{agent_id:agent}/{svcname:service}/"


def register_service(**over):
    spec = dict(id="svc-start", module_id="remote-background", method="POST", route=SVC, permissions=[FLAG],
                scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=[],
                audit={"action": "run", "object_type": "service", "params": ["svcname"]})
    spec.update(over)
    return ops.register_tactical_operation(**spec)


fresh()
op = register_service()
must(dict(op.params) == {"agent_id": "agent", "svcname": "service"}, op.params)
try:
    register_service(id="svc-start", module_id="agents", route=SVC)
except ops.TacticalOperationRegistrationError as exc:
    must("services" in str(exc) or "owner" in str(exc).lower() or "own" in str(exc).lower(), str(exc))
else:
    raise AssertionError("another module must be refused services/")
try:
    register_service(id="svc-other", module_id="reportmanager")
except ops.TacticalOperationRegistrationError:
    pass
else:
    raise AssertionError("reportmanager must be refused services/")
print("       service kind registers for remote-background and is refused to other modules")

good = ("MSSQL$SQLEXPRESS", "Print Spooler", "Foo (bar).svc", "a,b", "_svc", "9lives", "Name#1", "x" * 256)
for name in good:
    path = f"/services/{AGENT}/{name}/"
    ROUTES[path] = (seeing(), (), {})
    result = run("remote-background", "svc-start", {"agent_id": AGENT, "svcname": name})
    must(result.status == 200, name)
    must(G["RESOLVED"][-1] == path, (name, G["RESOLVED"][-1]))
    must(ROWS[0]["after_value"] == {"svcname": name[:255]}, (name, ROWS[0]["after_value"]))  # audit.params names it (the row keeps 255 characters)
must(G["RESOLVED"][-1] == f"/services/{AGENT}/{'x' * 256}/", "the longest name")
ROUTES[f"/services/{AGENT}/MSSQL$SQLEXPRESS/"] = (seeing(), (), {})
run("remote-background", "svc-start", {"agent_id": AGENT, "svcname": " MSSQL$SQLEXPRESS "})  # stripped first, as for every kind
must(G["RESOLVED"][-1] == f"/services/{AGENT}/MSSQL$SQLEXPRESS/", "the value is stripped, the path is built unquoted")
print("       accepted names, unquoted path, audit param in the row")

for bad in ("../x", "a/b", "..", ".x", "-x", "x" * 257, "", "   ", "a..b", "a\nb", "a\\b", "a%b", "a;b", "a:b"):
    refusal(lambda bad=bad: run("remote-background", "svc-start", {"agent_id": AGENT, "svcname": bad}), 400, "invalid_params")
for bad in (None, True, 1.5, ["a"], {"a": 1}):
    refusal(lambda bad=bad: run("remote-background", "svc-start", {"agent_id": AGENT, "svcname": bad}), 400, "invalid_params")
print("       bad names refused invalid_params")

# the str kind still refuses '$' and a space
fresh()
ops.register_tactical_operation(id="str-kind", module_id="remote-background", method="POST", route="services/{agent_id:agent}/{svcname}/",
                                permissions=[FLAG], scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=[],
                                audit={"action": "run", "object_type": "service"})
for name in ("MSSQL$SQLEXPRESS", "Print Spooler"):
    refusal(lambda name=name: run("remote-background", "str-kind", {"agent_id": AGENT, "svcname": name}), 400, "invalid_params")
ROUTES[f"/services/{AGENT}/Spooler/"] = (seeing(), (), {})
must(run("remote-background", "str-kind", {"agent_id": AGENT, "svcname": "Spooler"}).status == 200, "a plain name still works")
print("       str kind unchanged")

# other kinds in a route are refused with the new text
text = ""
try:
    register_service(id="bad-kind", route="services/{agent_id:agent}/{svcname:float}/")
except ops.TacticalOperationRegistrationError as exc:
    text = str(exc)
must("service" in text, text)

# docs
root = Path(__file__).resolve().parents[1]
docs = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("{name:service}", "MSSQL$SQLEXPRESS", "query_params", "Added in 1.17.41"):
    must(needle in docs, f"docs/tactical-operations.md lacks {needle!r}")
contract = (root / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must("{name:service}" in contract and "any method since" in contract, "contracts.py rows")

print("[TEST] PASS tactical operation query_params and service kind 1.17.41")
