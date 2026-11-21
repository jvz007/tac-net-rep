#!/usr/bin/env python3
"""1.18.30 regression: file browser routes part 1 (ORDER Core 1.18.30, Johan, 21 November 2026, plan A1).

Three additions, all opt-in: (1) route owners agents/{}/files/ and agents/{}/file-browser-defaults/ go to remote-background;
(2) the route parameter kind {name:uuid}; (3) register_tactical_operation(path_query_params=[...]) lets up to four declared query
names hold 4096 characters (every other query value stays at 512). Capability core.tactical_operations moves to 1.17.0.

Covered: remote-background registers both routes, and agents, agent-management, take-control, endpoints, scriptexecution and a
premium module are refused; an untyped {x} at the third segment under agents/ is judged against both new literals; the older
agents/{}/ owners are unchanged. The uuid kind: registration, the concrete path, accepted and refused values, never a scope
source, named in audit.params. path_query_params: 4096 passes and reaches request.GET and QUERY_STRING, 4097 and an undeclared
600-character value are refused, registration refusals, the unchanged control-character, '..' and blank rules, a 1.18.29-style
declaration unchanged, describe() and the metadata, a 4096-character audit field in the success row. A compatibility check reads
every route declared in modules/ as data and proves each is judged exactly as it was before the two owner rules existed.
Uses the stubs of tests/tactical-operations-1.17.7.py.
"""
from __future__ import annotations

import ast
import sys
import tomllib
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
FakeResponse, refusal = G["FakeResponse"], G["refusal"]
PLUGINS = G["PLUGINS"]
for name, category in (("remote-background", "core"), ("agents", "core"), ("agent-management", "core"), ("take-control", "core"),
                       ("endpoints", "core"), ("scriptexecution", "core"), ("somepremium", "premium"), ("someserver", "server")):
    PLUGINS[name] = SimpleNamespace(plugin_id=name, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False,
                                    audit_events=(), category=category)


class QueryDict(dict):
    def __init__(self, qs=""):
        super().__init__({key: values[0] for key, values in parse_qs(qs, keep_blank_values=True).items()})
        self.qs = qs


sys.modules["django.http"].QueryDict = QueryDict
FLAG = "can_manage_notes"  # the stub Role has no can_use_file_browser (Tactical 1.5.2 has none either; Core refuses an unknown flag)
tech = User("rb", Roleish(FLAG))
tech.sees = {"agents": {AGENT}, "clients": {1}, "sites": {10}}
SEEN: list = []
UUID = "0b9d6a3e-4c1f-4f7e-9a52-3d8e6f1c2b47"


def seeing(response=None):
    def view(request, *args, **kwargs):
        SEEN.append(request)
        return response if response is not None else FakeResponse(200, b'{"ok": true}')
    return view


SCOPE = [{"type": "agent", "source": "path:agent_id"}]


def spec(**over):
    out = dict(id="file-list", module_id="remote-background", method="GET", route="agents/{agent_id:agent}/files/", permissions=[FLAG],
               scope=SCOPE, body_fields=[], audit={"action": "view", "object_type": "agent", "audit_fields": []})
    out.update(over)
    return out


def register(**over):
    return ops.register_tactical_operation(**spec(**over))


def refused(**over):
    try:
        register(**over)
    except ops.TacticalOperationRegistrationError as exc:
        return str(exc)
    raise AssertionError(f"registration was accepted: {over}")


def run(module, operation, params=None, body=None, query=None):
    del CALLS[:], SEEN[:], ROWS[:]
    return ops.run_tactical_operation(Request(tech), module, operation, params, body, query=query)


# ---- (1) the two route owners
must(ops.ROUTE_OWNERS[("agents", "{}", "files")] == frozenset({"remote-background"}), "files rule")
must(ops.ROUTE_OWNERS[("agents", "{}", "file-browser-defaults")] == frozenset({"remote-background"}), "file-browser-defaults rule")
fresh()
register()
register(id="file-defaults", route="agents/{agent_id:agent}/file-browser-defaults/")
register(id="file-session", method="POST", route="agents/{agent_id:agent}/files/{session_id:uuid}/chunks/",
         audit={"action": "run", "object_type": "agent", "params": ["session_id"]})
register(id="file-delete", method="DELETE", route="agents/{agent_id:agent}/files/")
for module in ("agents", "agent-management", "take-control", "endpoints", "scriptexecution", "somepremium", "someserver"):
    for route in ("agents/{agent_id:agent}/files/", "agents/{agent_id:agent}/file-browser-defaults/", "agents/{agent_id:agent}/files/{session_id:uuid}/chunks/"):
        refused(id="x-" + module.replace("-", ""), module_id=module, route=route)
text = refused(id="x-agents", module_id="agents", route="agents/{agent_id:agent}/files/")
must("does not own route" in text and "remote-background" in text, text)
print("       remote-background registers files/ and file-browser-defaults/; every other module is refused")

# an untyped {x} at the third segment is judged against the new literals too (it can be 'files' or 'file-browser-defaults')
for module in ("agents", "tasks"):
    PLUGINS.setdefault(module, SimpleNamespace(plugin_id=module, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False,
                                               audit_events=(), category="core"))
text = refused(id="untyped-agents", module_id="agents", route="agents/{agent_id:agent}/{x}/", method="POST")
must("does not own route" in text, text)
refused(id="untyped-rb", module_id="remote-background", route="agents/{agent_id:agent}/{x}/", method="POST")  # it would also reach tasks/ and checks/
rules = ops._expansion_rules(ops._parse_route("agents/{agent_id:agent}/{x}/")[0])
must(("agents", "{}", "files") in rules and ("agents", "{}", "file-browser-defaults") in rules, rules)
rules = ops._expansion_rules(ops._parse_route("agents/{agent_id:agent}/files/{session_id:uuid}/chunks/")[0])
must(rules == [("agents", "{}", "files")], rules)
print("       untyped third segment judged against both new literals; a uuid segment never widens the rules")

# the older agents/{}/ owners are unchanged
for tail, owner in (("terminal-defaults", "remote-background"), ("processes", "remote-background"), ("registry", "remote-background"),
                    ("eventlog", "remote-background"), ("cmd", "remote-background"), ("tasks", "tasks"), ("checks", "checks"),
                    ("runscript", "scriptexecution"), ("meshcentral", "take-control")):
    must(ops.ROUTE_OWNERS[("agents", "{}", tail)] == frozenset({owner}), tail)
must(ops.ROUTE_OWNERS[("agents",)] == frozenset({"agents"}), "agents/ is still Agents'")
print("       earlier agent sub-route owners unchanged")

# ---- (2) the uuid kind
fresh()
op = register(id="file-chunk", method="POST", route="agents/{agent_id:agent}/files/{session_id:uuid}/chunks/",
              audit={"action": "run", "object_type": "agent", "params": ["session_id"]}, query_params=["path"])
must(dict(op.params) == {"agent_id": "agent", "session_id": "uuid"}, op.params)
PATH = f"/agents/{AGENT}/files/{UUID}/chunks/"
ROUTES[PATH] = (seeing(), (), {})
result = run("remote-background", "file-chunk", {"agent_id": AGENT, "session_id": UUID})
must(result.status == 200 and G["RESOLVED"][-1] == PATH, (result, G["RESOLVED"][-1]))
must(ROWS[0]["after_value"] == {"session_id": UUID}, ROWS[0]["after_value"])  # audit.params names it
for good in ("00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"):
    ROUTES[f"/agents/{AGENT}/files/{good}/chunks/"] = (seeing(), (), {})
    must(run("remote-background", "file-chunk", {"agent_id": AGENT, "session_id": good}).status == 200, good)
for bad in (UUID.upper(), UUID.replace("-", ""), UUID[:-1], UUID + "0", UUID + "/", "../x", "a/b", UUID.replace("-", "/", 1), "..", "", "   ",
            "0b9d6a3e-4c1f-4f7e-9a52-3d8e6f1c2b4g", UUID[:8] + "_" + UUID[9:], "{" + UUID + "}", "urn:uuid:" + UUID):
    refusal(lambda bad=bad: run("remote-background", "file-chunk", {"agent_id": AGENT, "session_id": bad}), 400, "invalid_params")
for bad in (None, True, 1.5, [UUID], {"a": 1}):
    refusal(lambda bad=bad: run("remote-background", "file-chunk", {"agent_id": AGENT, "session_id": bad}), 400, "invalid_params")
must(not SEEN, "Tactical is never reached by a refused parameter")
# a uuid is never a scope source, whatever the entry type
for entry in ({"type": "agent", "source": "path:session_id"}, {"type": "client", "source": "path:session_id"},
              {"type": "site", "source": "path:session_id"}, {"type": "agent_pk", "source": "path:session_id"}):
    text = refused(id="uuid-scope", method="POST", route="agents/{agent_id:agent}/files/{session_id:uuid}/chunks/", scope=[entry])
    must("uuid" in text, text)
# the other kinds still behave as before
register(id="kind-int", method="POST", route="agents/{agent_id:agent}/files/{n:int}/x/", scope=SCOPE)
register(id="kind-str", method="POST", route="agents/{agent_id:agent}/files/{s}/y/", scope=SCOPE)
refused(id="kind-bad", method="POST", route="agents/{agent_id:agent}/files/{s:float}/y/")
print("       uuid kind: path built, values accepted and refused, never a scope source, audit param kept")

# ---- (3) path_query_params
fresh()
op = register(query_params=["path", "other"], path_query_params=["path"])
must(op.path_query_params == ("path",), op.path_query_params)
LIST = f"/agents/{AGENT}/files/"
ROUTES[LIST] = (seeing(), (), {})
long_path = "C:\\" + "dir\\" * 1020  # 4084 characters, backslashes as a registry or Windows path has
must(len(long_path) <= 4096, len(long_path))
exact = "x" * 4096
result = run("remote-background", "file-list", {"agent_id": AGENT}, query={"path": exact})
must(result.status == 200 and SEEN[0].META["QUERY_STRING"] == "path=" + exact and SEEN[0].GET["path"] == exact, "4096 characters arrive intact")
result = run("remote-background", "file-list", {"agent_id": AGENT}, query={"path": long_path, "other": "short"})
must(result.status == 200 and SEEN[0].GET["path"] == long_path and SEEN[0].GET["other"] == "short", "a long registry-style path passes")
refusal(lambda: run("remote-background", "file-list", {"agent_id": AGENT}, query={"path": "x" * 4097}), 400, "invalid_query")
refusal(lambda: run("remote-background", "file-list", {"agent_id": AGENT}, query={"other": "x" * 600}), 400, "invalid_query")
must(run("remote-background", "file-list", {"agent_id": AGENT}, query={"other": "x" * 512}).status == 200, "512 stays allowed on an undeclared name")
refusal(lambda: run("remote-background", "file-list", {"agent_id": AGENT}, query={"other": "x" * 513}), 400, "invalid_query")
for bad in ("a/../b", "..", "a\\..\\b", "%2e%2e", "a%2F..%2Fb", "a\nb", "a\x00b", "a\x7fb", "", "   "):
    refusal(lambda bad=bad: run("remote-background", "file-list", {"agent_id": AGENT}, query={"path": bad}), 400, "invalid_query")
for bad in (None, True, 1.5, ["a"], {"a": 1}):
    refusal(lambda bad=bad: run("remote-background", "file-list", {"agent_id": AGENT}, query={"path": bad}), 400, "invalid_query")
refusal(lambda: run("remote-background", "file-list", {"agent_id": AGENT}, query={"nope": "x"}), 400, "query_field_not_allowed")
print("       4096 on a declared name, 512 elsewhere, the other rules unchanged")

# registration refusals
fresh()
must("not in query_params" in refused(query_params=["path"], path_query_params=["other"]), "name not in query_params")
must("twice" in refused(query_params=["path"], path_query_params=["path", "path"]), "repeat")
must("at most 4" in refused(query_params=["a", "b", "c", "d", "e"], path_query_params=["a", "b", "c", "d", "e"]), "five names")
fresh()
register(query_params=["a", "b", "c", "d"], path_query_params=["a", "b", "c", "d"])  # four is the limit
for secretive in ("token", "api_key", "password"):
    fresh()
    refused(query_params=[secretive], path_query_params=[secretive])
for bad in ("path", {"path": 1}, 5, b"path"):
    fresh()
    must("list" in refused(query_params=["path"], path_query_params=bad), repr(bad))
for bad in ([1], [None], ["a b"], [["path"]], [""]):
    fresh()
    refused(query_params=["path"], path_query_params=bad)
fresh()
register(query_params=["path"], path_query_params=[])  # an empty list is the same as none
print("       registration refusals: not in query_params, repeat, five names, secret name, non-list, bad entries")

# a 1.18.29-style declaration (no path_query_params) registers and runs unchanged, with the 512 limit
fresh()
op = register(query_params=["path"])
must(op.path_query_params == (), op.path_query_params)
ROUTES[LIST] = (seeing(), (), {})
must(run("remote-background", "file-list", {"agent_id": AGENT}, query={"path": "x" * 512}).status == 200, "512")
refusal(lambda: run("remote-background", "file-list", {"agent_id": AGENT}, query={"path": "x" * 513}), 400, "invalid_query")
refusal(lambda: run("remote-background", "file-list", {"agent_id": AGENT}, query={"path": "x" * 600}), 400, "invalid_query")

# describe, list_operations, get_operation and the metadata
fresh()
register(query_params=["path"], path_query_params=["path"])
must(ops.get_operation("remote-background", "file-list")["path_query_params"] == ["path"], ops.get_operation("remote-background", "file-list"))
must(ops.list_operations()[0]["path_query_params"] == ["path"], ops.list_operations())
register(id="plain", route="agents/{agent_id:agent}/file-browser-defaults/", query_params=["path"])
must(ops.get_operation("remote-background", "plain")["path_query_params"] == [], "an operation without the key shows an empty list")
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.18.0" and meta["version"] == "1.18.0" and meta["version"].split(".")[0] == "1", meta["version"])
must(meta["limits"]["path_query_value_chars"] == 4096 and meta["limits"]["query_value_chars"] == 512 and meta["limits"]["path_query_names"] == 4, meta["limits"])
must(any("path_query_params" in item for item in meta["declaration_keys_added_in_1_17_0"]) and any("uuid" in item for item in meta["declaration_keys_added_in_1_17_0"]),
     meta["declaration_keys_added_in_1_17_0"])
text = " ".join(meta["behaviour_added_in_1_17_0"])
must("files/" in text and "file-browser-defaults/" in text and "4096" in text and "uuid" in text, text)
must("path_query_params=None" in meta["declaration"], "the declaration line shows the keyword")
print("       describe, list_operations, get_operation and the metadata show the new key, kind and limit; capability 1.18.0")

# a 4096-character declared audit field is written to the success row without error
fresh()
register(query_params=["path"], path_query_params=["path"], audit={"action": "view", "object_type": "agent", "audit_fields": ["path"]})
ROUTES[LIST] = (seeing(), (), {})
result = run("remote-background", "file-list", {"agent_id": AGENT}, query={"path": exact})
must(result.status == 200 and len(ROWS) == 1 and ROWS[0]["after_value"]["path"], ROWS)
print("       a 4096-character audit field reaches the success row")

# ---- docs and contract rows
root = Path(__file__).resolve().parents[1]
docs = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("{name:uuid}", "path_query_params", "file-browser-defaults", "1.18.30", "`core.tactical_operations` 1.18.0"):
    must(needle in docs, f"docs/tactical-operations.md lacks {needle!r}")
contract = (root / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
for needle in ("Added in 1.18.30", "path_query_params", "{name:uuid}", "file-browser-defaults", "framework >=1.18.30"):
    must(needle in contract, f"contracts.py lacks {needle!r}")

# ---- compatibility: every route declared in modules/ is judged exactly as before the two owner rules existed
MODULES = Path(__file__).resolve().parents[3] / "modules"
GROUPS = {"agents", "alerts", "automation", "checks", "clients", "core", "logs", "reporting", "scripts", "services", "software", "tasks", "winupdate"}
NEW_RULES = (("agents", "{}", "files"), ("agents", "{}", "file-browser-defaults"))
if MODULES.is_dir() and (MODULES / "catalog.toml").is_file():
    catalog = tomllib.loads((MODULES / "catalog.toml").read_text(encoding="utf-8"))
    entries = catalog.get("modules") or catalog.get("module") or []
    if isinstance(entries, dict):
        entries = [{"id": key, **value} for key, value in entries.items()]
    category = {str(e.get("id")): str(e.get("category", "")) for e in entries if isinstance(e, dict)}
    found = []
    for folder in sorted(p for p in MODULES.iterdir() if (p / "package").is_dir()):
        files = [f for f in (folder / "package").rglob("*.py") if f.name in ("operations.py", "apps.py") and "tests" not in f.parts]
        for file in files:
            tree = ast.parse(file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and "/" in node.value and node.value.split("/")[0] in GROUPS:
                    found.append((folder.name, node.value))
                # 1.18.33: the new keyword and kind have one intended user, remote-background (it declares them now); any other module using them is a surprise
                if isinstance(node, ast.keyword) and node.arg == "path_query_params":
                    must(folder.name == "remote-background", f"{folder.name} uses path_query_params: re-check the compatibility of this release")
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and ":uuid}" in node.value and "/" in node.value:
                    must(folder.name == "remote-background", f"{folder.name} declares a uuid route {node.value!r}")
    found = sorted(set(found))
    must(found, "the scan found no declared routes: the extraction is broken")
    rules = dict(ops.ROUTE_OWNERS)
    old_rules = {k: v for k, v in rules.items() if k not in NEW_RULES}

    def judge(module_id, route):
        try:
            segments, _ = ops._parse_route(route)
        except ops.TacticalOperationRegistrationError:
            return "unparsed"
        try:
            ops._check_route_owner({"id": module_id, "category": category.get(module_id) or "core"}, segments, route)
            return "ok"
        except ops.TacticalOperationRegistrationError as exc:
            return str(exc).replace("\\", "/")

    checked = 0
    for module_id, route in found:
        with_new = judge(module_id, route)
        ops.ROUTE_OWNERS.clear(); ops.ROUTE_OWNERS.update(old_rules)
        try:
            with_old = judge(module_id, route)
        finally:
            ops.ROUTE_OWNERS.clear(); ops.ROUTE_OWNERS.update(rules)
        if with_new == "unparsed":
            continue
        if module_id == "remote-background" and with_new == "ok" and with_old != "ok" and ("/files" in route or "/file-browser-defaults" in route):
            continue  # 1.18.33: remote-background declares its file routes now, which is what the two owner rules are for
        checked += 1
        must(with_new == with_old, f"{module_id} {route}: judged differently now. before: {with_old}; now: {with_new}")
        third = route.split("/")
        must(not (third[0] == "agents" and len(third) > 2 and third[2].startswith("{") and ":" not in third[2]),
             f"{module_id} {route}: an untyped parameter at the third segment under agents/ appeared")
    must(checked >= 20, f"too few routes checked: {checked}")
    print(f"       compatibility: {checked} declared routes of {len({m for m, _ in found})} modules judged exactly as before")
else:
    print("       compatibility check skipped: modules/ is not beside this repository")

print("[TEST] PASS tactical operation file browser routes, uuid kind and path query values 1.18.30")
