#!/usr/bin/env python3
"""1.17.40 regression: failing_checks, agent_count and maintenance_mode on client and site records (core.resources 1.9.0 -> 1.10.0).

Request 'endpoints 0.7.0: failing_checks, agent_count and maintenance_mode on the core.resources client and site records'. The real
resources.py and resources_adapter.py run against the in-memory Tactical of tests/resource-alert-template-1.17.17.py (extended with a
grouped Count, a query log and failing_checks columns). Django and Tactical's own ClientSerializer are dev-server only:
tests/resource-live-state-runtime-1.17.40.py.
"""
from __future__ import annotations

import pathlib

_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())  # noqa: S102 - test-only: the shared harness
H = globals()
must, resources, adapter, reset_tactical, Client, Site, Agent, User, Role, ROOT, AUDITS, QUERY_LOG, ctx_for = (
    H[k] for k in ("must", "resources", "adapter", "reset_tactical", "Client", "Site", "Agent", "User", "Role", "ROOT", "AUDITS", "QUERY_LOG", "ctx_for"))

LIVE = ("failing_checks", "agent_count", "maintenance_mode")
NONE = {"error": False, "warning": False}


def world():
    """Clients 1 (sites 11, 12) and 2 (site 21). Site 11: 3 agents, one in maintenance. Site 12: 2 agents, failing error. Site 21: none."""
    reset_tactical()
    Agent.STORE.clear()
    for n, (site, maint) in enumerate([(11, False), (11, True), (11, False), (12, False), (12, False)], start=1):
        Agent.STORE[f"a-{n}"] = {"pk": n, "agent_id": f"a-{n}", "site_id": site, "maintenance_mode": maint}
    Site.STORE[12]["failing_checks"] = {"error": True, "warning": False}
    Client.STORE[1]["failing_checks"] = {"error": True, "warning": True}  # Tactical's stored client value (also covers hidden sites)


def shape(row):
    return {k: row[k] for k in LIVE}


def triple(row):
    return (row["agent_count"], row["maintenance_mode"], row["failing_checks"])


admin = User(Role())
whole = User(Role(clients=[1]))
site_11 = User(Role(sites=[11]))
site_12 = User(Role(sites=[12]))
no_role = User(None)
root = User(Role(superuser=True), superuser=True)

# ------------------------------------------------------------------------------------------------ shape and key order
world()
ctx = ctx_for(admin)
CLIENT_TAIL = ("block_policy_inheritance", *LIVE)
must(resources.CONTRACT_VERSION == "1.10.0", resources.CONTRACT_VERSION)
must(resources.CLIENT_FIELDS[-4:] == CLIENT_TAIL and resources.SITE_FIELDS[-4:] == CLIENT_TAIL, "the live keys come last")
clients = resources.list_clients(context=ctx)["items"]
sites = resources.list_sites(context=ctx)["items"]
must(all(tuple(c) == resources.CLIENT_FIELDS for c in clients), [tuple(c) for c in clients])
must(all(tuple(s) == resources.SITE_FIELDS for s in sites), [tuple(s) for s in sites])
must(all(tuple(s) == resources.SITE_FIELDS for c in clients for s in c["sites"]), "nested sites carry the keys in order")
must(tuple(resources.get_client(1, context=ctx)) == resources.CLIENT_FIELDS and tuple(resources.get_site(11, context=ctx)) == resources.SITE_FIELDS, "gets")
must(tuple(resources.resolve_resource("client", 1, context=ctx)) == resources.CLIENT_FIELDS, "resolve client")
must(tuple(resources.resolve_resource("site", 12, context=ctx)) == resources.SITE_FIELDS, "resolve site")

# ------------------------------------------------------------------------------------------------ values, unrestricted
by_site = {s["id"]: s for s in sites}
must(triple(by_site[11]) == (3, True, NONE), triple(by_site[11]))
must(triple(by_site[12]) == (2, False, {"error": True, "warning": False}), triple(by_site[12]))
must(triple(by_site[21]) == (0, False, NONE), triple(by_site[21]))
by_client = {c["id"]: c for c in clients}
must(triple(by_client[1]) == (5, True, {"error": True, "warning": True}), triple(by_client[1]))   # Tactical's stored client value
must(triple(by_client[2]) == (0, False, NONE), triple(by_client[2]))
must({s["id"]: triple(s) for s in by_client[1]["sites"]} == {11: triple(by_site[11]), 12: triple(by_site[12])}, "nested site values equal the site read")
must(shape(resources.get_site(11, context=ctx)) == shape(by_site[11]) and shape(resources.get_client(1, context=ctx)) == shape(by_client[1]), "get equals list")
must(type(by_site[11]["agent_count"]) is int and type(by_site[11]["maintenance_mode"]) is bool, "types")

# malformed stored JSON reads both false
for bad in (None, "x", ["error"], {"error": "x", "warning": 1}, {"error": 1}, {}):
    Site.STORE[21]["failing_checks"] = bad
    must(resources.get_site(21, context=ctx)["failing_checks"] == NONE, bad)
Site.STORE[21].pop("failing_checks", None)

# ------------------------------------------------------------------------------------------------ scope rule (AD-12)
world()
must(triple(resources.get_client(1, context=ctx_for(whole))) == (5, True, {"error": True, "warning": True}), "a client-limited role sees the full client")
site_client = resources.get_client(1, context=ctx_for(site_11))
must([s["id"] for s in site_client["sites"]] == [11], "a site-only role sees one nested site")
must(triple(site_client) == (3, True, NONE), triple(site_client))          # hidden site 12 neither fails nor counts; the stored client value is not used
other = resources.get_client(1, context=ctx_for(site_12))
must(triple(other) == (2, False, {"error": True, "warning": False}), triple(other))   # OR of the visible site only
listed = {c["id"]: c for c in resources.list_clients(context=ctx_for(site_11))["items"]}
must(set(listed) == {1} and triple(listed[1]) == triple(site_client), "list equals get for the limited role")
must(triple(resources.resolve_resource("client", 1, context=ctx_for(site_11))) == triple(site_client), "resolve equals get")
must(triple(resources.get_site(11, context=ctx_for(site_11))) == (3, True, NONE), "the granted site")
# a caller that sees no site of the client: the adapter gives 0, false, both false
bare = adapter.attach_sites([adapter.client_row({"pk": 2, "name": "Beta"})], {})[0]
must(triple(bare) == (0, False, NONE) and tuple(bare) == resources.CLIENT_FIELDS, bare)
# a trusted global service context sees everything
service = resources.trusted_service_context(actor="live-state-test", purpose="read", global_access=True)
must(triple(resources.get_client(1, context=service)) == (5, True, {"error": True, "warning": True}), "global service context")
must(triple(resources.get_site(12, context=service)) == (2, False, {"error": True, "warning": False}), "global service site")
# a superuser (role superuser) is unrestricted
must(triple(resources.get_client(1, context=ctx_for(root))) == (5, True, {"error": True, "warning": True}), "superuser")
# a role with no role object sees nothing
try:
    resources.get_client(1, context=ctx_for(no_role))
    raise AssertionError("no role got a client")
except (resources.ResourceNotFound, resources.ResourcePermissionDenied):
    pass

# a client with a partly visible site set whose hidden site is the failing one: the client does not fail
world()
Client.STORE[1]["failing_checks"] = {"error": True, "warning": False}
Site.STORE[12]["failing_checks"] = {"error": True, "warning": False}
Site.STORE[11]["failing_checks"] = {"error": False, "warning": True}
partial = resources.get_client(1, context=ctx_for(site_11))
must(partial["failing_checks"] == {"error": False, "warning": True}, partial["failing_checks"])

# ------------------------------------------------------------------------------------------------ agent records carry none of them
world()
for _agent in Agent.STORE.values():
    _agent.update({"hostname": _agent["agent_id"].upper(), "site__client_id": 1, "plat": "windows", "monitoring_type": "workstation", "last_seen": None})
agents = resources.list_agents(context=ctx)["items"]
must(agents and all(not (set(a) & set(LIVE)) for a in agents), agents)
must(not (set(resources.get_agent("a-1", context=ctx)) & set(LIVE)), "get_agent")

# ------------------------------------------------------------------------------------------------ writes return the live keys; audit stays clean
world()
wctx = ctx_for(admin)
created = resources.create_client(name="Gamma", site_name="Gamma One", context=wctx)
must(tuple(created) == resources.CLIENT_FIELDS and triple(created) == (0, False, NONE), created)
must(tuple(created["sites"][0]) == resources.SITE_FIELDS and triple(created["sites"][0]) == (0, False, NONE), created["sites"])
new_site = resources.create_site(client_id=1, name="Alpha Three", context=wctx)
must(tuple(new_site) == resources.SITE_FIELDS and triple(new_site) == (0, False, NONE), new_site)
renamed = resources.update_client(1, name="Alpha B", context=wctx)
must(tuple(renamed) == resources.CLIENT_FIELDS and renamed["agent_count"] == 5 and renamed["maintenance_mode"] is True, renamed)
must(all(tuple(s) == resources.SITE_FIELDS for s in renamed["sites"]), "nested sites after update_client")
moved = resources.update_site(11, name="Alpha One B", context=wctx)
must(tuple(moved) == resources.SITE_FIELDS and triple(moved) == (3, True, NONE), moved)
for entry in AUDITS:
    for side in ("before", "after"):
        row = entry.get(side)
        must(row is None or not (set(row) & set(LIVE)), (entry["action"], side, row))
must(any(e["action"] == "modify" for e in AUDITS), "the renames wrote modify rows")

# a Tactical refresh of failing_checks between the read and the save writes no spurious modify row
world()
del AUDITS[:]
original_client, original_site = adapter.update_client_row, adapter.update_site_row


def refresh_client(**kw):
    Client.STORE[1]["failing_checks"] = {"error": False, "warning": True}   # Tactical's cache task ran between the read and the write
    return original_client(**kw)


def refresh_site(**kw):
    Site.STORE[11]["failing_checks"] = {"error": True, "warning": True}
    return original_site(**kw)


adapter.update_client_row, adapter.update_site_row = refresh_client, refresh_site
try:
    out = resources.update_client(1, name="Alpha", context=wctx)
    must(not AUDITS and out["failing_checks"]["warning"] is True, (AUDITS, out))
    out = resources.update_site(11, name="Alpha One", context=wctx)
    must(not AUDITS and out["failing_checks"] == {"error": True, "warning": True}, (AUDITS, out))
    out = resources.update_site(11, client_id=1, context=wctx)   # the same-client early return carries the keys too
    must(tuple(out) == resources.SITE_FIELDS and not AUDITS, (out, AUDITS))
finally:
    adapter.update_client_row, adapter.update_site_row = original_client, original_site


# ------------------------------------------------------------------------------------------------ a bounded query count per page
def queries(call):
    del QUERY_LOG[:]
    call()
    return list(QUERY_LOG)


def grow(extra):
    world()
    for n in range(extra):
        client_pk = 100 + n
        Client.STORE[client_pk] = {"pk": client_pk, "name": f"Bulk {n}", "alert_template_id": None, **H["POLICY_DEFAULTS"]}
        for s in range(2):
            site_pk = 1000 + n * 10 + s
            Site.STORE[site_pk] = {"pk": site_pk, "name": f"Bulk {n}-{s}", "client_id": client_pk, "alert_template_id": None, **H["POLICY_DEFAULTS"]}
            Agent.STORE[f"b-{n}-{s}"] = {"pk": 5000 + n * 10 + s, "agent_id": f"b-{n}-{s}", "site_id": site_pk, "maintenance_mode": s == 0}


counts = {}
for extra in (1, 30):
    grow(extra)
    counts[extra] = (len(queries(lambda: resources.list_clients(context=ctx, page_size=500))), len(queries(lambda: resources.list_sites(context=ctx, page_size=500))),
                     len(queries(lambda: resources.list_clients(context=ctx_for(site_11), page_size=500))))
    agent_queries = [q for q in queries(lambda: resources.list_clients(context=ctx, page_size=500)) if q[0] == "Agent"]
    must(len(agent_queries) == 1, agent_queries)                    # one grouped agent query per page, never one per row
must(counts[1] == counts[30], counts)                               # the number of queries does not grow with the rows
must(counts[30][1] <= 6 and counts[30][0] <= 10, counts)
grow(30)
page = resources.list_sites(context=ctx, page_size=500)["items"]
must(len(page) == 63 and all(tuple(s) == resources.SITE_FIELDS for s in page), len(page))
must(triple(next(s for s in page if s["name"] == "Bulk 3-0")) == (1, True, NONE) and triple(next(s for s in page if s["name"] == "Bulk 3-1")) == (1, False, NONE), "bulk values")

# ------------------------------------------------------------------------------------------------ the contract text
meta = resources.resource_contract_metadata()
must(meta["version"] == "1.10.0" and meta["version"].split(".")[0] == "1", meta["version"])
must(all(k in meta["resource_types"]["client"]["fields"] and k in meta["resource_types"]["site"]["fields"] for k in LIVE), meta["resource_types"])
must(not (set(LIVE) & set(meta["resource_types"]["agent"]["fields"])), "agent fields")
text = meta["failing_checks_agent_count_maintenance_mode"]
must(all(k in text for k in LIVE) and "1.10.0" in text and "no List agents flag" in text, text)
must("AD-12" in meta["live_state"] and "hidden site" in meta["live_state"] and "last refresh" in meta["live_state"], meta.get("live_state"))
registration = resources.register_core_resources_capability()
must(registration["version"] == "1.10.0", registration["version"])
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("Contract version: `1.10.0`" in doc and "Contract 1.10 (Core 1.17.40" in doc and "#### Live state (since 1.10.0" in doc, "docs header and section")
must("OR of the visible sites" in doc and "Stale by design" in doc and "constant number of queries" in doc, "docs scope rule")
source = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
for name in ("list_clients", "get_client", "list_sites", "get_site"):
    start = source.index(f'"name":"{name}"')
    row = source[start: source.index("\n", start)]
    must(all(k in row for k in LIVE) and "1.10.0" in row, f"contracts.py row {name} names the three keys")
print("[TEST] PASS resource live state 1.17.40")
