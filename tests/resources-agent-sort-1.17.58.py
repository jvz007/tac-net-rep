#!/usr/bin/env python3
"""1.17.58 regression: sort_by and sort_dir on the agent list (core.resources 1.11.0 -> 1.12.0).

Closes the request "core.resources: sort_by and sort_dir on the agent list" (agent-management 0.15.0). The real resources.py,
resources_adapter.py and resource_views.py run against the in-memory Tactical of tests/resource-alert-template-1.17.17.py, with an
order_by that understands the real column names, a stand-in for ``F(...).asc/desc(nulls_last=True)`` and a query log. The real SQL
ordering needs Django and a database, which only the dev server has.

Covered: every key in both directions; the default order is the 1.17.57 order; last_seen puts a never-seen agent last in both
directions; a tie-break keeps paging stable; 400 for an unknown key, an unknown direction, an empty-but-present value, a wrong case and a
non-text value (Python and HTTP); a valid sort_dir without sort_by is accepted and ignored; the scope is applied before the page and the
count, with a sort on; the query count is one count and one page query; the metadata and the contract version.
"""
from __future__ import annotations

import datetime as dt
import pathlib
import sys

sys.dont_write_bytecode = True
_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())  # noqa: S102 - test-only: the shared harness
H = globals()
must, resources, adapter, views = H["must"], H["resources"], H["adapter"], H["views"]
reset_tactical, Client, Site, Agent, User, Role = H["reset_tactical"], H["Client"], H["Site"], H["Agent"], H["User"], H["Role"]
Query, QUERY_LOG, ctx_for = H["Query"], H["QUERY_LOG"], H["ctx_for"]

ORDERS = []  # the order_by arguments of every agent query


class Expr:
    def __init__(self, field, descending, nulls_last):
        self.field, self.descending, self.nulls_last = field, descending, nulls_last


class F:
    def __init__(self, field):
        self.field = field

    def asc(self, nulls_last=False):
        return Expr(self.field, False, nulls_last)

    def desc(self, nulls_last=False):
        return Expr(self.field, True, nulls_last)


sys.modules["django.db.models"].F = F


def value(row, field):
    site = Site.STORE[row["site_id"]]
    if field == "site__client__name":
        return Client.STORE[site["client_id"]]["name"]
    if field == "site__name":
        return site["name"]
    if field == "site__client_id":
        return site["client_id"]
    return row.get(field)


_plain_order_by = Query.order_by


def order_by(self, *fields):
    if self.model is not Agent:
        return _plain_order_by(self, *fields)
    ORDERS.append(fields)
    rows = list(self.rows)
    for item in reversed(fields):  # stable sorts from the last key to the first
        if isinstance(item, Expr):
            name, descending, nulls_last = item.field, item.descending, item.nulls_last
        else:
            name, descending, nulls_last = item.lstrip("-"), item.startswith("-"), False
        present = sorted((r for r in rows if value(r, name) is not None), key=lambda r: value(r, name), reverse=descending)
        missing = [r for r in rows if value(r, name) is None]
        rows = present + missing if (nulls_last or not descending) else missing + present
    return Query(self.model, rows)


Query.order_by = order_by

T = lambda day: dt.datetime(2026, 10, day, 12, 0, tzinfo=dt.timezone.utc)  # noqa: E731
AGENTS = [  # id, hostname, site, platform, last_seen
    ("a-1", "delta", 11, "windows", T(10)),
    ("a-2", "alpha", 21, "linux", T(18)),
    ("a-3", "charlie", 12, "windows", None),
    ("a-4", "bravo", 11, "darwin", T(12)),
    ("a-5", "echo", 21, "linux", None),
    ("a-6", "alpha", 12, "linux", T(15)),  # same hostname as a-2: the tie-break decides
]


def world():
    reset_tactical()
    Agent.STORE.clear()
    del ORDERS[:], QUERY_LOG[:]
    for n, (agent_id, host, site, plat, seen) in enumerate(AGENTS, start=1):
        Agent.STORE[agent_id] = {"pk": n, "agent_id": agent_id, "hostname": host, "site_id": site, "site__client_id": Site.STORE[site]["client_id"],
                                 "plat": plat, "monitoring_type": "workstation", "last_seen": seen}


def ids(answer):
    return [row["id"] for row in answer["items"]]


class Req:
    def __init__(self, user, query=None):
        self.user, self.data, self.query_params = user, None, dict(query or {})


def http(user, **query):
    view = views.ResourceListView()
    view.resource_type = "agent"
    return view.get(Req(user, query))


def refused(call):
    try:
        call()
    except resources.ResourceValidationError as exc:
        return str(exc)
    raise AssertionError("expected a refusal")


admin = User(Role())
site_11 = User(Role(sites=[11]))
ctx = ctx_for(admin)

must(resources.CONTRACT_VERSION == "1.12.0", resources.CONTRACT_VERSION)

# (1) the default order is the 1.17.57 order: client, site, hostname, agent id
world()
default = ids(resources.list_agents(context=ctx))
must(default == ["a-4", "a-1", "a-6", "a-3", "a-2", "a-5"], default)
must(ORDERS[-1] == ("site__client_id", "site_id", "hostname", "agent_id"), ORDERS[-1])
must(ids(resources.list_agents(context=ctx, sort_dir="desc")) == default, "sort_dir alone does not change the order")
must(ids(http(admin).data) == default, "HTTP without a sort")
print("       the default order is client, site, hostname, agent id, as before")

# (2) every key in both directions, the tie-break after the chosen column
EXPECT = {
    ("hostname", "asc"): ["a-6", "a-2", "a-4", "a-3", "a-1", "a-5"],   # alpha twice: a-6 (client 1) before a-2 (client 2)
    ("hostname", "desc"): ["a-5", "a-1", "a-3", "a-4", "a-6", "a-2"],
    ("client", "asc"): ["a-4", "a-1", "a-6", "a-3", "a-2", "a-5"],
    ("client", "desc"): ["a-2", "a-5", "a-4", "a-1", "a-6", "a-3"],
    ("site", "asc"): ["a-4", "a-1", "a-6", "a-3", "a-2", "a-5"],       # Alpha One, Alpha Two, Beta One
    ("site", "desc"): ["a-2", "a-5", "a-6", "a-3", "a-4", "a-1"],
    ("platform", "asc"): ["a-4", "a-6", "a-2", "a-5", "a-1", "a-3"],   # darwin, linux x3, windows x2
    ("platform", "desc"): ["a-1", "a-3", "a-6", "a-2", "a-5", "a-4"],
    ("last_seen", "asc"): ["a-1", "a-4", "a-6", "a-2", "a-3", "a-5"],
    ("last_seen", "desc"): ["a-2", "a-6", "a-4", "a-1", "a-3", "a-5"],
}
world()
for (key, direction), expected in EXPECT.items():
    got = ids(resources.list_agents(context=ctx, sort_by=key, sort_dir=direction))
    must(got == expected, (key, direction, got, expected))
    must(ids(http(admin, sort_by=key, sort_dir=direction).data) == expected, (key, direction, "http"))
    must(ids(resources.list_agents(context=ctx, sort_by=key)) == ids(resources.list_agents(context=ctx, sort_by=key, sort_dir="asc")), "asc is the default")
print("       all five keys order correctly in both directions, over Python and HTTP")

# (3) last_seen: a never-seen agent is last in both directions, and the tie-break follows the chosen column
for direction in ("asc", "desc"):
    got = resources.list_agents(context=ctx, sort_by="last_seen", sort_dir=direction)["items"]
    must([r["last_seen"] is None for r in got] == [False] * 4 + [True] * 2, (direction, [r["last_seen"] for r in got]))
    must(ORDERS[-1][0].nulls_last is True and ORDERS[-1][0].descending is (direction == "desc"), ORDERS[-1])
    must(ORDERS[-1][1:] == ("site__client_id", "site_id", "hostname", "agent_id"), ORDERS[-1])
print("       last_seen puts agents that never reported last, both ways")

# (4) paging stays stable under a sort
pages = []
for page in (1, 2, 3):
    pages += ids(resources.list_agents(context=ctx, sort_by="platform", page=page, page_size=2))
must(pages == EXPECT[("platform", "asc")] and len(set(pages)) == 6, pages)
must(http(admin, sort_by="hostname", page="2", page_size="2").data["page"] == 2, "page and sort together")
print("       paging walks the sorted list without a repeat or a gap")

# (5) strict validation: Python and HTTP
for bad in ["", "Hostname", "HOSTNAME", "name", "hostname ", "client_id", "platform,site", "last-seen", "id"]:
    world()
    refused(lambda bad=bad: resources.list_agents(context=ctx, sort_by=bad))
    response = http(admin, sort_by=bad)
    must(response.status_code == 400 and response.data["code"] == "invalid_resource_request" and "sort_by" in response.data["detail"], (bad, response.data))
    must(not QUERY_LOG, ("no query ran for", bad))
for bad in ["", "ASC", "up", "descending", "1", " desc"]:
    refused(lambda bad=bad: resources.list_agents(context=ctx, sort_by="hostname", sort_dir=bad))
    response = http(admin, sort_by="hostname", sort_dir=bad)
    must(response.status_code == 400 and "sort_dir" in response.data["detail"], (bad, response.data))
    must(http(admin, sort_dir=bad).status_code == 400, "a bad direction is refused even without sort_by")
for odd in (1, True, ["hostname"], b"hostname"):
    refused(lambda odd=odd: resources.list_agents(context=ctx, sort_by=odd))
refused(lambda: resources.list_agents(context=ctx, sort_by="hostname", sort_dir=7))
must(http(admin, sort_dir="desc").status_code == 200, "a valid sort_dir without sort_by is accepted and ignored")
print("       an unknown key or direction, an empty value, a wrong case and a non-text value are all 400")

# (6) the scope is applied before the sort, the count and the page
world()
for key in ("hostname", "client", "site", "platform", "last_seen"):
    for direction in ("asc", "desc"):
        answer = resources.list_agents(context=ctx_for(site_11), sort_by=key, sort_dir=direction)
        must(set(ids(answer)) == {"a-1", "a-4"} and answer["count"] == 2, (key, direction, ids(answer), answer["count"]))
        must(all(r["site_id"] == 11 for r in answer["items"]), "no row of another site")
        paged = resources.list_agents(context=ctx_for(site_11), sort_by=key, sort_dir=direction, page=1, page_size=1)
        must(paged["count"] == 2 and paged["pages"] == 2 and len(paged["items"]) == 1, paged)
must(resources.list_agents(context=ctx_for(site_11), sort_by="hostname")["items"][0]["id"] == "a-4", "bravo before delta inside the site")
must(ids(resources.list_agents(context=ctx, site_id=12, sort_by="hostname", sort_dir="desc")) == ["a-3", "a-6"], "filter and sort")
print("       a site-limited user never sees or counts another site's agents, with a sort on")

# (7) the query count does not grow: one count and one page query
for kwargs in ({}, {"sort_by": "hostname"}, {"sort_by": "client", "sort_dir": "desc"}, {"sort_by": "last_seen", "sort_dir": "desc"}):
    world()
    resources.list_agents(context=ctx, **kwargs)
    must([op for model, op in QUERY_LOG if model == "Agent"] == ["count", "values"], (kwargs, QUERY_LOG))
print("       one count query and one page query, sorted or not")

# (8) get_agent is untouched; the metadata names the sort
world()
must(resources.get_agent("a-3", context=ctx)["hostname"] == "charlie", "get_agent")
agent_meta = resources.resource_contract_metadata()["resource_types"]["agent"]
must(agent_meta["sort"]["sort_by"] == ["hostname", "client", "site", "platform", "last_seen"] and agent_meta["sort"]["sort_dir"] == ["asc", "desc"], agent_meta)
must(resources.resource_contract_metadata()["version"] == "1.12.0", "metadata version")
print("[TEST] PASS resources agent sort 1.17.58")
