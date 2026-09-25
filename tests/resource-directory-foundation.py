#!/usr/bin/env python3
"""Pure contract regression for Core Resource Directory (no Tactical DB required)."""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"

# Load tec_tac.resources in isolation while replacing the Tactical adapter with
# an in-memory scope-aware adapter. This keeps the contract test independent of
# Tactical's current model implementation.
pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(PKG)]
sys.modules["tec_tac"] = pkg

capabilities = types.ModuleType("tec_tac.capabilities")
capabilities.register_capability = lambda **kwargs: kwargs
sys.modules["tec_tac.capabilities"] = capabilities

DATA = {
    "clients": [
        {"type": "client", "id": 1, "name": "Alpha", "active": True},
        {"type": "client", "id": 2, "name": "Beta", "active": True},
    ],
    "sites": [
        {"type": "site", "id": 11, "name": "Alpha One", "client_id": 1, "active": True},
        {"type": "site", "id": 12, "name": "Alpha Two", "client_id": 1, "active": True},
        {"type": "site", "id": 21, "name": "Beta One", "client_id": 2, "active": True},
    ],
    "agents": [
        {"type": "agent", "id": "a-1", "hostname": "ALPHA-PC", "client_id": 1, "site_id": 11, "active": True, "platform": "windows", "monitoring_type": "workstation", "last_seen": None},
        {"type": "agent", "id": "a-2", "hostname": "BETA-SRV", "client_id": 2, "site_id": 21, "active": True, "platform": "linux", "monitoring_type": "server", "last_seen": None},
    ],
}

class FakeQS:
    def __init__(self, rows): self.rows = list(rows)

adapter = types.ModuleType("tec_tac.resources_adapter")

def scoped(rows, user, trusted, kind):
    if trusted: return list(rows)
    allowed = getattr(user, f"allowed_{kind}", set())
    return [row for row in rows if row["id"] in allowed]

def clients_queryset(*, user=None, trusted=False, search=None, active=None):
    rows = scoped(DATA["clients"], user, trusted, "clients")
    if active is False: rows = []
    if search: rows = [r for r in rows if search.lower() in r["name"].lower()]
    return FakeQS(rows)

def sites_queryset(*, user=None, trusted=False, client_id=None, search=None, active=None):
    rows = scoped(DATA["sites"], user, trusted, "sites")
    if client_id is not None: rows = [r for r in rows if r["client_id"] == client_id]
    if active is False: rows = []
    if search: rows = [r for r in rows if search.lower() in r["name"].lower()]
    return FakeQS(rows)

def agents_queryset(*, user=None, trusted=False, client_id=None, site_id=None, search=None, active=None):
    rows = scoped(DATA["agents"], user, trusted, "agents")
    if client_id is not None: rows = [r for r in rows if r["client_id"] == client_id]
    if site_id is not None: rows = [r for r in rows if r["site_id"] == site_id]
    if active is False: rows = []
    if search: rows = [r for r in rows if search.lower() in (r["hostname"] + r["id"]).lower()]
    return FakeQS(rows)

def page(qs, offset, limit): return list(qs.rows[offset:offset+limit]), len(qs.rows)
def get(qs, rid): return next((dict(r) for r in qs.rows if r["id"] == rid), None)
adapter.clients_queryset = clients_queryset
adapter.sites_queryset = sites_queryset
adapter.agents_queryset = agents_queryset
adapter.page_clients = lambda qs, *, offset, limit: page(qs, offset, limit)
adapter.page_sites = lambda qs, *, offset, limit: page(qs, offset, limit)
adapter.page_agents = lambda qs, *, offset, limit: page(qs, offset, limit)
adapter.get_client_row = lambda qs, rid: get(qs, rid)
adapter.get_site_row = lambda qs, rid: get(qs, rid)
adapter.get_agent_row = lambda qs, rid: get(qs, rid)
sys.modules["tec_tac.resources_adapter"] = adapter

spec = importlib.util.spec_from_file_location("tec_tac.resources", PKG / "resources.py")
resources = importlib.util.module_from_spec(spec)
sys.modules["tec_tac.resources"] = resources
spec.loader.exec_module(resources)

class Role:
    def __init__(self, *, clients=True, sites=True, agents=True, superuser=False):
        self.can_list_clients = clients
        self.can_list_sites = sites
        self.can_list_agents = agents
        self.is_superuser = superuser

class User:
    is_authenticated = True
    is_superuser = False
    def __init__(self, role, *, clients=(), sites=(), agents=()):
        self.role = role
        self.allowed_clients = set(clients)
        self.allowed_sites = set(sites)
        self.allowed_agents = set(agents)

u = User(Role(), clients={1}, sites={11,12}, agents={"a-1"})
ctx = resources.user_context(u)

# Required list/get paths and stable shapes.
clients = resources.list_clients(context=ctx)
assert [x["id"] for x in clients["items"]] == [1]
assert tuple(clients["items"][0]) == resources.CLIENT_FIELDS
assert resources.get_client(1, context=ctx)["name"] == "Alpha"

sites = resources.list_sites(context=ctx)
assert [x["id"] for x in sites["items"]] == [11,12]
assert tuple(sites["items"][0]) == resources.SITE_FIELDS
assert [x["id"] for x in resources.list_sites(context=ctx, client_id=1)["items"]] == [11,12]
assert resources.get_site(11, context=ctx)["client_id"] == 1

agents = resources.list_agents(context=ctx)
assert [x["id"] for x in agents["items"]] == ["a-1"]
assert tuple(agents["items"][0]) == resources.AGENT_FIELDS
assert [x["id"] for x in resources.list_agents(context=ctx, client_id=1)["items"]] == ["a-1"]
assert [x["id"] for x in resources.list_agents(context=ctx, site_id=11)["items"]] == ["a-1"]
assert resources.get_agent("a-1", context=ctx)["hostname"] == "ALPHA-PC"

# Site/resource isolation: caller cannot resolve another scoped resource.
for fn, rid in ((resources.get_client, 2), (resources.get_site, 21), (resources.get_agent, "a-2")):
    try:
        fn(rid, context=ctx)
        raise AssertionError("out-of-scope resource unexpectedly resolved")
    except resources.ResourceNotFound:
        pass

# Missing resource has the same not-found result as an out-of-scope one.
try:
    resources.get_agent("does-not-exist", context=ctx)
    raise AssertionError("missing agent unexpectedly resolved")
except resources.ResourceNotFound:
    pass

# Permission checks are independent from scope filters.
no_site = resources.user_context(User(Role(sites=False), clients={1}, sites={11}, agents={"a-1"}))
try:
    resources.list_sites(context=no_site)
    raise AssertionError("site list permission was not enforced")
except resources.ResourcePermissionDenied:
    pass

# Pagination and filtering.
service = resources.trusted_service_context(actor="governance", purpose="test", global_access=True)
p1 = resources.list_sites(context=service, page=1, page_size=2)
assert p1["count"] == 3 and len(p1["items"]) == 2 and p1["next_page"] == 2
p2 = resources.list_sites(context=service, page=2, page_size=2)
assert len(p2["items"]) == 1 and p2["previous_page"] == 1
assert resources.list_clients(context=service, search="bet")["items"][0]["id"] == 2
assert resources.list_agents(context=service, active=False)["count"] == 0

# Generic resolver and context safety.
assert resources.resolve_resource("site", 21, context=service)["id"] == 21
for bad in (None, object()):
    try:
        resources.list_clients(context=bad)
        raise AssertionError("implicit authority unexpectedly accepted")
    except resources.ResourcePermissionDenied:
        pass
try:
    resources.trusted_service_context(actor="governance", purpose="test")
    raise AssertionError("service context unexpectedly received implicit global access")
except resources.ResourcePermissionDenied:
    pass

# Contract metadata is versioned and discoverable.
meta = resources.resource_contract_metadata()
assert meta["id"] == "core.resources" and meta["version"] == "1.0.0"
registration = resources.register_core_resources_capability()
assert registration["module_id"] == "core" and registration["id"] == "core.resources"
assert set(meta["resource_types"]) == {"client", "site", "agent"}
assert meta["read_only"] is True

# Tactical model implementation details stay in the adapter, not public contract.
public_source = (PKG / "resources.py").read_text(encoding="utf-8")
adapter_source = (PKG / "resources_adapter.py").read_text(encoding="utf-8")
assert "from clients.models" not in public_source and "from agents.models" not in public_source
assert "from clients.models import Client, Site" in adapter_source
assert "from agents.models import Agent" in adapter_source
assert "filter_by_role" in adapter_source

print("[TEST] PASS Core Resource Directory contract")
