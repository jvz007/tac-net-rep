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

rbac = types.ModuleType("tec_tac.rbac")
rbac.has_extension_permission = lambda user, codename: codename in getattr(user, "core_permissions", set())
sys.modules["tec_tac.rbac"] = rbac

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
class TacticalResourceAdapterError(RuntimeError): pass
class TacticalResourceConflictError(TacticalResourceAdapterError): pass
adapter.TacticalResourceAdapterError = TacticalResourceAdapterError
adapter.TacticalResourceConflictError = TacticalResourceConflictError

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

def client_write_in_scope(*, user, client_id):
    return client_id in user.allowed_clients

def site_write_in_scope(*, user, site_id):
    site = next((r for r in DATA["sites"] if r["id"] == site_id), None)
    if site is None:
        return False
    return site_id in user.allowed_sites or site["client_id"] in user.allowed_clients

def create_client_row(*, name):
    if any(r["name"].lower() == name.lower() for r in DATA["clients"]):
        raise TacticalResourceConflictError("A client with that name already exists.")
    new_id = max(r["id"] for r in DATA["clients"]) + 1
    row = {"type":"client","id":new_id,"name":name,"active":True}
    DATA["clients"].append(row)
    return dict(row)

def update_client_row(*, user, client_id, name):
    if not client_write_in_scope(user=user, client_id=client_id): return None
    row = next((r for r in DATA["clients"] if r["id"] == client_id), None)
    if row is None: return None
    if any(r["id"] != client_id and r["name"].lower() == name.lower() for r in DATA["clients"]):
        raise TacticalResourceConflictError("A client with that name already exists.")
    row["name"] = name
    return dict(row)

def create_site_row(*, client_id, name):
    if any(r["client_id"] == client_id and r["name"].lower() == name.lower() for r in DATA["sites"]):
        raise TacticalResourceConflictError("A site with that name already exists for the selected client.")
    new_id = max(r["id"] for r in DATA["sites"]) + 1
    row = {"type":"site","id":new_id,"name":name,"client_id":client_id,"active":True}
    DATA["sites"].append(row)
    return dict(row)

def update_site_row(*, user, site_id, name=None, client_id=None):
    if not site_write_in_scope(user=user, site_id=site_id): return None
    row = next((r for r in DATA["sites"] if r["id"] == site_id), None)
    if row is None: return None
    target_client = client_id if client_id is not None else row["client_id"]
    target_name = name if name is not None else row["name"]
    if any(r["id"] != site_id and r["client_id"] == target_client and r["name"].lower() == target_name.lower() for r in DATA["sites"]):
        raise TacticalResourceConflictError("A site with that name already exists for the selected client.")
    if name is not None: row["name"] = name
    if client_id is not None: row["client_id"] = client_id
    return dict(row)

adapter.client_write_in_scope = client_write_in_scope
adapter.site_write_in_scope = site_write_in_scope
adapter.create_client_row = create_client_row
adapter.update_client_row = update_client_row
adapter.create_site_row = create_site_row
adapter.update_site_row = update_site_row
sys.modules["tec_tac.resources_adapter"] = adapter

spec = importlib.util.spec_from_file_location("tec_tac.resources", PKG / "resources.py")
resources = importlib.util.module_from_spec(spec)
sys.modules["tec_tac.resources"] = resources
spec.loader.exec_module(resources)

class Role:
    def __init__(self, *, clients=True, sites=True, agents=True, manage_clients=True, manage_sites=True, superuser=False):
        self.can_list_clients = clients
        self.can_list_sites = sites
        self.can_list_agents = agents
        self.can_manage_clients = manage_clients
        self.can_manage_sites = manage_sites
        self.is_superuser = superuser

class User:
    is_authenticated = True
    is_superuser = False
    def __init__(self, role, *, clients=(), sites=(), agents=(), core_permissions=()):
        self.role = role
        self.allowed_clients = set(clients)
        self.allowed_sites = set(sites)
        self.allowed_agents = set(agents)
        self.core_permissions = set(core_permissions)

u = User(Role(), clients={1}, sites={11,12}, agents={"a-1"}, core_permissions={"core.resources.clients.manage", "core.resources.sites.manage"})
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

# Create/update is additive and preserves stable record shapes.
created_client = resources.create_client(name="Gamma", context=ctx)
assert tuple(created_client) == resources.CLIENT_FIELDS and created_client["name"] == "Gamma"
u.allowed_clients.add(created_client["id"])
updated_client = resources.update_client(created_client["id"], name="Gamma Renamed", context=ctx)
assert updated_client["name"] == "Gamma Renamed"

created_site = resources.create_site(client_id=1, name="Alpha Three", context=ctx)
assert tuple(created_site) == resources.SITE_FIELDS and created_site["client_id"] == 1
u.allowed_sites.add(created_site["id"])
updated_site = resources.update_site(created_site["id"], name="Alpha Three Renamed", context=ctx)
assert updated_site["name"] == "Alpha Three Renamed"

# Core RBAC and Tactical manage permissions are both required for writes.
missing_core = resources.user_context(User(Role(), clients={1}, sites={11}, core_permissions=set()))
for fn, kwargs in ((resources.create_client, {"name":"Denied"}), (resources.create_site, {"client_id":1, "name":"Denied"})):
    try:
        fn(context=missing_core, **kwargs)
        raise AssertionError("write unexpectedly bypassed Core RBAC")
    except resources.ResourcePermissionDenied:
        pass
missing_tactical = resources.user_context(User(Role(manage_clients=False, manage_sites=False), clients={1}, sites={11}, core_permissions={"core.resources.clients.manage", "core.resources.sites.manage"}))
for fn, kwargs in ((resources.create_client, {"name":"Denied2"}), (resources.create_site, {"client_id":1, "name":"Denied2"})):
    try:
        fn(context=missing_tactical, **kwargs)
        raise AssertionError("write unexpectedly bypassed Tactical manage permission")
    except resources.ResourcePermissionDenied:
        pass

# Read visibility must never become broader write scope.  A Tactical role can
# see client 2 transitively because it can see site 21, while native client
# object writes still permit only explicitly allowed client 1.
transitive = User(Role(), clients={1}, sites={21}, core_permissions={"core.resources.clients.manage", "core.resources.sites.manage"})
transitive_ctx = resources.user_context(transitive)
for fn, kwargs in (
    (resources.update_client, {"client_id": 2, "name": "Denied rename"}),
    (resources.create_site, {"client_id": 2, "name": "Denied create"}),
    (resources.update_site, {"site_id": 11, "client_id": 2}),
):
    try:
        fn(context=transitive_ctx, **kwargs)
        raise AssertionError("read visibility became write scope")
    except (resources.ResourceNotFound, resources.ResourcePermissionDenied):
        pass

# Site create/move is constrained to a visible client.
try:
    resources.create_site(client_id=2, name="Foreign", context=ctx)
    raise AssertionError("site created outside client scope")
except resources.ResourceNotFound:
    pass
try:
    resources.update_site(created_site["id"], client_id=2, context=ctx)
    raise AssertionError("site moved outside client scope")
except resources.ResourceNotFound:
    pass

# Duplicate names surface a stable conflict, not Tactical ORM details.
try:
    resources.create_client(name="Alpha", context=ctx)
    raise AssertionError("duplicate client unexpectedly created")
except resources.ResourceConflict:
    pass

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
try:
    resources.create_client(name="Service Write", context=service)
    raise AssertionError("trusted read service unexpectedly received write authority")
except resources.ResourcePermissionDenied:
    pass
p1 = resources.list_sites(context=service, page=1, page_size=2)
assert p1["count"] == 4 and len(p1["items"]) == 2 and p1["next_page"] == 2
p2 = resources.list_sites(context=service, page=2, page_size=2)
assert len(p2["items"]) == 2 and p2["previous_page"] == 1
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
assert meta["id"] == "core.resources" and meta["version"] == "1.1.0"
registration = resources.register_core_resources_capability()
assert registration["module_id"] == "core" and registration["id"] == "core.resources"
assert set(meta["resource_types"]) == {"client", "site", "agent"}
assert meta["read_only"] is False
assert meta["write_support"]["client"] == ["create", "update"]
assert meta["write_support"]["site"] == ["create", "update"]
assert meta["write_support"]["agent"] == []
assert meta["rbac"]["client_write"] == "core.resources.clients.manage"
assert meta["rbac"]["site_write"] == "core.resources.sites.manage"

# Tactical model implementation details stay in the adapter, not public contract.
public_source = (PKG / "resources.py").read_text(encoding="utf-8")
adapter_source = (PKG / "resources_adapter.py").read_text(encoding="utf-8")
assert "from clients.models" not in public_source and "from agents.models" not in public_source
assert "from clients.models import Client, Site" in adapter_source
assert "from agents.models import Agent" in adapter_source
assert "filter_by_role" in adapter_source

print("[TEST] PASS Core Resource Directory contract")
