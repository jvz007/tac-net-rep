#!/usr/bin/env python3
"""1.17.22 regression: client records carry their sites and site records carry client_name (core.resources 1.4.0 -> 1.5.0).

Tactical's own GET /clients/ returns each client with its sites cut to the caller's scope, so List clients alone is enough to
build a client and site tree. The real resources.py and resources_adapter.py run here on the in-memory Tactical of
tests/resource-alert-template-1.17.17.py (its harness). Django and the real database are dev server only:
tests/resource-client-sites-runtime-1.17.22.py.
"""
from __future__ import annotations

import pathlib

_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())
H = globals()
must, resources, adapter, reset_tactical, Site, Client, User, Role, AUDITS, ctx_for, ROOT = (
    H[k] for k in ("must", "resources", "adapter", "reset_tactical", "Site", "Client", "User", "Role", "AUDITS", "ctx_for", "ROOT"))

reset_tactical()


def refused(call):
    try:
        call()
    except resources.ResourcePermissionDenied as exc:
        assert exc.code == "resource_permission_denied"
        return exc
    raise AssertionError("call was accepted")


def names(items):
    return [row["name"] for row in items]


# the cast: clients 1 (sites 11, 12) and 2 (site 21)
clients_only = User(Role(clients=[1]))
clients_only.role.can_list_sites = False        # List clients, no List sites
sites_only = User(Role(sites=[11]))
sites_only.role.can_list_clients = False        # List sites, no List clients
both = User(Role(clients=[1], sites=[21]))
neither = User(Role(clients=[1]))
neither.role.can_list_clients = neither.role.can_list_sites = False
admin = User(Role())
root = User(Role(superuser=True), superuser=True)

# 1. a client-limited role with List clients and no List sites: its client with nested in-scope sites, sites read refused
page = resources.list_clients(context=ctx_for(clients_only))
must(names(page["items"]) == ["Alpha"], page)
must(names(page["items"][0]["sites"]) == ["Alpha One", "Alpha Two"], page["items"][0]["sites"])
refused(lambda: resources.list_sites(context=ctx_for(clients_only)))

# 2. a site-only role with List sites: site records carry client_name, clients read refused
listed = resources.list_sites(context=ctx_for(sites_only))
must(names(listed["items"]) == ["Alpha One"] and listed["items"][0]["client_name"] == "Alpha", listed)
refused(lambda: resources.list_clients(context=ctx_for(sites_only)))
must(resources.get_site(11, context=ctx_for(sites_only))["client_name"] == "Alpha", "get_site")

# 3. a role holding both reads gets both
mixed_page = resources.list_clients(context=ctx_for(both))
must(names(mixed_page["items"]) == ["Alpha", "Beta"], mixed_page)
alpha, beta = mixed_page["items"]
must(names(alpha["sites"]) == ["Alpha One", "Alpha Two"] and names(beta["sites"]) == ["Beta One"], mixed_page)
must(len(resources.list_sites(context=ctx_for(both))["items"]) == 3, "both: sites read")

# 4. neither flag: both reads refused, unchanged
refused(lambda: resources.list_clients(context=ctx_for(neither)))
refused(lambda: resources.list_sites(context=ctx_for(neither)))

# 5. an unrestricted caller and a trusted service context get every site
for context in (ctx_for(admin), ctx_for(root)):
    rows = resources.list_clients(context=context)["items"]
    must([len(r["sites"]) for r in rows] == [2, 1], rows)
service = resources.trusted_service_context(actor="governance", purpose="test", global_access=True)
must([len(r["sites"]) for r in resources.list_clients(context=service)["items"]] == [2, 1], "service context")

# 6. the nested site record has the shape and key order of a list_sites record
nested = resources.list_clients(context=ctx_for(admin))["items"][0]["sites"][0]
flat = next(r for r in resources.list_sites(context=ctx_for(admin))["items"] if r["id"] == nested["id"])
must(nested == flat and tuple(nested) == resources.SITE_FIELDS, (nested, flat))
must(all(tuple(r) == resources.CLIENT_FIELDS for r in resources.list_clients(context=ctx_for(admin))["items"]), "client key order")
must(resources.CLIENT_FIELDS[5] == "sites" and resources.SITE_FIELDS[6] == "client_name", "appended after the earlier keys (1.7.0 appends the policy keys after them)")
must(tuple(resources.get_client(1, context=ctx_for(admin))) == resources.CLIENT_FIELDS, "get_client key order")
must(tuple(resources.resolve_resource("client", 1, context=ctx_for(admin))) == resources.CLIENT_FIELDS, "resolve_resource")

# 7. one sites query per page, however many clients
calls = []
real = adapter.sites_by_client
adapter.sites_by_client = lambda ids, **kw: calls.append(sorted(ids)) or real(ids, **kw)
resources.list_clients(context=ctx_for(admin))
must(calls == [[1, 2]], calls)
calls.clear()
resources.get_client(1, context=ctx_for(admin))
must(calls == [[1]], calls)
adapter.sites_by_client = real

# 8. get_client for a site-only role nests only the granted site (a role with List clients and a site grant of client 1)
site_reader = User(Role(sites=[11]))
got = resources.get_client(1, context=ctx_for(site_reader))
must(names(got["sites"]) == ["Alpha One"], got)

# 9. a client with no site in scope has an empty list
Site.STORE.pop(21)
must(resources.get_client(2, context=ctx_for(admin))["sites"] == [], "empty list")
reset_tactical()

# 10. update results carry sites; audit rows for client and site writes contain no sites and no client_name
AUDITS.clear()
writer = User(Role(clients=[1]))
updated = resources.update_client(1, name="Alpha Renamed", context=ctx_for(writer))
must(names(updated["sites"]) == ["Alpha One", "Alpha Two"] and tuple(updated) == resources.CLIENT_FIELDS, updated)
site_updated = resources.update_site(11, name="Alpha One Renamed", context=ctx_for(writer))
must(site_updated["client_name"] == "Alpha Renamed" and tuple(site_updated) == resources.SITE_FIELDS, site_updated)
for row in AUDITS:
    for side in ("before", "after"):
        record = row.get(side) or {}
        must("sites" not in record and "client_name" not in record, (row["action"], side, record))
must(len(AUDITS) == 2, AUDITS)

# 11. metadata
meta = resources.resource_contract_metadata()
must(meta["version"] == "1.12.0" and resources.CONTRACT_VERSION == "1.12.0", meta["version"])  # 1.8.0 (Core 1.17.25, CQ79)
must(meta["version"].split(".")[0] == "1", "still major 1")
must(meta["resource_types"]["client"]["fields"][5] == "sites" and meta["resource_types"]["site"]["fields"][6] == "client_name", "fields")
must("client_sites" in meta and "site_client_name" in meta and "role_reads" in meta and "role_scope_lists" in meta, sorted(meta))
must("create_client" in meta["mutation_contracts"] and "create_site" in meta["mutation_contracts"], "mutation contracts")

# 12. docs and contracts name the rule
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("Contract version: `1.12.0`" in doc and "client_name" in doc and "List clients only" in doc, "docs/resource-directory.md")
contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must("core.resources 1.5.0" in contracts, "contracts.py")

# 13. the installer's bounds still admit 1.5.0
installer = (ROOT / "install.sh").read_text(encoding="utf-8")
must(">=1.1.0,<2.0.0" in installer, "install.sh range")

print("[TEST] PASS resource client sites 1.17.22")
