#!/usr/bin/env python3
"""1.17.17 regression: the role scope descriptor and has_whole_client_access (core.resources 1.4.0).

One descriptor, computed once in resources_adapter from the same rule Scheduler targets, report row scope and client writes use, so
no module reads Tactical's Role again: ``role_scope_descriptor(user)`` and, on ``core.resources``, ``scope_descriptor(context=)``,
``scope_unrestricted(context)``, ``has_whole_client_access(client_id, context=)`` and ``ResourceAccessContext.scope``.
Uses the harness of tests/resource-alert-template-1.17.17.py (real resources.py and resources_adapter.py on an in-memory Tactical).
"""
from __future__ import annotations

import pathlib

_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())
H = globals()
must, resources, adapter, reset_tactical, Site, User, Role, ROOT, PKG = (H[k] for k in ("must", "resources", "adapter", "reset_tactical", "Site", "User", "Role", "ROOT", "PKG"))

reset_tactical()


def U(role, **kw):
    return User(role, **kw)


def ids(**kw):
    return Role(**kw)


# the cast: clients 1 and 2, sites 11 and 12 (client 1) and 21 (client 2)
superuser = U(ids(superuser=True), superuser=True)
role_superuser = U(ids(superuser=True))
empty_relations = U(ids())
clients_only = U(ids(clients=[1]))
clients_two = U(ids(clients=[2, 1]))            # unsorted on purpose: the descriptor sorts
sites_only = U(ids(sites=[11]))                 # a site of client 1, and nothing else
sites_two = U(ids(sites=[21, 11]))
mixed = U(ids(clients=[2], sites=[11]))
no_role = U(None)
installer = U(ids(clients=[1]), installer=True)
raising = U(ids(clients=[1], boom=True))
no_list_flags = U(ids(clients=[1], list_perms=False))


def D(user):
    return adapter.role_scope_descriptor(user)


def shape(d):
    return (d["mode"], d["unrestricted"], d["whole_client_ids"], d["site_ids"], d["whole_client_count"], d["site_count"])


# ------------------------------------------------------------------------------------------------ the descriptor
none = ("none", False, [], [], 0, 0)
must(shape(D(superuser)) == ("unrestricted", True, [], [], 0, 0), D(superuser))
must(shape(D(role_superuser)) == ("unrestricted", True, [], [], 0, 0), D(role_superuser))
must(shape(D(empty_relations)) == ("unrestricted", True, [], [], 0, 0), "both relations empty is Tactical's own unrestricted rule")
must(shape(D(clients_only)) == ("clients", False, [1], [], 1, 0), D(clients_only))
must(shape(D(clients_two)) == ("clients", False, [1, 2], [], 2, 0), "sorted ids")
must(shape(D(sites_only)) == ("sites", False, [], [11], 0, 1), D(sites_only))
must(shape(D(sites_two)) == ("sites", False, [], [11, 21], 0, 2), D(sites_two))
must(shape(D(mixed)) == ("mixed", False, [2], [11], 1, 1), D(mixed))
# site_ids are the explicit grants only, never the sites of a granted client
must(D(clients_only)["site_ids"] == [] and 11 not in D(clients_only)["site_ids"], "no sites of granted clients")
# no role, an installer user, no user, an unauthenticated user and a raising relation all fail closed
must(shape(D(no_role)) == none, D(no_role))
must(shape(D(installer)) == none, "an installer user has no scope")
must(shape(D(raising)) == none, "a lookup failure reads as none")
must(shape(D(None)) == none, "no user")
anon = U(ids(clients=[1]))
anon.is_authenticated = False
must(shape(D(anon)) == none, "unauthenticated")
must(all(not D(u)["unrestricted"] for u in (no_role, installer, raising, None)), "none is never unrestricted")
# the keys are exactly these and the lists are new every time
must(list(D(mixed)) == ["mode", "unrestricted", "whole_client_ids", "site_ids", "whole_client_count", "site_count"], list(D(mixed)))
first = D(clients_only)
first["whole_client_ids"].append(99)
must(D(clients_only)["whole_client_ids"] == [1], "a caller cannot change what the next call returns")
import json
json.dumps(D(mixed))

# ------------------------------------------------------------------------------------------------ the core.resources functions
for user in (superuser, role_superuser, empty_relations, clients_only, sites_only, mixed, no_role, installer, raising):
    context = resources.user_context(user)
    must(resources.scope_descriptor(context=context) == D(user), "scope_descriptor is the adapter's descriptor")
    must(context.scope == D(user), "ResourceAccessContext.scope matches scope_descriptor")
    must(resources.scope_unrestricted(context) is D(user)["unrestricted"], "scope_unrestricted")
    must(resources.scope_unrestricted(context=context) is D(user)["unrestricted"], "scope_unrestricted as a keyword")
# it is lazy and never cached on the frozen context
context = resources.user_context(clients_only)
must(context.scope["mode"] == "clients", context.scope)
clients_only.role.can_view_sites.ids.append(11)
must(context.scope["mode"] == "mixed" and context.scope["site_ids"] == [11], "read when asked, so it reflects the role now")
clients_only.role.can_view_sites.ids.remove(11)
try:
    context.scope = {}
    raise AssertionError("the context is frozen")
except Exception as exc:
    must(type(exc).__name__ in ("FrozenInstanceError", "AttributeError"), exc)
must("scope" not in vars(context), "nothing is stored on the context")
# a scope question only: no can_list_clients or can_list_sites is needed
must(resources.scope_descriptor(context=resources.user_context(no_list_flags))["mode"] == "clients", "no list flag needed")
must(resources.has_whole_client_access(1, context=resources.user_context(no_list_flags)) is True, "no list flag needed")
refused = None  # (the helper of the alert template test is not used here)


def denied(call, *errors):
    try:
        call()
    except errors as exc:
        return exc
    raise AssertionError(f"call was accepted: {call}")


# ------------------------------------------------------------------------------------------------ has_whole_client_access
def whole(user, client_id):
    return resources.has_whole_client_access(client_id, context=resources.user_context(user))


for user in (superuser, role_superuser, empty_relations):
    must(whole(user, 1) is True and whole(user, 2) is True, "an unrestricted caller holds every existing client")
    must(whole(user, 999) is False, "but the client must exist")
must(whole(clients_only, 1) is True and whole(clients_only, 2) is False, "a granted client, an ungranted one")
must(whole(clients_only, 999) is False, "a missing client")
must(whole(clients_two, 1) is True and whole(clients_two, 2) is True, "two grants")
# a site-only role never holds a whole client, not even the one that owns its site
must(whole(sites_only, 1) is False and whole(sites_only, 2) is False, "a site-only role holds no whole client")
must(whole(sites_two, 1) is False and whole(sites_two, 2) is False, "even the client of a granted site")
must(whole(mixed, 2) is True and whole(mixed, 1) is False, "mixed: the granted client only")
must(whole(no_role, 1) is False and whole(installer, 1) is False and whole(raising, 1) is False, "no role, installer and a failed lookup are False")
must(whole(clients_only, "1") is True and whole(clients_only, " 1 ") is True, "a numeric text id is read like the other functions read it")
for bad in ("x", "", None, 0, -1, True, [], "1; drop", {}):
    denied(lambda bad=bad: whole(superuser, bad), resources.ResourceValidationError)
    denied(lambda bad=bad: whole(clients_only, bad), resources.ResourceValidationError)
# a trusted global service context is unrestricted with whole access to every existing client
service = resources.ResourceAccessContext(service_actor="governance", service_purpose="test", trusted_global=True)
must(resources.has_whole_client_access(1, context=service) is True and resources.has_whole_client_access(2, context=service) is True, "service: every client")
must(resources.has_whole_client_access(999, context=service) is False, "service: a missing client")
must(resources.scope_unrestricted(service) is True and shape(resources.scope_descriptor(context=service)) == ("unrestricted", True, [], [], 0, 0), "service descriptor")
must(service.scope["unrestricted"] is True, "service context.scope")
denied(lambda: resources.has_whole_client_access("x", context=service), resources.ResourceValidationError)
# a service context that is not global, a missing user and a wrong context are refused
not_global = resources.ResourceAccessContext(service_actor="governance", service_purpose="test", trusted_global=False)
for call in (lambda: resources.has_whole_client_access(1, context=not_global), lambda: resources.scope_descriptor(context=not_global),
             lambda: resources.scope_unrestricted(not_global), lambda: not_global.scope):
    denied(call, resources.ResourcePermissionDenied)
nobody = resources.ResourceAccessContext(user=None)
anonymous = resources.ResourceAccessContext(user=anon)
for context in (nobody, anonymous, object(), None):
    denied(lambda context=context: resources.has_whole_client_access(1, context=context), resources.ResourcePermissionDenied)
    denied(lambda context=context: resources.scope_descriptor(context=context), resources.ResourcePermissionDenied)
    denied(lambda context=context: resources.scope_unrestricted(context), resources.ResourcePermissionDenied)

# ------------------------------------------------------------------------------------------------ one rule: the descriptor agrees with the others
reset_tactical()
fixture = {
    "superuser": superuser, "role_superuser": role_superuser, "empty": empty_relations, "clients_only": clients_only, "clients_two": clients_two,
    "sites_only": sites_only, "sites_two": sites_two, "mixed": mixed, "no_role": no_role,
}
for label, user in fixture.items():
    d = D(user)
    snapshot = adapter.scheduler_scope_snapshot(user=user)
    report = adapter.report_scope_ids(user)
    must(snapshot["unrestricted"] is d["unrestricted"] and report["unrestricted"] is d["unrestricted"], (label, "unrestricted", d, snapshot, report))
    if d["unrestricted"]:
        continue
    must(set(snapshot["client_ids"]) == set(d["whole_client_ids"]), (label, "scheduler client_ids", snapshot, d))
    must(set(report["client_ids"]) == set(d["whole_client_ids"]), (label, "report client_ids", report, d))
    # the sites Tactical shows are the explicit grants plus the sites of the whole clients
    from_whole = {s["pk"] for s in Site.STORE.values() if s["client_id"] in d["whole_client_ids"]}
    must(set(snapshot["site_ids"]) == set(d["site_ids"]) | from_whole and set(report["site_ids"]) == set(snapshot["site_ids"]), (label, "sites", snapshot, report, d))
    must(report.get("denied", False) is (d["mode"] == "none"), (label, "denied", report))
for label, user in fixture.items():
    if user.role is None:
        continue  # client_write_in_scope reads no role as no write scope; whole access is False for it as well
    d = D(user)
    for client_id in (1, 2):
        expected = d["unrestricted"] or client_id in d["whole_client_ids"]
        must(adapter.client_write_in_scope(user=user, client_id=client_id) is expected, (label, client_id, "client_write_in_scope"))
        must(whole(user, client_id) is expected, (label, client_id, "has_whole_client_access"))
        must(adapter.explicit_client_target_ids_in_scope(user=user, client_ids=[client_id]) == ({client_id} if expected else set()), (label, client_id, "explicit ids"))
    for site_id in (11, 12, 21):
        client_of_site = Site.STORE[site_id]["client_id"]
        expected = d["unrestricted"] or site_id in d["site_ids"] or client_of_site in d["whole_client_ids"]
        must(adapter.site_write_in_scope(user=user, site_id=site_id) is expected, (label, site_id, "site_write_in_scope"))

# ------------------------------------------------------------------------------------------------ the public contract names them
meta = resources.resource_contract_metadata()
for op in ("scope_descriptor", "scope_unrestricted", "has_whole_client_access"):
    must(op in meta["operations"], op)
must(meta["context_properties"] == ["ResourceAccessContext.scope"], meta.get("context_properties"))
must(meta["mutation_contracts"]["scope_descriptor"]["response"]["mode"] == "unrestricted | clients | sites | mixed | none", "response shape")
registration = resources.register_core_resources_capability()
for op in ("scope_descriptor", "scope_unrestricted", "has_whole_client_access"):
    must(op in registration["operations"] and callable(getattr(registration["provider"], op)), op)
provider = registration["provider"]
must(provider.scope_unrestricted(resources.user_context(superuser)) is True and provider.has_whole_client_access(1, context=resources.user_context(clients_only)) is True, "provider")
contracts = (PKG / "contracts.py").read_text(encoding="utf-8")
for needle in ('"name":"scope_descriptor"', '"name":"scope_unrestricted"', '"name":"has_whole_client_access"', '"name":"ResourceAccessContext"', "tactical_scope"):
    must(needle in contracts, needle)
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("has_whole_client_access" in doc and "tactical_scope" in doc and "`mixed`" in doc, "docs/resource-directory.md")

print("[TEST] PASS resource scope descriptor 1.17.17")
