#!/usr/bin/env python3
"""1.17.24 regression: policy fields on client and site records (core.resources 1.6.0 -> 1.7.0; C9, AU8, AU10).

Core holds only the ids: Automation owns the policy list. The real resources.py, resources_adapter.py and resource_views.py run
here against the in-memory Tactical of tests/resource-alert-template-1.17.17.py (a policy id that does not exist fails
``full_clean`` like Tactical's ForeignKey, and Tactical's own save hook is recorded). Django, Tactical and the real ForeignKey
are dev-server only: tests/resource-policy-runtime-1.17.24.py.
"""
from __future__ import annotations

import pathlib

_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())
H = globals()
must, resources, adapter, views = H["must"], H["resources"], H["adapter"], H["views"]
reset_tactical, Client, Site, User, Role = H["reset_tactical"], H["Client"], H["Site"], H["User"], H["Role"]
AUDITS, HOOKS, ctx_for, ROOT, PKG = H["AUDITS"], H["HOOKS"], H["ctx_for"], H["ROOT"], H["PKG"]

POLICY_KEYS = ("workstation_policy_id", "server_policy_id", "block_policy_inheritance")
reset_tactical()
admin = User(Role())
whole_client = User(Role(clients=[1]))
site_only = User(Role(sites=[11]))
client_limited = User(Role(clients=[2]))
no_manage = User(Role(manage=False))
no_core = User(Role(), core=())
root = User(Role(superuser=True), superuser=True)
ctx_admin, ctx_whole, ctx_site = ctx_for(admin), ctx_for(whole_client), ctx_for(site_only)


def refused(call, *errors):
    try:
        call()
    except errors as exc:
        return exc
    raise AssertionError(f"call was accepted: {call}")


# ----------------------------------------------------------------------------------- record shape and field order
must(resources.CONTRACT_VERSION == "1.10.0", resources.CONTRACT_VERSION)
must(resources.CLIENT_FIELDS[-6:-3] == POLICY_KEYS and resources.SITE_FIELDS[-6:-3] == POLICY_KEYS, "appended last")
must(resources.CLIENT_FIELDS[:6] == ("type", "id", "name", "active", "alert_template_id", "sites"), resources.CLIENT_FIELDS)
must(resources.SITE_FIELDS[:7] == ("type", "id", "name", "client_id", "active", "alert_template_id", "client_name"), resources.SITE_FIELDS)
clients = resources.list_clients(context=ctx_admin)["items"]
must(all(tuple(row) == resources.CLIENT_FIELDS for row in clients), clients[0])
must(all(tuple(site) == resources.SITE_FIELDS for row in clients for site in row["sites"]), "nested sites carry the policy keys in order")
must(all(tuple(row) == resources.SITE_FIELDS for row in resources.list_sites(context=ctx_admin)["items"]), "list_sites")
must(tuple(resources.get_client(1, context=ctx_admin)) == resources.CLIENT_FIELDS and tuple(resources.get_site(11, context=ctx_admin)) == resources.SITE_FIELDS, "gets")
must(tuple(resources.resolve_resource("site", 11, context=ctx_admin)) == resources.SITE_FIELDS, "resolve_resource")
must(clients[0]["workstation_policy_id"] is None and clients[0]["server_policy_id"] is None and clients[0]["block_policy_inheritance"] is False, clients[0])
# defaults when the keys are missing (rows built for deletes)
bare_client = adapter.client_row({"pk": 4, "name": "X"})
bare_site = adapter.site_row({"pk": 5, "name": "Y", "client_id": 4})
must(tuple(bare_client) == ("type", "id", "name", "active", "alert_template_id", *POLICY_KEYS) and tuple(bare_site)[-3:] == POLICY_KEYS, (bare_client, bare_site))
must((bare_client["workstation_policy_id"], bare_client["server_policy_id"], bare_client["block_policy_inheritance"]) == (None, None, False), bare_client)
must(adapter.client_row({"pk": 4, "name": "X", "workstation_policy_id": "31", "block_policy_inheritance": 1})["workstation_policy_id"] == 31, "ids are integers")
nested = adapter.nest_sites([bare_client], user=admin, trusted=True)[0]
must(tuple(nested) == resources.CLIENT_FIELDS, tuple(nested))

# ----------------------------------------------------------------------------------- client: set, clear, leave alone
del AUDITS[:], HOOKS[:]
row = resources.update_client(1, workstation_policy_id=31, context=ctx_whole)
must(row["workstation_policy_id"] == 31 and row["server_policy_id"] is None and row["block_policy_inheritance"] is False and tuple(row) == resources.CLIENT_FIELDS, row)
must(Client.STORE[1]["workstation_policy_id"] == 31 and Client.STORE[1]["name"] == "Alpha", "persisted; the name is untouched")
must(HOOKS == [("client", 1)], "Tactical's own save hook ran")
audit = AUDITS[-1]
must(len(AUDITS) == 1 and audit["action"] == "modify" and audit["object_type"] == "resource_client" and audit["strict"] is True, audit)
must(audit["before"]["workstation_policy_id"] is None and audit["after"]["workstation_policy_id"] == 31, audit)
must(audit["metadata"] == {"alert_template_changed": False, "policy_changed": ["workstation_policy_id"]}, audit["metadata"])
row = resources.update_client(1, server_policy_id=32, block_policy_inheritance=True, context=ctx_whole)
must((row["workstation_policy_id"], row["server_policy_id"], row["block_policy_inheritance"]) == (31, 32, True), row)
must(AUDITS[-1]["metadata"]["policy_changed"] == ["server_policy_id", "block_policy_inheritance"], AUDITS[-1]["metadata"])
# a name-only update leaves the policy alone and has no policy_changed key
row = resources.update_client(1, name="Alpha B", context=ctx_whole)
must(row["workstation_policy_id"] == 31 and row["server_policy_id"] == 32 and row["block_policy_inheritance"] is True, row)
must("policy_changed" not in AUDITS[-1]["metadata"], AUDITS[-1]["metadata"])
resources.update_client(1, name="Alpha", context=ctx_whole)
# UNSET is the same as leaving the keyword out
resources.update_client(1, name="Alpha", workstation_policy_id=resources.UNSET, context=ctx_whole)
must(Client.STORE[1]["workstation_policy_id"] == 31, "UNSET leaves it")
# None clears; false clears the flag
row = resources.update_client(1, workstation_policy_id=None, block_policy_inheritance=False, context=ctx_whole)
must(row["workstation_policy_id"] is None and row["block_policy_inheritance"] is False and row["server_policy_id"] == 32, row)
must(AUDITS[-1]["metadata"]["policy_changed"] == ["workstation_policy_id", "block_policy_inheritance"], AUDITS[-1]["metadata"])
# a digit string is accepted
must(resources.update_client(1, server_policy_id=" 33 ", context=ctx_whole)["server_policy_id"] == 33, "digits as text")
# the update_fields: the model fields, no stray ones
obj = Client.objects.filter(pk=1).first()
adapter.update_client_row(user=admin, client_id=1, workstation_policy_id=31, server_policy_id=None, block_policy_inheritance=True)
must(sorted(Client.objects.filter(pk=1).first().__dict__["last_update_fields"] or []) == [], "a fresh object has no recorded fields")
saved = {}
orig_save = Client.save


def spy_save(self, update_fields=None):
    saved["fields"] = list(update_fields or [])
    return orig_save(self, update_fields=update_fields)


Client.save = spy_save
adapter.update_client_row(user=admin, client_id=1, workstation_policy_id=32, server_policy_id=31, block_policy_inheritance=False)
Client.save = orig_save
must(saved["fields"][:3] == ["workstation_policy", "server_policy", "block_policy_inheritance"], saved)
# an unchanged value is not saved by the adapter at all
Client.save = spy_save
saved.clear()
adapter.update_client_row(user=admin, client_id=1, workstation_policy_id=32, server_policy_id=31, block_policy_inheritance=False)
Client.save = orig_save
must("fields" not in saved, "an unchanged policy is not saved")

# ----------------------------------------------------------------------------------- the same for a site
reset_tactical()
del AUDITS[:], HOOKS[:]
row = resources.update_site(11, workstation_policy_id=31, server_policy_id=32, block_policy_inheritance=True, context=ctx_whole)
must((row["workstation_policy_id"], row["server_policy_id"], row["block_policy_inheritance"]) == (31, 32, True) and tuple(row) == resources.SITE_FIELDS, row)
must(Site.STORE[11]["workstation_policy_id"] == 31 and HOOKS == [("site", 11)], (Site.STORE[11], HOOKS))
must(AUDITS[-1]["object_type"] == "resource_site" and AUDITS[-1]["metadata"]["policy_changed"] == list(POLICY_KEYS), AUDITS[-1]["metadata"])
must(AUDITS[-1]["before"]["server_policy_id"] is None and AUDITS[-1]["after"]["server_policy_id"] == 32, AUDITS[-1])
row = resources.update_site(11, server_policy_id=None, context=ctx_whole)
must(row["server_policy_id"] is None and row["workstation_policy_id"] == 31 and row["block_policy_inheritance"] is True, row)
row = resources.update_site(11, name="Alpha One B", context=ctx_whole)
must(row["workstation_policy_id"] == 31 and "policy_changed" not in AUDITS[-1]["metadata"], row)
resources.update_site(11, name="Alpha One", context=ctx_whole)
# a nested site carries the policy too
nested_row = resources.get_client(1, context=ctx_admin)
must(next(s for s in nested_row["sites"] if s["id"] == 11)["workstation_policy_id"] == 31, nested_row["sites"])

# ----------------------------------------------------------------------------------- validation
for call in (lambda: resources.update_client(1, context=ctx_whole), lambda: resources.update_site(11, context=ctx_admin)):
    exc = refused(call, resources.ResourceValidationError)
    must("At least one" in str(exc) and "block_policy_inheritance" in str(exc), exc)
for bad in (True, False, 0, -1, "abc", "5.5", "", " ", "-3", 1.5, 31.0, [], {}, 2**63, "١٢"):
    for key in ("workstation_policy_id", "server_policy_id"):
        refused(lambda bad=bad, key=key: resources.update_client(1, context=ctx_whole, **{key: bad}), resources.ResourceValidationError)
        refused(lambda bad=bad, key=key: resources.update_site(11, context=ctx_admin, **{key: bad}), resources.ResourceValidationError)
for bad in (1, 0, "true", "false", "yes", None, [], {}, 1.0):
    refused(lambda bad=bad: resources.update_client(1, block_policy_inheritance=bad, context=ctx_whole), resources.ResourceValidationError)
    refused(lambda bad=bad: resources.update_site(11, block_policy_inheritance=bad, context=ctx_admin), resources.ResourceValidationError)
must(Client.STORE[1]["workstation_policy_id"] is None and Site.STORE[11]["workstation_policy_id"] == 31, "refused values change nothing")
# a policy that does not exist: plain 400 text, nothing stored, no hook, no row
del AUDITS[:], HOOKS[:]
for key in ("workstation_policy_id", "server_policy_id"):
    for kind, call in (("client", lambda key=key: resources.update_client(1, context=ctx_whole, **{key: 99})),
                       ("site", lambda key=key: resources.update_site(11, context=ctx_admin, **{key: 99}))):
        exc = refused(call, resources.ResourceValidationError)
        must(str(exc) == f"{key} does not name an existing policy." and exc.code == "invalid_resource_request", (kind, str(exc)))
must(Client.STORE[1]["server_policy_id"] is None and not AUDITS and not HOOKS, "a missing policy writes nothing")
# the alert template message is unchanged
exc = refused(lambda: resources.update_client(1, alert_template_id=99, context=ctx_whole), resources.ResourceValidationError)
must(str(exc) == "alert_template_id does not name an existing alert template.", exc)

# ----------------------------------------------------------------------------------- an unchanged value writes no row
reset_tactical()
resources.update_client(1, workstation_policy_id=31, block_policy_inheritance=True, context=ctx_whole)
del AUDITS[:], HOOKS[:]
row = resources.update_client(1, workstation_policy_id=31, block_policy_inheritance=True, context=ctx_whole)
must(row["workstation_policy_id"] == 31 and not AUDITS and not HOOKS, (AUDITS, HOOKS))
resources.update_site(11, server_policy_id=32, context=ctx_whole)
del AUDITS[:], HOOKS[:]
resources.update_site(11, server_policy_id=32, context=ctx_whole)
must(not AUDITS and not HOOKS, "site: same value, no row")

# ----------------------------------------------------------------------------------- scope and permission, same as a rename
reset_tactical()
exc = refused(lambda: resources.update_client(1, workstation_policy_id=31, context=ctx_site), resources.ResourceNotFound)   # a site-only role
exc = refused(lambda: resources.update_client(1, workstation_policy_id=31, context=ctx_for(client_limited)), resources.ResourceNotFound)  # another client
must(Client.STORE[1]["workstation_policy_id"] is None, "refused: nothing changed")
must(resources.update_site(11, workstation_policy_id=31, context=ctx_site)["workstation_policy_id"] == 31, "a site grant may set the site's policy")
refused(lambda: resources.update_site(12, workstation_policy_id=31, context=ctx_site), resources.ResourceNotFound)
refused(lambda: resources.update_site(11, workstation_policy_id=32, context=ctx_for(client_limited)), resources.ResourceNotFound)
refused(lambda: resources.update_client(1, workstation_policy_id=31, context=ctx_for(no_manage)), resources.ResourcePermissionDenied)
refused(lambda: resources.update_site(11, workstation_policy_id=31, context=ctx_for(no_manage)), resources.ResourcePermissionDenied)
refused(lambda: resources.update_client(1, workstation_policy_id=31, context=ctx_for(no_core)), resources.ResourcePermissionDenied)
refused(lambda: resources.update_site(11, workstation_policy_id=31, context=ctx_for(no_core)), resources.ResourcePermissionDenied)
service = resources.ResourceAccessContext(service_actor="automation", service_purpose="test", trusted_global=True)
refused(lambda: resources.update_client(1, workstation_policy_id=31, context=service), resources.ResourcePermissionDenied)
refused(lambda: resources.update_site(11, workstation_policy_id=31, context=service), resources.ResourcePermissionDenied)
must(not hasattr(Role(), "can_manage_automation_policies"), "the test role has no can_manage_automation_policies and still succeeded above")
must(resources.update_client(2, server_policy_id=33, context=ctx_for(root))["server_policy_id"] == 33, "a superuser passes")
# reads: anyone who can list sees the ids (a site-only role reads its site)
must(resources.get_site(11, context=ctx_site)["workstation_policy_id"] == 31, "the site read shows it")

# ----------------------------------------------------------------------------------- list filters
reset_tactical()
resources.update_client(1, alert_template_id=5, workstation_policy_id=31, context=ctx_admin)
resources.update_client(2, alert_template_id=6, server_policy_id=31, context=ctx_admin)
resources.update_site(11, alert_template_id=5, context=ctx_admin)
resources.update_site(21, workstation_policy_id=32, server_policy_id=31, context=ctx_admin)


def client_ids(**kw):
    return [r["id"] for r in resources.list_clients(context=kw.pop("context", ctx_admin), **kw)["items"]]


def site_ids(**kw):
    return [r["id"] for r in resources.list_sites(context=kw.pop("context", ctx_admin), **kw)["items"]]


must(client_ids() == [1, 2] and site_ids() == [11, 12, 21], "no filter, all rows")
must(client_ids(alert_template_id=5) == [1] and client_ids(alert_template_id=6) == [2] and client_ids(alert_template_id=7) == [], "client template filter")
must(client_ids(policy_id=31) == [1, 2], "policy matches the workstation or the server policy")
must(client_ids(policy_id=32) == [] and client_ids(policy_id="31") == [1, 2], "policy filter, digit text")
must(client_ids(alert_template_id=5, policy_id=31) == [1] and client_ids(alert_template_id=6, policy_id=31) == [2] and client_ids(alert_template_id=5, policy_id=32) == [], "both together")
must(site_ids(alert_template_id=5) == [11] and site_ids(policy_id=31) == [21] and site_ids(policy_id=32) == [21], "site filters")
must(site_ids(alert_template_id=5, policy_id=31) == [], "site: both together must both match")
must(site_ids(client_id=2, policy_id=31) == [21] and site_ids(client_id=1, policy_id=31) == [], "with client_id")
must(client_ids(alert_template_id="", policy_id=None) == [1, 2], "empty means no filter")
# scoped: a whole-client role sees only its own rows through the filter
must(client_ids(policy_id=31, context=ctx_whole) == [1] and site_ids(policy_id=31, context=ctx_whole) == [], "scope applies")
must(site_ids(alert_template_id=5, context=ctx_whole) == [11], "scope applies to sites")
must(site_ids(policy_id=31, context=ctx_for(User(Role(sites=[11])))) == [], "a site-only role never sees another site")
for bad in (0, -1, "abc", True, 1.5, "5.5", [], {}):
    for key in ("alert_template_id", "policy_id"):
        refused(lambda bad=bad, key=key: resources.list_clients(context=ctx_admin, **{key: bad}), resources.ResourceValidationError)
        refused(lambda bad=bad, key=key: resources.list_sites(context=ctx_admin, **{key: bad}), resources.ResourceValidationError)
# the same permission as the list
no_list = User(Role(list_perms=False))
refused(lambda: resources.list_clients(context=ctx_for(no_list), policy_id=31), resources.ResourcePermissionDenied)

# ----------------------------------------------------------------------------------- HTTP: PATCH whitelist, null clears, filters
reset_tactical()


class Req:
    def __init__(self, user, data=None, query=None):
        self.user, self.data, self.query_params = user, data, query or {}


def patch(kind, rid, data, user=admin):
    view = views.ResourceMutableDetailView()
    view.resource_type = kind
    return view.patch(Req(user, data), rid)


def get_list(kind, query, user=admin):
    view = views.ResourceListView()
    view.resource_type = kind
    return view.get(Req(user, query=query))


r = patch("client", 1, {"workstation_policy_id": 31, "server_policy_id": 32, "block_policy_inheritance": True})
must(r.status_code == 200 and (r.data["workstation_policy_id"], r.data["server_policy_id"], r.data["block_policy_inheritance"]) == (31, 32, True), r.__dict__)
r = patch("client", 1, {"workstation_policy_id": None})
must(r.status_code == 200 and r.data["workstation_policy_id"] is None and r.data["server_policy_id"] == 32, r.__dict__)
r = patch("client", 1, {"block_policy_inheritance": False})
must(r.status_code == 200 and r.data["block_policy_inheritance"] is False, r.__dict__)
r = patch("site", 11, {"workstation_policy_id": 31, "name": "Alpha One", "client_id": 1})
must(r.status_code == 200 and r.data["workstation_policy_id"] == 31 and r.data["client_id"] == 1, r.__dict__)
r = patch("site", 11, {"workstation_policy_id": None, "server_policy_id": 33, "block_policy_inheritance": True})
must(r.status_code == 200 and r.data["workstation_policy_id"] is None and r.data["server_policy_id"] == 33 and r.data["block_policy_inheritance"] is True, r.__dict__)
for kind, rid in (("client", 1), ("site", 11)):
    for body, code in (({}, 400), ({"colour": "red"}, 400), ({"block_policy_inheritance": 1}, 400), ({"block_policy_inheritance": "true"}, 400),
                       ({"workstation_policy_id": True}, 400), ({"server_policy_id": 0}, 400), ({"workstation_policy_id": 99}, 400), ({"server_policy_id": 99}, 400)):
        r = patch(kind, rid, body)
        must(r.status_code == code and r.data["code"] == "invalid_resource_request", (kind, body, r.__dict__))
must("workstation_policy_id does not name an existing policy." == patch("client", 1, {"workstation_policy_id": 99}).data["detail"], "plain text in the answer")
must(patch("client", 1, {"workstation_policy_id": 31}, user=site_only).status_code == 404, "scope refusal is 404")
must(patch("client", 1, {"workstation_policy_id": 31}, user=no_manage).status_code == 403, "permission refusal is 403")
# list filters over HTTP
resources.update_client(1, alert_template_id=5, workstation_policy_id=31, context=ctx_admin)
resp = get_list("client", {"policy_id": "31", "alert_template_id": "5"})
must(resp.status_code == 200 and [x["id"] for x in resp.data["items"]] == [1], resp.__dict__)
resp = get_list("site", {"policy_id": "33"})
must(resp.status_code == 200 and [x["id"] for x in resp.data["items"]] == [11], resp.__dict__)
resp = get_list("site", {"alert_template_id": "x"})
must(resp.status_code == 400 and resp.data["code"] == "invalid_resource_request", resp.__dict__)
resp = get_list("client", {"policy_id": "0"})
must(resp.status_code == 400, resp.__dict__)

# ----------------------------------------------------------------------------------- the contract text and the docs
meta = resources.resource_contract_metadata()
must(meta["version"] == "1.10.0" and meta["version"].split(".")[0] == "1", meta["version"])
must(meta["write_support"]["update_fields"] == {"client": ["name", "alert_template_id", *POLICY_KEYS], "site": ["name", "client_id", "alert_template_id", *POLICY_KEYS]}, meta["write_support"])
must(meta["resource_types"]["client"]["fields"] == list(resources.CLIENT_FIELDS) and meta["resource_types"]["site"]["fields"] == list(resources.SITE_FIELDS), "fields")
must("alert_template_id" in meta["resource_types"]["client"]["filters"] and "policy_id" in meta["resource_types"]["site"]["filters"], "filters")
must("policy_id" in meta["list_contracts"]["clients"]["query"] and "alert_template_id" in meta["list_contracts"]["sites"]["query"], "list contracts")
for key in ("update_client", "update_site"):
    body = meta["mutation_contracts"][key]["body"]
    must(all(k in body for k in POLICY_KEYS), (key, body))
    must("1.7.0" in meta["mutation_contracts"][key]["semantics"] and "policy_changed" in meta["mutation_contracts"][key]["semantics"], key)
must("policy_fields" in meta and "list_filters_1_7" in meta, "contract notes")
contracts_text = (PKG / "contracts.py").read_text(encoding="utf-8")
must("workstation_policy_id" in contracts_text and "framework >=1.17.24" in contracts_text and "policy_changed" in contracts_text, "python rows")
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("Contract version: `1.10.0`" in doc and "Policy fields (since 1.7.0" in doc and "List filters (since 1.7.0)" in doc and "can_manage_automation_policies" in doc, "docs")
registration = resources.register_core_resources_capability()
must(registration["version"] == "1.10.0", registration["version"])

print("[TEST] PASS resource policy fields 1.17.24")
