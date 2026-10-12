#!/usr/bin/env python3
"""1.17.22 regression: Add client takes the first site's name and custom fields; Add site takes custom fields; both extend a
limited role the way Tactical does (clients/views.py GetAddClients.post and GetAddSites.post); '|' is refused in names.

Runs the real resources.py and resources_adapter.py on the in-memory Tactical of tests/resource-alert-template-1.17.17.py. The custom-field
models are stand-ins here. Real models and database: tests/resource-directory-custom-fields-postgres.py (dev server only).
"""
from __future__ import annotations

import pathlib
import types

_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())
H = globals()
must, resources, adapter, reset_tactical, Site, Client, User, Role, AUDITS, ctx_for, views = (
    H[k] for k in ("must", "resources", "adapter", "reset_tactical", "Site", "Client", "User", "Role", "AUDITS", "ctx_for", "views"))

# ---- custom-field stand-ins: field 1 text (required), field 2 checkbox, field 3 hidden
FIELD_DEFS = {
    1: types.SimpleNamespace(pk=1, name="Account code", type="text", options=[], required=True, default_value="", hide_in_ui=False, model="client"),
    2: types.SimpleNamespace(pk=2, name="VIP", type="checkbox", options=[], required=False, default_value=False, hide_in_ui=False, model="client"),
    3: types.SimpleNamespace(pk=3, name="Hidden", type="text", options=[], required=False, default_value="", hide_in_ui=True, model="client"),
    4: types.SimpleNamespace(pk=4, name="Site note", type="text", options=[], required=False, default_value="", hide_in_ui=False, model="site"),
}
SAVED = []


class _CFQuery(list):
    pass


class _CustomFieldManager:
    @staticmethod
    def filter(pk__in=None, model=None, hide_in_ui=None):
        return [f for f in FIELD_DEFS.values() if (pk__in is None or f.pk in set(pk__in)) and f.model == model and f.hide_in_ui == hide_in_ui]


class CustomField:
    objects = _CustomFieldManager()


class _ValueRecord:
    def __init__(self, kind, owner_id, field_id):
        self.kind, self.owner_id, self.field_id = kind, owner_id, field_id
        self.string_value, self.bool_value, self.multiple_value = "", False, []

    def save(self, update_fields=None):
        SAVED.append((self.kind, self.owner_id, self.field_id, self.string_value, self.bool_value))


class _ValueManager:
    def __init__(self, kind, owner_attr):
        self.kind, self.owner_attr = kind, owner_attr

    def select_for_update(self):
        return self

    def get_or_create(self, **kw):
        return _ValueRecord(self.kind, kw[self.owner_attr], kw["field_id"]), True


class ClientCustomField:
    objects = _ValueManager("client", "client_id")


class SiteCustomField:
    objects = _ValueManager("site", "site_id")


adapter._custom_models = lambda: (CustomField, ClientCustomField, SiteCustomField)


import contextlib
import copy


@contextlib.contextmanager
def _rolling_back_atomic():
    """Like transaction.atomic: an exception leaving the block restores the rows written inside it."""
    snapshot = (copy.deepcopy(Client.STORE), copy.deepcopy(Site.STORE), list(SAVED))
    try:
        yield
    except BaseException:
        Client.STORE.clear(), Site.STORE.clear()
        Client.STORE.update(snapshot[0]), Site.STORE.update(snapshot[1])
        SAVED[:] = snapshot[2]
        raise


adapter.transaction.atomic = _rolling_back_atomic


def refused(call, exc_type):
    try:
        call()
    except exc_type as exc:
        return exc
    raise AssertionError("call was accepted")


def fresh():
    reset_tactical()
    SAVED.clear()


def site_names(client_id):
    return sorted(r["name"] for r in Site.STORE.values() if r["client_id"] == client_id)


def new_client_id(name):
    return next(pk for pk, r in Client.STORE.items() if r["name"] == name)


# 1. the first site's name is used when given, and "Default Site" when omitted (the old call keeps working)
fresh()
admin = User(Role())
made = resources.create_client(name="Gamma", site_name="Head office", context=ctx_for(admin))
must(site_names(made["id"]) == ["Head office"] and [s["name"] for s in made["sites"]] == ["Head office"], made)
must(tuple(made) == resources.CLIENT_FIELDS and made["sites"][0]["client_name"] == "Gamma", made)
meta = AUDITS[-1]["metadata"]
must(meta["default_site_created"] is False and meta["first_site_id"] == made["sites"][0]["id"], meta)
old = resources.create_client(name="Delta", context=ctx_for(admin))      # the old call, name only
must(site_names(old["id"]) == ["Default Site"], "old call")
must(AUDITS[-1]["metadata"]["default_site_created"] is True, AUDITS[-1])
# the audit snapshot is the base record
must("sites" not in AUDITS[-1]["after"], AUDITS[-1]["after"])

# 2. a blank or non-string site_name is refused
fresh()
for bad in ("", "   ", 5, ["x"]):
    refused(lambda bad=bad: resources.create_client(name="Epsilon", site_name=bad, context=ctx_for(admin)), resources.ResourceValidationError)
must(not any(r["name"] == "Epsilon" for r in Client.STORE.values()), "nothing created")

# 3. '|' is refused in create and rename, client and site, with the plain message
exc = refused(lambda: resources.create_client(name="A|B", site_name="X", context=ctx_for(admin)), resources.ResourceValidationError)
must(str(exc) == "Client name cannot contain the | character", str(exc))
exc = refused(lambda: resources.create_client(name="AB", site_name="X|Y", context=ctx_for(admin)), resources.ResourceValidationError)
must(str(exc) == "Site name cannot contain the | character", str(exc))
exc = refused(lambda: resources.update_client(1, name="Al|pha", context=ctx_for(admin)), resources.ResourceValidationError)
must(str(exc) == "Client name cannot contain the | character", str(exc))
exc = refused(lambda: resources.create_site(client_id=1, name="Bad|Site", context=ctx_for(admin)), resources.ResourceValidationError)
must(str(exc) == "Site name cannot contain the | character", str(exc))
exc = refused(lambda: resources.update_site(11, name="Bad|Site", context=ctx_for(admin)), resources.ResourceValidationError)
must(str(exc) == "Site name cannot contain the | character", str(exc))

# 4. a client-limited role (non-empty can_view_clients) that creates a client and a site gets both in its lists
fresh()
limited = User(Role(clients=[1]))
made = resources.create_client(name="Zeta", site_name="Zeta HQ", context=ctx_for(limited))
must(made["id"] in limited.role.can_view_clients.ids, "new client joins can_view_clients")
must(AUDITS[-1]["metadata"]["role_scope_extended"] == "clients", AUDITS[-1])
site_role_user = User(Role(clients=[1], sites=[12]))
new_site = resources.create_site(client_id=1, name="Alpha Four", context=ctx_for(site_role_user))
must(new_site["id"] in site_role_user.role.can_view_sites.ids and AUDITS[-1]["metadata"]["role_scope_extended"] == "sites", AUDITS[-1])
must(new_site["client_name"] == "Alpha", new_site)

# 5. a role with an empty can_view_clients does not get the client added
fresh()
sites_only = User(Role(sites=[11]))            # limited by sites only; Tactical does not widen it
sites_only.role.can_manage_clients = True
made = resources.create_client(name="Eta", site_name="Eta HQ", context=ctx_for(sites_only))
must(sites_only.role.can_view_clients.ids == [], "a site-only role is not widened to the new client")
must(AUDITS[-1]["metadata"]["role_scope_extended"] == "none", AUDITS[-1])
must([s["name"] for s in made["sites"]] == ["Eta HQ"], "the response still names the first site")

# 6. a role with an empty can_view_sites does not get the site added (clients-only role)
fresh()
clients_only = User(Role(clients=[1]))
site = resources.create_site(client_id=1, name="Alpha Five", context=ctx_for(clients_only))
must(clients_only.role.can_view_sites.ids == [] and AUDITS[-1]["metadata"]["role_scope_extended"] == "none", AUDITS[-1])

# 7. an unrestricted caller and a superuser change nothing
fresh()
root = User(Role(superuser=True), superuser=True)
resources.create_client(name="Theta", site_name="T1", context=ctx_for(root))
resources.create_client(name="Iota", site_name="I1", context=ctx_for(admin))
must(root.role.can_view_clients.ids == [] and admin.role.can_view_clients.ids == [], "unrestricted roles stay unrestricted")
must(AUDITS[-1]["metadata"]["role_scope_extended"] == "none", AUDITS[-1])

# 8. custom fields are saved with the create, ids only in the audit row
fresh()
made = resources.create_client(
    name="Kappa", site_name="K1", custom_fields=[{"field_id": 1, "value": "AC-9"}, {"field_id": 2, "value": True}],
    context=ctx_for(limited := User(Role(clients=[1]))),
)
must(("client", made["id"], 1, "AC-9", False) in SAVED and any(r[2] == 2 and r[4] is True for r in SAVED), SAVED)
meta = AUDITS[-1]["metadata"]
must(meta["custom_field_ids"] == [1, 2], meta)
must("AC-9" not in repr(AUDITS[-1]), "values never reach the audit row")
SAVED.clear()
site = resources.create_site(client_id=1, name="Alpha Six", custom_fields=[{"field_id": 4, "value": "note"}], context=ctx_for(admin))
must(("site", site["id"], 4, "note", False) in SAVED and AUDITS[-1]["metadata"]["custom_field_ids"] == [4], SAVED)
# a limited creator is not blocked by the write-scope check on the object it just made
must(made["id"] in limited.role.can_view_clients.ids, "limited creator")

# 9. a bad custom field is refused (the real transaction rolls the client and site back)
fresh()
for bad in ([{"field_id": 1, "value": ""}], [{"field_id": 3, "value": "x"}], [{"field_id": 99, "value": "x"}],
            [{"field_id": 1, "value": "x", "extra": 1}], "nope", [{"field_id": 1, "value": "a"}, {"field_id": 1, "value": "b"}]):
    before_audits = len(AUDITS)
    refused(lambda bad=bad: resources.create_client(name="Lambda", site_name="L1", custom_fields=bad, context=ctx_for(admin)), resources.ResourceValidationError)
    must(len(AUDITS) == before_audits, "no audit row for a refused create")
    must(not any(r["name"] == "Lambda" for r in Client.STORE.values()), ("client rolled back", bad))
    must(not any(r["name"] == "L1" for r in Site.STORE.values()), ("site rolled back", bad))
# a bad site custom field rolls the site back too
refused(lambda: resources.create_site(client_id=1, name="Rolled back", custom_fields=[{"field_id": 1, "value": "x"}], context=ctx_for(admin)), resources.ResourceValidationError)
must(not any(r["name"] == "Rolled back" for r in Site.STORE.values()), "site rolled back")
# the adapter raised before any audit row, and in Django that exception leaves transaction.atomic, which rolls the rows back
src = (pathlib.Path(adapter.__file__)).read_text(encoding="utf-8")
body = src[src.index("def create_client_row("):src.index("_NOT_GIVEN = object()")]
must("with transaction.atomic():" in body and "_save_custom_field_values(\"client\"" in body, "custom fields saved inside the create transaction")
site_body = src[src.index("def create_site_row("):src.index("def update_site_row(")]
must("with transaction.atomic():" in site_body and "_save_custom_field_values(\"site\"" in site_body, "site custom fields inside the transaction")

# 10. a failed audit write leaves the create rolled back (the strict audit raises inside the transaction)
fresh()
real_record = H["resources"]._record_resource_change


def boom(**kw):
    raise resources.ResourceDirectoryError("Resource change requires a persisted Core audit record.")


resources._record_resource_change = boom
refused(lambda: resources.create_client(name="Mu", site_name="M1", context=ctx_for(admin)), resources.ResourceDirectoryError)
resources._record_resource_change = real_record
must(not any(r["name"] == "Mu" for r in Client.STORE.values()), "a failed strict audit write rolls the client back")
must(not any(r["name"] == "M1" for r in Site.STORE.values()), "and the first site")
rsrc = (pathlib.Path(resources.__file__)).read_text(encoding="utf-8")
cc = rsrc[rsrc.index("def create_client("):rsrc.index("def update_client(")]
must(cc.index("with _transaction_atomic():") < cc.index("_record_resource_change("), "the audit write is inside the transaction")

# 11. audit carries ids only
fresh()
resources.create_client(name="Nu", site_name="N1", custom_fields=[{"field_id": 1, "value": "SECRET-VALUE"}], context=ctx_for(admin))
must("SECRET-VALUE" not in repr(AUDITS), "no custom field value in any audit row")

# 12. HTTP: bodies accept site_name and custom_fields; unknown fields stay refused
fresh()
class Req:
    def __init__(self, data, user): self.data, self.user, self.query_params = data, user, {}
view = views.ResourceMutableListView(); view.resource_type = "client"
resp = view.post(Req({"name": "Xi", "site_name": "X1", "custom_fields": [{"field_id": 1, "value": "v"}]}, admin))
must(resp.status_code == 201 and resp.data["sites"][0]["name"] == "X1", resp.data)
resp = view.post(Req({"name": "Omicron"}, admin))
must(resp.status_code == 201 and resp.data["sites"][0]["name"] == "Default Site", resp.data)
resp = view.post(Req({"name": "Pi", "bogus": 1}, admin))
must(resp.status_code == 400 and resp.data["code"] == "invalid_resource_request", resp.data)
resp = view.post(Req({"name": "Pi|2", "site_name": "x"}, admin))
must(resp.status_code == 400 and "|" in resp.data["detail"], resp.data)
view = views.ResourceMutableListView(); view.resource_type = "site"
resp = view.post(Req({"name": "S1", "client_id": 1, "custom_fields": [{"field_id": 4, "value": "n"}]}, admin))
must(resp.status_code == 201 and resp.data["client_name"] == "Alpha", resp.data)

# 13. docs and contracts name the rule
doc = (pathlib.Path(adapter.__file__).parents[2] / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("site_name" in doc and "custom_fields" in doc and "Default Site" in doc and "role limited only by sites" in doc, "docs")
meta = resources.resource_contract_metadata()
must("site_name" in meta["mutation_contracts"]["create_client"]["body"], meta["mutation_contracts"]["create_client"])

print("[TEST] PASS resource create client site 1.17.22")
