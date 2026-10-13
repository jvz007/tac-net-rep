#!/usr/bin/env python3
"""1.17.23 regression: a read of the client or site custom-field definitions without an id (core.resources 1.5.0 -> 1.6.0).

``list_custom_field_definitions(resource_type, *, context)`` and ``GET /api/tfd/resources/custom-fields/?resource_type=client|site``
serve the Add client and Add site forms, which need the fields before the object exists. The answer has the order and shape of the
id read, hidden fields never appear, and ``value`` is the field's default. Nothing is scoped. The gate is the create's own
(Tactical can_manage_clients or can_manage_sites plus the Core permission); a service context is refused. Runs the real
resources.py, resources_adapter.py and resource_views.py on the in-memory Tactical of tests/resource-alert-template-1.17.17.py
(this test fails on 1.17.22).
"""
from __future__ import annotations

import ast
import pathlib
import types

_here = pathlib.Path(__file__).resolve().parent
_base = _here / "resource-alert-template-1.17.17.py"
_source = _base.read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_base), "exec"), globals())
H = globals()
must, resources, adapter, reset_tactical, Site, Client, User, Role, AUDITS, ctx_for, views = (
    H[k] for k in ("must", "resources", "adapter", "reset_tactical", "Site", "Client", "User", "Role", "AUDITS", "ctx_for", "views"))
ROOT = _here.parent

# ---- custom-field stand-ins: client fields 1 (order 2), 2 (order 1) and a hidden 3; site field 4; one more client field 5 with options
FIELDS = [
    types.SimpleNamespace(pk=1, name="Account code", type="text", options=[], required=True, default_value="AC-0", hide_in_ui=False, model="client", order=2),
    types.SimpleNamespace(pk=2, name="VIP", type="checkbox", options=[], required=False, default_value=False, hide_in_ui=False, model="client", order=1),
    types.SimpleNamespace(pk=3, name="Hidden", type="text", options=[], required=False, default_value="x", hide_in_ui=True, model="client", order=0),
    types.SimpleNamespace(pk=4, name="Site note", type="text", options=[], required=False, default_value="", hide_in_ui=False, model="site", order=0),
    types.SimpleNamespace(pk=5, name="Tier", type="single", options=["gold", "silver"], required=False, default_value="silver", hide_in_ui=False, model="client", order=2),
]
READS = []


class _Rows(list):
    def order_by(self, *names):
        READS.append(names)
        return _Rows(sorted(self, key=lambda f: tuple(getattr(f, n) for n in names)))


class _CustomFieldManager:
    @staticmethod
    def filter(model=None, hide_in_ui=None, pk__in=None):
        return _Rows(f for f in FIELDS if (model is None or f.model == model) and (hide_in_ui is None or f.hide_in_ui == hide_in_ui)
                     and (pk__in is None or f.pk in set(pk__in)))


class CustomField:
    objects = _CustomFieldManager()


class _NoValues:
    @staticmethod
    def filter(**kw):
        return types.SimpleNamespace(select_related=lambda *a: [])


adapter._custom_models = lambda: (CustomField, types.SimpleNamespace(objects=_NoValues), types.SimpleNamespace(objects=_NoValues))


def refused(call, exc_type):
    try:
        call()
    except exc_type as exc:
        return exc
    raise AssertionError("call was accepted")


reset_tactical()
manager = User(Role())
root = User(Role(superuser=True), superuser=True)

# 1. a manager gets the non-hidden definitions with defaults, for client and for site; no hidden field
got = resources.list_custom_field_definitions("client", context=ctx_for(manager))
must(set(got) == {"resource_type", "fields"} and got["resource_type"] == "client", got)
must([f["field_id"] for f in got["fields"]] == [2, 1, 5], got)  # order, then name, then pk: VIP (1), Account code (2), Tier (2)
must(3 not in [f["field_id"] for f in got["fields"]], "hidden field never appears")
must(got["fields"][1] == {"field_id": 1, "name": "Account code", "type": "text", "options": [], "required": True, "value": "AC-0"}, got["fields"][1])
must(got["fields"][0]["value"] is False and got["fields"][2]["options"] == ["gold", "silver"] and got["fields"][2]["value"] == "silver", got["fields"])
for row in got["fields"]:
    must(tuple(row) == ("field_id", "name", "type", "options", "required", "value"), row)
got_site = resources.list_custom_field_definitions("site", context=ctx_for(manager))
must(got_site["resource_type"] == "site" and [f["field_id"] for f in got_site["fields"]] == [4], got_site)
must(("order", "name", "pk") in READS, "the same ordering as the id read")
# the order and shape match the id read's builder
adapter_rows = adapter.custom_field_definition_rows("client")
must(adapter_rows == got["fields"], "the HTTP and Python answer is the adapter's rows")
must(adapter.custom_field_rows.__name__ == "custom_field_rows" and callable(adapter._custom_field_row), "one shared row builder")
# a superuser passes
must(resources.list_custom_field_definitions("client", context=ctx_for(root))["fields"] == got["fields"], "superuser")

# 2. the gate is the create's own
no_manage = User(Role(manage=False))
exc = refused(lambda: resources.list_custom_field_definitions("client", context=ctx_for(no_manage)), resources.ResourcePermissionDenied)
must("can_manage_clients" in str(exc), str(exc))
exc = refused(lambda: resources.list_custom_field_definitions("site", context=ctx_for(no_manage)), resources.ResourcePermissionDenied)
must("can_manage_sites" in str(exc), str(exc))
# a role with only List clients (no Manage clients) is refused
list_only = User(Role(list_perms=True, manage=False))
refused(lambda: resources.list_custom_field_definitions("client", context=ctx_for(list_only)), resources.ResourcePermissionDenied)
# Tactical's flag without the Core permission is refused
refused(lambda: resources.list_custom_field_definitions("client", context=ctx_for(User(Role(), core=()))), resources.ResourcePermissionDenied)
# the Core permission of the other type does not open this one
refused(lambda: resources.list_custom_field_definitions("client", context=ctx_for(User(Role(), core=("core.resources.sites.manage",)))), resources.ResourcePermissionDenied)
# no role
refused(lambda: resources.list_custom_field_definitions("client", context=ctx_for(User(None))), resources.ResourcePermissionDenied)

# 3. no scope dependence: a role limited to one client still gets the definitions
limited = User(Role(clients=[1]))
must(resources.list_custom_field_definitions("client", context=ctx_for(limited))["fields"] == got["fields"], "scope does not matter")
site_limited = User(Role(sites=[11]))
must(resources.list_custom_field_definitions("site", context=ctx_for(site_limited))["fields"] == got_site["fields"], "site-limited role")

# 4. a service context is refused, a missing context too
service = resources.trusted_service_context(actor="probe", purpose="test", global_access=True)
refused(lambda: resources.list_custom_field_definitions("client", context=service), resources.ResourcePermissionDenied)
refused(lambda: resources.list_custom_field_definitions("client", context=None), resources.ResourcePermissionDenied)

# 5. resource_type: missing, 'agent', 'Client ', 'CLIENT', numbers and lists are a validation error
for bad in (None, "", "agent", "Client ", "CLIENT", " client", "clients", 1, ["client"], True):
    refused(lambda bad=bad: resources.list_custom_field_definitions(bad, context=ctx_for(manager)), resources.ResourceValidationError)

# 6. the HTTP view
view = views.ResourceCustomFieldDefinitionsView()


def http(user, **query):
    request = types.SimpleNamespace(user=user, query_params=dict(query))
    return view.get(request)


ok = http(manager, resource_type="client")
must(ok.status_code == 200 and ok.data == got, ok.data)
must(http(manager, resource_type="site").data == got_site, "site over HTTP")
for query in ({}, {"resource_type": "agent"}, {"resource_type": "Client "}, {"resource_type": "client", "client_id": "1"}, {"resource_type": "client", "page": "1"}):
    resp = http(manager, **query)
    must(resp.status_code == 400 and resp.data["code"] == resources.ResourceValidationError.code, (query, resp.data))
must(http(no_manage, resource_type="client").status_code == 403, "no Manage clients: 403")
must(http(list_only, resource_type="client").status_code == 403, "List clients only: 403")
must(http(limited, resource_type="client").status_code == 200, "a limited role: 200")
# no user object means no access over HTTP either
must(http(types.SimpleNamespace(is_authenticated=False), resource_type="client").status_code == 403, "unauthenticated user: 403")

# 7. the route is registered and sits before the id routes
urls_src = (ROOT / "framwork/tec_tac/urls.py").read_text(encoding="utf-8")
must('path("resources/custom-fields/", ResourceCustomFieldDefinitionsView.as_view()' in urls_src, "route registered")
must(urls_src.index('"resources/custom-fields/"') < urls_src.index('"resources/clients/<int:resource_id>/"'), "before the id routes")
must("ResourceCustomFieldDefinitionsView" in urls_src.split("\n")[2], "imported")

# 8. the version, the contract rows, the capability and the docs
must(resources.CONTRACT_VERSION == "1.7.0", resources.CONTRACT_VERSION)  # 1.17.24 raised it from 1.6.0
meta = resources.resource_contract_metadata()
must(meta["version"] == "1.7.0" and "list_custom_field_definitions" in meta["operations"], meta["operations"])
must(meta["operations"][:15] == ["list_clients", "get_client", "create_client", "update_client", "delete_client", "list_sites", "get_site", "create_site",
                                 "update_site", "delete_site", "list_custom_fields", "update_custom_fields", "list_agents", "get_agent", "resolve_resource"], "earlier operations keep their order")
must("custom_field_definitions" in meta["mutation_contracts"] and "/api/tfd/resources/custom-fields/" in meta["mutation_contracts"]["custom_field_definitions"]["http"], "metadata row")
registration = resources.register_core_resources_capability()
must("list_custom_field_definitions" in registration["operations"] and callable(registration["provider"].list_custom_field_definitions), registration["operations"])
tree = ast.parse((ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8"))
rows = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_RESOURCE_CONTRACTS" for t in n.targets))
row = next(r for r in rows if r["name"] == "list_custom_field_definitions")
must(row["import_path"] == "tec_tac.resources" and "/api/tfd/resources/custom-fields/" in row["purpose"] and "1.6.0" in row["purpose"], row)
doc = (ROOT / "docs/resource-directory.md").read_text(encoding="utf-8")
must("Contract version: `1.7.0`" in doc and "list_custom_field_definitions" in doc and "/api/tfd/resources/custom-fields/" in doc, "docs")
installer = (ROOT / "install.sh").read_text(encoding="utf-8")
must("(1,1,0) <= resource_version < (2,0,0)" in installer, "the installer bound still admits 1.6.0")

print("[TEST] PASS resource custom field definitions 1.17.23")
