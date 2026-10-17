#!/usr/bin/env python3
"""Core 1.17.51: a reader other than the owner never sees an out-of-scope id value in a shared filter set (CQ144, secure default).

Runs the real tec_tac.filter_sets and filter_set_views on the 1.17.50 boundary (tests/filter_sets_boundary_1_17_50.py) with stubbed
resources.get_client, get_site, list_clients and list_sites. Django is not installed on the PC that prepares a release.

Covered: the named case (a site-restricted reader, a shared set 'client equals <out-of-scope id>': value null, withheld true,
values_withheld 1, while the owner still sees it); an in-scope client id is shown; an unrestricted reader sees all; a site rule uses
site_ids; an id field with no scope_kind is withheld; a name operator value that is a substring of a visible client name is shown and
one that is not is withheld; a lookup that raises withholds; fields=None withholds every value of a non-owner; text and bool values stay
shown; a private set a reader is not listed on still gives 404; the audit rows are unchanged; the lookup cap; the declaration key.
"""
from __future__ import annotations

import json
import logging
import sys
import uuid
from pathlib import Path

logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import filter_sets_boundary_1_17_50 as boundary  # noqa: E402

ns = boundary.install(real_capabilities=True)
fs = ns.filter_sets
alice, bob, carol, root = ns.alice, ns.bob, ns.carol, ns.root
AUDIT, STORE, SCOPES = ns.AUDIT, ns.STORE, ns.SCOPES


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


FIELDS = [
    {"id": "hostname", "label": "Hostname", "kind": "text", "lookup": "hostname", "row_key": "hostname"},
    {"id": "client", "label": "Client", "kind": "id", "lookup": "site__client_id", "row_key": "client_id", "scope_kind": "client",
     "name_lookup": "site__client__name", "name_key": "client_name", "values": {"source": "distinct"}},
    {"id": "site", "label": "Site", "kind": "id", "lookup": "site_id", "row_key": "site_id", "scope_kind": "site",
     "name_lookup": "site__name", "name_key": "site_name"},
    {"id": "other", "label": "Other id", "kind": "id", "lookup": "other_id", "row_key": "other_id"},
    {"id": "needs_reboot", "label": "Needs reboot", "kind": "bool", "lookup": "needs_reboot", "row_key": "needs_reboot"},
]


def rule(field, operator, value):
    return {"kind": "rule", "field": field, "operator": operator, "value": value}


def flt(match, *rules):
    return {"version": 1, "match": match, "rules": list(rules)}


# --- stubbed resources --------------------------------------------------------------------------
resources = sys.modules["tec_tac.resources"]
CLIENTS = {7: "Acme Holdings", 8: "Blue Sky"}      # what the reader may see
SITES = {5: "Head Office"}
CALLS = []
RAISE = []


class NotFound(Exception):
    pass


def get_client(client_id, *, context):
    CALLS.append(("get_client", client_id))
    if RAISE or client_id not in CLIENTS:
        raise NotFound("not in scope")
    return {"id": client_id}


def get_site(site_id, *, context):
    CALLS.append(("get_site", site_id))
    if RAISE or site_id not in SITES:
        raise NotFound("not in scope")
    return {"id": site_id}


def _lister(names):
    def call(*, context, search=None, page=1, page_size=25):
        CALLS.append(("list", search, page_size))
        if RAISE:
            raise RuntimeError("down")
        return {"items": [{"id": k, "name": v} for k, v in names.items() if search.casefold() in v.casefold()][:page_size]}
    return call


resources.get_client, resources.get_site = get_client, get_site
resources.list_clients, resources.list_sites = _lister(CLIENTS), _lister(SITES)


class Provider:
    def describe_fields(self, *, context):
        return [dict(f) for f in FIELDS]

    def distinct_values(self, field_id, *, context, search, page, page_size):
        raise AssertionError("not used here")


ns.capabilities._core_module_may_register = lambda owner, capability_id: True
ns.capabilities.register_capability(id="demo-open.filter_fields", module_id="demo-open", version="1.0.0", provider=Provider(),
                                    operations=("describe_fields", "distinct_values"))
RESTRICTED = {"mode": "sites", "unrestricted": False, "whole_client_ids": [], "site_ids": [5]}
CLIENT_ONLY = {"mode": "clients", "unrestricted": False, "whole_client_ids": [8], "site_ids": []}
UNRESTRICTED = {"mode": "unrestricted", "unrestricted": True, "whole_client_ids": [], "site_ids": []}


def make(owner, name, *rules, readers=None):
    return fs.create_filter_set(owner, "demo-open", "endpoints", name, flt("all", *rules), readers, fields=FIELDS)


def view_of(reader, set_id, fields=FIELDS):
    return fs.get_filter_set(reader, set_id, fields=fields)


def reset():
    ns.reset()
    del CALLS[:]
    del RAISE[:]


# === 1. the named case ===============================================================================
reset()
SCOPES[bob.pk] = RESTRICTED
shared = make(alice, "Out of scope", rule("client", "equals", 99))
seen = view_of(bob, shared["id"])
must(seen["definition"]["rules"] == [{"kind": "rule", "field": "client", "operator": "equals", "value": None, "withheld": True}], seen)
must(seen["values_withheld"] == 1 and seen["mine"] is False and seen["definition"]["match"] == "all" and seen["definition"]["version"] == 1, seen)
must("99" not in json.dumps(seen["definition"]), "the id is nowhere in the answer")
owner = view_of(alice, shared["id"], fields=None)
must(owner["definition"]["rules"] == [rule("client", "equals", 99)] and owner["values_withheld"] == 0, "the owner still sees it, with no fields needed")
must(fs.list_filter_sets(alice, "demo-open", "endpoints")[0]["definition"]["rules"][0]["value"] == 99)
# the same through the HTTP views, and the audit rows hold no value
response = ns.views.FilterSetDetailView().get(ns.Request(bob), uuid.UUID(shared["id"]))
must(response.status_code == 200 and response.data["definition"]["rules"][0]["withheld"] is True and response.data["values_withheld"] == 1, response.data)
response = ns.views.FilterSetListCreateView().get(ns.Request(bob, query={"module": "demo-open", "view_key": "endpoints"}))
must(response.status_code == 200 and response.data["filter_sets"][0]["values_withheld"] == 1, response.data)
must("99" not in json.dumps(response.data["filter_sets"][0]["definition"]))
must([(r["action"], r["object_type"]) for r in AUDIT] == [("add", "filter_set")], "reading writes no audit row")
# a reader the set is private to, and one it is not
reset()
SCOPES[bob.pk] = RESTRICTED
private = make(alice, "Private", rule("client", "equals", 99), readers=[bob.pk])
must(view_of(bob, private["id"])["values_withheld"] == 1)
must(ns.views.FilterSetDetailView().get(ns.Request(carol), uuid.UUID(private["id"])).status_code == 404, "a private set the reader is not on is 404")
must(ns.views.FilterSetListCreateView().get(ns.Request(carol, query={"module": "demo-open", "view_key": "endpoints"})).data["count"] == 0)

# === 2. client ids: in scope shown, others withheld ==================================================
reset()
SCOPES[bob.pk] = CLIENT_ONLY
row = make(alice, "Two clients", rule("client", "equals", 8), rule("client", "not_equals", 99))
got = view_of(bob, row["id"])["definition"]["rules"]
must(got[0] == rule("client", "equals", 8), "whole_client_ids grants it")
must(got[1]["withheld"] is True and got[1]["value"] is None and got[1]["operator"] == "not_equals", got)
# found by the Resource Directory (a client that owns the reader's site)
reset()
SCOPES[bob.pk] = RESTRICTED
row = make(alice, "Client of my site", rule("client", "equals", 7))
must(view_of(bob, row["id"])["definition"]["rules"][0]["value"] == 7, "get_client found it in scope")
# an unrestricted reader sees all, with no lookup
reset()
SCOPES[carol.pk] = UNRESTRICTED
row2 = make(alice, "Anything", rule("client", "equals", 99), rule("client", "contains", "Zed"), rule("site", "equals", 12345))
must(all("withheld" not in r for r in view_of(carol, row2["id"])["definition"]["rules"]) and view_of(carol, row2["id"])["values_withheld"] == 0)
must(CALLS == [], CALLS)
must(all("withheld" not in r for r in view_of(root, row2["id"])["definition"]["rules"]), "the default scope is unrestricted")
# a site rule uses site_ids
reset()
SCOPES[bob.pk] = RESTRICTED
site_set = make(alice, "Sites", rule("site", "equals", 5), rule("site", "equals", 6))
site_rules = view_of(bob, site_set["id"])["definition"]["rules"]
must(site_rules[0] == rule("site", "equals", 5) and site_rules[1]["withheld"] is True, site_rules)
must(("get_site", 6) in CALLS and ("get_site", 5) not in CALLS, CALLS)

# === 3. an id field with no scope_kind is always withheld ============================================
reset()
SCOPES[bob.pk] = RESTRICTED
row = make(alice, "Other", rule("other", "equals", 5))
must(view_of(bob, row["id"])["definition"]["rules"][0]["withheld"] is True and CALLS == [])
SCOPES[carol.pk] = UNRESTRICTED
must(view_of(carol, row["id"])["definition"]["rules"][0]["withheld"] is True, "even an unrestricted reader: Core cannot place an id with no scope_kind")

# === 4. name operators ===============================================================================
reset()
SCOPES[bob.pk] = RESTRICTED
row = make(alice, "Names", rule("client", "contains", "acme"), rule("client", "starts_with", "Secret Corp"), rule("site", "ends_with", "office"))
names = view_of(bob, row["id"])["definition"]["rules"]
must(names[0]["value"] == "acme" and names[1]["withheld"] is True and names[2]["value"] == "office", names)
must(("list", "acme", 1) in CALLS, CALLS)
# a lookup that raises withholds
reset()
SCOPES[bob.pk] = RESTRICTED
row = make(alice, "Raises", rule("client", "equals", 7), rule("client", "contains", "acme"))
RAISE.append(1)
got = view_of(bob, row["id"])
must(got["values_withheld"] == 2 and all(r["withheld"] for r in got["definition"]["rules"]), got)
# a reader whose scope cannot be read gets nothing
reset()
ns.SCOPE_ERRORS.add(bob.pk)
row = make(alice, "No scope", rule("client", "equals", 7), rule("hostname", "equals", "x"))
got = view_of(bob, row["id"])
must(got["definition"]["rules"][0]["withheld"] is True and got["definition"]["rules"][1]["value"] == "x" and CALLS == [], got)

# === 5. fail closed ==================================================================================
reset()
SCOPES[bob.pk] = RESTRICTED
row = make(alice, "Everything", rule("hostname", "contains", "srv"), rule("needs_reboot", "equals", True), rule("client", "equals", 7))
none = fs.get_filter_set(bob, row["id"])  # no fields given
must(none["values_withheld"] == 3 and all(r["withheld"] and r["value"] is None for r in none["definition"]["rules"]), none)
must(CALLS == [], "no lookup without fields")
with_fields = view_of(bob, row["id"])
must(with_fields["definition"]["rules"][0] == rule("hostname", "contains", "srv"), "text stays shown")
must(with_fields["definition"]["rules"][1] == rule("needs_reboot", "equals", True), "bool stays shown")
must(with_fields["values_withheld"] == 0, with_fields)
unknown_fields = [f for f in FIELDS if f["id"] != "hostname"]
must(view_of(bob, row["id"], fields=unknown_fields)["definition"]["rules"][0]["withheld"] is True, "a field the reader does not know")
# nested groups are walked, and a tampered stored value is withheld
stored = next(iter(STORE.values()))
stored.payload = {"kind": "filter_set", "version": 1, "match": "any", "rules": [
    {"kind": "group", "match": "all", "rules": [rule("client", "equals", 99), rule("hostname", "equals", "x"), "junk",
                                                 rule("hostname", "equals", ["x"]), rule("ghost", "equals", "x")]}]}
nested = view_of(bob, row["id"])
inner = nested["definition"]["rules"][0]
must(inner["kind"] == "group" and inner["match"] == "all" and nested["values_withheld"] == 4, nested)
must(inner["rules"][1] == rule("hostname", "equals", "x") and all(inner["rules"][i]["withheld"] for i in (0, 2, 3, 4)), inner)

# === 6. the lookup cap and the memo ==================================================================
reset()
SCOPES[bob.pk] = RESTRICTED
for i in range(5):
    make(alice, f"Set {i}", *[rule("client", "equals", 1000 + i * 50 + j) for j in range(50)])
listed = fs.list_filter_sets(bob, "demo-open", "endpoints", fields=FIELDS)
must(len(listed) == 5 and len([c for c in CALLS if c[0] == "get_client"]) == 200, len(CALLS))
must(sum(s["values_withheld"] for s in listed) == 250 and all(r.get("withheld") for s in listed for r in s["definition"]["rules"]))
reset()
SCOPES[bob.pk] = RESTRICTED
make(alice, "A", rule("client", "equals", 7))
make(alice, "B", rule("client", "equals", 7), rule("client", "not_equals", 7))
fs.list_filter_sets(bob, "demo-open", "endpoints", fields=FIELDS)
must(CALLS == [("get_client", 7)], CALLS)

# === 7. the declaration key ==========================================================================
fields = fs.clean_fields(FIELDS + [
    {"id": "bad_kind", "label": "x", "kind": "id", "lookup": "a", "scope_kind": "agent"},
    {"id": "on_text", "label": "x", "kind": "text", "lookup": "a", "scope_kind": "client"},
])
must([f["id"] for f in fields] == [f["id"] for f in FIELDS], "a bad scope_kind drops the declaration")
must(next(f for f in fields if f["id"] == "client")["scope_kind"] == "client" and next(f for f in fields if f["id"] == "other")["scope_kind"] is None)
must("scope_kind" not in json.dumps(fs.browser_fields(FIELDS)), "the browser never sees scope_kind")
must(fs.CAPABILITY_VERSION == "1.1.0", "core.filter_sets is 1.1.0 since 1.17.52")

# === 8. the owner's evaluation is unchanged ===========================================================
reset()
SCOPES[bob.pk] = RESTRICTED
row = make(alice, "Eval", rule("client", "equals", 99), rule("hostname", "contains", "srv"))
tree = fs.resolve_filter_set(bob, "demo-open", row["id"], FIELDS)
must(tree["rules"][0] == rule("client", "equals", 99), "resolve keeps the value: evaluation never leaks it")
must(fs.matches(tree, {"client_id": 99, "hostname": "srv1"}, FIELDS) is True)
# === 9. the contract text and the docs name the rule ==================================================
ROOT = HERE.parent
contracts_text = " ".join((ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8").split())
for needle in ("scope_kind", "withheld: true", "values_withheld", "value: null", "list_filter_sets(user, module_id, view_key, *, fields=None)",
               "get_filter_set(user, set_id, *, fields=None)", "An id field with no scope_kind is always withheld", "At most 200 lookups",
               "stays visible", "before the module's provider is called"):
    must(needle in contracts_text, f"contracts.py names {needle!r}")
must("A rule value is visible to everyone the set is shared with" not in contracts_text, "the 1.17.50 sentence is gone from contracts.py")
meta = fs.filter_sets_contract_metadata()
must(any("scope_kind" in key for key in meta["field_declaration_keys"]) and "withheld" in meta["reader_view"] and meta["requires_framework"] == ">=1.17.50", meta)
doc = " ".join((ROOT / "docs" / "filter-sets.md").read_text(encoding="utf-8").split())
for needle in ("What a reader sees of a shared set's values (Core 1.17.51)", "scope_kind", "withheld: true", "values_withheld", "no `scope_kind`", "at most 200 lookups",
               "The set's name is a label its owner typed and stays visible"):
    must(needle in doc, f"docs/filter-sets.md names {needle!r}")
must("Rule values are visible to the people a set is shared with" not in doc, "the old section is replaced")
must("scope_kind" in " ".join((ROOT / "docs" / "developer-contracts.md").read_text(encoding="utf-8").split()))
print("filter-sets scope 1.17.51 ok")
