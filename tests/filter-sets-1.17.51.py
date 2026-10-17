#!/usr/bin/env python3
"""Core 1.17.51: a non-owner PUT on a filter set answers 403 before any provider call (1.17.50 review, LOW).

Runs the real filter_set_views on the 1.17.50 boundary. The provider counts describe_fields calls. Covered: a non-owner reader PUTs a
shared set with a definition and gets 403 with the provider count unchanged and the stored row and audit log unchanged; the same PUT
gets 403 even when the provider raises (the old code answered 502); a PUT without a definition is 403 as well; the owner's PUT still
calls the provider once; a non-owner on a private set gets 404 and no provider call.
"""
from __future__ import annotations

import copy
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
alice, bob, carol = ns.alice, ns.bob, ns.carol
AUDIT, STORE = ns.AUDIT, ns.STORE
FIELDS = [{"id": "hostname", "label": "Hostname", "kind": "text", "lookup": "hostname", "row_key": "hostname"}]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


class Provider:
    def __init__(self):
        self.calls = 0
        self.fail = False

    def describe_fields(self, *, context):
        self.calls += 1
        if self.fail:
            raise RuntimeError("provider down")
        return [dict(f) for f in FIELDS]

    def distinct_values(self, field_id, *, context, search, page, page_size):
        raise AssertionError("not used")


PROVIDER = Provider()
ns.capabilities._core_module_may_register = lambda owner, capability_id: True
ns.capabilities.register_capability(id="demo-open.filter_fields", module_id="demo-open", version="1.0.0", provider=PROVIDER,
                                    operations=("describe_fields", "distinct_values"))
DEFINITION = {"version": 1, "match": "all", "rules": [{"kind": "rule", "field": "hostname", "operator": "contains", "value": "srv"}]}
NEW = {"version": 1, "match": "any", "rules": [{"kind": "rule", "field": "hostname", "operator": "equals", "value": "other"}]}


def detail_put(user, set_id, data):
    return ns.views.FilterSetDetailView().put(ns.Request(user, data), uuid.UUID(str(set_id)))


def snapshot():
    return {k: (v.name, copy.deepcopy(v.payload), list(v.readers)) for k, v in STORE.items()}, len(AUDIT)


ns.reset()
shared = ns.filter_sets.create_filter_set(alice, "demo-open", "endpoints", "Shared", DEFINITION, None, fields=FIELDS)
private = ns.filter_sets.create_filter_set(alice, "demo-open", "endpoints", "Private", DEFINITION, [bob.pk], fields=FIELDS)
PROVIDER.calls = 0
before = snapshot()

for body in ({"definition": NEW}, {"name": "Renamed"}, {"readers": [carol.pk]}, {"name": "x", "definition": NEW, "readers": []}):
    response = detail_put(bob, shared["id"], body)
    must(response.status_code == 403 and response.data["code"] == "permission_denied", (body, response.status_code, response.data))
    must(response.data["detail"] == "Only the owner can change this filter set.", response.data)
must(PROVIDER.calls == 0, "no provider call for a non-owner")
must(snapshot() == before, "the stored rows and the audit log are unchanged")

PROVIDER.fail = True
response = detail_put(bob, shared["id"], {"definition": NEW})
must(response.status_code == 403, "403 even when the provider raises (the old code answered 502)")
must(PROVIDER.calls == 0 and snapshot() == before)
response = detail_put(alice, shared["id"], {"definition": NEW})
must(response.status_code == 502 and PROVIDER.calls == 1, "the owner's PUT still needs the provider")
PROVIDER.fail = False

PROVIDER.calls = 0
response = detail_put(carol, private["id"], {"definition": NEW})
must(response.status_code == 404 and PROVIDER.calls == 0, "a set the person cannot read is 404, with no provider call")
response = detail_put(bob, private["id"], {"definition": NEW})
must(response.status_code == 403 and PROVIDER.calls == 0, "a private reader is not the owner")

response = detail_put(alice, shared["id"], {"definition": NEW})
must(response.status_code == 200 and PROVIDER.calls == 1, (response.status_code, PROVIDER.calls))
must(response.data["definition"]["match"] == "any" and [r["action"] for r in AUDIT][-1] == "modify")
response = detail_put(alice, shared["id"], {"name": "Only a name"})
must(response.status_code == 200 and PROVIDER.calls == 1, "a rename needs no provider")
response = detail_put(alice, str(uuid.uuid4()), {"name": "x"})
must(response.status_code == 404)
print("filter-sets 1.17.51 ok")
