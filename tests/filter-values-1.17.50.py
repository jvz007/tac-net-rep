#!/usr/bin/env python3
"""Core 1.17.50: GET /api/tfd/filter-values/, the scope-safe distinct-values lookup for 'Equals' pickers.

Runs the real filter_sets.py, filter_set_views.py and the real capabilities registry with a fake provider. Only the Django/DRF boundary
is faked (tests/filter_sets_boundary_1_17_50.py).

Covered: two people with different scopes get different answers and the second never receives the first's cached values; scope mode
none, or a scope that cannot be read, answers an empty list and never calls the provider; a field the person was not offered is 404;
a module the person cannot use is 403; only that module's own capability answers; search and page limits; an oversize value, a wrong
type and a repeated value are trimmed; the answer is cut to the page size and has_more is kept; a failing provider is 502 with no
secret or stack text and no fallback; the cache holds 30 seconds, then misses, and the 257th key evicts the oldest; nothing here uses
Django's cache, Redis or Celery.
"""
from __future__ import annotations

import ast
import json
import logging
import sys
from pathlib import Path

logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import filter_sets_boundary_1_17_50 as boundary  # noqa: E402

ns = boundary.install(real_capabilities=True)
fs = ns.filter_sets
alice, bob, carol, root = ns.alice, ns.bob, ns.carol, ns.root


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


FIELDS = [
    {"id": "operating_system", "label": "Operating system", "kind": "text", "lookup": "operating_system", "values": {"source": "distinct"}},
    {"id": "hostname", "label": "Hostname", "kind": "text", "lookup": "hostname", "values": {"source": "none"}},
    {"id": "client", "label": "Client", "kind": "id", "lookup": "site__client_id", "name_lookup": "site__client__name", "values": {"source": "distinct"}},
    {"id": "type", "label": "Type", "kind": "text", "lookup": "monitoring_type", "values": {"source": "static", "options": [{"value": "server"}]}},
    {"id": "secret", "label": "Secret", "kind": "text", "lookup": "secret", "values": {"source": "distinct"}},
]
# What each client's agents run. The provider answers only from the client ids in the person's scope.
OS_BY_CLIENT = {
    1: ["Windows 11 Pro", "Ubuntu 22.04"],
    2: ["Windows Server 2022", "Windows 11 Pro", "Zorin OS 17 (client two only)"],
    3: ["Debian 12"],
}


class Provider:
    def __init__(self):
        self.describe_calls = []
        self.value_calls = []
        self.hidden = {}
        self.override = None
        self.fail = None

    def describe_fields(self, *, context):
        self.describe_calls.append(context.user.pk)
        return [f for f in FIELDS if f["id"] not in self.hidden.get(context.user.pk, ())]

    def distinct_values(self, field_id, *, context, search, page, page_size):
        self.value_calls.append((context.user.pk, field_id, search, page, page_size))
        if self.fail is not None:
            raise self.fail
        if self.override is not None:
            return self.override
        scope = context.scope
        clients = sorted(set(scope.get("whole_client_ids", []))) if not scope.get("unrestricted") else sorted(OS_BY_CLIENT)
        found = sorted({name for c in clients for name in OS_BY_CLIENT.get(c, []) if search.casefold() in name.casefold()})
        start = (page - 1) * page_size
        return {"values": [{"value": n, "label": n} for n in found[start:start + page_size]], "has_more": len(found) > start + page_size}


PROVIDER = Provider()
ns.capabilities._core_module_may_register = lambda owner, capability_id: True
ns.capabilities.register_capability(id="demo-open.filter_fields", module_id="demo-open", version="1.0.0", provider=PROVIDER,
                                    operations=("describe_fields", "distinct_values"))
GRANTS = ns.GRANTS
VIEW = ns.views.FilterValuesView()


def get(user, *, module="demo-open", field="operating_system", search=None, page=None):
    query = {"module": module, "field": field}
    if search is not None:
        query["search"] = search
    if page is not None:
        query["page"] = page
    return VIEW.get(ns.Request(user, query=query))


def values(response):
    return [row["value"] for row in response.data["values"]]


def reset():
    ns.reset()
    PROVIDER.describe_calls.clear()
    PROVIDER.value_calls.clear()
    PROVIDER.hidden = {}
    PROVIDER.override = None
    PROVIDER.fail = None


# === scope: two people, two answers, no shared cache ==================================================
reset()
ns.SCOPES[alice.pk] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [2], "site_ids": []}
ns.SCOPES[bob.pk] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [1], "site_ids": []}
first = get(alice)
must(first.status_code == 200 and "Zorin OS 17 (client two only)" in values(first), first.data)
must(set(first.data) == {"values", "has_more", "page", "page_size"} and first.data["page_size"] == 25 and first.data["page"] == 1)
second = get(bob)
must(second.status_code == 200 and values(second) == ["Ubuntu 22.04", "Windows 11 Pro"], second.data)
must("Zorin OS 17 (client two only)" not in json.dumps(second.data), "an OS seen only on client two is never served to a person who sees client one")
must(len(PROVIDER.value_calls) == 2, "two people, two provider calls (never the other person's cache)")
# the same person again is served from the cache; the scope is part of the key
get(alice)
must(len(PROVIDER.value_calls) == 2, "a repeat is a cache hit")
# the same user, a changed role: the answer follows at once
ns.SCOPES[alice.pk] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [3], "site_ids": []}
changed = get(alice)
must(values(changed) == ["Debian 12"] and len(PROVIDER.value_calls) == 3, changed.data)
must("Zorin OS 17 (client two only)" not in json.dumps(changed.data))
# another person with the SAME scope as alice has their own key (the person is part of the key)
ns.SCOPES[carol.pk] = dict(ns.SCOPES[alice.pk])
get(carol)
must(len(PROVIDER.value_calls) == 4, "the person is part of the key")
# unrestricted
ns.SCOPES[root.pk] = {"mode": "unrestricted", "unrestricted": True, "whole_client_ids": [], "site_ids": []}
must(len(values(get(root))) == 5 + 1 - 1 and "Debian 12" in values(get(root)))

# === scope none / unreadable: empty, and the provider is not called =======================================
reset()
ns.SCOPES[alice.pk] = {"mode": "none", "unrestricted": False, "whole_client_ids": [], "site_ids": []}
response = get(alice)
must(response.status_code == 200 and response.data == {"values": [], "has_more": False, "page": 1, "page_size": 25}, response.data)
must(PROVIDER.value_calls == [] and PROVIDER.describe_calls == [], "mode none: the provider is not called at all")
ns.SCOPES.pop(alice.pk)
ns.SCOPE_ERRORS.add(alice.pk)
response = get(alice)
must(response.status_code == 200 and response.data["values"] == [] and PROVIDER.value_calls == [] and PROVIDER.describe_calls == [], "unreadable scope fails closed")
ns.SCOPE_ERRORS.clear()
ns.SCOPES[alice.pk] = {"mode": "weird"}
must(get(alice).status_code == 200 and PROVIDER.value_calls != [], "a readable scope of another mode goes on to the provider")
ns.SCOPES[alice.pk] = "not a dict"
reset()
ns.SCOPES[alice.pk] = "not a dict"
must(get(alice).data["values"] == [] and PROVIDER.value_calls == [], "a scope that is not an object fails closed")

# === field, module and capability checks ============================================================
reset()
must(get(alice, field="hostname").status_code == 404, "a field with no distinct source")
must(get(alice, field="type").status_code == 404, "a static field")
must(get(alice, field="nope").status_code == 404, "an unknown field")
must(get(alice, field="Bad Id").status_code == 404 and get(alice, field=None).status_code == 404 and get(alice, field="x" * 80).status_code == 404)
must(PROVIDER.value_calls == [], "no value call for a field Core refused")
PROVIDER.hidden = {alice.pk: ("operating_system",)}
must(get(alice).status_code == 404, "a field the person was not offered")
must(get(bob).status_code == 200, "another person is offered it")
PROVIDER.hidden = {}
error = get(alice, field="secret")
must(error.status_code == 200, "a distinct field the person is offered is served")
PROVIDER.hidden = {alice.pk: ("secret",)}
must(get(alice, field="secret").status_code == 404)
PROVIDER.hidden = {}
# a module the person cannot use is 403; the provider is not called
reset()
before = len(PROVIDER.describe_calls)
response = get(alice, module="demo-locked", field="operating_system")
must(response.status_code == 403 and len(PROVIDER.describe_calls) == before, response.data)
must(get(alice, module="demo-disabled").status_code == 400 and get(alice, module="demo-legacy").status_code == 400 and get(alice, module="nope").status_code == 400)
must(get(alice, module=None).status_code == 400)
GRANTS[alice.pk] = {"demo-locked.use"}
must(get(alice, module="demo-locked").status_code == 404, "may use the module, but it offers no filter fields")
# only that module's own capability answers: another module's registration is never asked
other = Provider()
other.describe_calls = []
ns.PLUGINS.append(ns.spec("demo-other"))
ns.capabilities.register_capability(id="demo-other.filter_fields", module_id="demo-other", version="1.0.0", provider=other, operations=("describe_fields",))
get(alice, module="demo-open")
must(other.describe_calls == [] and PROVIDER.describe_calls[-1] == alice.pk, "demo-open never reaches demo-other's provider")
get(alice, module="demo-other")
must(other.describe_calls == [alice.pk], "demo-other's own provider answers for demo-other")
# a module cannot register another module's provider name
try:
    ns.capabilities.register_capability(id="demo-open.filter_fields", module_id="demo-locked", version="1.0.0", provider=other, operations=())
    raise AssertionError("a foreign registration must be refused")
except ValueError as exc:
    must("must begin with provider module prefix" in str(exc), str(exc))
must(ns.capabilities._registration("demo-open.filter_fields").provider is PROVIDER, "the real provider stays")
# a provider at the wrong major version is not used
registration = ns.capabilities._CAPABILITIES["demo-other.filter_fields"]
ns.capabilities._CAPABILITIES["demo-other.filter_fields"] = ns.capabilities.CapabilityRegistration(
    id="demo-other.filter_fields", module_id="demo-other", version="2.0.0", provider=other, operations=())
other.describe_calls.clear()
must(get(alice, module="demo-other").status_code == 404 and other.describe_calls == [], "version 2 is not honoured")
ns.capabilities._CAPABILITIES["demo-other.filter_fields"] = registration
ns.PLUGINS[:] = [p for p in ns.PLUGINS if p.plugin_id != "demo-other"]
must(get(alice, module="demo-other").status_code == 400, "a module that is not installed")

# === search and page limits ===========================================================================
reset()
must(get(alice, search="x" * 100).status_code == 200 and get(alice, search="x" * 101).status_code == 400)
for bad in ("a\x00b", "a\nb", "\x7f"):
    must(get(alice, search=bad).status_code == 400, bad)
for page in (0, -1, 201, "abc", "1.5", "", "99999999999999999999"):
    must(get(alice, page=page).status_code == 400, page)
must(get(alice, page=1).status_code == 200 and get(alice, page=200).status_code == 200 and get(alice, page="2").data["page"] == 2)
last = PROVIDER.value_calls[-1]
must(last[3] == 2 and last[4] == 25, last)
must(all(call[4] == 25 for call in PROVIDER.value_calls), "the page size sent to the provider is always 25")
must(get(alice, search="  win  ").data["values"] and PROVIDER.value_calls[-1][2] == "win", "search is trimmed")
PROVIDER.value_calls.clear()
get(alice, search="Windows")
get(alice, search="windows")
must(len(PROVIDER.value_calls) == 1, "the cache key casefolds the search")

# === the provider's answer is cut to what Core allows ====================================================
reset()
PROVIDER.override = {"values": [
    {"value": "ok one", "label": "Fine"}, {"value": "ok one", "label": "A repeat"}, {"value": 7, "label": "Seven"}, {"value": 7},
    {"value": "x" * 201, "label": "too long"}, {"value": "x" * 200, "label": "L" * 400}, {"value": 1.5, "label": "float"}, {"value": True, "label": "bool"},
    {"value": None}, {"value": ["a"]}, {"value": {"a": 1}}, {"value": "bad\x00value"}, {"value": "   "}, {"value": "ctl\nvalue"},
    "bare text", 42, {"label": "no value"}, "bare text", {"value": "lab", "label": "  has\x07control  "}, {"value": "nolabel"},
], "has_more": False, "secret_extra": "must not pass"}
response = get(alice)
rows = response.data["values"]
must(response.status_code == 200 and set(response.data) == {"values", "has_more", "page", "page_size"}, response.data)
must([r["value"] for r in rows] == ["ok one", 7, "x" * 200, "bare text", 42, "lab", "nolabel"], [r["value"] for r in rows])
must(rows[0]["label"] == "Fine" and rows[1]["label"] == "Seven", rows[:2])
must(len(rows[2]["label"]) == 300 and rows[3]["label"] == "bare text" and rows[4]["label"] == "42" and rows[5]["label"] == "hascontrol" and rows[6]["label"] == "nolabel", rows)
must(all(isinstance(r["value"], (str, int)) and not isinstance(r["value"], bool) and set(r) == {"value", "label"} for r in rows))
must("must not pass" not in json.dumps(response.data))
# the answer is cut to the page size and has_more is kept
reset()
PROVIDER.override = {"values": [{"value": f"v{i}", "label": f"V {i}"} for i in range(60)], "has_more": False}
response = get(alice)
must(len(response.data["values"]) == 25 and response.data["values"][-1]["value"] == "v24" and response.data["has_more"] is True, "cut to 25, and the cut shows there is more")
reset()
PROVIDER.override = {"values": [{"value": f"v{i}"} for i in range(25)], "has_more": True}
response = get(alice)
must(len(response.data["values"]) == 25 and response.data["has_more"] is True, "the provider's has_more is kept")
reset()
PROVIDER.override = {"values": [{"value": f"v{i}"} for i in range(3)], "has_more": False}
must(get(alice).data["has_more"] is False)
# an answer that is not an object, or has no list, is a 502
for broken in ([], "text", {"values": "x"}, {"values": None}, {}, 5):
    reset()
    PROVIDER.override = broken
    must(get(alice).status_code == 502, broken)
PROVIDER.override = None
# a provider that returns a tuple of rows works
reset()
PROVIDER.override = {"values": (({"value": "a"}), {"value": "b"})}
must(values(get(alice)) == ["a", "b"])

# === a failing provider: 502, no secret, no fallback ======================================================
reset()
PROVIDER.fail = RuntimeError("secret db password=hunter2 /srv/tactical/agents/models.py line 99")
response = get(alice)
body = json.dumps(response.data)
must(response.status_code == 502 and response.data["code"] == "values_unavailable", response.data)
must("hunter2" not in body and "models.py" not in body and "Traceback" not in body and "RuntimeError" not in body, body)
must(len(PROVIDER.value_calls) == 1 and ns.filter_sets._VALUES_CACHE.get((alice.pk,)) is None, "one call, nothing cached, no other source asked")
PROVIDER.fail = None
must(get(alice).status_code == 200, "recovers on the next call")
reset()


class DescribeBoom(Provider):
    def describe_fields(self, *, context):
        raise RuntimeError("describe failed: token=abc123")


boom = DescribeBoom()
ns.capabilities._CAPABILITIES["demo-open.filter_fields"] = ns.capabilities.CapabilityRegistration(
    id="demo-open.filter_fields", module_id="demo-open", version="1.0.0", provider=boom, operations=())
response = get(alice)
must(response.status_code == 502 and "abc123" not in json.dumps(response.data) and boom.value_calls == [], response.data)
ns.capabilities._CAPABILITIES["demo-open.filter_fields"] = ns.capabilities.CapabilityRegistration(
    id="demo-open.filter_fields", module_id="demo-open", version="1.0.0", provider=PROVIDER, operations=())

# === the cache: 30 seconds, then a miss; the 257th key evicts the oldest ==================================
reset()
clock = [1000.0]
cache = ns.filter_sets._VALUES_CACHE
cache._clock = lambda: clock[0]
must(cache._seconds == 30 and cache._maximum == 256)
get(alice, search="a")
must(len(PROVIDER.value_calls) == 1)
clock[0] += 29.9
get(alice, search="a")
must(len(PROVIDER.value_calls) == 1, "a hit inside 30 seconds")
clock[0] += 0.2
get(alice, search="a")
must(len(PROVIDER.value_calls) == 2, "a miss after 30 seconds")
reset()
cache._clock = lambda: clock[0]
for i in range(256):
    get(alice, search=f"s{i:03d}")
must(len(cache) == 256 and len(PROVIDER.value_calls) == 256)
get(alice, search="s255")
must(len(PROVIDER.value_calls) == 256, "the newest is still cached")
get(alice, search="s000")
must(len(PROVIDER.value_calls) == 256, "the oldest is still cached while there is room")
get(alice, search="one more")
must(len(cache) == 256 and len(PROVIDER.value_calls) == 257, "the 257th key is stored and the cache stays at 256")
get(alice, search="s001")
must(len(PROVIDER.value_calls) == 257, "the second oldest is still cached")
get(alice, search="s000")
must(len(PROVIDER.value_calls) == 258, "the oldest key (s000, the first stored) was evicted by the 257th")
get(alice, search="s255")
must(len(PROVIDER.value_calls) == 258, "a newer key is still cached")
# a cached answer cannot be changed by the caller
reset()
cache._clock = lambda: clock[0]
one = get(alice)
one.data["values"].append({"value": "tampered", "label": "tampered"})
two = get(alice)
must("tampered" not in json.dumps(two.data), "the cache hands out copies")
cache._clock = __import__("time").monotonic
# the cache is process-local and bounded, with no Django cache, Redis or Celery
src = (ROOT / "framwork" / "tec_tac" / "filter_sets.py").read_text(encoding="utf-8")
names = set()
for node in ast.walk(ast.parse(src)):
    if isinstance(node, ast.Import):
        names.update(alias.name for alias in node.names)
    elif isinstance(node, ast.ImportFrom):
        names.add(("." * node.level) + (node.module or ""))
must(not any(word in name.lower() for name in names for word in ("cache", "redis", "celery", "tasks")), names)
must(isinstance(ns.filter_sets._VALUES_CACHE, ns.filter_sets._TTLCache), "a process-local cache object")
# the throttle is on the route
throttles = (ROOT / "framwork" / "tec_tac" / "throttles.py").read_text(encoding="utf-8")
must("class FilterValuesMinThrottle" in throttles and '"240/min"' in throttles)
views_src = (ROOT / "framwork" / "tec_tac" / "filter_set_views.py").read_text(encoding="utf-8")
must("throttle_classes = [FilterValuesMinThrottle]" in views_src and "permission_classes = [SessionAuthenticated]" in views_src)
anonymous = type("Anonymous", (), {"is_authenticated": False, "pk": None})()
must(get(anonymous).status_code == 403, "signed out")

print("filter-values 1.17.50 ok")
