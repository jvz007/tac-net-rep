#!/usr/bin/env python3
"""1.17.51 regression: the optional compare-and-set guard of update_client and update_site (core.resources 1.10.0 -> 1.11.0).

Closes the Core half of the request from Automation 0.10.0. The real resources.py, resources_adapter.py and resource_views.py run
against the in-memory Tactical of tests/resource-alert-template-1.17.17.py, as in tests/resource-policy-fields-1.17.24.py. The compare
itself (``check_expected``) runs on the object the adapter locked; the real ``select_for_update`` row lock needs Django and a database,
which only the dev server has, so the lock is not exercised here.

Covered: a matching guard writes and audits; a stale workstation, server and block guard each answer 409 record_changed with no write and
no audit row; a guard of None matches an unset policy; a guard with no change key is a 400; no guard key behaves as before (an unchanged
update writes no audit row); a bad guard value (a bool for an id, text for the flag) is a 400; the PATCH route accepts and refuses the
keys; for a site the guard is judged with a move in the same call; the compare helper with stub rows; the answer names the field and no value.
"""
from __future__ import annotations

import pathlib
import types

_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())
H = globals()
must, resources, adapter, views = H["must"], H["resources"], H["adapter"], H["views"]
reset_tactical, Client, Site, User, Role = H["reset_tactical"], H["Client"], H["Site"], H["User"], H["Role"]
AUDITS, HOOKS, ctx_for = H["AUDITS"], H["HOOKS"], H["ctx_for"]

admin = User(Role())
whole_client = User(Role(clients=[1]))
ctx_whole = ctx_for(whole_client)
UNSET = resources.UNSET


def refused(call, *errors):
    try:
        call()
    except errors as exc:
        return exc
    raise AssertionError(f"call was accepted: {call}")


class Req:
    def __init__(self, user, data=None):
        self.user, self.data, self.query_params = user, data, {}


def patch(kind, rid, data, user=whole_client):
    view = views.ResourceMutableDetailView()
    view.resource_type = kind
    return view.patch(Req(user, data), rid)


must(resources.CONTRACT_VERSION == "1.12.0", resources.CONTRACT_VERSION)
meta = resources.resource_contract_metadata()
must(meta["version"] == "1.12.0" and meta["write_support"]["update_guards"] == [
    "expected_workstation_policy_id", "expected_server_policy_id", "expected_block_policy_inheritance"], meta["write_support"])
must("update_guard" in meta and "record_changed" in meta["update_guard"], "the metadata describes the guard")


def seed_client():
    reset_tactical()
    del AUDITS[:], HOOKS[:]
    resources.update_client(1, workstation_policy_id=31, server_policy_id=32, block_policy_inheritance=True, context=ctx_whole)
    del AUDITS[:], HOOKS[:]


def snapshot():
    return dict(Client.STORE[1]), len(AUDITS), list(HOOKS)


# ------------------------------------------------------------------------------------------ client: a matching guard writes and audits
seed_client()
row = resources.update_client(1, workstation_policy_id=33, expected_workstation_policy_id=31, expected_server_policy_id=32,
                              expected_block_policy_inheritance=True, context=ctx_whole)
must(row["workstation_policy_id"] == 33 and Client.STORE[1]["workstation_policy_id"] == 33, row)
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "modify" and AUDITS[0]["metadata"]["policy_changed"] == ["workstation_policy_id"], AUDITS)
must(AUDITS[0]["before"]["workstation_policy_id"] == 31 and AUDITS[0]["after"]["workstation_policy_id"] == 33, "the guard is not in the row")
must("expected" not in str(AUDITS[0]["metadata"]), AUDITS[0]["metadata"])

# ------------------------------------------------------------------------------------------ client: each stale guard is a 409 with no write
for key, stale, change in (
    ("expected_workstation_policy_id", 99, {"name": "Renamed"}),
    ("expected_server_policy_id", 99, {"workstation_policy_id": 33}),
    ("expected_block_policy_inheritance", False, {"server_policy_id": 33}),
    ("expected_workstation_policy_id", None, {"name": "Renamed"}),
):
    seed_client()
    before = snapshot()
    err = refused(lambda: resources.update_client(1, context=ctx_whole, **change, **{key: stale}), resources.ResourceConflict)
    must(err.code == "record_changed", err.code)
    field = key[len("expected_"):]
    must(field in str(err) and "99" not in str(err) and "31" not in str(err) and "32" not in str(err), str(err))
    must(snapshot() == before, f"{key}: nothing written, no audit row, no Tactical hook")
    # and through the route
    response = patch("client", 1, {**change, key: stale})
    must(response.status_code == 409 and response.data["code"] == "record_changed" and field in response.data["detail"], response.data)
    must(snapshot() == before)

# a guard of None matches an unset policy
reset_tactical()
del AUDITS[:]
row = resources.update_client(1, name="Alpha 2", expected_workstation_policy_id=None, expected_server_policy_id=None,
                              expected_block_policy_inheritance=False, context=ctx_whole)
must(row["name"] == "Alpha 2" and len(AUDITS) == 1, row)
seed_client()
refused(lambda: resources.update_client(1, name="X", expected_workstation_policy_id=None, context=ctx_whole), resources.ResourceConflict)

# a guard alone is not a change
seed_client()
before = snapshot()
exc = refused(lambda: resources.update_client(1, expected_workstation_policy_id=31, context=ctx_whole), resources.ResourceValidationError)
must("At least one of" in str(exc), str(exc))
must(patch("client", 1, {"expected_workstation_policy_id": 31}).status_code == 400 and snapshot() == before)

# no guard key: as before. An unchanged update writes no audit row.
seed_client()
row = resources.update_client(1, workstation_policy_id=31, context=ctx_whole)
must(row["workstation_policy_id"] == 31 and AUDITS == [] and HOOKS == [], "an unchanged update writes no audit row")
resources.update_client(1, workstation_policy_id=33, context=ctx_whole)
must(len(AUDITS) == 1)
# a matching guard with nothing to change writes nothing either
seed_client()
resources.update_client(1, workstation_policy_id=31, expected_workstation_policy_id=31, context=ctx_whole)
must(AUDITS == [], "a guard that matches and a change that changes nothing: no audit row")

# bad guard values: a 400, nothing written
seed_client()
before = snapshot()
for kwargs in ({"expected_workstation_policy_id": True}, {"expected_server_policy_id": False}, {"expected_workstation_policy_id": 0},
               {"expected_workstation_policy_id": "abc"}, {"expected_server_policy_id": 1.5}, {"expected_block_policy_inheritance": "true"},
               {"expected_block_policy_inheritance": 1}, {"expected_block_policy_inheritance": None}):
    refused(lambda kwargs=kwargs: resources.update_client(1, name="Y", context=ctx_whole, **kwargs), resources.ResourceValidationError)
    must(patch("client", 1, {"name": "Y", **kwargs}).status_code == 400, kwargs)
must(snapshot() == before)

# the PATCH route accepts the keys and still refuses unknown ones
seed_client()
response = patch("client", 1, {"workstation_policy_id": 33, "expected_workstation_policy_id": 31})
must(response.status_code == 200 and response.data["workstation_policy_id"] == 33, response.data)
must(patch("client", 1, {"name": "Z", "expected_other": 1}).status_code == 400, "an unknown key is refused")

# ------------------------------------------------------------------------------------------ site
def seed_site():
    reset_tactical()
    del AUDITS[:], HOOKS[:]
    resources.update_site(11, workstation_policy_id=31, server_policy_id=32, block_policy_inheritance=True, context=ctx_whole)
    del AUDITS[:], HOOKS[:]


def site_snapshot():
    return dict(Site.STORE[11]), len(AUDITS), list(HOOKS)


seed_site()
row = resources.update_site(11, server_policy_id=33, expected_workstation_policy_id=31, expected_block_policy_inheritance=True, context=ctx_whole)
must(row["server_policy_id"] == 33 and len(AUDITS) == 1 and AUDITS[0]["object_type"] == "resource_site", AUDITS)
for key, stale in (("expected_workstation_policy_id", 99), ("expected_server_policy_id", None), ("expected_block_policy_inheritance", False)):
    seed_site()
    before = site_snapshot()
    err = refused(lambda: resources.update_site(11, name="Beta B", context=ctx_whole, **{key: stale}), resources.ResourceConflict)
    must(err.code == "record_changed" and key[len("expected_"):] in str(err) and "99" not in str(err), str(err))
    must(site_snapshot() == before, f"{key}: no write, no audit row")
    response = patch("site", 11, {"name": "Beta B", key: stale})
    must(response.status_code == 409 and response.data["code"] == "record_changed", response.data)
    must(site_snapshot() == before)

# the guard is judged with a move in the same call: a stale guard moves nothing
seed_site()
other_client = max(Client.STORE)
sites_before = {pk: dict(v) for pk, v in Site.STORE.items()}
destination = next(pk for pk in Client.STORE if pk != Site.STORE[11]["client_id"])
refused(lambda: resources.update_site(11, client_id=destination, expected_server_policy_id=99, context=ctx_for(admin)), resources.ResourceConflict)
must({pk: dict(v) for pk, v in Site.STORE.items()} == sites_before and AUDITS == [], "a stale guard moves nothing")
# a same-client move with a guard is judged too (no shortcut past the compare)
current_client = Site.STORE[11]["client_id"]
refused(lambda: resources.update_site(11, client_id=current_client, expected_server_policy_id=99, context=ctx_whole), resources.ResourceConflict)
must(AUDITS == [], AUDITS)
must(resources.update_site(11, client_id=current_client, expected_server_policy_id=32, context=ctx_whole)["id"] == 11 and AUDITS == [], "a matching guard, nothing to change: no row")
# a site guard alone is a 400, and a bad value is a 400
refused(lambda: resources.update_site(11, expected_server_policy_id=32, context=ctx_whole), resources.ResourceValidationError)
refused(lambda: resources.update_site(11, name="Q", expected_block_policy_inheritance="no", context=ctx_whole), resources.ResourceValidationError)
must(patch("site", 11, {"name": "Q", "expected_server_policy_id": True}).status_code == 400)
# no guard key: unchanged behaviour
seed_site()
resources.update_site(11, server_policy_id=32, context=ctx_whole)
must(AUDITS == [], "an unchanged site update writes no audit row")

# ------------------------------------------------------------------------------------------ the compare helper with stub rows
row = types.SimpleNamespace(workstation_policy_id=31, server_policy_id=None, block_policy_inheritance=True)
adapter.check_expected(row, None, "client")
adapter.check_expected(row, {}, "client")
adapter.check_expected(row, {"workstation_policy_id": 31, "server_policy_id": None, "block_policy_inheritance": True}, "client")
for expected in ({"workstation_policy_id": 32}, {"workstation_policy_id": None}, {"server_policy_id": 5}, {"block_policy_inheritance": False}):
    exc = refused(lambda e=expected: adapter.check_expected(row, e, "site"), adapter.TacticalResourceConflictError)
    must(exc.code == "record_changed" and list(expected)[0] in str(exc) and str(list(expected.values())[0]) not in str(exc).replace(list(expected)[0], ""), str(exc))
must(adapter.TacticalResourceConflictError("A client with that name already exists.").code is None, "the older conflicts carry no code")
must(resources.ResourceConflict("x").code == "resource_conflict" and resources.ResourceConflict("x", code="record_changed").code == "record_changed")
loose = types.SimpleNamespace(workstation_policy_id="31", server_policy_id=None, block_policy_inheritance=None)
adapter.check_expected(loose, {"workstation_policy_id": 31, "block_policy_inheritance": False}, "client")  # text ids and a missing flag read as Tactical stores them

print("resource expected guard 1.17.51 ok")
