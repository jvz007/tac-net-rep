#!/usr/bin/env python3
"""1.17.24 regression: move a site to another client (Tactical's Edit site; CO25, C7), keeping the one-site-per-client rule.

The mechanism is older (update_site with client_id). Since core.resources 1.7.0 the rules are documented and pinned here:
the agents follow the site, the destination needs the client write grant of create_site, the last site of a client cannot leave,
a name clash is a 409, the same client is a no-op, and the strict audit row says what moved (ids and a count, never a name).
Uses the in-memory Tactical of tests/resource-alert-template-1.17.17.py. The real move with Postgres runs in
tests/resource-directory-site-move-postgres.py, and the Tactical save hooks on the dev server in tests/resource-policy-runtime-1.17.24.py.
"""
from __future__ import annotations

import pathlib

_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())
H = globals()
must, resources, adapter, views = H["must"], H["resources"], H["adapter"], H["views"]
reset_tactical, Client, Site, Agent, User, Role = H["reset_tactical"], H["Client"], H["Site"], H["Agent"], H["User"], H["Role"]
AUDITS, HOOKS, ctx_for, ROOT, PKG = H["AUDITS"], H["HOOKS"], H["ctx_for"], H["ROOT"], H["PKG"]

reset_tactical()
admin = User(Role())
both_clients = User(Role(clients=[1, 2]))     # holds the source and the destination client
client_one_only = User(Role(clients=[1]))     # holds only the source client
site_only = User(Role(sites=[12]))            # one site, no whole client
ctx_admin = ctx_for(admin)


def refused(call, *errors):
    try:
        call()
    except errors as exc:
        return exc
    raise AssertionError(f"call was accepted: {call}")


saved = {}
orig_save = Site.save


def spy_save(self, update_fields=None):
    saved["fields"] = list(update_fields or [])
    return orig_save(self, update_fields=update_fields)


# ----------------------------------------------------------------------------------- a move succeeds
Agent.STORE.update({"a-2": {"pk": 2, "agent_id": "a-2", "site_id": 12}, "a-3": {"pk": 3, "agent_id": "a-3", "site_id": 12}})
del AUDITS[:], HOOKS[:]
Site.save = spy_save
row = resources.update_site(12, client_id=2, context=ctx_for(both_clients))
Site.save = orig_save
must(row["client_id"] == 2 and row["client_name"] == "Beta" and row["name"] == "Alpha Two" and tuple(row) == resources.SITE_FIELDS, row)
must(Site.STORE[12]["client_id"] == 2 and Site.STORE[11]["client_id"] == 1, "stored")
# Tactical's Site.save ran with the model fields: client, modified_by and modified_time
must(saved["fields"] == ["client", "modified_by", "modified_time"], saved)
must(HOOKS == [("site", 12)], HOOKS)  # Tactical's own Site.save hook refreshed the agents' caches
# the agents follow the site because they point at the site row (their site_id is unchanged)
must(all(Agent.STORE[a]["site_id"] == 12 for a in ("a-2", "a-3")), "agents stay on the site")
must(len(AUDITS) == 1, AUDITS)
audit = AUDITS[0]
must(audit["action"] == "modify" and audit["object_type"] == "resource_site" and audit["object_id"] == "12" and audit["strict"] is True, audit)
must(audit["before"]["client_id"] == 1 and audit["after"]["client_id"] == 2, audit)
must(audit["metadata"] == {"alert_template_changed": False, "client_changed": True, "from_client_id": 1, "to_client_id": 2, "agents_moved": 2}, audit["metadata"])
for value in audit["metadata"].values():
    must(isinstance(value, (bool, int)), f"numbers and flags only: {value!r}")
must("Alpha" not in repr(audit["metadata"]) and "Beta" not in repr(audit["metadata"]), "no names in the metadata")

# ----------------------------------------------------------------------------------- the last site is refused
reset_tactical()
del AUDITS[:], HOOKS[:]
exc = refused(lambda: resources.update_site(21, client_id=1, context=ctx_admin), resources.ResourceValidationError)
must(str(exc) == "A client must retain at least one site." and exc.code == "invalid_resource_request", (str(exc), exc.code))
must(Site.STORE[21]["client_id"] == 2 and not AUDITS and not HOOKS, "nothing saved, no row")
# a move together with a rename is refused whole
refused(lambda: resources.update_site(21, client_id=1, name="Renamed", context=ctx_admin), resources.ResourceValidationError)
must(Site.STORE[21]["name"] == "Beta One" and not AUDITS, "the rename was not applied either")

# ----------------------------------------------------------------------------------- the destination must be in the caller's grant
del AUDITS[:]
exc = refused(lambda: resources.update_site(12, client_id=2, context=ctx_for(client_one_only)), resources.ResourceNotFound)
must(exc.code == "resource_not_found" and str(exc) == "Client was not found in the caller's resource scope.", (exc.code, str(exc)))
exc_missing = refused(lambda: resources.update_site(12, client_id=999, context=ctx_for(client_one_only)), resources.ResourceNotFound)
must(str(exc_missing) == str(exc) and exc_missing.code == exc.code, "a client that does not exist reads the same: no enumeration difference")
exc_missing_admin = refused(lambda: resources.update_site(12, client_id=999, context=ctx_admin), resources.ResourceNotFound)
must(str(exc_missing_admin) == str(exc), "also for an unrestricted caller")
refused(lambda: resources.update_site(12, client_id=2, context=ctx_for(site_only)), resources.ResourceNotFound)  # a site grant is not a client grant
must(Site.STORE[12]["client_id"] == 1 and not AUDITS, "refused: nothing changed")
# a source site the caller does not hold
refused(lambda: resources.update_site(11, client_id=2, context=ctx_for(site_only)), resources.ResourceNotFound)
must(Site.STORE[11]["client_id"] == 1, "unchanged")
# the Tactical permission and the Core permission are both still needed
refused(lambda: resources.update_site(12, client_id=2, context=ctx_for(User(Role(manage=False)))), resources.ResourcePermissionDenied)
refused(lambda: resources.update_site(12, client_id=2, context=ctx_for(User(Role(), core=()))), resources.ResourcePermissionDenied)

# ----------------------------------------------------------------------------------- a name clash in the destination is 409
resources.update_site(21, name="Alpha Two", context=ctx_admin)
del AUDITS[:], HOOKS[:]
exc = refused(lambda: resources.update_site(12, client_id=2, context=ctx_admin), resources.ResourceConflict)
must(str(exc) == "A site with that name already exists for the selected client." and exc.code == "resource_conflict", (str(exc), exc.code))
must(Site.STORE[12]["client_id"] == 1 and not AUDITS and not HOOKS, "nothing saved, no row")

# ----------------------------------------------------------------------------------- the same client is a no-op
reset_tactical()
del AUDITS[:], HOOKS[:]
Site.save = spy_save
saved.clear()
row = resources.update_site(11, client_id=1, context=ctx_admin)
Site.save = orig_save
must(row["id"] == 11 and row["client_id"] == 1 and not AUDITS and not HOOKS and "fields" not in saved, (row, AUDITS, saved))
# the destination check is skipped too: a site-only role sending its own client changes nothing and is not refused
row = resources.update_site(12, client_id=1, context=ctx_for(site_only))
must(row["client_id"] == 1 and not AUDITS, "same client: no destination check, no row")
# same client with a rename is only a rename: one row, no client_changed keys
row = resources.update_site(11, client_id=1, name="Alpha One B", context=ctx_admin)
must(row["name"] == "Alpha One B" and len(AUDITS) == 1 and AUDITS[0]["metadata"] == {"alert_template_changed": False}, AUDITS)
resources.update_site(11, name="Alpha One", context=ctx_admin)

# ----------------------------------------------------------------------------------- combined move and rename is one row
reset_tactical()
del AUDITS[:], HOOKS[:]
row = resources.update_site(12, client_id=2, name="Moved Two", alert_template_id=5, context=ctx_admin)
must(row["client_id"] == 2 and row["name"] == "Moved Two" and row["alert_template_id"] == 5, row)
must(len(AUDITS) == 1 and AUDITS[0]["metadata"]["client_changed"] is True and AUDITS[0]["metadata"]["alert_template_changed"] is True, AUDITS)
must(AUDITS[0]["metadata"]["agents_moved"] == 0 and AUDITS[0]["metadata"]["from_client_id"] == 1 and AUDITS[0]["metadata"]["to_client_id"] == 2, AUDITS[0]["metadata"])
must(AUDITS[0]["before"]["name"] == "Alpha Two" and AUDITS[0]["after"]["name"] == "Moved Two", AUDITS[0])

# ----------------------------------------------------------------------------------- a failed audit write rolls back the move
reset_tactical()
orig_record = resources._record_resource_change


def failing_record(**kw):
    raise resources.ResourceDirectoryError("Resource change requires a persisted Core audit record.")


resources._record_resource_change = failing_record
refused(lambda: resources.update_site(12, client_id=2, context=ctx_admin), resources.ResourceDirectoryError)
resources._record_resource_change = orig_record
# (the in-memory Tactical has no rollback; the real transaction.atomic rolls the row back on this raise, as for every Core write)

# ----------------------------------------------------------------------------------- HTTP: client_id with and without name and alert_template_id
reset_tactical()


class Req:
    def __init__(self, user, data):
        self.user, self.data, self.query_params = user, data, {}


def patch(rid, data, user=admin):
    view = views.ResourceMutableDetailView()
    view.resource_type = "site"
    return view.patch(Req(user, data), rid)


r = patch(12, {"client_id": 2})
must(r.status_code == 200 and r.data["client_id"] == 2 and r.data["name"] == "Alpha Two", r.__dict__)
r = patch(12, {"client_id": 1, "name": "Alpha Two B"})
must(r.status_code == 200 and r.data["client_id"] == 1 and r.data["name"] == "Alpha Two B", r.__dict__)
r = patch(12, {"client_id": 2, "alert_template_id": 6})
must(r.status_code == 200 and r.data["client_id"] == 2 and r.data["alert_template_id"] == 6, r.__dict__)
r = patch(12, {"client_id": 1, "name": "Alpha Two", "alert_template_id": None})
must(r.status_code == 200 and r.data["client_id"] == 1 and r.data["alert_template_id"] is None, r.__dict__)
r = patch(21, {"client_id": 1})
must(r.status_code == 400 and r.data["detail"] == "A client must retain at least one site.", r.__dict__)
r = patch(12, {"client_id": 999})
must(r.status_code == 404 and r.data["code"] == "resource_not_found", r.__dict__)
r = patch(12, {"client_id": 2}, user=client_one_only)
must(r.status_code == 404, r.__dict__)
resources.update_site(21, name="Alpha Two", context=ctx_admin)
r = patch(12, {"client_id": 2})
must(r.status_code == 409 and r.data["code"] == "resource_conflict", r.__dict__)
r = patch(11, {"client_id": "x"})
must(r.status_code == 400, r.__dict__)
r = patch(11, {"client_id": 1})
must(r.status_code == 200 and r.data["client_id"] == 1, "same client over HTTP is a no-op, not an error")

# ----------------------------------------------------------------------------------- contract text and docs
meta = resources.resource_contract_metadata()
must("move_site" in meta["mutation_contracts"], list(meta["mutation_contracts"]))
text = meta["mutation_contracts"]["move_site"]["semantics"]
for needle in ("agents follow", "A client must retain at least one site.", "409", "no-op", "client_changed", "from_client_id", "to_client_id", "agents_moved", "stricter than Tactical", "404"):
    must(needle in text, needle)
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("#### Move a site" in doc and "agents_moved" in doc and "A client must retain at least one site." in doc, "docs")
contracts_text = (PKG / "contracts.py").read_text(encoding="utf-8")
must("agents_moved" in contracts_text, "python row")

print("[TEST] PASS resource move site 1.17.24")
