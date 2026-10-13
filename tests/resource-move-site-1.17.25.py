#!/usr/bin/env python3
"""1.17.25 regression (Johan CQ79, held Low): moving a site follows Tactical's Edit site (core.resources 1.8.0).

Tactical's Edit site checks the Edit sites permission and the source site's scope. It never checks a grant on the destination
client, so a limited role may move a site into a client it holds no grant on. Core follows that rule. The held Low: a same-client
update returned before the write-scope check, so a caller who could read the site but not write it got a 200. Now the source site's
write scope is checked first, and the refusal is the same 404 every other write gives. Also pinned: the source scope, a missing
destination (a 400 from the model's foreign-key check, never a 500), the last site (400), a name clash (409), the same client (a
no-op with no row when the write scope holds), the Tactical and Core permissions, the audit row (ids and a count only), the HTTP
route, and the contract and doc text (core.resources 1.8.0).
Uses the in-memory Tactical of tests/resource-alert-template-1.17.17.py. The real move with Postgres runs in
tests/resource-directory-site-move-postgres.py, and the Tactical save hooks on the dev server in tests/resource-policy-runtime-1.17.24.py.
"""
from __future__ import annotations

import pathlib

_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())
H = globals()
must, resources, views = H["must"], H["resources"], H["views"]
reset_tactical, Client, Site, Agent, User, Role = H["reset_tactical"], H["Client"], H["Site"], H["Agent"], H["User"], H["Role"]
ValidationError = H["ValidationError"]
AUDITS, HOOKS, ctx_for, ROOT, PKG = H["AUDITS"], H["HOOKS"], H["ctx_for"], H["ROOT"], H["PKG"]

reset_tactical()
admin = User(Role())
client_one_only = User(Role(clients=[1]))     # holds the source client only: no grant on client 2
site_only = User(Role(sites=[12]))            # one site, no whole client
ctx_admin = ctx_for(admin)


def refused(call, *errors):
    try:
        call()
    except errors as exc:
        return exc
    raise AssertionError(f"call was accepted: {call}")


def install_fk_check():
    """Django's foreign-key check on the destination client (the in-memory Site model does not run it). Returns the restore."""
    real_full_clean = Site.full_clean

    def full_clean(self, **kw):
        if self.client_id not in Client.STORE:
            raise ValidationError("bad client", {"client": ["client instance does not exist."]})
        return real_full_clean(self, **kw)

    Site.full_clean = full_clean
    return lambda: setattr(Site, "full_clean", real_full_clean)


# ----------------------------------------------------------------------------------- a limited role moves into a client it holds no grant on
Agent.STORE.update({"a-2": {"pk": 2, "agent_id": "a-2", "site_id": 12}, "a-3": {"pk": 3, "agent_id": "a-3", "site_id": 12}})
del AUDITS[:], HOOKS[:]
row = resources.update_site(12, client_id=2, context=ctx_for(client_one_only))
must(row["client_id"] == 2 and row["client_name"] == "Beta" and tuple(row) == resources.SITE_FIELDS, row)
must(Site.STORE[12]["client_id"] == 2 and Site.STORE[11]["client_id"] == 1, "moved, and only that site")
must(all(Agent.STORE[a]["site_id"] == 12 for a in ("a-2", "a-3")), "the agents follow the site")
must(len(AUDITS) == 1, AUDITS)
audit = AUDITS[0]
must(audit["action"] == "modify" and audit["object_type"] == "resource_site" and audit["object_id"] == "12" and audit["strict"] is True, audit)
must(audit["metadata"] == {"alert_template_changed": False, "client_changed": True, "from_client_id": 1, "to_client_id": 2, "agents_moved": 2}, audit["metadata"])
must(all(isinstance(value, (bool, int)) for value in audit["metadata"].values()), "ids and counts only")
must("Alpha" not in repr(audit["metadata"]) and "Beta" not in repr(audit["metadata"]), "no names in the metadata")
must(HOOKS == [("site", 12)], HOOKS)
resources.update_site(12, client_id=1, context=ctx_admin)
del AUDITS[:], HOOKS[:]

# ----------------------------------------------------------------------------------- a site-only role moves its own site
row = resources.update_site(12, client_id=2, context=ctx_for(site_only))
must(row["client_id"] == 2 and len(AUDITS) == 1 and AUDITS[0]["metadata"]["client_changed"] is True, (row, AUDITS))
resources.update_site(12, client_id=1, context=ctx_admin)
del AUDITS[:], HOOKS[:]

# ----------------------------------------------------------------------------------- the source site must be in the caller's write scope
exc = refused(lambda: resources.update_site(11, client_id=2, context=ctx_for(site_only)), resources.ResourceNotFound)
must(exc.code == "resource_not_found" and str(exc) == "Site was not found in the caller's resource scope.", (exc.code, str(exc)))
must(Site.STORE[11]["client_id"] == 1 and not AUDITS and not HOOKS, "refused: nothing saved, no row")
exc = refused(lambda: resources.update_site(999, client_id=2, context=ctx_for(client_one_only)), resources.ResourceNotFound)
must(exc.code == "resource_not_found", exc.code)

# ----------------------------------------------------------------------------------- the held Low: a same-client update is write-scope checked first
# The in-memory scope gives reads and writes the same answer, so the read-only case the Low describes is simulated: the site is
# found for the caller (the read answer) while the write-scope check says no. Before the fix a same-client update gave a 200.
reset_tactical()
del AUDITS[:], HOOKS[:]
real_write_check = resources.adapter.site_write_in_scope
resources.adapter.site_write_in_scope = lambda **kw: False
try:
    exc = refused(lambda: resources.update_site(11, client_id=1, context=ctx_for(client_one_only)), resources.ResourceNotFound)
    exc_rename = refused(lambda: resources.update_site(11, client_id=1, name="Read Only", context=ctx_for(client_one_only)), resources.ResourceNotFound)
finally:
    resources.adapter.site_write_in_scope = real_write_check
must(exc.code == "resource_not_found" and str(exc) == "Site was not found in the caller's resource scope.", (exc.code, str(exc)))
must(str(exc_rename) == str(exc) and Site.STORE[11]["name"] == "Alpha One" and not AUDITS and not HOOKS, "refused the same way, nothing saved")
# with the write scope, the same client is still a no-op: no row, nothing saved
row = resources.update_site(11, client_id=1, context=ctx_for(client_one_only))
must(row["id"] == 11 and row["client_id"] == 1 and not AUDITS and not HOOKS, (row, AUDITS))

# ----------------------------------------------------------------------------------- a missing destination client is a 400, not a 500
restore = install_fk_check()
try:
    exc = refused(lambda: resources.update_site(12, client_id=999, context=ctx_for(client_one_only)), resources.ResourceValidationError)
    exc_admin = refused(lambda: resources.update_site(12, client_id=999, context=ctx_admin), resources.ResourceValidationError)
finally:
    restore()
must(exc.code == "invalid_resource_request" and str(exc) == str(exc_admin), (exc.code, str(exc)))
must(Site.STORE[12]["client_id"] == 1 and not AUDITS and not HOOKS, "a missing destination writes nothing")

# ----------------------------------------------------------------------------------- the last site, the name clash, the permissions
reset_tactical()
del AUDITS[:], HOOKS[:]
exc = refused(lambda: resources.update_site(21, client_id=1, context=ctx_admin), resources.ResourceValidationError)
must(str(exc) == "A client must retain at least one site." and exc.code == "invalid_resource_request", (str(exc), exc.code))
must(Site.STORE[21]["client_id"] == 2 and not AUDITS, "the last site stays where it is")
resources.update_site(21, name="Alpha Two", context=ctx_admin)
del AUDITS[:]
exc = refused(lambda: resources.update_site(12, client_id=2, context=ctx_for(client_one_only)), resources.ResourceConflict)
must(str(exc) == "A site with that name already exists for the selected client." and exc.code == "resource_conflict", (str(exc), exc.code))
must(Site.STORE[12]["client_id"] == 1 and not AUDITS and not HOOKS, "a name clash writes nothing")
refused(lambda: resources.update_site(12, client_id=2, context=ctx_for(User(Role(manage=False)))), resources.ResourcePermissionDenied)
refused(lambda: resources.update_site(12, client_id=2, context=ctx_for(User(Role(), core=()))), resources.ResourcePermissionDenied)

# ----------------------------------------------------------------------------------- HTTP
reset_tactical()


class Req:
    def __init__(self, user, data):
        self.user, self.data, self.query_params = user, data, {}


def patch(rid, data, user):
    view = views.ResourceMutableDetailView()
    view.resource_type = "site"
    return view.patch(Req(user, data), rid)


r = patch(12, {"client_id": 2}, client_one_only)
must(r.status_code == 200 and r.data["client_id"] == 2, r.__dict__)
r = patch(12, {"client_id": 1}, admin)
must(r.status_code == 200 and r.data["client_id"] == 1, r.__dict__)
r = patch(12, {"client_id": 2}, site_only)
must(r.status_code == 200 and r.data["client_id"] == 2, r.__dict__)
r = patch(12, {"client_id": 1}, admin)
must(r.status_code == 200 and r.data["client_id"] == 1, r.__dict__)
r = patch(11, {"client_id": 2}, site_only)
must(r.status_code == 404, r.__dict__)

# ----------------------------------------------------------------------------------- contract text, docs and version
meta = resources.resource_contract_metadata()
must(meta["version"] == "1.8.0" and meta["version"].split(".")[0] == "1", meta["version"])
must(resources.CONTRACT_VERSION == "1.8.0", resources.CONTRACT_VERSION)
text = meta["mutation_contracts"]["move_site"]["semantics"]
for needle in ("1.8.0", "needs no grant", "Edit sites", "A missing destination client is a 400", "A client must retain at least one site.", "agents_moved"):
    must(needle in text, needle)
must("stricter than Tactical" not in text and "grant on the destination" not in text, "the 1.7.0 destination grant is gone")
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("Contract version: `1.8.0`" in doc and "Contract 1.8 (Core 1.17.25" in doc, "doc header and contract note")
must("needs no grant" in doc and "This loosens Core's 1.17.24 rule" in doc and "stricter than Tactical, which checks only" not in doc, "doc move section")
contracts_text = (PKG / "contracts.py").read_text(encoding="utf-8")
must("Since core.resources 1.8.0 (framework >=1.17.25, CQ79) it follows Tactical's Edit site" in contracts_text, "python contract row")

print("[TEST] PASS resource move site 1.17.25")
