#!/usr/bin/env python3
"""1.17.16 regression (held Medium of the 1.17.7 review): the Python ``run`` no longer trusts any object that has a ``user``.

AD-19 condition 2 says Core never substitutes another user. ``run_tactical_operation`` now accepts only a real Django HttpRequest, or
a DRF Request wrapping one, whose user is authenticated and which carries ``tec_tac_session`` (left by Core's SessionAuthenticated
guard, so the session-security check ran). Anything else is refused 401 ``authenticated_request_required`` with a fixed Core text
and no audit row, because no trustworthy actor exists to write. The HTTP route is unchanged.

Uses the stubs of tests/tactical-operations-1.17.7.py the way tests/tactical-operations-audit-object-1.17.13.py does.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, declare, fresh, must = (G[k] for k in ("ops", "declare", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, tech, Request, User, DRFWrapper = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "tech", "Request", "User", "DRFWrapper"))
FakeResponse, refusal, route, HttpRequest = G["FakeResponse"], G["refusal"], G["route"], G["HttpRequest"]

PATH = f"/agents/{AGENT}/reboot/"
PARAMS, BODY = {"agent_id": AGENT}, {"mode": "now"}
fresh()
declare()
route(PATH, FakeResponse(200))
superuser = User("root", superuser=True)


def attempt(request):
    del ROWS[:], CALLS[:]
    return ops.run_tactical_operation(request, "agents", "reboot", PARAMS, BODY)


def refused_identity(request, why):
    exc = refusal(lambda: attempt(request), 401, "authenticated_request_required")
    must(exc.message == ops.MESSAGES["authenticated_request_required"] and exc.audit is None, why)
    must(not ROWS and not CALLS, f"{why}: no row and no call")


# an object that merely has a user, even a superuser, is refused
refused_identity(SimpleNamespace(user=superuser), "a SimpleNamespace with a superuser")
refused_identity(SimpleNamespace(user=tech, tec_tac_session=object(), META={}), "a namespace that copies the session proof")
refused_identity(SimpleNamespace(), "an empty object")
refused_identity(None, "None")
refused_identity("tech", "a string")

# a real request without the session proof
bare = HttpRequest()
bare.user = tech
refused_identity(bare, "an HttpRequest without tec_tac_session")
proofless = Request(tech)
del proofless.tec_tac_session
refused_identity(proofless, "a request that never passed SessionAuthenticated")
none_proof = Request(tech)
none_proof.tec_tac_session = None
refused_identity(none_proof, "a session of None")

# a wrapper around something that is not a real request is refused even when it carries the proof
refused_identity(DRFWrapper(SimpleNamespace(user=superuser, tec_tac_session=object())), "a DRF-style wrapper of a stand-in")
fake_wrapper = SimpleNamespace(_request=Request(tech), user=superuser, tec_tac_session=object())
refused_identity(fake_wrapper, "a stand-in that only names a real request in _request")

# the refusal is the first step: a bad operation id or bad keyword on a bad request is still the identity refusal
exc = refusal(lambda: ops.run_tactical_operation(SimpleNamespace(user=tech), "agents", "nope", None, None, correlation_id="bad id"), 401, "authenticated_request_required")

# a real, signed-in request that carries the proof runs
result = attempt(Request(tech))
must(result.status == 200 and len(ROWS) == 1 and CALLS, (result.status, ROWS))
must(ROWS[0]["username"] == "tech", "the row names the signed-in user")

# a DRF-style wrapper with _request works
wrapped = DRFWrapper(Request(tech))
result = attempt(wrapped)
must(result.status == 200 and len(ROWS) == 1, ROWS)

# a real request whose user is not authenticated is still the old 401, and writes no row
refusal(lambda: attempt(Request(User(anonymous=True))), 401, "authentication_required")
must(not ROWS and not CALLS, "an unauthenticated user writes nothing")

# the HTTP route is unchanged
reply = G["views"].TacticalOperationView().post(Request(tech, data={"params": PARAMS, "body": BODY}), "agents", "reboot")
must(reply.status_code == 200, reply.__dict__)

# the shared stub now models SessionAuthenticated: the helper Request is an HttpRequest with the proof
must(isinstance(Request(tech), HttpRequest) and Request(tech).tec_tac_session is not None, "the shared stub")

print("[TEST] PASS tactical operations request identity 1.17.16")
