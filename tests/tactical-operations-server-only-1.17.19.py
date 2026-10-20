#!/usr/bin/env python3
"""1.17.19 regression: ``server_only`` operations, the 403 that names the missing flag, and the 1.17.18 documentation fixes.

Covered: ``server_only`` is a strict bool at registration; Core's HTTP route refuses a server-only operation 403
``operation_server_only`` with exactly one deny row (reason ``server_only``, ``refused_action`` the declared action) and the audit
header, never calls Tactical, and never parses a multipart body or reads an upload; an unauthenticated request is refused first; the
refusal comes before the Tactical flag check; a backend calling ``run_tactical_operation`` runs it with ``audit_before`` and writes
the normal row; a normal operation through the view is unchanged; ``list_operations`` carries ``server_only``; one and two missing
flags are named while the deny row text and the code stay fixed; the docs state the caller_scope and body_selector facts. Uses the
stubs of tests/tactical-operations-1.17.7.py.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, views, fresh, must = (G[k] for k in ("ops", "views", "fresh", "must"))
ROWS, CALLS, AGENT, tech, User, Roleish, Request = (G[k] for k in ("ROWS", "CALLS", "AGENT", "tech", "User", "Roleish", "Request"))
FakeResponse, route, refusal, DRFResponse = (G[k] for k in ("FakeResponse", "route", "refusal", "DRFResponse"))

PATH = f"/agents/{AGENT}/bulk/"
ROUTE = "agents/{agent_id:agent}/bulk/"


def declare(op_id="bulk", route_=ROUTE, **over):
    spec = dict(id=op_id, module_id="agents", method="POST", route=route_, permissions=["can_reboot_agents"],
                scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["mode"],
                audit={"action": "run", "object_type": "agent", "audit_fields": ["mode"]})
    spec.update(over)
    return ops.register_tactical_operation(**spec)


# ---- registration: a strict bool
fresh()
must(declare(server_only=True).server_only is True, "True")
fresh()
must(declare(server_only=False).server_only is False and declare("other", "agents/{agent_id:agent}/other/").server_only is False, "False and the default")
for bad in (1, 0, "yes", "", None, [], {}):
    fresh()
    try:
        declare(server_only=bad)
        raise AssertionError(f"accepted {bad!r}")
    except ops.TacticalOperationRegistrationError as exc:
        must("server_only must be true or false" in str(exc), str(exc))

# ---- list_operations and get_operation carry it
fresh()
declare(server_only=True)
declare("plain", "agents/{agent_id:agent}/plain/")
rows = {row["id"]: row for row in ops.list_operations("agents")}
must(rows["bulk"]["server_only"] is True and rows["plain"]["server_only"] is False, rows)
must(ops.get_operation("agents", "bulk")["server_only"] is True, "get_operation")

# ---- the view refuses a server-only operation
view = views.TacticalOperationView()
route(PATH, FakeResponse(200, b'{"ok": true}'))
del ROWS[:], CALLS[:]
reply = view.post(Request(tech, data={"params": {"agent_id": AGENT}, "body": {"mode": "now"}}), "agents", "bulk")
must(isinstance(reply, DRFResponse) and reply.status_code == 403 and reply.data == {"detail": ops.MESSAGES["server_only"], "code": "operation_server_only"}, reply.__dict__)
must(reply.headers == {"X-Tec-Tac-Audit": "recorded"}, reply.headers)
must(not CALLS, "Tactical was never called")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", ROWS)
meta = ROWS[0]["debug_info"]["metadata"]
must(meta["refused_action"] == "run" and meta["reason"] == "server_only" and meta["status"] == 403, meta)
must(ROWS[0]["message"] == ops.DENY_MESSAGES["server_only"], ROWS[0]["message"])


# a multipart body is not parsed and no upload is read: any access to data or FILES would raise
class Untouchable(Request):
    @property
    def data(self):
        raise AssertionError("the body was parsed")

    @property
    def FILES(self):
        raise AssertionError("the upload was read")


del ROWS[:], CALLS[:]
big = Untouchable(tech, content_type="multipart/form-data; boundary=x")
big.META["CONTENT_LENGTH"] = str(10 ** 12)
reply = view.post(big, "agents", "bulk")
must(reply.status_code == 403 and reply.data["code"] == "operation_server_only" and len(ROWS) == 1, reply.__dict__)

# an unauthenticated request is refused first, with no row
del ROWS[:]
reply = view.post(Request(User(anonymous=True, role=tech.role), data={"params": {"agent_id": AGENT}}), "agents", "bulk")
must(reply.status_code == 401 and reply.data["code"] == "authentication_required" and not ROWS, reply.__dict__)
reply = view.post(SimpleNamespace(user=tech, data={}), "agents", "bulk")
must(reply.status_code == 401 and reply.data["code"] == "authenticated_request_required" and not ROWS, reply.__dict__)

# the server-only refusal comes before the Tactical flag check
weak = User("weak", Roleish("can_send_wol"))
weak.sees = tech.sees
del ROWS[:]
reply = view.post(Request(weak, data={"params": {"agent_id": AGENT}}), "agents", "bulk")
must(reply.status_code == 403 and reply.data["code"] == "operation_server_only", reply.__dict__)
must(len(ROWS) == 1 and ROWS[0]["debug_info"]["metadata"]["reason"] == "server_only", ROWS)

# ---- a backend runs it directly, with audit_before, and gets the normal row
del ROWS[:], CALLS[:]
result = ops.run_tactical_operation(Request(tech), "agents", "bulk", {"agent_id": AGENT}, {"mode": "now"}, audit_before={"state": "old"})
must(result.status == 200 and len(CALLS) == 1, "the backend call reached Tactical")
must(len(ROWS) == 1 and ROWS[0]["action"] == "run" and ROWS[0]["before_value"] == {"state": "old"}, ROWS)
# the private keyword only makes Core stricter
del ROWS[:], CALLS[:]
refusal(lambda: ops.run_tactical_operation(Request(tech), "agents", "bulk", {"agent_id": AGENT}, {"mode": "now"}, _via_http_route=True), 403, "operation_server_only")
must(not CALLS, "never called Tactical")
# a normal operation is unchanged, through the view
route(f"/agents/{AGENT}/plain/", FakeResponse(200, b'{"ok": true}'))
del ROWS[:], CALLS[:]
reply = view.post(Request(tech, data={"params": {"agent_id": AGENT}, "body": {"mode": "now"}}), "agents", "plain")
must(reply.status_code == 200 and len(CALLS) == 1 and ROWS[0]["action"] == "run", reply.__dict__)

# ---- the 403 names the missing flag; the row and the code stay fixed
fresh()
declare("two", "agents/{agent_id:agent}/two/", permissions=["can_reboot_agents", "can_manage_notes"])
declare("one", "agents/{agent_id:agent}/one/")
route(f"/agents/{AGENT}/one/")
route(f"/agents/{AGENT}/two/")
nothing = User("nothing", Roleish())
nothing.sees = tech.sees
del ROWS[:]
exc = refusal(lambda: ops.run_tactical_operation(Request(nothing), "agents", "one", {"agent_id": AGENT}, {}), 403, "tactical_permission_denied")
must(exc.message == ops.MESSAGES["permission_denied"] + " It needs the Tactical permission can_reboot_agents.", exc.message)
must(ROWS[0]["message"] == ops.DENY_MESSAGES["permission_denied"] and ROWS[0]["action"] == "deny", ROWS)
del ROWS[:]
exc = refusal(lambda: ops.run_tactical_operation(Request(nothing), "agents", "two", {"agent_id": AGENT}, {}), 403, "tactical_permission_denied")
must("can_reboot_agents" in exc.message and "can_manage_notes" in exc.message and "permissions" in exc.message, exc.message)
must(ROWS[0]["message"] == ops.DENY_MESSAGES["permission_denied"], ROWS)
one_missing = User("half", Roleish("can_reboot_agents"))
one_missing.sees = tech.sees
exc = refusal(lambda: ops.run_tactical_operation(Request(one_missing), "agents", "two", {"agent_id": AGENT}, {}), 403, "tactical_permission_denied")
must("can_manage_notes" in exc.message and "can_reboot_agents" not in exc.message.split("It needs")[1], exc.message)

# ---- capability metadata and documentation
meta = ops.tactical_operations_contract_metadata()
must(meta["version"] == "1.16.0" and meta["declaration_keys_added_in_1_5_0"] == ["server_only"] and meta["refusal_codes_added_in_1_5_0"] == ["operation_server_only"], meta)
must("server_only=False" in meta["declaration"], meta["declaration"])
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
must("server_only" in contracts and "operation_server_only" in contracts and "custom:operation-failed" in contracts, "contracts.py names server_only and, since 1.17.20, the failed-row action")
must(any(line.lstrip().startswith('"403": "a Tactical flag') and "operation_server_only" in line for line in contracts.splitlines()), "the 403 entry of the errors table lists operation_server_only")
must("Any other 4xx: no row." not in contracts and "Any other 4xx from Tactical still writes no row" not in contracts, "1.17.20: the contract no longer says other 4xx write nothing")
docs = " ".join((ROOT / "docs/tactical-operations.md").read_text(encoding="utf-8").split())  # line breaks do not matter
must("Server-only operations" in docs and "operation_server_only" in docs and "not a verified caller identity" in docs and "_via_http_route" in docs, "server-only docs")
caller_scope_text = "applies to every call of the operation, including a call whose body names no agent"
must(caller_scope_text in docs and caller_scope_text in contracts, "caller_scope wording agrees in the docs and contracts.py")
must("belongs to a `row_lookup` scope entry" in docs, "the CQ57 rule is placed with row_lookup")
must("A selector field must also be one of the operation's `body_fields`" in docs and "still lists the field" in docs, "body_selector docs")
print("[TEST] PASS tactical operations server only 1.17.19")
