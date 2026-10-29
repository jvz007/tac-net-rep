#!/usr/bin/env python3
"""1.17.90 regression: the endpoint agent identity check (authenticate_endpoint_agent), the header parser, the failure limit and the audit
actor. Stubbed Django models (tests/endpoint_transport_harness.py), the real endpoint_transport.py."""
from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must, reset, add_agent, TOKENS, CACHE = H.et, H.must, H.reset, H.add_agent, H.TOKENS, H.CACHE
FakeUser, FakeAgent, FakeTokenRow, TOKEN, TOKEN2 = H.FakeUser, H.FakeAgent, H.FakeTokenRow, H.TOKEN, H.TOKEN2

# a valid token with the matching agent id is accepted; the result never carries the token
reset()
add_agent("agentone", pk=7)
ok = et.authenticate_endpoint_agent(TOKEN, "agentone")
must(ok.ok and ok.reason is None and ok.agent_pk == 7 and ok.agent_id == "agentone", ok)
must(TOKEN not in repr(ok), "the result holds no token")

# each refusal has its own code
must(et.authenticate_endpoint_agent(TOKEN, "agenttwo").reason == "agent_mismatch", "wrong agent id")
must(et.authenticate_endpoint_agent(TOKEN, "agentone ").reason == "malformed_agent_id", "space in id")
must(et.authenticate_endpoint_agent(TOKEN, "").reason == "malformed_agent_id", "empty id")
must(et.authenticate_endpoint_agent(TOKEN, None).reason == "malformed_agent_id", "no id")
must(et.authenticate_endpoint_agent("c" * 40, "agentone").reason == "unknown_token", "unknown token")
must(et.authenticate_endpoint_agent("", "agentone").reason == "malformed_token", "empty token")
must(et.authenticate_endpoint_agent("a b", "agentone").reason == "malformed_token", "malformed token")
must(et.authenticate_endpoint_agent(None, "agentone").reason == "malformed_token", "no token")
TOKENS[TOKEN2] = FakeTokenRow(TOKEN2, FakeUser("dashboard-user", agent=None))
must(et.authenticate_endpoint_agent(TOKEN2, "agentone").reason == "no_agent", "a dashboard user's token has no agent")
add_agent("agentthree", token="d" * 40, pk=3, active=False)
must(et.authenticate_endpoint_agent("d" * 40, "agentthree").reason == "inactive", "inactive account")
# the stored key differing from the presented one (a lookup that is not exact) is refused
TOKENS["e" * 40] = FakeTokenRow("f" * 40, FakeUser("x", FakeAgent(9, "agentnine")))
must(et.authenticate_endpoint_agent("e" * 40, "agentnine").reason == "token_mismatch", "stored key must equal the presented one")


# a database fault never accepts (fail closed) and is not an identity answer
class _Raising:
    class objects:  # noqa: N801
        @staticmethod
        def select_related(*args):
            raise RuntimeError("db down")


sys.modules["rest_framework.authtoken.models"].Token = _Raising
fault = et.authenticate_endpoint_agent(TOKEN, "agentone")
must(not fault.ok and fault.reason == "unavailable" and fault.transient, "a fault is transient, not an identity refusal (1.17.92)")
sys.modules["rest_framework.authtoken.models"].Token = H.FakeToken

# the comparison is constant time (hmac.compare_digest), not a plain ==
src = inspect.getsource(et.authenticate_endpoint_agent)
must(src.count("hmac.compare_digest") >= 2, "constant-time compares")
must("row.key ==" not in src and "== token" not in src and "== agent_id" not in src, "no plain equality on secrets")

# headers: token from Authorization only, one of each header, exact scheme
must(et.parse_endpoint_headers({"headers": H.headers_for()}) == (TOKEN, "agentone", None), "good headers")
must(et.parse_endpoint_headers({"headers": H.headers_for(token=None)})[2] == "malformed_token", "no Authorization")
must(et.parse_endpoint_headers({"headers": H.headers_for(agent_id=None)})[2] == "malformed_agent_id", "no X-Agent-Id")
must(et.parse_endpoint_headers({"headers": H.headers_for(extra=[(b"x-agent-id", b"other")])})[2] == "malformed_agent_id", "duplicate id header")
must(et.parse_endpoint_headers({"headers": [(b"authorization", b"Bearer " + TOKEN.encode()), (b"x-agent-id", b"a")]})[2] == "malformed_token", "Bearer")
must(et.parse_endpoint_headers({"headers": [(b"authorization", b"Token"), (b"x-agent-id", b"a")]})[2] == "malformed_token", "no key")
must(et.parse_endpoint_headers({"headers": [(b"authorization", b"Token " + b"a" * 300), (b"x-agent-id", b"a")]})[2] == "malformed_token", "long key")
must(et.parse_endpoint_headers({"headers": [(b"authorization", b"Token \xff\xfe"), (b"x-agent-id", b"a")]})[2] == "malformed_token", "bytes")
must(et.parse_endpoint_headers({"headers": []})[2] == "malformed_agent_id", "empty")
for reason, text in et.REFUSAL_MESSAGES.items():
    must(TOKEN not in text, reason)

# the source address: X-Real-IP wins, a forged X-Forwarded-For never does, then the ASGI client
forged = H.headers_for(real_ip="198.51.100.4", extra=[(b"x-forwarded-for", b"1.2.3.4")])
must(et.client_ip({"headers": forged, "client": ("10.0.0.1", 1)}) == "198.51.100.4", "real ip")
must(et.client_ip({"headers": [(b"x-forwarded-for", b"1.2.3.4")], "client": ("10.0.0.1", 1)}) == "10.0.0.1", "xff ignored")
must(et.client_ip({"headers": [(b"x-real-ip", b"not-an-ip")], "client": ("10.0.0.1", 1)}) == "10.0.0.1", "bad real ip falls back")
must(et.client_ip({"headers": []}) == "unknown", "nothing")
must(et.forwarded_plaintext({"headers": [(b"x-forwarded-proto", b"http")]}) and not et.forwarded_plaintext({"headers": [(b"x-forwarded-proto", b"https")]})
     and not et.forwarded_plaintext({"headers": []}), "plain text only where the proxy says so")

# the address ceiling (1.17.92): 10 failures a minute from one address (the signed AD-54 limit), then limited; another address and a new minute are free
reset()
ip = "203.0.113.9"
for _ in range(et.FAILURES_PER_ADDRESS_PER_MINUTE - 1):
    et.note_failure(ip)
must(not et.rate_limited(ip), "under the ceiling")
et.note_failure(ip)
must(et.rate_limited(ip), "the 10 failures are counted; the next attempt is limited")
must(not et.rate_limited("203.0.113.10"), "another address is free")
H.WALL[0] += 61
must(not et.rate_limited(ip), "a new minute is free")
CACHE.down = True
must(not et.rate_limited(ip), "a cache fault reads as not limited")
et.note_failure(ip)  # never raises
CACHE.down = False
reset()
add_agent("agentone")
et.authenticate_endpoint_agent(TOKEN, "agentone")  # a good check writes no counter
must(not any(k.startswith(et.FAILURE_PREFIX) for k in CACHE.data), "success does not count")

# frames (plan 7.2)
good = {"v": 1, "type": "event", "id": "e1", "func": "anything.at.all", "payload": {}}
must(et.validate_frame(good) is None, "good frame; unknown func passes")
cases = (([], "not_an_object"), ({**good, "v": 2}, "bad_version"), ({**good, "v": True}, "bad_version"), ({**good, "type": "nope"}, "unknown_type"),
         ({**good, "id": 5}, "bad_id"), ({**good, "id": ""}, "bad_id"), ({**good, "func": 5}, "bad_func"), ({**good, "func": ""}, "bad_func"),
         ({**good, "payload": []}, "bad_payload"), ({k: v for k, v in good.items() if k != "payload"}, "bad_payload"))
for bad, why in cases:
    must(et.validate_frame(bad) == why, (bad, why, et.validate_frame(bad)))
must(et.validate_frame({"v": 1, "type": "ping", "id": "p"}) is None, "ping needs no func or payload")
must(et.validate_frame(good, allowed_types=("request",)) == "type_not_allowed", "type filter")

# the audit writer is private, takes the agent as device provenance and carries no token field
audit_src = (H.APP / "audit.py").read_text(encoding="utf-8")
writer = audit_src[audit_src.index("def _record_endpoint_transport"):audit_src.index("def _record_row(")]
must("SERVER_PROVENANCE_ENDPOINT_TRANSPORT" in writer and "device_audit_actor" in writer, "audit writer")
must("token=" not in writer and "authorization" not in writer.lower().replace("never a token, an authorization header", ""), "no token field in the writer")
reset()
et.record_endpoint_event("custom:endpoint-refused", "bad id with spaces", reason="unknown_token", ip="1.2.3.4", refusal=True)
must(H.AUDITS[-1]["agent_id"] is None and H.AUDITS[-1]["metadata"] == {"reason": "unknown_token", "ip": "1.2.3.4"} and H.AUDITS[-1]["refusal"], H.AUDITS)
et.record_endpoint_event("custom:endpoint-event", "agentone", func="f\x00x", frame_id="id1")
must(H.AUDITS[-1]["agent_id"] == "agentone" and H.AUDITS[-1]["metadata"]["func"] == "fx", H.AUDITS[-1])
must(not any(m in repr(H.AUDITS) for m in H.SECRET_MARKERS), "no token in any audit row")

# the REAL audit writer (audit.py with a fake AuditLog table): device provenance for an agent, service provenance without one, Core-only context
spec_audit = importlib.util.spec_from_file_location("audit_under_test", H.APP / "audit.py")
real_audit = importlib.util.module_from_spec(spec_audit)
spec_audit.loader.exec_module(real_audit)
CREATED: list = []


class _Log:
    class objects:  # noqa: N801
        @staticmethod
        def create(**kwargs):
            CREATED.append(kwargs)
            return H.SimpleNamespace(pk=len(CREATED))


real_audit._auditlog_model = lambda: _Log
real_audit._framework_version = lambda: "1.17.90"
done = real_audit._record_endpoint_transport(action="custom:endpoint-connect", agent_id="agentone", message="m", metadata={"ip": "1.2.3.4"})
must(done["recorded"] and done["module_id"] == "core", done)
row = CREATED[-1]
info = row["debug_info"]
must(row["username"] == "device:agentone" and row["object_type"] == "agent" and info["actor_kind"] == "device", row)
must(info["operation_context"]["server_provenance"] == "endpoint-transport" and info["object_id"] == "agentone", info)
real_audit._record_endpoint_transport(action="custom:endpoint-refused", message="m", metadata={"reason": "unknown_token"}, refusal=True)
row = CREATED[-1]
must(row["username"].startswith("service:") and row["debug_info"]["operation_context"]["core_refusal"] is True, row)
must(not any(m in repr(CREATED) for m in H.SECRET_MARKERS), "no token in the real rows")
# a module cannot forge the provenance through the public record()
try:
    real_audit.record(actor=real_audit.service_audit_actor(module_id="core", service="x"), module_id="core", action="custom:endpoint-connect",
                      object_type="agent", operation_context={"server_provenance": "endpoint-transport"})
    raise AssertionError("record() must refuse Core-owned context")
except real_audit.AuditContractError:
    pass
print("PASS endpoint transport identity 1.17.90")
