#!/usr/bin/env python3
"""1.17.41 regression: relay a streamed Tactical file answer for an operation that declares file_response (Report Manager PDF run,
PDF history open and report asset download; Johan, dev-server test, 15 October 2026).

Covered: a declared operation whose answer is a 3-chunk stream returns the status, content type, Content-Disposition and the joined bytes,
writes exactly one success row, and the row holds no bytes and no file name; the same stream without file_response is still refused as
tactical_response_refused with the outcome-unknown row on a POST (and the stream is closed); a stream over MAX_RESPONSE_BYTES is cut,
closed and refused; a 403 stream writes the deny row; a 500 stream writes the outcome-unknown row; a 404 stream on a change writes the
failed row; file_response must be a strict bool and belongs to GET or POST; the HTTP view returns the bytes with the content type, the
disposition and the X-Tec-Tac-Audit header; describe and the capability metadata show file_response and version 1.11.0.
Uses the stubs of tests/tactical-operations-1.17.7.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)  # noqa: S102 - test-only reuse of the 1.17.7 stubs
ops, views, declare, refused, fresh, must = (G[k] for k in ("ops", "views", "declare", "refused", "fresh", "must"))
CALLS, ROWS, AGENT, tech, Request, ROUTES = (G[k] for k in ("CALLS", "ROWS", "AGENT", "tech", "Request", "ROUTES"))
FakeResponse, refusal, route, tactical_view = G["FakeResponse"], G["refusal"], G["route"], G["tactical_view"]


class StreamResponse:
    """What Django's FileResponse looks like to Core: streaming True, streaming_content, close()."""

    def __init__(self, chunks, status=200, content_type="application/pdf", disposition='attachment; filename="secret-name.pdf"'):
        self.status_code, self.streaming = status, True
        self.streaming_content = iter(chunks)
        self._headers = {"Content-Type": content_type}
        if disposition:
            self._headers["Content-Disposition"] = disposition
        self.closed = 0
        self.read = 0

    def get(self, name, default=None):
        return self._headers.get(name, default)

    def close(self):
        self.closed += 1


class CountingChunks:
    """A generator that counts how many chunks Core pulled."""

    def __init__(self, response, chunks):
        self.response, self.chunks = response, chunks

    def __iter__(self):
        for chunk in self.chunks:
            self.response.read += 1
            yield chunk


PATH = f"/agents/{AGENT}/export/"
PARAMS = {"agent_id": AGENT}


def declare_file(**over):
    spec = dict(id="export", route="agents/{agent_id:agent}/export/", method="POST", body_fields=["mode"], file_response=True,
                audit={"action": "export", "object_type": "agent", "audit_fields": ["mode"]})
    spec.update(over)
    return declare(**spec)


def run(body=None):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(tech), "agents", "export", PARAMS, body if body is not None else {"mode": "pdf"})


# (1) a declared file_response operation relays the stream
fresh()
op = declare_file()
must(op.file_response is True, op)
stream = StreamResponse([b"%PDF-1.7\n", b"middle-", b"end"])
route(PATH, stream)
result = run()
must(result.status == 200 and result.content == b"%PDF-1.7\nmiddle-end", result.content)
must(result.data == b"%PDF-1.7\nmiddle-end", "data stays the raw bytes for a type that is not JSON")
must(result.content_type == "application/pdf", result.content_type)
must(result.headers == {"Content-Type": "application/pdf", "Content-Disposition": 'attachment; filename="secret-name.pdf"'}, result.headers)
must(stream.closed == 1, "the stream was closed")
must(ROWS and ROWS[0]["action"] == "export", ROWS)
must(len(ROWS) == 1, ROWS)
dump = json.dumps(ROWS, default=str)
must("secret-name" not in dump and "%PDF" not in dump and "middle-end" not in dump, "the row carries no file name and no bytes")
must(result.audit, "the audit verdict is returned")
print("       declared stream: status, type, disposition and bytes relayed; one row; no bytes or name in it")

# (2) without file_response the stream is still refused
fresh()
declare_file(file_response=False)
stream = StreamResponse([b"a", b"b"])
route(PATH, stream)
try:
    run()
except ops.TacticalOperationError as error:
    must(error.code == "tactical_response_refused", (error.status, error.code))
else:
    raise AssertionError("a stream without file_response must be refused")
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown", ROWS)
must(stream.closed == 1 and stream.read == 0, "closed, never read")
print("       without file_response: refused as before, outcome-unknown row, stream closed")

# (3) over the cap: cut, closed and refused
fresh()
declare_file()
big = StreamResponse([])
chunk = b"x" * (ops.MAX_RESPONSE_BYTES // 2 + 1)
big.streaming_content = iter(CountingChunks(big, [chunk, chunk, chunk, chunk]))
route(PATH, big)
try:
    run()
except ops.TacticalOperationError as error:
    must(error.code == "tactical_response_refused", error.code)
else:
    raise AssertionError("a stream over the cap must be refused")
must(big.closed == 1, "the stream was closed")
must(big.read == 2, ("reading stopped at the chunk that passed the cap", big.read))
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown", ROWS)
# exactly at the cap is accepted
fresh()
declare_file()
exact = StreamResponse([b"y" * ops.MAX_RESPONSE_BYTES])
route(PATH, exact)
must(len(run().content) == ops.MAX_RESPONSE_BYTES, "exactly the cap is relayed")
print("       over the cap: cut, closed, refused; exactly the cap passes")

# (4) a 403 stream writes the deny row; 404 on a change the failed row; 500 the outcome-unknown row
for status, action in ((403, "deny"), (404, "custom:operation-failed"), (500, "custom:outcome-unknown")):
    fresh()
    declare_file()
    stream = StreamResponse([b"no", b"pe"], status=status)
    route(PATH, stream)
    result = run()
    must(result.status == status and result.content == b"nope", (status, result.content))
    must(len(ROWS) == 1 and ROWS[0]["action"] == action, (status, ROWS))
    must(stream.closed == 1, "closed")
# a GET declaration: a 404 writes no row, a 200 writes the declared row
fresh()
declare_file(method="GET", body_fields=[], audit={"action": "export", "object_type": "agent"})
route(PATH, StreamResponse([b"1", b"2"], status=404))
result = ops.run_tactical_operation(Request(tech), "agents", "export", PARAMS)
must(result.status == 404 and ROWS == [], ROWS)
route(PATH, StreamResponse([b"1", b"2"]))
result = ops.run_tactical_operation(Request(tech), "agents", "export", PARAMS)
must(result.content == b"12" and len(ROWS) == 1, ROWS)
print("       403, 404, 500 and GET handled as for a normal answer")

# (5) strict bool, GET or POST only
fresh()
for bad in (1, 0, "yes", "true", None, [], {}):
    text = refused(id="bad", route="agents/{agent_id:agent}/bad/", body_fields=[], file_response=bad,
                   audit={"action": "export", "object_type": "agent"})
    must("file_response" in text, (bad, text))
for verb in ("PUT", "PATCH", "DELETE"):
    text = refused(id="bad", route="agents/{agent_id:agent}/bad/", method=verb, body_fields=[], file_response=True,
                   audit={"action": "export", "object_type": "agent"})
    must("GET or POST" in text, (verb, text))
must(not ops.list_operations(), "nothing was registered")
default = declare(id="plain", route="agents/{agent_id:agent}/plain/", body_fields=[], audit={"action": "run", "object_type": "agent"})
must(default.file_response is False, default)
print("       file_response must be a strict bool for GET or POST")

# (6) the HTTP view relays the bytes
fresh()
declare_file()
route(PATH, StreamResponse([b"%PDF", b"-1"]))
view = views.TacticalOperationView()
reply = view.post(Request(tech, data={"params": PARAMS, "body": {"mode": "pdf"}}), "agents", "export")
must(reply.status_code == 200 and reply.content == b"%PDF-1" and reply.content_type == "application/pdf", reply.__dict__)
must(reply.headers.get("Content-Disposition") == 'attachment; filename="secret-name.pdf"', reply.headers)
must(reply.headers.get("X-Tec-Tac-Audit") == "recorded", reply.headers)
print("       HTTP view: bytes, content type, disposition and audit header")

# (7) describe and the capability
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.11.0" and meta["version"] == "1.11.0" and meta["version"].split(".")[0] == "1", meta["version"])
must("file_response" in meta["declaration"] and meta["declaration_keys_added_in_1_11_0"] and meta["behaviour_added_in_1_11_0"], meta)
fresh()
declare_file()
must(ops.list_operations("agents")[0]["file_response"] is True, "list_operations shows file_response")
cap = ops.register_core_tactical_operations_capability()
must(G["CAPS"][-1]["version"] == "1.11.0", G["CAPS"][-1])

# docs and contract text
root = Path(__file__).resolve().parents[1]
docs = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("file_response", "1.11.0", "Added in 1.17.41"):
    must(needle in docs, f"docs/tactical-operations.md lacks {needle!r}")
must("Relaying a streamed file answer is a separate\nrequest" not in docs, "the stale 'separate request' paragraph is gone")
contract = (root / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must("file_response" in contract and "core.tactical_operations 1.11.0" in contract, "contracts.py rows")

print("[TEST] PASS tactical operation file response 1.17.41")
