#!/usr/bin/env python3
"""1.18.33 regression: file transfers (ORDER Core 1.18.33, Johan, 21 November 2026): a binary chunk, a binary answer, 204 and 408 pass
through, and one audit row per transfer (AD-69). Capability core.tactical_operations moves to 1.18.0.

All four additions are opt-in. Covered: registration of binary_body, binary_response and audit.transfer (what is accepted and refused);
read_binary_body (Content-Length checked before a byte is read, never request.body); the Content-Range check and the exact bytes that
reach Tactical's view; the three relayed headers and the shape check; 408 and 204 for a transfer operation and unchanged for any other;
the rows of a whole upload, download and cancel (start row, end row, one correlation id, no row for chunks); the once-only end row with a
cache that works, one that is missing and one that raises; refusal rows with the session link; no file content or Tactical text in any
row; the ten operations Remote Background will declare; a 1.18.32-style declaration unchanged; describe(), metadata, docs and contract
rows; and a scan of modules/ that proves every declaration there still passes the registration keys.
Uses the stubs of tests/tactical-operations-1.17.7.py (Django and Tactical are not installed on the development PC).
"""
from __future__ import annotations

import ast
import inspect
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)  # noqa: S102 - test-only reuse of the 1.17.7 stubs
ops, fresh, must = (G[k] for k in ("ops", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, User, Roleish, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "User", "Roleish", "Request"))
FakeResponse, refusal, views, HttpRequest = G["FakeResponse"], G["refusal"], G["views"], G["HttpRequest"]
PLUGINS = G["PLUGINS"]
for name, category in (("remote-background", "core"), ("agents", "core"), ("agent-management", "core"), ("take-control", "core"),
                       ("somepremium", "premium")):
    PLUGINS[name] = SimpleNamespace(plugin_id=name, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False,
                                    audit_events=(), category=category)

class QueryDict(dict):
    def __init__(self, qs=""):
        super().__init__({key: values[0] for key, values in parse_qs(qs, keep_blank_values=True).items()})
        self.qs = qs


sys.modules["django.http"].QueryDict = QueryDict
FLAG = "can_manage_notes"  # the stub Role has no can_use_file_browser (Tactical 1.5.2 has none either; Core refuses an unknown flag)
tech = User("rb", Roleish(FLAG))
tech.sees = {"agents": {AGENT}, "clients": {1}, "sites": {10}}
SEEN: list = []
SID = "0b9d6a3e-4c1f-4f7e-9a52-3d8e6f1c2b47"
SID2 = "11111111-2222-3333-4444-555555555555"
MIB = 2**20
CAP = 4 * MIB + 64 * 1024
SECRET_BYTES = b"TOP-SECRET-FILE-CONTENT"
TACTICAL_TEXT = "TACTICAL-OWN-ERROR-TEXT"


class FakeCache:
    """Django's cache stub: add() is atomic and says whether the key was new."""

    def __init__(self):
        self.data, self.adds, self.deleted, self.mode = {}, [], [], "ok"

    def add(self, key, value, timeout=None):
        if self.mode == "raise":
            raise RuntimeError("redis down")
        self.adds.append((key, timeout))
        if key in self.data:
            return False
        self.data[key] = value
        return True

    def get(self, key, default=None):  # 1.18.35: the read-only check of the success end-row key
        if self.mode == "raise":
            raise RuntimeError("redis down")
        return self.data.get(key, default)

    def delete(self, key):
        if self.mode == "raise":
            raise RuntimeError("redis down")
        self.deleted.append(key)
        self.data.pop(key, None)


CACHE = FakeCache()
cache_module = types.ModuleType("django.core.cache")
cache_module.cache = CACHE
sys.modules["django.core.cache"] = cache_module


def seeing(response=None):
    def view(request, *args, **kwargs):
        SEEN.append(request)
        return response if response is not None else FakeResponse(200, b'{"ok": true}')
    return view


def json_view(status, payload, headers=None):
    return seeing(FakeResponse(status, json.dumps(payload).encode(), headers=headers))


SCOPE = [{"type": "agent", "source": "path:agent_id"}]
ROOT_ = "agents/{agent_id:agent}/files/"
SESSION_ROOT = ROOT_ + "{session_id:uuid}/"


def spec(**over):
    out = {"id": "file-list", "module_id": "remote-background", "method": "GET", "route": ROOT_, "permissions": [FLAG],
           "scope": SCOPE, "body_fields": [], "audit": {"action": "view", "object_type": "agent", "audit_fields": []}}
    out.update(over)
    return out


def register(**over):
    return ops.register_tactical_operation(**spec(**over))


def refused(**over):
    try:
        register(**over)
    except ops.TacticalOperationRegistrationError as exc:
        return str(exc)
    raise AssertionError(f"registration was accepted: {over}")


def audit_of(action="custom:file-transfer", **extra):
    return {"action": action, "object_type": "agent", **extra}


def run(module, operation, params=None, body=None, query=None, binary=None, correlation_id=None, request=None):
    del CALLS[:], SEEN[:], ROWS[:]
    request = request or Request(tech)
    return ops.run_tactical_operation(request, module, operation, params, body, query=query, correlation_id=correlation_id, binary_body=binary)


def meta(row):
    return row["debug_info"]["metadata"]


def corr(row):
    return row["debug_info"]["correlation_id"]


def chunk(size, start=0, total=None, content=b"x"):
    total = total if total is not None else start + size
    return {"content": (content * size)[:size], "content_range": f"bytes {start}-{start + size - 1}/{total}"}


def rows_text():
    return json.dumps(ROWS, default=str)


def declare_transfer_set():
    """The ten (and a few more) file transfer operations Remote Background will declare, under agents/{}/files/ (1.18.30 owner rules)."""
    fields = ["path", "file_name", "total_size", "session_id", "chunk_size"]
    def init_audit(direction):
        return audit_of(audit_fields=["path", "file_name"], transfer={"role": "init", "direction": direction})

    register(id="upload-init", method="POST", route=ROOT_ + "uploads/", body_fields=fields, audit=init_audit("upload"))
    register(id="download-init", method="POST", route=ROOT_ + "downloads/", body_fields=fields, audit=init_audit("download"))
    register(id="archive-init", method="POST", route=ROOT_ + "archives/", body_fields=fields, audit=init_audit("archive"))
    register(id="extract-init", method="POST", route=ROOT_ + "extract/", body_fields=fields, audit=init_audit("extract"))
    for name, role, direction, verb, tail, extra in (
        ("upload-chunk", "chunk", "upload", "PUT", "uploads/{session_id:uuid}/chunks/", {"binary_body": True}),
        ("upload-complete", "complete", "upload", "POST", "uploads/{session_id:uuid}/complete/", {}),
        ("download-chunk", "chunk", "download", "GET", "downloads/{session_id:uuid}/chunks/",
         {"binary_response": True, "query_params": ["committed_offset"]}),
        ("download-ack", "ack", "download", "POST", "downloads/{session_id:uuid}/ack/", {}),
        ("download-status", "status", "download", "GET", "downloads/{session_id:uuid}/status/", {}),
        ("download-complete", "complete", "download", "POST", "downloads/{session_id:uuid}/complete/", {}),
        ("extract-status", "status", "extract", "GET", "extract/{session_id:uuid}/", {}),
    ):
        register(id=name, method=verb, route=ROOT_ + tail, audit=audit_of(transfer={"role": role, "direction": direction}, params=["session_id"]), **extra)
    for prefix, direction in (("upload", "upload"), ("download", "download"), ("extract", "extract")):
        route = ROOT_ + f"{prefix}s/{{session_id:uuid}}/cancel/" if prefix != "extract" else ROOT_ + "extract/{session_id:uuid}/cancel/"
        register(id=f"{prefix}-cancel", method="POST", route=route, body_fields=["reason"],
                 body_selector=[{"field": "reason", "equals": "user"}], audit=audit_of(transfer={"role": "cancel", "direction": direction}, params=["session_id"]))
        register(id=f"{prefix}-fail", method="POST", route=route, body_fields=["reason"],
                 body_selector=[{"field": "reason", "equals": "error"}], audit=audit_of(transfer={"role": "fail", "direction": direction}, params=["session_id"]))


P = {"agent_id": AGENT}
PS = {"agent_id": AGENT, "session_id": SID}


def paths(session=SID):
    base = f"/agents/{AGENT}/files/"
    return {
        "upload-init": base + "uploads/", "upload-chunk": base + f"uploads/{session}/chunks/", "upload-complete": base + f"uploads/{session}/complete/",
        "upload-cancel": base + f"uploads/{session}/cancel/", "download-init": base + "downloads/", "download-chunk": base + f"downloads/{session}/chunks/",
        "download-ack": base + f"downloads/{session}/ack/", "download-status": base + f"downloads/{session}/status/",
        "download-complete": base + f"downloads/{session}/complete/", "download-cancel": base + f"downloads/{session}/cancel/",
        "archive-init": base + "archives/", "extract-init": base + "extract/", "extract-status": base + f"extract/{session}/",
        "extract-cancel": base + f"extract/{session}/cancel/", "download-init2": base + "downloads/",
    }


def serve(name, response, session=SID):
    ROUTES[paths(session)[name]] = (seeing(response) if not callable(response) else response, (), {})


# ===================================================================================== registration: binary_body
fresh()
op = register(id="chunk-put", method="PUT", route=SESSION_ROOT + "chunks/", binary_body=True, query_params=["path"])
must(op.binary_body is True and op.binary_response is False and op.audit_transfer == (), op)
register(id="chunk-post", method="POST", route=SESSION_ROOT + "blob/", binary_body=True)
for verb in ("GET", "PATCH", "DELETE"):
    must("PUT or POST" in refused(id="bad-verb", method=verb, route=SESSION_ROOT + "x/", binary_body=True), verb)
must("whole body" in refused(id="b1", method="PUT", route=SESSION_ROOT + "c1/", binary_body=True, body_fields=["a"]), "body_fields")
must("whole body" in refused(id="b2", method="PUT", route=SESSION_ROOT + "c2/", binary_body=True,
                             upload={"field": "f", "max_bytes": 1024, "extensions": ["txt"]}), "upload")
must("whole body" in refused(id="b3", method="POST", route=SESSION_ROOT + "c3/", binary_body=True, file_response=True), "file_response")
must("whole body" in refused(id="b4", method="PUT", route=SESSION_ROOT + "c4/", binary_body=True, body_fields=["a"],
                             body_selector=[{"field": "a", "equals": "x"}]), "body_selector")
for bad in (1, "yes", None, [], 0):
    must("true or false" in refused(id="b5", method="PUT", route=SESSION_ROOT + "c5/", binary_body=bad), repr(bad))
print("       binary_body: PUT and POST accepted; GET, PATCH, DELETE, upload, body_fields, file_response, body_selector and non-bool refused")

# registration: binary_response
fresh()
must(register(id="dl-get", route=SESSION_ROOT + "chunks/", binary_response=True).binary_response is True, "GET")
must(register(id="dl-post", method="POST", route=SESSION_ROOT + "chunks/", binary_response=True).binary_response is True, "POST")
for verb in ("PUT", "PATCH", "DELETE"):
    must("GET or POST" in refused(id="bad-resp", method=verb, route=SESSION_ROOT + "y/", binary_response=True), verb)
must("declare one" in refused(id="b6", route=SESSION_ROOT + "z/", binary_response=True, file_response=True), "with file_response")
for bad in (1, "yes", None, []):
    must("true or false" in refused(id="b7", route=SESSION_ROOT + "w/", binary_response=bad), repr(bad))
register(id="both", method="POST", route=SESSION_ROOT + "both/", binary_body=True, binary_response=True)  # a chunk that answers in kind is fine
print("       binary_response: GET and POST accepted; PUT, DELETE, file_response and non-bool refused")

# registration: audit.transfer
fresh()
for bad in ("init", ["init"], {"role": "init"}, {"role": "init", "direction": "upload", "x": 1}, {"role": "nope", "direction": "upload"},
            {"role": "init", "direction": "sideways"}, {"role": 1, "direction": "upload"}, {"role": "init", "direction": None}):
    refused(id="t1", method="POST", route=ROOT_ + "uploads/", audit=audit_of(transfer=bad))
must("session_id" in refused(id="t2", method="PUT", route=ROOT_ + "chunks/", audit=audit_of(transfer={"role": "chunk", "direction": "upload"})), "chunk without session")
must("session_id" in refused(id="t3", method="POST", route=ROOT_ + "x/{n:int}/done/", audit=audit_of(transfer={"role": "complete", "direction": "upload"})), "int is not a uuid")
must("opens a session" in refused(id="t4", method="POST", route=SESSION_ROOT + "init/", audit=audit_of(transfer={"role": "init", "direction": "upload"})), "init with session")
for role in ("init", "complete", "cancel", "fail"):
    route = ROOT_ + "start/" if role == "init" else SESSION_ROOT + "end/"
    must("cannot be a GET" in refused(id="t5", method="GET", route=route, audit=audit_of(transfer={"role": role, "direction": "upload"})), role)
for role in ("chunk", "ack", "status"):
    register(id=f"ok-get-{role}", method="GET", route=SESSION_ROOT + f"{role}/", audit=audit_of(transfer={"role": role, "direction": "download"}))
must("action_by_body" in refused(id="t6", method="POST", route=SESSION_ROOT + "ab/", body_fields=["mode"],
                                 audit=audit_of(transfer={"role": "complete", "direction": "upload"}, action_by_body={"field": "mode", "map": {"a": "modify"}})), "action_by_body")
for role in ("ack", "status", "complete", "cancel", "fail"):
    must("chunk role" in refused(id="t7", method="PUT", route=SESSION_ROOT + "bin/", binary_body=True,
                                 audit=audit_of(transfer={"role": role, "direction": "upload"})), role)
register(id="t8", method="PUT", route=SESSION_ROOT + "bin/", binary_body=True, audit=audit_of(transfer={"role": "chunk", "direction": "upload"}))
for direction in ops.TRANSFER_DIRECTIONS:
    register(id=f"dir-{direction}", method="POST", route=ROOT_ + f"{direction}-start/", audit=audit_of(transfer={"role": "init", "direction": direction}))
must(ops.TRANSFER_ROLES == ("init", "chunk", "ack", "status", "complete", "cancel", "fail") and ops.TRANSFER_DIRECTIONS == ("upload", "download", "archive", "extract"), "vocabulary")
print("       audit.transfer: roles, directions, session route, GET, action_by_body and binary_body rules")

# the ten operations of Remote Background (and the three split cancel/fail pairs) register under agents/{}/files/ and only for that owner
fresh()
declare_transfer_set()
must(len(ops.list_operations("remote-background")) == 11 + 6, len(ops.list_operations("remote-background")))
for module in ("agents", "agent-management", "take-control", "somepremium"):
    refused(id="x-" + module.replace("-", ""), module_id=module, method="PUT", route=SESSION_ROOT + "chunks/", binary_body=True,
            audit=audit_of(transfer={"role": "chunk", "direction": "upload"}))
print("       the ten Remote Background transfer operations (and the cancel/fail splits) register under agents/{}/files/; other modules refused")

# ===================================================================================== read_binary_body
fresh()
declare_transfer_set()
ROUTES[paths()["upload-chunk"]] = (seeing(), (), {})


class Stream:
    def __init__(self, data, pieces=None):
        self.data, self.pos, self.reads, self.pieces = data, 0, [], pieces

    def read(self, size=-1):
        self.reads.append(size)
        step = size if self.pieces is None else min(size, self.pieces)
        out = self.data[self.pos:self.pos + step]
        self.pos += len(out)
        return out


class ChunkRequest(Request):
    """A request whose body is a stream. request.body and request.data fail the test: the helper must never touch them."""

    def __init__(self, user, data, length="auto", content_range=None, pieces=None):
        super().__init__(user)
        self.stream = Stream(data, pieces)
        if length == "auto":
            length = str(len(data))
        if length is not None:
            self.META["CONTENT_LENGTH"] = length
        if content_range:
            self.META["HTTP_CONTENT_RANGE"] = content_range

    def read(self, size=-1):
        return self.stream.read(size)

    @property
    def body(self):
        raise AssertionError("request.body was read")

    @property
    def data(self):
        raise AssertionError("request.data was read")


def helper(request, op_id="upload-chunk"):
    return ops.read_binary_body(request, "remote-background", op_id)


def helper_error(request, status, code, op_id="upload-chunk"):
    del ROWS[:]
    CACHE.data.clear()
    try:
        helper(request, op_id)
    except ops.TacticalOperationError as exc:
        must(exc.status == status and exc.code == code, (exc.status, exc.code, exc.message))
        # 1.18.34: a helper refusal writes one limited core_refused row (was: no row in 1.18.33)
        must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed" and meta(ROWS[0])["failure"] == "core_refused" and meta(ROWS[0])["code"] == code, ROWS)
        must(exc.audit is not None and exc.audit.get("recorded"), exc.audit)
        return exc
    raise AssertionError(f"expected {status} {code}")


data4 = b"a" * (4 * MIB)
req = ChunkRequest(tech, data4, content_range=f"bytes 0-{4 * MIB - 1}/{8 * MIB}")
got = helper(req)
must(got == {"content": data4, "content_range": f"bytes 0-{4 * MIB - 1}/{8 * MIB}"}, "4 MiB read in full")
must(max(req.stream.reads) <= len(data4) + 1, req.stream.reads)
# a stream that hands out small pieces is read until the length is reached
req = ChunkRequest(tech, b"b" * 1000, content_range="bytes 0-999/1000", pieces=77)
must(helper(req)["content"] == b"b" * 1000, "pieces")
# 4 MiB and 64 KiB passes the helper
edge = b"c" * CAP
req = ChunkRequest(tech, edge, content_range="bytes 0-1/2")
must(len(helper(req)["content"]) == CAP, "cap passes")
# one byte more is 413 before any read
over = ChunkRequest(tech, b"d" * (CAP + 1))
exc = helper_error(over, 413, "body_too_large")
must(str(CAP) in exc.message, exc.message)
must(over.stream.reads == [], f"read() was never called, got {over.stream.reads}")
# a missing, empty or invalid Content-Length is 411 and nothing is read
for bad in (None, "", "  ", "abc", "-1", "1e3", "12.5", "9" * 13, "١٢٣"):
    req = ChunkRequest(tech, b"x" * 10, length=bad)
    helper_error(req, 411, "length_required")
    must(req.stream.reads == [], f"nothing read for {bad!r}")
# bytes read must equal Content-Length
helper_error(ChunkRequest(tech, b"x" * 5, length="10"), 400, "content_length_mismatch")
helper_error(ChunkRequest(tech, b"x" * 15, length="10"), 400, "content_length_mismatch")
# zero length: nothing to read, the range check refuses it in run
req = ChunkRequest(tech, b"", content_range="bytes 0-0/1")
must(helper(req) == {"content": b"", "content_range": "bytes 0-0/1"}, "empty chunk returned as sent")
# no Content-Range header: returned as an empty string, run refuses it
must(helper(ChunkRequest(tech, b"xy"))["content_range"] == "", "no header")
# an operation that does not declare binary_body, and an unknown one
helper_error(ChunkRequest(tech, b"x"), 400, "binary_body_not_allowed", op_id="upload-init")
try:
    helper(ChunkRequest(tech, b"x"), "nope")
except ops.TacticalOperationError as exc:
    must(exc.status == 404 and exc.code == "tactical_operation_not_found", exc.code)
else:
    raise AssertionError("unknown operation")
# a DRF wrapper: the helper reads the underlying request's stream
inner = ChunkRequest(tech, b"wrapped", content_range="bytes 0-6/7")
must(helper(G["DRFWrapper"](inner))["content"] == b"wrapped", "wrapped request")
print("       read_binary_body: Content-Length first (411, 413 before any read), stream read in pieces, never request.body or request.data, length must match")

# ===================================================================================== run: the bytes, Content-Type, Content-Range
serve("upload-chunk", json_view(200, {"committed_offset": 4 * MIB}))
big = chunk(4 * MIB, start=0, total=8 * MIB, content=b"z")
result = run("remote-background", "upload-chunk", PS, binary=big)
must(result.status == 200 and len(SEEN) == 1, result)
sent = SEEN[0]
must(sent._body == big["content"] and len(sent._body) == 4 * MIB, "Tactical's view sees the exact bytes")
must(sent.META["CONTENT_TYPE"] == "application/octet-stream" and sent.content_type == "application/octet-stream", sent.META["CONTENT_TYPE"])
must(sent.META["CONTENT_LENGTH"] == str(4 * MIB) and sent.META["HTTP_CONTENT_RANGE"] == f"bytes 0-{4 * MIB - 1}/{8 * MIB}", sent.META)
must(sent.method == "PUT", sent.method)
must("HTTP_AUTHORIZATION" not in sent.META and "HTTP_COOKIE" not in sent.META, "no credentials forwarded")
# 4 MiB + 64 KiB passes the run check too (the range matches it); one byte over is 413
edge = chunk(CAP, start=0, total=CAP + 5)
must(run("remote-background", "upload-chunk", PS, binary=edge).status == 200, "cap passes")
CACHE.data.clear()
refusal(lambda: run("remote-background", "upload-chunk", PS, binary=chunk(CAP + 1, start=0, total=CAP + 10)), 413, "body_too_large")
# 1.18.34: the refusal writes one limited core_refused row (was: no row in 1.18.33)
must(not SEEN and len(ROWS) == 1 and meta(ROWS[0])["failure"] == "core_refused" and meta(ROWS[0])["code"] == "body_too_large", "an oversize chunk never reaches Tactical and writes one row")
# a bytearray and a memoryview are accepted and sent as bytes
for kind in (bytearray, memoryview):
    item = {"content": kind(b"abc"), "content_range": "bytes 3-5/9"}
    run("remote-background", "upload-chunk", PS, binary=item)
    must(SEEN[0]._body == b"abc" and type(SEEN[0]._body) is bytes, kind)
# the range is rebuilt from the numbers Core checked
run("remote-background", "upload-chunk", PS, binary={"content": b"abc", "content_range": "bytes 003-005/0009"})
must(SEEN[0].META["HTTP_CONTENT_RANGE"] == "bytes 3-5/9", SEEN[0].META["HTTP_CONTENT_RANGE"])
print("       binary_body: a 4 MiB chunk reaches Tactical's view byte for byte with Content-Type, Content-Length and HTTP_CONTENT_RANGE; no JSON body")

# bad ranges: 400 invalid_content_range, Tactical never called, no row
good = b"abcd"
CACHE.data.clear()
first_range = True
for bad in ("bytes 0-3/3", "bytes 4-3/10", "bytes 0-4/10", "bytes 0-2/10", "bytes 0-3/*", "bytes */4", "bytes 0-3", "text", "", "bytes 0-3/10 ",
            " bytes 0-3/10", "bytes 0-3/10\n", "BYTES 0-3/10", "bytes 0 - 3/10", "bytes -1-3/10", "bytes 0-3/-10", "bytes 0-3/1e1", "bytes 0-3/" + "9" * 20,
            "bytes " + "9" * 20 + "-" + "9" * 20 + "/" + "9" * 20, "bytes ٠-٣/١٠", "items 0-3/10", "bytes 0-3/10/4", None, 7, b"bytes 0-3/10", ["bytes 0-3/10"]):
    refusal(lambda bad=bad: run("remote-background", "upload-chunk", PS, binary={"content": good, "content_range": bad}), 400, "invalid_content_range")
    # 1.18.34: the first refusal of the session and code writes the row, every repeat writes none (was: no row in 1.18.33)
    must(not SEEN and len(ROWS) == (1 if first_range else 0), f"Tactical never called; one row for the first refusal only: {bad!r}")
    first_range = False
run("remote-background", "upload-chunk", PS, binary={"content": good, "content_range": "bytes 0-3/4"})  # the edge: end == total - 1
must(SEEN, "the exact fit passes")
refusal(lambda: run("remote-background", "upload-chunk", PS, binary={"content": b"", "content_range": "bytes 0-0/1"}), 400, "invalid_content_range")
must(not ROWS, "a repeat of the code in the same session writes no second row")
print("       a bad Content-Range (end >= total, start > end, length mismatch, text, '*' total, 20 digits ...) is 400 invalid_content_range; Tactical never called")

# required and not allowed
CACHE.data.clear()
refusal(lambda: run("remote-background", "upload-chunk", PS), 400, "binary_body_required")
must(len(ROWS) == 1 and meta(ROWS[0])["code"] == "binary_body_required", ROWS)  # 1.18.34: one limited row
refusal(lambda: run("remote-background", "upload-chunk", PS, body={"a": 1}), 400, "body_field_not_allowed")
must(len(ROWS) == 1 and meta(ROWS[0])["code"] == "body_field_not_allowed", "an AD-19 code still writes its row")
for bad in ("bytes", {"content": b"x"}, {"content": b"x", "content_range": "bytes 0-0/1", "extra": 1}, {"content": "text", "content_range": "bytes 0-3/4"},
            {"content": 5, "content_range": "bytes 0-0/1"}, [b"x"]):
    refusal(lambda bad=bad: run("remote-background", "upload-chunk", PS, binary=bad), 400, "binary_body_required")
must(not SEEN, "never called")
serve("upload-complete", json_view(200, {"status": "completed", "committed_offset": 8}))
refusal(lambda: run("remote-background", "upload-complete", PS, binary=chunk(4)), 400, "binary_body_not_allowed")
refusal(lambda: run("remote-background", "upload-init", P, {"path": "C:\\x"}, binary=chunk(4)), 400, "binary_body_not_allowed")
must(not SEEN and len(ROWS) == 1 and meta(ROWS[0])["code"] == "binary_body_not_allowed" and meta(ROWS[0])["transfer_role"] == "init", ROWS)
print("       binary_body_required (binary op without it) and binary_body_not_allowed (any other op with it), one limited row each, no Tactical call")

# binary_body is checked after the scope: a caller out of scope is refused for scope, not for the chunk
refusal(lambda: run("remote-background", "upload-chunk", {"agent_id": "z" * 21, "session_id": SID}, binary={"content": b"x", "content_range": "bad"}), 404, "object_not_found")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and meta(ROWS[0])["transfer_role"] == "chunk" and meta(ROWS[0])["transfer_session"] == SID, ROWS)
must(corr(ROWS[0]) == f"transfer:{SID}", corr(ROWS[0]))
print("       scope and permission checks run before the chunk is looked at")

# a stray Content-Range on the inbound request: never reaches an ordinary operation, and is replaced for a binary one
serve("upload-complete", seeing(FakeResponse(200, b'{"status": "completed"}')))
request = Request(tech)
request.META["HTTP_CONTENT_RANGE"] = "bytes 0-1/2"
run("remote-background", "upload-complete", PS, request=request)
must("HTTP_CONTENT_RANGE" not in SEEN[0].META, "an ordinary operation never sees the inbound Content-Range")
serve("download-status", seeing(FakeResponse(200, b'{"status": "x"}')))
request = Request(tech)
request.META["HTTP_CONTENT_RANGE"] = "bytes 0-1/2"
run("remote-background", "download-status", PS, request=request)
must("HTTP_CONTENT_RANGE" not in SEEN[0].META, "a GET never sees it")
serve("upload-chunk", seeing(FakeResponse(200, b"{}")))
request = Request(tech)
request.META["HTTP_CONTENT_RANGE"] = "bytes 0-999/1000"
run("remote-background", "upload-chunk", PS, binary={"content": b"abcd", "content_range": "bytes 4-7/20"}, request=request)
must(SEEN[0].META["HTTP_CONTENT_RANGE"] == "bytes 4-7/20", "the validated range overrides the inbound one")
print("       an inbound Content-Range never reaches an ordinary operation and is overridden for a binary one")

# the JSON route cannot carry a chunk: a binary operation over Core's HTTP route is binary_body_required
view = views.TacticalOperationView()


class HttpCall(HttpRequest):
    def __init__(self, params, body=None):
        self.user, self.tec_tac_session = tech, SimpleNamespace(id="s")
        self.META = {"CONTENT_LENGTH": "12", "HTTP_CONTENT_RANGE": "bytes 0-3/4"}
        self.content_type = "application/json"
        self.tec_tac_request_id = "req-http"
        self.data = {"params": params, **({"body": body} if body is not None else {})}


del SEEN[:], ROWS[:]
response = view.post(HttpCall(PS), "remote-background", "upload-chunk")
must(response.status_code == 400 and response.data["code"] == "binary_body_required", (response.status_code, response.data))
must(not SEEN, "Tactical never reached over the JSON route")
print("       a binary operation reached over the JSON route is refused 400 binary_body_required (never reaches Tactical)")

# ===================================================================================== binary_response
fresh()
declare_transfer_set()
payload = b"\x00\x01binary\xff" * 100
ok_headers = {"Content-Range": "bytes 0-4194303/8388608", "X-Chunk-Start": "0", "X-Chunk-End": "4194303"}
serve("download-chunk", FakeResponse(200, payload, "application/octet-stream", headers=ok_headers))
result = run("remote-background", "download-chunk", PS, query={"committed_offset": "0"})
must(result.status == 200 and result.content == payload and result.data == payload, "raw bytes")
must(result.headers == {"Content-Type": "application/octet-stream", **ok_headers}, result.headers)
must(SEEN[0].GET["committed_offset"] == "0" if hasattr(SEEN[0], "GET") else True, "committed_offset passed")
# an ordinary GET relays the same Tactical answer with the two usual headers only
register(id="plain-chunk", route=SESSION_ROOT + "plain/", audit=audit_of(action="view"))
ROUTES[f"/agents/{AGENT}/files/{SID}/plain/"] = (seeing(FakeResponse(200, payload, "application/octet-stream", headers=ok_headers)), (), {})
result = run("remote-background", "plain-chunk", PS)
must(result.headers == {"Content-Type": "application/octet-stream"}, result.headers)
# malformed values are dropped, one by one
for bad_range in ("bytes a-b/c", "bytes 0-1", "bytes -1-5/10", "bytes 0-1/" + "9" * 20, "bytes 0-1/2\r\nSet-Cookie: x=1", " bytes 0-1/2", "bytes 0-1/2\n", "", "bytes 0-1/*"):
    serve("download-chunk", FakeResponse(200, payload, "application/octet-stream", headers={**ok_headers, "Content-Range": bad_range}))
    result = run("remote-background", "download-chunk", PS)
    must("Content-Range" not in result.headers and result.headers["X-Chunk-Start"] == "0", (bad_range, result.headers))
for bad_num in ("abc", "-1", "1.5", "1" * 20, "5\r\nX: y", "5\n", " 5", "", "0x10", "٣"):
    serve("download-chunk", FakeResponse(200, payload, "application/octet-stream", headers={**ok_headers, "X-Chunk-Start": bad_num, "X-Chunk-End": bad_num}))
    result = run("remote-background", "download-chunk", PS)
    must("X-Chunk-Start" not in result.headers and "X-Chunk-End" not in result.headers and "Content-Range" in result.headers, (bad_num, result.headers))
serve("download-chunk", FakeResponse(200, payload, "application/octet-stream", headers={"X-Chunk-Start": "1" * 19}))
must(run("remote-background", "download-chunk", PS).headers["X-Chunk-Start"] == "1" * 19, "19 digits pass")
# the cap still holds
serve("download-chunk", FakeResponse(200, b"x" * (ops.MAX_RESPONSE_BYTES + 1), "application/octet-stream", headers=ok_headers))
refusal(lambda: run("remote-background", "download-chunk", PS), 502, "tactical_response_refused")
serve("download-chunk", FakeResponse(200, b"x" * ops.MAX_RESPONSE_BYTES, "application/octet-stream", headers=ok_headers))
must(len(run("remote-background", "download-chunk", PS).content) == ops.MAX_RESPONSE_BYTES, "25 MiB passes")
# the HTTP route returns the bytes and the three headers (a GET works there)
serve("download-chunk", FakeResponse(200, payload, "application/octet-stream", headers=ok_headers))
del SEEN[:], ROWS[:]
response = view.post(HttpCall(PS), "remote-background", "download-chunk")
must(response.status_code == 200 and response.content == payload, (response.status_code,))
must(response.headers.get("Content-Range") == ok_headers["Content-Range"] and response.headers.get("X-Chunk-Start") == "0" and response.headers.get("X-Chunk-End") == "4194303", response.headers)
must(response.content_type == "application/octet-stream", response.content_type)
print("       binary_response: three headers relayed when digits-only, dropped when not; ordinary GET relays two; 25 MiB cap; the HTTP route returns bytes and headers")

# ===================================================================================== 204 and 408
fresh()
declare_transfer_set()
register(id="plain-post", method="POST", route=ROOT_ + "plain-post/", body_fields=["a"], audit=audit_of(action="run"))
register(id="plain-delete", method="DELETE", route=ROOT_ + "plain-delete/", audit=audit_of(action="delete"))
plain_post, plain_delete = f"/agents/{AGENT}/files/plain-post/", f"/agents/{AGENT}/files/plain-delete/"
# a transfer-role PUT answered 408: relayed, no row, empty audit
serve("upload-chunk", FakeResponse(408, json.dumps({"detail": TACTICAL_TEXT}).encode()))
result = run("remote-background", "upload-chunk", PS, binary=chunk(10))
must(result.status == 408 and result.audit == {} and not ROWS, (result.status, result.audit, ROWS))
must(json.loads(result.content)["detail"] == TACTICAL_TEXT, "the body is relayed unchanged")
for name in ("upload-complete", "download-ack"):
    serve(name, FakeResponse(408, b'{"detail": "retry"}'))
    result = run("remote-background", name, PS)
    must(result.status == 408 and result.audit == {} and not ROWS, (name, result.audit))
serve("download-chunk", FakeResponse(408, b'{"detail": "retry"}'))
must(run("remote-background", "download-chunk", PS).status == 408 and not ROWS, "GET 408")
# a GET chunk answered 204: relayed with an empty body, no row
serve("download-chunk", FakeResponse(204, b"", "text/html; charset=utf-8"))
result = run("remote-background", "download-chunk", PS)
must(result.status == 204 and result.content == b"" and not ROWS and result.audit == {}, (result.status, ROWS))
for name in ("download-ack", "download-status"):
    serve(name, FakeResponse(204, b"", "text/html"))
    result = run("remote-background", name, PS)
    must(result.status == 204 and not ROWS, name)
# an init, complete, cancel or fail answered 204 is a normal success of that role
ROUTES[paths()["upload-init"]] = (seeing(FakeResponse(204, b"", "text/html")), (), {})
result = run("remote-background", "upload-init", P, {"path": "C:\\a", "file_name": "a.txt"})
must(result.status == 204 and len(ROWS) == 1 and meta(ROWS[0])["transfer_stage"] == "start" and meta(ROWS[0])["transfer_session"] is None, ROWS)
CACHE.data.clear()
serve("upload-complete", FakeResponse(204, b"", "text/html"))
result = run("remote-background", "upload-complete", PS)
must(result.status == 204 and len(ROWS) == 1 and meta(ROWS[0])["transfer_stage"] == "end" and meta(ROWS[0])["transfer_outcome"] == "completed", ROWS)
CACHE.data.clear()
serve("upload-cancel", FakeResponse(204, b"", "text/html"))
result = run("remote-background", "upload-cancel", PS, {"reason": "user"})
must(result.status == 204 and len(ROWS) == 1 and meta(ROWS[0])["transfer_outcome"] == "cancelled", ROWS)
# operations WITHOUT a transfer role behave exactly as before
ROUTES[plain_post] = (seeing(FakeResponse(408, b'{"detail": "retry"}')), (), {})
result = run("remote-background", "plain-post", P, {"a": 1})
must(result.status == 408 and len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed" and result.audit.get("recorded"), ROWS)
must(meta(ROWS[0])["tactical_status"] == 408 and "transfer_role" not in meta(ROWS[0]), meta(ROWS[0]))
ROUTES[plain_delete] = (seeing(FakeResponse(204, b"", "text/html")), (), {})
result = run("remote-background", "plain-delete", P)
must(result.status == 204 and len(ROWS) == 1 and ROWS[0]["action"] == "delete", ROWS)
must(len(ROWS) == 1 and result.audit.get("recorded"), "a DELETE answered 204 still writes its success row")
# and the audit header over the HTTP route: a transfer 408 carries none
serve("upload-complete", FakeResponse(408, b'{"detail": "retry"}'))
del SEEN[:], ROWS[:]
response = view.post(HttpCall(PS), "remote-background", "upload-complete")
must(response.status_code == 408 and "X-Tec-Tac-Audit" not in response.headers, response.headers)
print("       transfer roles: 408 relayed with no row and no audit header, 204 chunk relayed with no row; ordinary operations audited as before")

# 401, 403 and 5xx still write their rows on a transfer operation
for status, action in ((403, "deny"), (401, "deny")):
    serve("upload-chunk", FakeResponse(status, json.dumps({"detail": TACTICAL_TEXT}).encode()))
    result = run("remote-background", "upload-chunk", PS, binary=chunk(10))
    must(result.status == status and len(ROWS) == 1 and ROWS[0]["action"] == action, (status, ROWS))
    must(meta(ROWS[0])["transfer_role"] == "chunk" and meta(ROWS[0])["transfer_direction"] == "upload" and meta(ROWS[0])["transfer_session"] == SID, meta(ROWS[0]))
    must(corr(ROWS[0]) == f"transfer:{SID}", corr(ROWS[0]))
serve("upload-chunk", FakeResponse(500, json.dumps({"detail": TACTICAL_TEXT}).encode()))
result = run("remote-background", "upload-chunk", PS, binary=chunk(10))
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown" and meta(ROWS[0])["transfer_session"] == SID and corr(ROWS[0]) == f"transfer:{SID}", ROWS)
for status in (400, 404, 409, 422):
    serve("upload-chunk", FakeResponse(status, json.dumps({"detail": TACTICAL_TEXT}).encode()))
    result = run("remote-background", "upload-chunk", PS, binary=chunk(10, content=SECRET_BYTES))
    must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed" and meta(ROWS[0])["transfer_role"] == "chunk", (status, ROWS))
    must(meta(ROWS[0])["transfer_session"] == SID and corr(ROWS[0]) == f"transfer:{SID}", ROWS)
    must(TACTICAL_TEXT not in rows_text() and SECRET_BYTES.decode() not in rows_text(), "no Tactical text and no content in the failed row")
# GET refusals write no row (as before), 5xx on a GET writes none
serve("download-chunk", FakeResponse(400, b'{"detail": "x"}'))
must(run("remote-background", "download-chunk", PS).status == 400 and not ROWS, "GET 4xx writes nothing")
serve("download-chunk", FakeResponse(500, b'{"detail": "x"}'))
must(run("remote-background", "download-chunk", PS).status == 500 and not ROWS, "GET 5xx writes nothing")
# a dispatch that raises is an outcome-unknown row with the session link
def boom(request, *a, **k):
    raise RuntimeError("view blew up")
ROUTES[paths()["upload-chunk"]] = (boom, (), {})
refusal(lambda: run("remote-background", "upload-chunk", PS, binary=chunk(10)), 502, "tactical_call_failed")
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown" and corr(ROWS[0]) == f"transfer:{SID}" and meta(ROWS[0])["transfer_role"] == "chunk", ROWS)
# Core's own refusals of a chunk: before the path is cleaned (permission) they carry role and direction only (1.18.34)
poor = User("poor", Roleish())
poor.sees = tech.sees
del ROWS[:]
refusal(lambda: ops.run_tactical_operation(Request(poor), "remote-background", "upload-chunk", PS, binary_body=chunk(10)), 403, "tactical_permission_denied")
# 1.18.34: a row written before the path parameters are cleaned has a null session and no transfer correlation id (was: the session and the link)
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and corr(ROWS[0]) == "req-1" and meta(ROWS[0])["transfer_role"] == "chunk"
     and meta(ROWS[0])["transfer_direction"] == "upload" and meta(ROWS[0])["transfer_session"] is None, ROWS)
# a caller-supplied correlation_id is replaced
serve("upload-chunk", FakeResponse(500, b"{}"))
run("remote-background", "upload-chunk", PS, binary=chunk(10), correlation_id="caller-chose-this")
must(corr(ROWS[0]) == f"transfer:{SID}", corr(ROWS[0]))
refusal(lambda: run("remote-background", "upload-chunk", PS, binary=chunk(10), correlation_id="bad id with spaces"), 400, "invalid_correlation_id")
# an invalid session id: refused as invalid_params; the row (non-GET, core_refused) carries no link and no session
refusal(lambda: run("remote-background", "upload-chunk", {"agent_id": AGENT, "session_id": "not-a-uuid"}, binary=chunk(10)), 400, "invalid_params")
must(len(ROWS) == 1 and meta(ROWS[0])["transfer_session"] is None and corr(ROWS[0]) != "transfer:not-a-uuid", ROWS)
print("       refusal rows of a chunk carry transfer_role, transfer_direction, transfer_session and the transfer correlation id once the path is cleaned; a caller's id is replaced")

# ===================================================================================== rows: a whole upload
fresh()
declare_transfer_set()
CACHE.data.clear(), CACHE.adds.clear(), CACHE.deleted.clear()
ROUTES[paths()["upload-init"]] = (seeing(FakeResponse(200, json.dumps({"session_id": SID, "total_size": 12345, "status": "open"}).encode())), (), {})
del ROWS[:]
init_result = ops.run_tactical_operation(Request(tech), "remote-background", "upload-init", P, {"path": "C:\\Temp", "file_name": "a.bin", "total_size": 999, "chunk_size": 4194304})
must(init_result.status == 200 and len(ROWS) == 1, ROWS)
start = ROWS[0]
m = meta(start)
must(start["action"] == "custom:file-transfer" and start["object_type"] == "agent", start)
must(m["transfer_stage"] == "start" and m["transfer_role"] == "init" and m["transfer_direction"] == "upload" and m["transfer_session"] == SID and m["transfer_size"] == 12345, m)
must(start["after_value"] == {"path": "C:\\Temp", "file_name": "a.bin"}, start["after_value"])
must(corr(start) == f"transfer:{SID}" and len(corr(start)) == 45, corr(start))
must(init_result.audit.get("recorded") and init_result.audit["action"] == "custom:file-transfer", init_result.audit)
serve("upload-chunk", json_view(200, {"committed_offset": 100}))
del ROWS[:]
for index in range(3):
    result = ops.run_tactical_operation(Request(tech), "remote-background", "upload-chunk", PS, binary_body=chunk(10, start=index * 10, total=30, content=SECRET_BYTES))
    must(result.status == 200 and result.audit == {}, result.audit)
must(not ROWS, "three chunks write no row")
serve("upload-complete", json_view(200, {"status": "completed", "committed_offset": 30}))
result = ops.run_tactical_operation(Request(tech), "remote-background", "upload-complete", PS)
must(len(ROWS) == 1 and result.audit.get("recorded"), ROWS)
end = ROWS[0]
m = meta(end)
must(m["transfer_stage"] == "end" and m["transfer_role"] == "complete" and m["transfer_direction"] == "upload" and m["transfer_outcome"] == "completed", m)
must(m["transfer_bytes"] == 30 and m["transfer_session"] == SID and "transfer_reason" not in m, m)
must(corr(end) == corr(start) == f"transfer:{SID}", (corr(end), corr(start)))
must(end["after_value"] == {"session_id": SID}, end["after_value"])
must(CACHE.adds == [(f"tectac:transfer-end:{SID}", ops.TRANSFER_END_TTL_SECONDS)] and ops.TRANSFER_END_TTL_SECONDS == 7200, CACHE.adds)
must(SECRET_BYTES.decode() not in rows_text(), "no file content in any row")
print("       upload: init -> 3 chunks -> complete writes exactly two rows (start and end), one correlation id, the same session, no chunk rows")

# a repeated complete or cancel for the same session writes no second end row
del ROWS[:]
result = ops.run_tactical_operation(Request(tech), "remote-background", "upload-complete", PS)
must(result.status == 200 and not ROWS and result.audit == {}, (ROWS, result.audit))
serve("upload-cancel", json_view(200, {"status": "cancelled", "committed_offset": 10}))
result = ops.run_tactical_operation(Request(tech), "remote-background", "upload-cancel", PS, {"reason": "user"})
must(result.status == 200 and not ROWS, "a cancel after a complete writes no second end row either")
# another session is independent
serve("upload-complete", json_view(200, {"status": "completed", "committed_offset": 5}), session=SID2)
result = ops.run_tactical_operation(Request(tech), "remote-background", "upload-complete", {"agent_id": AGENT, "session_id": SID2})
must(len(ROWS) == 1 and meta(ROWS[0])["transfer_session"] == SID2 and corr(ROWS[0]) == f"transfer:{SID2}", ROWS)
print("       a repeated complete or cancel writes no second end row; another session writes its own")

# cancel: end row with outcome cancelled and reason user; the fail operation: outcome failed and reason error
fresh()
declare_transfer_set()
CACHE.data.clear()
serve("upload-cancel", json_view(200, {"status": "cancelled", "committed_offset": 7}))
del ROWS[:]
run("remote-background", "upload-cancel", PS, {"reason": "user"})
m = meta(ROWS[0])
must(len(ROWS) == 1 and m["transfer_stage"] == "end" and m["transfer_role"] == "cancel" and m["transfer_outcome"] == "cancelled" and m["transfer_reason"] == "user" and m["transfer_bytes"] == 7, m)
CACHE.data.clear()
serve("upload-cancel", json_view(200, {"status": "failed"}))
run("remote-background", "upload-fail", PS, {"reason": "error"})
m = meta(ROWS[0])
must(len(ROWS) == 1 and m["transfer_role"] == "fail" and m["transfer_outcome"] == "failed" and m["transfer_reason"] == "error" and "transfer_bytes" not in m, m)
# the word is taken from the answer only when it is a known one; else by role
for role_op, body, word, expected in (("upload-cancel", {"reason": "user"}, "expired", "expired"), ("upload-cancel", {"reason": "user"}, "weird", "cancelled"),
                                      ("upload-cancel", {"reason": "user"}, None, "cancelled"), ("upload-fail", {"reason": "error"}, "weird", "failed"),
                                      ("upload-fail", {"reason": "error"}, "cancelled", "cancelled")):
    CACHE.data.clear()
    serve("upload-cancel", json_view(200, {"status": word} if word else {}))
    run("remote-background", role_op, PS, body)
    must(meta(ROWS[0])["transfer_outcome"] == expected, (role_op, word, meta(ROWS[0])))
# a body that names no reason leaves the reason out; the selector keeps cancel and fail apart
refusal(lambda: run("remote-background", "upload-cancel", PS, {"reason": "error"}), 400, "body_selector_mismatch")
must(ROWS[0]["action"] == "deny" and meta(ROWS[0])["transfer_role"] == "cancel", ROWS)
# committed_offset: only a whole number >= 0
for value, kept in ((0, True), (5, True), (-1, False), (True, False), (1.5, False), ("7", False), (None, False)):
    CACHE.data.clear()
    serve("upload-complete", json_view(200, {"status": "completed", "committed_offset": value}))
    run("remote-background", "upload-complete", PS)
    must(("transfer_bytes" in meta(ROWS[0])) is kept, (value, meta(ROWS[0])))
print("       cancel -> end row (cancelled, reason user); the fail operation -> end row (failed, reason error); outcome and bytes only from known values")

# ===================================================================================== rows: a whole download
fresh()
declare_transfer_set()
CACHE.data.clear()
ROUTES[paths()["download-init"]] = (seeing(FakeResponse(200, json.dumps({"session_id": SID, "total_size": 20}).encode())), (), {})
del ROWS[:]
run("remote-background", "download-init", P, {"path": "C:\\Temp", "file_name": "d.bin", "chunk_size": 1024})
must(len(ROWS) == 1 and meta(ROWS[0])["transfer_direction"] == "download" and meta(ROWS[0])["transfer_size"] == 20, ROWS)
start_corr = corr(ROWS[0])
del ROWS[:]
serve("download-chunk", FakeResponse(204, b"", "text/html"))
run("remote-background", "download-chunk", PS, query={"committed_offset": "0"})
serve("download-chunk", FakeResponse(200, b"0123456789", "application/octet-stream", headers={"Content-Range": "bytes 0-9/20", "X-Chunk-Start": "0", "X-Chunk-End": "9"}))
run("remote-background", "download-chunk", PS, query={"committed_offset": "0"})
serve("download-ack", json_view(200, {"committed_offset": 10}))
run("remote-background", "download-ack", PS)
serve("download-status", json_view(200, {"status": "transferring", "committed_offset": 10}))
run("remote-background", "download-status", PS)
must(not ROWS, "204 chunk, 200 chunk, ack and status write no row")
serve("download-complete", json_view(200, {"status": "completed", "committed_offset": 20}))
run("remote-background", "download-complete", PS)
must(len(ROWS) == 1 and meta(ROWS[0])["transfer_stage"] == "end" and meta(ROWS[0])["transfer_direction"] == "download" and corr(ROWS[0]) == start_corr, ROWS)
# archive init and extract init: a start row each; extract: status writes none, cancel writes the end row
ROUTES[paths()["archive-init"]] = (seeing(FakeResponse(200, json.dumps({"session_id": SID2}).encode())), (), {})
run("remote-background", "archive-init", P, {"path": "C:\\Dir"})
must(len(ROWS) == 1 and meta(ROWS[0])["transfer_direction"] == "archive" and meta(ROWS[0])["transfer_session"] == SID2 and "transfer_size" not in meta(ROWS[0]), ROWS)
ROUTES[paths()["extract-init"]] = (seeing(FakeResponse(200, json.dumps({"session_id": SID}).encode())), (), {})
run("remote-background", "extract-init", P, {"path": "C:\\a.zip"})
must(len(ROWS) == 1 and meta(ROWS[0])["transfer_direction"] == "extract", ROWS)
serve("extract-status", json_view(200, {"status": "extracting"}))
run("remote-background", "extract-status", PS)
must(not ROWS, "extract status writes no row")
CACHE.data.clear()
serve("extract-cancel", json_view(200, {"status": "cancelled"}))
run("remote-background", "extract-cancel", PS, {"reason": "user"})
must(len(ROWS) == 1 and meta(ROWS[0])["transfer_stage"] == "end" and meta(ROWS[0])["transfer_direction"] == "extract", ROWS)
print("       download: init -> chunk 204 -> chunk 200 -> ack -> status -> complete writes two rows; archive and extract write their start row, extract its cancel end row")

# init: an answer without a valid session id writes the row with a null session; a resume (body session_id) writes none
for answer in ({}, {"session_id": "not-a-uuid"}, {"session_id": SID.upper()}, {"session_id": 5}, {"session_id": None}, {"session_id": SID + "x"}):
    ROUTES[paths()["upload-init"]] = (seeing(FakeResponse(200, json.dumps(answer).encode())), (), {})
    run("remote-background", "upload-init", P, {"path": "C:\\a", "file_name": "a"})
    must(len(ROWS) == 1 and meta(ROWS[0])["transfer_session"] is None and meta(ROWS[0])["transfer_stage"] == "start", (answer, ROWS))
    must(not corr(ROWS[0]).startswith("transfer:"), "no link without a valid session")
ROUTES[paths()["upload-init"]] = (seeing(FakeResponse(200, json.dumps({"session_id": SID, "total_size": 5}).encode())), (), {})
run("remote-background", "upload-init", P, {"path": "C:\\a", "file_name": "a", "session_id": SID})
must(not ROWS, "an init that resumes an open session writes no row")
run("remote-background", "upload-init", P, {"path": "C:\\a", "file_name": "a", "session_id": ""})
must(len(ROWS) == 1, "an empty session_id is not a resume")
# total_size from the answer wins over the body; the body's is used when the answer has none; only whole numbers
for answer, body_size, expected in (({"session_id": SID, "total_size": 10}, 99, 10), ({"session_id": SID}, 99, 99), ({"session_id": SID, "total_size": "10"}, 99, 99),
                                    ({"session_id": SID, "total_size": -1}, None, None), ({"session_id": SID, "total_size": 2.5}, True, None)):
    ROUTES[paths()["upload-init"]] = (seeing(FakeResponse(200, json.dumps(answer).encode())), (), {})
    body = {"path": "C:\\a", "file_name": "a"}
    if body_size is not None:
        body["total_size"] = body_size
    run("remote-background", "upload-init", P, body)
    must(meta(ROWS[0]).get("transfer_size") == expected, (answer, body_size, meta(ROWS[0])))
# an init answered 4xx: the failed row with the transfer metadata, no link, no Tactical text
ROUTES[paths()["upload-init"]] = (seeing(FakeResponse(400, json.dumps({"detail": TACTICAL_TEXT}).encode())), (), {})
run("remote-background", "upload-init", P, {"path": "C:\\a", "file_name": "a"})
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed" and meta(ROWS[0])["transfer_role"] == "init" and meta(ROWS[0])["transfer_session"] is None, ROWS)
must(TACTICAL_TEXT not in rows_text(), "no Tactical text")
print("       init: a missing or invalid session id in the answer gives transfer_session null; a body session_id (resume) writes no row; size only as a whole number")

# the end-row guard: no cache module, a raising cache, and a row write that fails
fresh()
declare_transfer_set()
serve("upload-complete", json_view(200, {"status": "completed"}))
CACHE.mode = "raise"
for _ in range(2):
    run("remote-background", "upload-complete", PS)
    must(len(ROWS) == 1, "a cache that raises fails open: the row is written")
CACHE.mode = "ok"
saved = sys.modules.pop("django.core.cache")
try:
    run("remote-background", "upload-complete", PS)
    must(len(ROWS) == 1, "no cache module at all fails open")
finally:
    sys.modules["django.core.cache"] = saved
CACHE.data.clear(), CACHE.deleted.clear()
G["FakeAuditLog"].objects.fail = True
result = run("remote-background", "upload-complete", PS)
must(not result.audit.get("recorded") and CACHE.deleted == [f"tectac:transfer-end:{SID}"] and f"tectac:transfer-end:{SID}" not in CACHE.data, (result.audit, CACHE.deleted))
G["FakeAuditLog"].objects.fail = False
run("remote-background", "upload-complete", PS)
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:file-transfer", "the retry can write it")
G["FakeAuditLog"].objects.fail = True
CACHE.mode = "raise"
run("remote-background", "upload-complete", PS)  # neither the row nor the key release works: must not raise
CACHE.mode = "ok"
G["FakeAuditLog"].objects.fail = False
print("       the end-row guard fails open (cache raises or missing), and the key is freed when the row write fails")

# no content, no Tactical text and nothing secret-looking in any row of a full run
fresh()
declare_transfer_set()
CACHE.data.clear()
ROUTES[paths()["upload-init"]] = (seeing(FakeResponse(200, json.dumps({"session_id": SID, "total_size": 9, "detail": TACTICAL_TEXT, "token": "S3CRET-TOKEN"}).encode())), (), {})
ROUTES[paths()["upload-chunk"]] = (seeing(FakeResponse(500, json.dumps({"detail": TACTICAL_TEXT}).encode())), (), {})
serve("upload-complete", json_view(200, {"status": "completed", "committed_offset": 9, "detail": TACTICAL_TEXT, "token": "S3CRET-TOKEN"}))
del ROWS[:]
run("remote-background", "upload-init", P, {"path": "C:\\a", "file_name": "a.txt", "total_size": 9})
init_rows = list(ROWS)
all_rows = list(init_rows)
for fn in (lambda: run("remote-background", "upload-chunk", PS, binary=chunk(9, content=SECRET_BYTES)),
           lambda: run("remote-background", "upload-complete", PS)):
    fn()
    all_rows += list(ROWS)
text = json.dumps(all_rows, default=str)
for needle in (SECRET_BYTES.decode(), TACTICAL_TEXT, "S3CRET-TOKEN"):
    must(needle not in text, f"{needle} reached a row")
must(len(all_rows) == 3, len(all_rows))
print("       no file content, no Tactical text and no secret in any row")

# ===================================================================================== compatibility
# a 1.18.32-style declaration registers and runs unchanged
fresh()
op = register(id="old-style", method="POST", route=ROOT_ + "old/", body_fields=["a"], query_params=["q"], audit=audit_of(action="run", audit_fields=["a"]))
must(op.binary_body is False and op.binary_response is False and op.audit_transfer == (), op)
ROUTES[f"/agents/{AGENT}/files/old/"] = (seeing(FakeResponse(200, b'{"ok": true}', headers={"Content-Range": "bytes 0-1/2", "X-Chunk-Start": "0"})), (), {})
result = run("remote-background", "old-style", P, {"a": 1}, query={"q": "v"})
must(result.status == 200 and result.headers == {"Content-Type": "application/json"}, result.headers)
must(SEEN[0].META["CONTENT_TYPE"] == "application/json" and json.loads(SEEN[0]._body) == {"a": 1}, "the JSON body is built as before")
must(len(ROWS) == 1 and ROWS[0]["action"] == "run" and "transfer_role" not in meta(ROWS[0]) and corr(ROWS[0]) == "req-1", ROWS)
result = run("remote-background", "old-style", P, {"a": 1}, query={"q": "v"}, correlation_id="module-chose-this")
must(corr(ROWS[0]) == "module-chose-this", "a caller's correlation id still works for an ordinary operation")
# an operation that declares audit.params with a uuid but no transfer role is untouched
register(id="old-session", method="POST", route=SESSION_ROOT + "x/", audit=audit_of(action="run", params=["session_id"]))
ROUTES[f"/agents/{AGENT}/files/{SID}/x/"] = (seeing(FakeResponse(200, b"{}")), (), {})
run("remote-background", "old-session", PS, correlation_id="keep-me")
must(corr(ROWS[0]) == "keep-me" and "transfer_session" not in meta(ROWS[0]), ROWS)
print("       a 1.18.32-style declaration registers and runs unchanged (JSON body, two headers, caller correlation id)")

# describe, list_operations, get_operation and the metadata
fresh()
declare_transfer_set()
chunk_op = ops.get_operation("remote-background", "upload-chunk")
must(chunk_op["binary_body"] is True and chunk_op["binary_response"] is False and chunk_op["audit"]["transfer"] == {"role": "chunk", "direction": "upload"}, chunk_op)
must(ops.get_operation("remote-background", "download-chunk")["binary_response"] is True, "binary_response shown")
must(ops.get_operation("remote-background", "upload-init")["audit"]["transfer"] == {"role": "init", "direction": "upload"}, "init")
register(id="plain", route=ROOT_ + "plain-x/")
plain = ops.get_operation("remote-background", "plain")
must(plain["binary_body"] is False and plain["binary_response"] is False and plain["audit"]["transfer"] is None, plain)
must(all("binary_body" in item and "binary_response" in item for item in ops.list_operations()), "list_operations")
cap = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.18.0" and cap["version"] == "1.18.0" and cap["version"].split(".")[0] == "1", cap["version"])
must(G["CAPS"][-1]["version"] == "1.18.0" if G["CAPS"] else True, "registered version")
must(cap["limits"]["binary_body_bytes"] == CAP == ops.MAX_BINARY_BODY_BYTES and ops.MAX_BINARY_BODY_BYTES < ops.MAX_BODY_CEILING_BYTES, cap["limits"])
must(cap["limits"]["body_bytes"] == 256 * 1024 and cap["limits"]["path_query_names"] == 4 and cap["limits"]["response_bytes"] == 25 * MIB, "older limits unchanged")
must(len(cap["declaration_keys_added_in_1_18_0"]) == 4 and cap["transfer_roles"] == list(ops.TRANSFER_ROLES) and cap["transfer_directions"] == list(ops.TRANSFER_DIRECTIONS), cap)
must({"invalid_content_range", "binary_body_required", "binary_body_not_allowed", "length_required"} <= {c.split(" ")[0] for c in cap["refusal_codes_added_in_1_18_0"]}, cap["refusal_codes_added_in_1_18_0"])
text = " ".join(cap["behaviour_added_in_1_18_0"])
for needle in ("read_binary_body", "Content-Range", "X-Chunk-Start", "transfer:<session id>", "408", "204", "AD-69", "once per session", "request.body"):
    must(needle in text or needle.lower() in text.lower(), needle)
must("binary_body=False, binary_response=False" in cap["declaration"], "the declaration line shows both keywords")
must(cap["refusal_row_codes"] == list(ops.CORE_REFUSAL_ROW_CODES) and "invalid_content_range" not in cap["refusal_row_codes"], "the new codes write no row")
sig = inspect.signature(ops.register_tactical_operation).parameters
must(list(sig)[-3:] == ["path_query_params", "binary_body", "binary_response"], list(sig))
run_sig = inspect.signature(ops.run_tactical_operation).parameters
must(list(run_sig)[:8] == ["request", "module_id", "operation_id", "params", "body", "query", "upload", "correlation_id"], list(run_sig))
must(run_sig["binary_body"].kind is inspect.Parameter.KEYWORD_ONLY and list(run_sig).index("binary_body") == list(run_sig).index("audit_before") + 1, "binary_body is keyword-only, after audit_before")
print("       describe(), list_operations, get_operation and the metadata show the new keys; capability 1.18.0; no positional shift")

# ===================================================================================== docs and contract rows
root = Path(__file__).resolve().parents[1]
docs = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
must("`core.tactical_operations` 1.18.0 (1.17.0 before Core 1.18.33" in docs, "the docs header")
for needle in ("1.18.33", "binary_body", "binary_response", "audit.transfer", "read_binary_body", "transfer:<session id>", "invalid_content_range", "length_required", "tectac:transfer-end",
               "408", "204", "AD-69", "binary_body_required"):
    must(needle in docs, f"docs/tactical-operations.md lacks {needle!r}")
contract = (root / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
for needle in ("Added in 1.18.33", "binary_body", "binary_response", "read_binary_body", "audit={..., 'transfer'", "framework >=1.18.33", "core.tactical_operations >= 1.18.0"):
    must(needle in contract, f"contracts.py lacks {needle!r}")

# ===================================================================================== modules/ still pass the registration keys
MODULES = Path(__file__).resolve().parents[3] / "modules"
OLD_AUDIT_KEYS = {"action", "object_type", "audit_fields", "object_param", "before", "params", "object_field", "object_body_field", "secret_fields", "object_id", "action_by_body"}
NEW_NAMES = ("binary_body", "binary_response", "read_binary_body")
if MODULES.is_dir() and (MODULES / "catalog.toml").is_file():
    accepted = set(sig) | {"failed"}  # "failed" is a key of an unrelated dict that shares the method, route and audit keys of a spec
    specs = 0
    found_modules = set()
    for folder in sorted(p for p in MODULES.iterdir() if (p / "package").is_dir()):
        for file in (folder / "package").rglob("*.py"):
            if "tests" in file.parts:
                continue
            text_ = file.read_text(encoding="utf-8")
            # 1.18.34: remote-background 0.11.4 is the module these additions were made for and now declares them (re-checked for 1.18.34:
            # it passes binary_body to run and declares audit.transfer; it does not call read_binary_body yet). Every other module must not.
            if folder.name != "remote-background":
                for name in NEW_NAMES:
                    must(name not in text_, f"{folder.name} already uses {name}: re-check the compatibility of this release")
                must("'transfer'" not in text_ and '"transfer"' not in text_, f"{folder.name} already declares audit.transfer")
            for node in ast.walk(ast.parse(text_)):
                if isinstance(node, ast.Dict):
                    keys = [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                    if {"method", "route", "audit"} <= set(keys):
                        specs += 1
                        found_modules.add(folder.name)
                        extra = set(keys) - accepted - {"id", "module_id"}
                        must(not extra, f"{folder.name} {file.name}: a spec uses keys the registration does not take: {sorted(extra)}")
                        audit_node = node.values[[k.value if isinstance(k, ast.Constant) else None for k in node.keys].index("audit")]
                        if isinstance(audit_node, ast.Dict):
                            audit_keys = {k.value for k in audit_node.keys if isinstance(k, ast.Constant)}
                            allowed_audit = OLD_AUDIT_KEYS | ({"transfer"} if folder.name == "remote-background" else set())
                            must(audit_keys <= allowed_audit, f"{folder.name} {file.name}: audit keys {sorted(audit_keys - allowed_audit)}")
                if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "register_tactical_operation":
                    names = {kw.arg for kw in node.keywords if kw.arg}
                    must(names <= set(sig), f"{folder.name}: register_tactical_operation keywords {sorted(names - set(sig))}")
                    must(len(node.args) <= 8, f"{folder.name}: positional arguments of register_tactical_operation")
    must(specs >= 100 and len(found_modules) >= 14, f"the scan found too little: {specs} specs in {len(found_modules)} modules")
    print(f"       compatibility: {specs} declarations in {len(found_modules)} modules use only keys the registration still takes; none uses the new keys")
else:
    print("       compatibility check skipped: modules/ is not beside this repository")

print("[TEST] PASS tactical operation file transfers 1.18.33")
