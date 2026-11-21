#!/usr/bin/env python3
"""1.18.34 regression: the audit trail of file transfers is complete (ORDER Core 1.18.34, Johan, 21 November 2026, AD-69).

Four fixes to the 1.18.33 additions, all additive; capability core.tactical_operations stays 1.18.0:
1. the refusals of a binary chunk write one limited core_refused row, one per session and code (run path and read_binary_body);
2. a complete, cancel or fail that Tactical or the agent fails (4xx or 5xx, except 401, 403, 408, 429) writes its AD-69 end row (outcome failed);
3. read_binary_body runs the authentication, permission, module-permission, caller-scope and (with params) role-scope checks before it reads;
4. a row written before the path parameters are cleaned carries transfer_session null and no transfer:<id> correlation id.

Uses the stubs of tests/tactical-operations-1.17.7.py and the prelude of tests/tactical-operation-file-transfer-1.18.33.py
(Django and Tactical are not installed on the development PC).
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PRIOR = HERE / "tactical-operation-file-transfer-1.18.33.py"
text33 = PRIOR.read_text(encoding="utf-8")
cut33 = text33.index("# ===================================================================================== registration: binary_body")
G = {"__name__": "prelude", "__file__": str(PRIOR)}
exec(compile(text33[:cut33], str(PRIOR), "exec"), G)  # noqa: S102 - test-only reuse of the 1.18.33 prelude and the 1.17.7 stubs
(ops, fresh, must, ROUTES, CALLS, ROWS, AGENT, User, Roleish, Request) = (
    G[k] for k in ("ops", "fresh", "must", "ROUTES", "CALLS", "ROWS", "AGENT", "User", "Roleish", "Request"))
FakeResponse, refusal, views, HttpRequest = G["FakeResponse"], G["refusal"], G["views"], G["HttpRequest"]
(tech, SID, SID2, CAP, MIB, CACHE, FLAG, TACTICAL_TEXT, SECRET_BYTES) = (
    G[k] for k in ("tech", "SID", "SID2", "CAP", "MIB", "CACHE", "FLAG", "TACTICAL_TEXT", "SECRET_BYTES"))
(register, refused, run, meta, corr, chunk, rows_text, declare_transfer_set, serve, json_view, seeing, paths, audit_of, ROOT_, SESSION_ROOT, P, PS) = (
    G[k] for k in ("register", "refused", "run", "meta", "corr", "chunk", "rows_text", "declare_transfer_set", "serve", "json_view", "seeing", "paths",
                   "audit_of", "ROOT_", "SESSION_ROOT", "P", "PS"))
SEEN = G["SEEN"]
STUBS = G["G"]  # the namespace of the 1.17.7 stubs
FakeAuditLog = STUBS["FakeAuditLog"]

# the caller-scope stub (as tests/tactical-operations-unrestricted-1.17.18.py): a user with .limited is a client-limited role
resources = types.ModuleType("tec_tac.resources")
resources.user_context = lambda user: SimpleNamespace(user=user)
resources.scope_unrestricted = lambda context: not getattr(context.user, "limited", False)
sys.modules["tec_tac.resources"] = resources

tech.pk = 5
other = User("other", Roleish(FLAG))
other.pk = 6
other.sees = tech.sees
poor = User("poor", Roleish())
poor.pk = 7
poor.sees = tech.sees
limited = User("limited", Roleish(FLAG))
limited.pk = 8
limited.limited = True
limited.sees = tech.sees
STUBS["GRANTS"][tech.role.id] = {"licensing.manage"}
STUBS["GRANTS"][other.role.id] = {"licensing.manage"}
STUBS["GRANTS"][limited.role.id] = {"licensing.manage"}

REFUSAL_KEY = "tectac:transfer-refusal:{}:{}"
END_KEY = "tectac:transfer-end:{}"


def reset():
    fresh()
    declare_transfer_set()
    CACHE.data.clear(), CACHE.adds.clear(), CACHE.deleted.clear()
    CACHE.mode = "ok"
    FakeAuditLog.objects.fail = False
    del ROWS[:], SEEN[:]


def run_as(user, module, operation, params=None, body=None, query=None, binary=None, correlation_id=None):
    del CALLS[:], SEEN[:], ROWS[:]
    return ops.run_tactical_operation(Request(user), module, operation, params, body, query=query, correlation_id=correlation_id, binary_body=binary)


def refusal_row(rows=None):
    rows = ROWS if rows is None else rows
    must(len(rows) == 1, rows)
    return rows[0]


def must_be_core_refused(row, code, role="chunk", session=SID, direction="upload"):
    m = meta(row)
    must(row["action"] == "custom:operation-failed", row["action"])
    must(m["failure"] == "core_refused" and m["code"] == code and m["result"] == "failed", m)
    must(m["transfer_role"] == role and m["transfer_direction"] == direction and m["transfer_session"] == session, m)
    must(row["message"] == ops.CORE_REFUSED_MESSAGE.format(code=code), row["message"])
    if session:
        must(corr(row) == f"transfer:{session}", corr(row))
    return m


# ============================================================ item 1: chunk refusals write one limited row per session and code
must(ops.CHUNK_REFUSAL_ROW_CODES == ("invalid_content_range", "binary_body_required", "binary_body_not_allowed", "body_too_large", "length_required",
                                     "content_length_mismatch"), ops.CHUNK_REFUSAL_ROW_CODES)
must(ops.CORE_REFUSAL_ROW_CODES == ("body_field_not_allowed", "invalid_body", "invalid_params", "scope_field_required", "invalid_correlation_id",
                                    "invalid_audit_before"), "the six AD-19 codes are unchanged")
must(ops.TRANSFER_REFUSAL_TTL_SECONDS == 7200, "ttl")
reset()
serve("upload-chunk", json_view(200, {"committed_offset": 1}))
serve("upload-complete", json_view(200, {"status": "completed"}))
SECRET_RANGE = "bytes 0-9/4 EVIL-RANGE-TEXT"
cases = (
    ("invalid_content_range", "upload-chunk", {"content": SECRET_BYTES, "content_range": SECRET_RANGE}, 400, "chunk"),
    ("binary_body_required", "upload-chunk", None, 400, "chunk"),
    ("binary_body_not_allowed", "upload-complete", chunk(4), 400, "complete"),
    ("body_too_large", "upload-chunk", chunk(CAP + 1, start=0, total=CAP + 10), 413, "chunk"),
)
for code, op, binary, status, role in cases:
    reset()
    serve("upload-chunk", json_view(200, {"committed_offset": 1}))
    serve("upload-complete", json_view(200, {"status": "completed"}))
    exc = refusal(lambda op=op, binary=binary: run("remote-background", op, PS, binary=binary), status, code)
    m = must_be_core_refused(refusal_row(), code, role=role)
    must(m["status"] == status and m["tactical_status"] is None, m)
    must(exc.audit and exc.audit["recorded"] and exc.audit["action"] == "custom:operation-failed", exc.audit)
    must((REFUSAL_KEY.format(SID, code), 7200) in CACHE.adds and REFUSAL_KEY.format(SID, code) in CACHE.data, CACHE.adds)
    must(not SEEN, "Tactical never called")
    # a second identical refusal in the same session writes no row and leaves exc.audit None
    exc = refusal(lambda op=op, binary=binary: run("remote-background", op, PS, binary=binary), status, code)
    must(not ROWS and exc.audit is None, (ROWS, exc.audit))
    # a different session writes its own row
    exc = refusal(lambda op=op, binary=binary: run("remote-background", op, {"agent_id": AGENT, "session_id": SID2}, binary=binary), status, code)
    must_be_core_refused(refusal_row(), code, role=role, session=SID2)
    # a different code in the first session writes its own row
    other_code = "binary_body_required" if code != "binary_body_required" else "invalid_content_range"
    other_binary = None if other_code == "binary_body_required" else {"content": b"abcd", "content_range": "bytes 0-9/4"}
    refusal(lambda other_binary=other_binary: run("remote-background", "upload-chunk", PS, binary=other_binary), 400, other_code)
    must_be_core_refused(refusal_row(), other_code)
    if code == "invalid_content_range":  # no chunk bytes, no Content-Range text, no caller text in the row
        reset()
        serve("upload-chunk", json_view(200, {}))
        refusal(lambda: run("remote-background", "upload-chunk", PS, binary=cases[0][2]), 400, code)
        must(SECRET_BYTES.decode() not in rows_text() and "EVIL-RANGE-TEXT" not in rows_text() and "bytes 0-9" not in rows_text(), rows_text())
print("       run path: invalid_content_range, binary_body_required, binary_body_not_allowed and body_too_large each write one core_refused row; a repeat writes none; another session or code writes its own")

# a refusal with no session id (an init operation given a chunk) is keyed by user pk and operation
reset()
for who, expect_row in ((tech, True), (tech, False), (other, True)):
    del ROWS[:]
    try:
        ops.run_tactical_operation(Request(who), "remote-background", "upload-init", P, {"path": "C:\\x"}, binary_body=chunk(4))
    except ops.TacticalOperationError as exc:
        must(exc.code == "binary_body_not_allowed", exc.code)
        must((exc.audit is not None) == expect_row, (who.username, exc.audit))
    must(len(ROWS) == (1 if expect_row else 0), (who.username, ROWS))
    if expect_row:
        m = meta(ROWS[0])
        must(m["transfer_role"] == "init" and m["transfer_session"] is None and corr(ROWS[0]) == "req-1", m)
keys = sorted(CACHE.data)
must(keys == ["tectac:transfer-refusal:user5-remote-background.upload-init:binary_body_not_allowed",
              "tectac:transfer-refusal:user6-remote-background.upload-init:binary_body_not_allowed"], keys)
print("       without a session id the row is limited per user pk and operation id")

# the cache: missing and raising still write the row; a failed audit write frees the key
reset()
CACHE.mode = "raise"
for _ in range(2):
    refusal(lambda: run("remote-background", "upload-chunk", PS), 400, "binary_body_required")
    must(len(ROWS) == 1, "a cache that raises fails open: the row is written each time")
CACHE.mode = "ok"
saved = sys.modules.pop("django.core.cache")
try:
    for _ in range(2):
        refusal(lambda: run("remote-background", "upload-chunk", PS), 400, "binary_body_required")
        must(len(ROWS) == 1, "no cache module at all fails open")
finally:
    sys.modules["django.core.cache"] = saved
CACHE.data.clear(), CACHE.deleted.clear()
FakeAuditLog.objects.fail = True
exc = refusal(lambda: run("remote-background", "upload-chunk", PS), 400, "binary_body_required")
must(exc.audit == {"recorded": False, "error": "audit_write_failed"} or not exc.audit.get("recorded"), exc.audit)
key = REFUSAL_KEY.format(SID, "binary_body_required")
must(CACHE.deleted == [key] and key not in CACHE.data, (CACHE.deleted, CACHE.data))
FakeAuditLog.objects.fail = False
refusal(lambda: run("remote-background", "upload-chunk", PS), 400, "binary_body_required")
must(len(ROWS) == 1 and key in CACHE.data, "the next refusal writes the row")
FakeAuditLog.objects.fail = True
CACHE.mode = "raise"
refusal(lambda: run("remote-background", "upload-chunk", PS), 400, "binary_body_required")  # neither the write nor the release works: no error
CACHE.mode = "ok"
FakeAuditLog.objects.fail = False
print("       the refusal guard fails open (cache raises or missing) and the key is freed when the row write fails")

# a JSON body_too_large writes no row; the six AD-19 codes write a row each time; a GET writes nothing
reset()
register(id="plain-post", method="POST", route=ROOT_ + "plain-post/", body_fields=["a"], audit=audit_of(action="run"))
big = {"a": "x" * (300 * 1024)}
refusal(lambda: run("remote-background", "plain-post", P, big), 413, "body_too_large")
must(not ROWS and not CACHE.data, "a JSON body_too_large still writes no row and takes no key")
for _ in range(3):
    exc = refusal(lambda: run("remote-background", "plain-post", P, {"zzz": 1}), 400, "body_field_not_allowed")
    must(len(ROWS) == 1 and meta(ROWS[0])["failure"] == "core_refused" and exc.audit["recorded"], "an AD-19 code writes a row every time")
must(not CACHE.data, "the AD-19 rows take no once-only key")
refusal(lambda: run("remote-background", "upload-chunk", {"agent_id": AGENT, "session_id": "not-a-uuid"}, binary=chunk(10)), 400, "invalid_params")
must(len(ROWS) == 1 and meta(ROWS[0])["code"] == "invalid_params" and meta(ROWS[0])["transfer_session"] is None, ROWS)
serve("download-chunk", json_view(200, {}))
refusal(lambda: run("remote-background", "download-chunk", PS, binary=chunk(4)), 400, "binary_body_not_allowed")
must(not ROWS and not CACHE.data, "a GET operation writes nothing")
print("       a JSON body_too_large writes no row; the six AD-19 codes write a row each time as before; a GET operation writes nothing")


# ----- read_binary_body: the same limited row, after the checks pass
class Stream:
    def __init__(self, data):
        self.data, self.pos, self.reads = data, 0, []

    def read(self, size=-1):
        self.reads.append(size)
        out = self.data[self.pos:self.pos + size]
        self.pos += len(out)
        return out


class ChunkRequest(Request):
    def __init__(self, user, data, length="auto", content_range=None):
        super().__init__(user)
        self.stream = Stream(data)
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


def helper(request, op="upload-chunk", **kw):
    del ROWS[:]
    return ops.read_binary_body(request, "remote-background", op, **kw)


def helper_refusal(request, status, code, op="upload-chunk", **kw):
    try:
        helper(request, op, **kw)
    except ops.TacticalOperationError as exc:
        must(exc.status == status and exc.code == code, (exc.status, exc.code, exc.message))
        return exc
    raise AssertionError(f"expected {status} {code}")


reset()
for length, status, code, reads_expected in ((None, 411, "length_required", False), ("abc", 411, "length_required", False),
                                             (str(CAP + 1), 413, "body_too_large", False), ("10", 400, "content_length_mismatch", True)):
    CACHE.data.clear()
    req = ChunkRequest(tech, b"x" * 5, length=length)
    exc = helper_refusal(req, status, code, params=PS)
    m = must_be_core_refused(refusal_row(), code)
    must(exc.audit and exc.audit["recorded"], exc.audit)
    must(bool(req.stream.reads) is reads_expected, f"read() for {code}: {req.stream.reads}")
    req = ChunkRequest(tech, b"x" * 5, length=length)  # the repeat writes none
    exc = helper_refusal(req, status, code, params=PS)
    must(not ROWS and exc.audit is None, (code, ROWS))
    # without params: the row has no session, keyed by user and operation
    CACHE.data.clear()
    exc = helper_refusal(ChunkRequest(tech, b"x" * 5, length=length), status, code)
    m = meta(refusal_row())
    must(m["failure"] == "core_refused" and m["transfer_session"] is None and m["code"] == code, m)
    must(REFUSAL_KEY.format("user5-remote-background.upload-chunk", code) in CACHE.data, sorted(CACHE.data))
# the not-allowed code, an operation without binary_body
CACHE.data.clear()
exc = helper_refusal(ChunkRequest(tech, b"x"), 400, "binary_body_not_allowed", op="upload-init", params=P)
must_be_core_refused(refusal_row(), "binary_body_not_allowed", role="init", session=None)
# a good chunk writes nothing and reads as in 1.18.33
req = ChunkRequest(tech, b"hello", content_range="bytes 0-4/5")
must(helper(req, params=PS) == {"content": b"hello", "content_range": "bytes 0-4/5"} and not ROWS, "an allowed caller reads exactly as before")
must(helper(ChunkRequest(tech, b"hello", content_range="bytes 0-4/5")) == {"content": b"hello", "content_range": "bytes 0-4/5"}, "no params")
# no chunk bytes, Content-Range text or Tactical text in the rows
req = ChunkRequest(tech, SECRET_BYTES, length="3", content_range=SECRET_RANGE)
CACHE.data.clear()
helper_refusal(req, 400, "content_length_mismatch", params=PS)
must(SECRET_BYTES.decode() not in rows_text() and "EVIL-RANGE-TEXT" not in rows_text(), rows_text())
print("       read_binary_body: length_required, body_too_large, content_length_mismatch and binary_body_not_allowed write one limited row; read() is never called for 411 and 413; no bytes in a row")

# ============================================================ item 3: read_binary_body checks before it reads
reset()
register(id="chunk-module", method="PUT", route=ROOT_ + "mod/{session_id:uuid}/chunks/", binary_body=True, module_permission="licensing.manage",
         audit=audit_of(transfer={"role": "chunk", "direction": "upload"}, params=["session_id"]))
register(id="chunk-open", method="PUT", route=ROOT_ + "open/{session_id:uuid}/chunks/", binary_body=True, caller_scope="unrestricted",
         audit=audit_of(transfer={"role": "chunk", "direction": "upload"}, params=["session_id"]))
no_module = User("nomod", Roleish(FLAG))
no_module.pk = 9
no_module.sees = tech.sees


def checked(user, op, status, code, params=None, reason=None):
    req = ChunkRequest(user, b"abcd", content_range="bytes 0-3/4")
    exc = helper_refusal(req, status, code, op=op, params=params)
    must(req.stream.reads == [], f"the stream was never read: {req.stream.reads}")
    row = refusal_row()
    must(row["action"] == "deny", row["action"])
    if reason:
        must(meta(row)["reason"] == reason and row["message"] == ops.DENY_MESSAGES[reason], meta(row))
    must(exc.audit and exc.audit["recorded"], exc.audit)
    return row


# the Tactical flag
row = checked(poor, "upload-chunk", 403, "tactical_permission_denied", reason="permission_denied")
must(meta(row)["transfer_session"] is None and meta(row)["transfer_role"] == "chunk", meta(row))
checked(poor, "upload-chunk", 403, "tactical_permission_denied", params=PS, reason="permission_denied")
# the module permission
checked(no_module, "chunk-module", 403, "module_permission_denied", reason="module_permission_denied")
checked(no_module, "chunk-module", 403, "module_permission_denied", params=PS, reason="module_permission_denied")
# a limited role for an operation for unrestricted callers only
checked(limited, "chunk-open", 403, "scope_unrestricted_required", reason="scope_unrestricted_required")
checked(limited, "chunk-open", 403, "scope_unrestricted_required", params=PS, reason="scope_unrestricted_required")
# with params, an agent outside the role's scope: 404 and a deny row that carries the session
row = checked(tech, "upload-chunk", 404, "object_not_found", params={"agent_id": "z" * 21, "session_id": SID}, reason="not_found")
must(meta(row)["transfer_session"] == SID and corr(row) == f"transfer:{SID}", (meta(row), corr(row)))
# without params the scope check stays in run: the same caller passes the helper and run refuses the agent
req = ChunkRequest(tech, b"abcd", content_range="bytes 0-3/4")
must(helper(req, op="upload-chunk")["content"] == b"abcd", "no params: only the permission checks run before the read")
# invalid params with params given: invalid_params, an AD-19 row, no read
req = ChunkRequest(tech, b"abcd")
exc = helper_refusal(req, 400, "invalid_params", params={"agent_id": AGENT, "session_id": "not-a-uuid"})
must(req.stream.reads == [] and meta(refusal_row())["code"] == "invalid_params" and meta(ROWS[0])["transfer_session"] is None, ROWS)
# unauthenticated and not a real request: 401 and no row, no read
anon = User("anon", anonymous=True)
req = ChunkRequest(anon, b"abcd")
helper_refusal(req, 401, "authentication_required")
must(not ROWS and req.stream.reads == [], "an anonymous request is refused with no read and no row")
req = ChunkRequest(tech, b"abcd")
req.tec_tac_session = None
helper_refusal(req, 401, "authenticated_request_required")
must(not ROWS and req.stream.reads == [], "a request without Core's session proof is refused")
fake = SimpleNamespace(user=tech, tec_tac_session=SimpleNamespace(id="s"), META={"CONTENT_LENGTH": "4"}, read=lambda n: b"abcd")
helper_refusal(fake, 401, "authenticated_request_required")
must(not ROWS, "a stand-in object is refused")
# a permitted caller passes every check and reads (module permission and unrestricted scope held)
for user, op in ((tech, "chunk-module"), (other, "chunk-module"), (tech, "chunk-open")):
    req = ChunkRequest(user, b"abcd", content_range="bytes 0-3/4")
    must(helper(req, op=op, params=PS)["content"] == b"abcd" and not ROWS, (user.username, op))
# the module permission check also runs for run_tactical_operation exactly as before (unchanged order, codes and rows)
serve("upload-chunk", json_view(200, {}))
refusal(lambda: ops.run_tactical_operation(Request(no_module), "remote-background", "chunk-module", PS, binary_body=chunk(4)), 403, "module_permission_denied")
must(meta(refusal_row())["reason"] == "module_permission_denied", ROWS)
print("       read_binary_body: no Tactical flag, no module permission, a limited role and (with params) an agent out of scope are refused with the deny row and no read; 401 for no session; an allowed caller reads as before")

# ============================================================ item 4: early rows carry transfer_session null
reset()
register(id="complete-module", method="POST", route=ROOT_ + "modc/{session_id:uuid}/complete/", module_permission="licensing.manage",
         audit=audit_of(transfer={"role": "complete", "direction": "upload"}, params=["session_id"]))
register(id="complete-open", method="POST", route=ROOT_ + "openc/{session_id:uuid}/complete/", caller_scope="unrestricted",
         audit=audit_of(transfer={"role": "complete", "direction": "upload"}, params=["session_id"]))
register(id="complete-server", method="POST", route=ROOT_ + "srvc/{session_id:uuid}/complete/", server_only=True,
         audit=audit_of(transfer={"role": "complete", "direction": "upload"}, params=["session_id"]))


def early(row, role="chunk", direction="upload"):
    m = meta(row)
    must(m["transfer_role"] == role and m["transfer_direction"] == direction and m["transfer_session"] is None, m)
    must(corr(row) == "req-1" and "transfer:" not in corr(row), corr(row))
    must(SID not in json.dumps(row, default=str) or m.get("object") != SID, "no session in the row")
    return m


# permission, module permission, caller scope: a valid uuid in the path does not reach the row
refusal(lambda: run_as(poor, "remote-background", "upload-chunk", PS, binary=chunk(10)), 403, "tactical_permission_denied")
early(refusal_row())
refusal(lambda: run_as(no_module, "remote-background", "complete-module", PS), 403, "module_permission_denied")
early(refusal_row(), role="complete")
refusal(lambda: run_as(limited, "remote-background", "complete-open", PS), 403, "scope_unrestricted_required")
early(refusal_row(), role="complete")
# server_only over the HTTP route
view = views.TacticalOperationView()


class HttpCall(HttpRequest):
    def __init__(self, params, body=None):
        self.user, self.tec_tac_session = tech, SimpleNamespace(id="s")
        self.META = {"CONTENT_LENGTH": "12"}
        self.content_type = "application/json"
        self.tec_tac_request_id = "req-http"
        self.data = {"params": params, **({"body": body} if body is not None else {})}


del ROWS[:]
response = view.post(HttpCall(PS), "remote-background", "complete-server")
must(response.status_code == 403 and response.data["code"] == "operation_server_only", (response.status_code, response.data))
row = refusal_row()
must(meta(row)["transfer_session"] is None and meta(row)["transfer_role"] == "complete" and corr(row) == "req-http", (meta(row), corr(row)))
# a caller without permission who sends another user's session id cannot write a row under transfer:<that id>
for bad_user, op in ((poor, "upload-chunk"), (no_module, "complete-module"), (limited, "complete-open")):
    try:
        run_as(bad_user, "remote-background", op, PS, binary=chunk(10) if op == "upload-chunk" else None)
    except ops.TacticalOperationError:
        pass
    must(all(corr(r) != f"transfer:{SID}" and meta(r)["transfer_session"] is None for r in ROWS), (op, ROWS))
# an invalid correlation id: raised before the path is cleaned, so the row has no session either
refusal(lambda: run_as(tech, "remote-background", "upload-complete", PS, correlation_id="bad id with spaces"), 400, "invalid_correlation_id")
early(refusal_row(), role="complete")
# invalid_params: no session
refusal(lambda: run_as(tech, "remote-background", "upload-chunk", {"agent_id": AGENT, "session_id": "nope"}, binary=chunk(10)), 400, "invalid_params")
early(refusal_row())
# after the path is cleaned the session and the link are on every row: scope not_found, body_selector_mismatch, chunk refusal, Tactical 403
refusal(lambda: run_as(tech, "remote-background", "upload-chunk", {"agent_id": "z" * 21, "session_id": SID}, binary=chunk(10)), 404, "object_not_found")
row = refusal_row()
must(row["action"] == "deny" and meta(row)["transfer_session"] == SID and corr(row) == f"transfer:{SID}", (meta(row), corr(row)))
refusal(lambda: run_as(tech, "remote-background", "upload-cancel", PS, {"reason": "error"}), 400, "body_selector_mismatch")
row = refusal_row()
must(row["action"] == "deny" and meta(row)["transfer_session"] == SID and corr(row) == f"transfer:{SID}" and meta(row)["transfer_role"] == "cancel", (meta(row), corr(row)))
serve("upload-complete", FakeResponse(403, json.dumps({"detail": TACTICAL_TEXT}).encode()))
CACHE.data.clear()
result = run_as(tech, "remote-background", "upload-complete", PS)
row = refusal_row()
must(row["action"] == "deny" and meta(row)["transfer_session"] == SID and corr(row) == f"transfer:{SID}" and "transfer_stage" not in meta(row), (meta(row), corr(row)))
# a caller's own valid correlation id on an early deny row is kept (the link replaces it only after cleaning)
refusal(lambda: run_as(poor, "remote-background", "upload-chunk", PS, binary=chunk(10), correlation_id="caller-id"), 403, "tactical_permission_denied")
must(corr(refusal_row()) == "caller-id", ROWS)
print("       early deny rows (permission, module permission, caller scope, server_only, invalid correlation id, invalid_params) carry transfer_session null and no transfer id; rows after cleaning carry both")

# ============================================================ item 2: a transfer that fails at Tactical gets its end row
reset()
END_CASES = (("upload-complete", None, "complete"), ("upload-cancel", {"reason": "user"}, "cancel"), ("upload-fail", {"reason": "error"}, "fail"),
             ("download-complete", None, "complete"))


def end_run(op, body, status, payload=None, session=SID, fresh_cache=True):
    if fresh_cache:
        CACHE.data.clear()
    serve(op.replace("fail", "cancel"), FakeResponse(status, json.dumps(payload if payload is not None else {"detail": TACTICAL_TEXT}).encode()), session)
    return run_as(tech, "remote-background", op, {"agent_id": AGENT, "session_id": session}, body)


def must_be_failed_end(row, role, action, status, session=SID, reason=None):
    m = meta(row)
    must(row["action"] == action, (row["action"], action))
    must(m["transfer_stage"] == "end" and m["transfer_outcome"] == "failed" and m["transfer_role"] == role and m["transfer_session"] == session, m)
    must(corr(row) == f"transfer:{session}" and m["tactical_status"] == status, (corr(row), m))
    if reason:
        must(m["transfer_reason"] == reason, m)
    must(TACTICAL_TEXT not in rows_text() and SECRET_BYTES.decode() not in rows_text(), "no Tactical text, no bytes")
    return m


for op, body, role in END_CASES:
    for status in (400, 404, 409, 422):
        result = end_run(op, body, status)
        must(result.status == status and result.audit.get("recorded"), (op, status, result.audit))
        m = must_be_failed_end(refusal_row(), role, "custom:operation-failed", status, reason=(body or {}).get("reason"))
        must(m["failure"] == "tactical_refused" and "transfer_bytes" not in m, m)
        must(END_KEY.format(SID) in CACHE.data, "the once-only key is taken")
    for status in (500, 502):
        result = end_run(op, body, status)
        must_be_failed_end(refusal_row(), role, "custom:outcome-unknown", status, reason=(body or {}).get("reason"))
print("       complete, cancel and fail answered 400, 404, 409, 422 write custom:operation-failed with transfer_stage end and outcome failed; 500 and 502 write custom:outcome-unknown with the same end fields")

# transfer_bytes only from a whole-number committed_offset of a JSON answer
for value, kept in ((12, True), (0, True), (-1, False), (True, False), (1.5, False), ("7", False), (None, False)):
    end_run("upload-complete", None, 400, {"committed_offset": value, "detail": TACTICAL_TEXT})
    m = meta(refusal_row())
    must(("transfer_bytes" in m) is kept and (not kept or m["transfer_bytes"] == value), (value, m))
CACHE.data.clear()
serve("upload-complete", FakeResponse(400, b"plain text answer with committed_offset 5", "text/plain"))
run_as(tech, "remote-background", "upload-complete", PS)
m = meta(refusal_row())
must(m["transfer_outcome"] == "failed" and "transfer_bytes" not in m, m)
print("       transfer_bytes only from a whole-number committed_offset in a JSON answer")

# 401, 403, 408 and 429 write no end fields and take no key
for op, body, role in END_CASES:
    for status, expect in ((401, "deny"), (403, "deny"), (408, None), (429, "custom:operation-failed")):
        result = end_run(op, body, status)
        if expect is None:
            must(not ROWS and result.audit == {}, (op, status, ROWS))
        else:
            row = refusal_row()
            must(row["action"] == expect and "transfer_stage" not in meta(row) and "transfer_outcome" not in meta(row), (op, status, meta(row)))
            must(meta(row)["transfer_session"] == SID, meta(row))
        must(END_KEY.format(SID) not in CACHE.data, (op, status, "no key"))
print("       401 and 403 stay deny rows, 408 is relayed with no row and 429 is an ordinary failure row: none has end fields or takes the key")

# a repeat of the failing call writes a failure row without end fields; the key is added once
CACHE.data.clear()
end_run("upload-complete", None, 400, fresh_cache=False)
first = meta(refusal_row())
must(first["transfer_stage"] == "end", first)
end_run("upload-complete", None, 400, fresh_cache=False)
second = meta(refusal_row())
must("transfer_stage" not in second and "transfer_outcome" not in second and second["failure"] == "tactical_refused" and second["transfer_session"] == SID, second)
must([key for key in CACHE.data if key.startswith("tectac:transfer-end:")] == [END_KEY.format(SID)], CACHE.data)
# a failed end row followed by a cancel or a success writes no second end row (same once-only key, as ordered)
end_run("upload-cancel", {"reason": "user"}, 200, {"status": "cancelled"}, fresh_cache=False)
must(not ROWS, "a cancel after a failed end row writes no second end row")
end_run("upload-complete", None, 200, {"status": "completed"}, fresh_cache=False)
must(not ROWS, "a success after a failed end row writes no second end row")
# another session is independent
end_run("upload-complete", None, 400, session=SID2, fresh_cache=False)
must(meta(refusal_row())["transfer_session"] == SID2 and meta(ROWS[0])["transfer_stage"] == "end", ROWS)
print("       a repeat of the failing call writes its failure row without end fields (one key); a later success or cancel writes no second end row; another session is independent")

# the guard: cache raises, missing, and a failed audit write frees the key
CACHE.data.clear()
CACHE.mode = "raise"
for _ in range(2):
    end_run("upload-complete", None, 400, fresh_cache=False)
    must(meta(refusal_row())["transfer_stage"] == "end", "a cache that raises writes the end row")
CACHE.mode = "ok"
saved = sys.modules.pop("django.core.cache")
try:
    end_run("upload-complete", None, 500, fresh_cache=False)
    must(meta(refusal_row())["transfer_stage"] == "end", "no cache module writes the end row")
finally:
    sys.modules["django.core.cache"] = saved
for status, action in ((400, "custom:operation-failed"), (500, "custom:outcome-unknown")):
    CACHE.data.clear(), CACHE.deleted.clear()
    FakeAuditLog.objects.fail = True
    result = end_run("upload-complete", None, status, fresh_cache=False)
    must(not result.audit.get("recorded") and CACHE.deleted == [END_KEY.format(SID)] and END_KEY.format(SID) not in CACHE.data, (status, result.audit, CACHE.deleted))
    FakeAuditLog.objects.fail = False
    end_run("upload-complete", None, status, fresh_cache=False)
    row = refusal_row()
    must(row["action"] == action and meta(row)["transfer_stage"] == "end", "the retry can write the end row")
FakeAuditLog.objects.fail = True
CACHE.mode = "raise"
CACHE.data.clear()
end_run("upload-complete", None, 400, fresh_cache=False)  # neither the write nor the release works: must not raise
CACHE.mode = "ok"
FakeAuditLog.objects.fail = False
print("       the end-row guard fails open for a failed transfer, and the key is freed when the row write fails")

# chunk, ack and status answered 4xx are unchanged; a GET is not an end role; ordinary operations unchanged
CACHE.data.clear()
serve("upload-chunk", FakeResponse(400, json.dumps({"detail": TACTICAL_TEXT}).encode()))
run_as(tech, "remote-background", "upload-chunk", PS, binary=chunk(10))
m = meta(refusal_row())
must(m["transfer_role"] == "chunk" and "transfer_stage" not in m and "transfer_outcome" not in m, m)
serve("download-ack", FakeResponse(404, json.dumps({"detail": TACTICAL_TEXT}).encode()))
run_as(tech, "remote-background", "download-ack", PS)
must("transfer_stage" not in meta(refusal_row()), ROWS)
serve("download-status", FakeResponse(500, json.dumps({"detail": TACTICAL_TEXT}).encode()))
run_as(tech, "remote-background", "download-status", PS)
must(not ROWS, "a GET status writes nothing")
serve("download-chunk", FakeResponse(400, b"{}"))
run_as(tech, "remote-background", "download-chunk", PS)
must(not ROWS and not any(k.startswith("tectac:transfer-end:") for k in CACHE.data), "a GET download answered 4xx writes nothing and takes no key")
must("cannot be a GET" in refused(id="get-complete", method="GET", route=SESSION_ROOT + "end/", audit=audit_of(transfer={"role": "complete", "direction": "download"})), "a GET cannot be an end role")
register(id="plain-post", method="POST", route=ROOT_ + "plain-post/", body_fields=["a"], audit=audit_of(action="run"))
ROUTES[f"/agents/{AGENT}/files/plain-post/"] = (seeing(FakeResponse(400, b'{"detail": "x"}')), (), {})
run_as(tech, "remote-background", "plain-post", P, {"a": 1})
m = meta(refusal_row())
must(ROWS[0]["action"] == "custom:operation-failed" and "transfer_stage" not in m and "transfer_role" not in m, m)
ROUTES[f"/agents/{AGENT}/files/plain-post/"] = (seeing(FakeResponse(500, b'{"detail": "x"}')), (), {})
run_as(tech, "remote-background", "plain-post", P, {"a": 1})
m = meta(refusal_row())
must(ROWS[0]["action"] == "custom:outcome-unknown" and "transfer_stage" not in m, m)
# the successful paths are as in 1.18.33
CACHE.data.clear()
serve("upload-complete", json_view(200, {"status": "completed", "committed_offset": 30}))
run_as(tech, "remote-background", "upload-complete", PS)
m = meta(refusal_row())
must(ROWS[0]["action"] == "custom:file-transfer" and m["transfer_outcome"] == "completed" and m["transfer_bytes"] == 30, m)
print("       chunk, ack and status answered 4xx and ordinary operations are unchanged; a GET is not an end role; the 2xx end row is as before")

# ============================================================ metadata, docs, contract rows
cap = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.18.0" and cap["version"] == "1.18.0", cap["version"])
must(cap["refusal_row_codes"] == list(ops.CORE_REFUSAL_ROW_CODES) and len(cap["refusal_row_codes"]) == 6, cap["refusal_row_codes"])
must(cap["chunk_refusal_row_codes"] == list(ops.CHUNK_REFUSAL_ROW_CODES), cap["chunk_refusal_row_codes"])
must("refusal_codes_without_row_added_in_1_18_0" not in cap and "once per session and code" in cap["chunk_refusal_rows_added_in_1_18_0"], cap.keys())
must(any("read_binary_body(request, module_id, operation_id, *, params=None)" in item for item in cap["declaration_keys_added_in_1_18_0"]), cap["declaration_keys_added_in_1_18_0"])
text = " ".join(cap["behaviour_added_in_1_18_0"])
for needle in ("transfer_outcome failed", "transfer_session null", "caller_scope checks", "same once-only key"):
    must(needle in text, f"behaviour text lacks {needle!r}")
import inspect

sig = inspect.signature(ops.read_binary_body).parameters
must(list(sig) == ["request", "module_id", "operation_id", "params"] and sig["params"].kind is inspect.Parameter.KEYWORD_ONLY and sig["params"].default is None, list(sig))
root = HERE.parent
docs = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("1.18.34", "chunk_refusal_row_codes", "tectac:transfer-refusal", "transfer_outcome: failed", "transfer_session` null", "params=None", "429", "Once per session and code"):
    must(needle in docs, f"docs/tactical-operations.md lacks {needle!r}")
contract = (root / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
for needle in ("Changed in 1.18.34", "limited core_refused row", "transfer_outcome failed", "read_binary_body(request, module_id, operation_id, *, params=None)"):
    must(needle in contract, f"contracts.py lacks {needle!r}")
must("These refusals write no Core row" not in contract and "These refusals write no Core row" not in docs, "the old 'no row' sentence is gone")
src = (root / "framwork" / "tec_tac" / "tactical_operations.py").read_text(encoding="utf-8")
must("writes no row for these refusals" not in src and "A refusal here writes no Core row" not in src, "the old docstrings are updated")
must("which no module declares" not in src and "Remote Background 0.11.4 declares them and calls" in src, "the module docstring says Remote Background calls read_binary_body")
notes = (root / "RELEASE_NOTES_1.18.34.md").read_text(encoding="utf-8")
must("does not call `read_binary_body`" not in notes and "calls `read_binary_body` without `params`" in notes and "tactical_permission_denied" in notes, "release notes state that Remote Background calls read_binary_body")
print("       metadata lists chunk_refusal_row_codes and the six AD-19 codes; capability stays 1.18.0; docs and contracts.py carry the 1.18.34 text")

print("[TEST] PASS tactical operation file transfer audit 1.18.34")
