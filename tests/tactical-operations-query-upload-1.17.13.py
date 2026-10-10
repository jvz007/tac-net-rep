#!/usr/bin/env python3
"""1.17.13 regression: a query string for GET operations and a multipart upload (Johan, 9 October 2026; Report Manager 0.5.0
asset download and upload).

Builds on the stubs of tests/tactical-operations-1.17.7.py. The real tactical_operations.py and tactical_operation_views.py
run against them. Tactical's own MultiPartParser and DRF's query_params are proven on the dev server by
tests/tactical-operations-runtime-1.17.13.py.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, views, declare, fresh, must = (G[k] for k in ("ops", "views", "declare", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, tech, User, Roleish, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "tech", "User", "Roleish", "Request"))
FakeResponse, refusal = G["FakeResponse"], G["refusal"]


class QueryDict(dict):
    def __init__(self, qs=""):
        super().__init__({key: values[0] for key, values in parse_qs(qs, keep_blank_values=True).items()})
        self.qs = qs


sys.modules["django.http"].QueryDict = QueryDict

fresh()
DOWNLOAD = dict(id="asset-download", module_id="reportmanager", method="GET", route="reporting/assets/download/", permissions=["can_manage_clients"], scope=[],
                body_fields=[], audit={"action": "export", "object_type": "report_asset", "audit_fields": ["path"]}, query_params=["path"])
UPLOAD = dict(id="asset-upload", module_id="reportmanager", method="POST", route="reporting/assets/upload/", permissions=["can_manage_clients"], scope=[],
              body_fields=["parentPath"], audit={"action": "add", "object_type": "report_asset", "audit_fields": ["parentPath"]},
              upload={"field": "file", "max_bytes": 1000, "extensions": ["png", "jpg", "svg"]})


def register(spec, **over):
    return ops.register_tactical_operation(**{**spec, **over})


def refused(spec, **over):
    try:
        register(spec, **over)
    except ops.TacticalOperationRegistrationError as exc:
        must(isinstance(exc, ValueError), "a registration refusal is a ValueError")
        return str(exc)
    raise AssertionError(f"registration was accepted: {over}")


# ------------------------------------------------------------------------------------------------ registration
refused(DOWNLOAD, id="x1", query_params=["bad name"])
refused(DOWNLOAD, id="x2", query_params=["path", "path"])
refused(DOWNLOAD, id="x3", query_params="path")
refused(DOWNLOAD, id="x4", query_params=[f"q{i}" for i in range(17)])
for secretive in ("token", "api_key", "password", "secret", "cookie"):
    refused(DOWNLOAD, id="x5", query_params=[secretive])
refused(UPLOAD, id="x6", query_params=["path"])  # a POST takes no query_params
refused(DOWNLOAD, id="x7", audit={"action": "export", "object_type": "report_asset", "audit_fields": ["nope"]})  # neither a body field nor a query name
for bad in ({"field": "params", "max_bytes": 10, "extensions": ["png"]}, {"field": "body", "max_bytes": 10, "extensions": ["png"]},
            {"field": "query", "max_bytes": 10, "extensions": ["png"]}, {"field": "parentPath", "max_bytes": 10, "extensions": ["png"]},  # a body field name
            {"field": "bad field", "max_bytes": 10, "extensions": ["png"]}, {"field": "file", "max_bytes": 0, "extensions": ["png"]},
            {"field": "file", "max_bytes": -1, "extensions": ["png"]}, {"field": "file", "max_bytes": True, "extensions": ["png"]},
            {"field": "file", "max_bytes": 1.5, "extensions": ["png"]}, {"field": "file", "max_bytes": ops.MAX_UPLOAD_ABSOLUTE_BYTES + 1, "extensions": ["png"]},  # 1.17.14: the fixed absolute ceiling is 25 MiB
            {"field": "file", "max_bytes": 10, "extensions": []}, {"field": "file", "max_bytes": 10, "extensions": [".png"]},
            {"field": "file", "max_bytes": 10, "extensions": ["PNG"]}, {"field": "file", "max_bytes": 10, "extensions": "png"},
            {"field": "file", "max_bytes": 10, "extensions": [f"e{i}" for i in range(17)]}, {"field": "file", "max_bytes": 10},
            {"field": "file", "max_bytes": 10, "extensions": ["png"], "extra": 1}, "png", ["png"]):
    refused(UPLOAD, id="x8", upload=bad)
must(ops.MAX_UPLOAD_BYTES == 10 * 2**20, "10 MiB stays the default ceiling and the exported constant (CQ40, 1.17.14: now a system setting)")
must(ops.MAX_UPLOAD_ABSOLUTE_BYTES == 25 * 2**20, "the absolute ceiling an operation may declare")
register(UPLOAD, id="ok-ceiling", route="reporting/assets/other/", upload={"field": "file", "max_bytes": ops.MAX_UPLOAD_BYTES, "extensions": ["png"]})
refused(DOWNLOAD, id="x9", method="DELETE", upload=UPLOAD["upload"], route="reporting/assets/x/", query_params=[])  # not for a DELETE
refused({**DOWNLOAD, "upload": UPLOAD["upload"]}, id="x10")  # not for a GET
download = register(DOWNLOAD)
upload = register(UPLOAD)
must(download.query_params == ("path",) and upload.upload.field == "file" and upload.upload.max_bytes == 1000, (download, upload))
must(register(DOWNLOAD) is download and register(UPLOAD) is upload, "idempotent")
d = ops.get_operation("reportmanager", "asset-upload")
must(d["upload"] == {"field": "file", "max_bytes": 1000, "extensions": ["png", "jpg", "svg"]} and ops.get_operation("reportmanager", "asset-download")["query_params"] == ["path"], d)
json.dumps(ops.list_operations())
old = declare()
must(old.query_params == () and old.upload is None, "an operation declared the 1.17.12 way has neither")

# ------------------------------------------------------------------------------------------------ the query string
SEEN = []


def seeing(response=None):
    def view(request, *args, **kwargs):
        SEEN.append(request)
        CALLS.append(SimpleNamespace(request=request, method=request.method))
        return response if response is not None else FakeResponse(200, b"PNGDATA", content_type="image/png", headers={"Content-Disposition": "attachment"})
    return view


ROUTES["/reporting/assets/download/"] = (seeing(), (), {})
ROUTES["/reporting/assets/upload/"] = (seeing(FakeResponse(200, b'"uploaded"')), (), {})
manager = User("mgr", Roleish("can_manage_clients"))
manager.sees = {"agents": set(), "clients": {1}, "sites": {10}}


def run(operation, params=None, body=None, query=None, upload=None, user=manager, module="reportmanager"):
    del CALLS[:], SEEN[:]
    return ops.run_tactical_operation(Request(user), module, operation, params, body, query=query, upload=upload)


del ROWS[:]
result = run("asset-download", query={"path": "logos/a b.png"})
must(result.status == 200 and result.content == b"PNGDATA" and result.content_type == "image/png", result)
request = SEEN[0]
must(request.method == "GET" and request._body == b"" and request.META["QUERY_STRING"] == "path=logos%2Fa%20b.png", request.META)
must(isinstance(request.GET, QueryDict) and request.GET["path"] == "logos/a b.png", "clone.GET is a QueryDict that DRF's query_params reads")
must(request.META["CONTENT_LENGTH"] == "0" and request.META["CONTENT_TYPE"] == "", request.META)
must(ROWS[0]["action"] == "export" and ROWS[0]["after_value"] == {"path": "logos/a b.png"}, ROWS[0])  # audit_fields may name a query name
must(result.headers == {"Content-Type": "image/png", "Content-Disposition": "attachment"}, result.headers)
# a whole number is allowed; no query at all is allowed
register(DOWNLOAD, id="asset-list", route="reporting/assets/list/", query_params=["path", "page"], audit={"action": "view", "object_type": "report_asset"})
ROUTES["/reporting/assets/list/"] = (seeing(), (), {})
run("asset-list", query={"page": 3, "path": "x"})
must(SEEN[0].META["QUERY_STRING"] == "path=x&page=3", SEEN[0].META)  # declared order
run("asset-list")
must(SEEN[0].META["QUERY_STRING"] == "" and not getattr(SEEN[0], "GET", None), "no query: no QueryDict is set")
# a value that would change the path or the request line is refused
for bad in ("../etc/passwd", "a/../b", "..", "a\\..\\b", "%2e%2e", "%2E%2E/x", "x/%2e%2e/y", "a\nb", "a\x00b", "a\rb", "\x7f", "", "   ", "x" * 513):
    refusal(lambda: run("asset-download", query={"path": bad}), 400, "invalid_query")
for bad in ({"path": None}, {"path": True}, {"path": 1.5}, {"path": ["a"]}, {"path": {"a": 1}}):
    refusal(lambda: run("asset-download", query=bad), 400, "invalid_query")
refusal(lambda: run("asset-download", query="path=a"), 400, "invalid_query")
refusal(lambda: run("asset-download", query=["path"]), 400, "invalid_query")
must(run("asset-download", query={"path": "ab..cd.png"}).status == 200, "two dots inside a name are not a '..' segment")
must(run("asset-download", query={"path": "x" * 512}).status == 200, "512 characters are allowed")
# a name outside the whitelist
refusal(lambda: run("asset-download", query={"path": "a", "other": "b"}), 400, "query_field_not_allowed")
refusal(lambda: run("asset-download", query={"other": "b"}), 400, "query_field_not_allowed")
refusal(lambda: ops.run_tactical_operation(Request(tech), "agents", "reboot", {"agent_id": AGENT}, {"mode": "x"}, query={"mode": "x"}), 400, "query_field_not_allowed")  # an operation with no query_params
must(not CALLS, "a refused query never reaches Tactical")
# the message never echoes a long or hostile name
try:
    run("asset-download", query={"x" * 5000: "1"})
except ops.TacticalOperationError as exc:
    must(len(exc.message) < 200 and "\x00" not in exc.message, exc.message)
# a refusal is audited like any other: a missing flag writes a deny row, no query is reached
weak = User("weak", Roleish("can_send_wol"))
weak.sees = manager.sees
del ROWS[:]
refusal(lambda: run("asset-download", query={"path": "a"}, user=weak), 403, "tactical_permission_denied")
must(ROWS[0]["action"] == "deny" and not CALLS, ROWS)

# ------------------------------------------------------------------------------------------------ upload
PNG = b"\x89PNG\r\n\x1a\nSECRETBYTES" + bytes(range(256))
good = {"name": "logo.png", "content_type": "image/png", "content": PNG}
del ROWS[:]
result = run("asset-upload", body={"parentPath": "/logos"}, upload=good)
must(result.status == 200 and result.data == "uploaded", result)
request = SEEN[0]
header = request.META["CONTENT_TYPE"]
must(header.startswith("multipart/form-data; boundary=TecTacBoundary") and request.content_type == "multipart/form-data", header)
boundary = header.split("boundary=")[1]
must(request.content_params == {"boundary": boundary} and request.META["CONTENT_LENGTH"] == str(len(request._body)), request.content_params)
payload = request._body
must(payload.endswith(f"--{boundary}--\r\n".encode()), "the payload is closed")
parts = [p for p in payload.split(f"--{boundary}".encode())[1:-1]]
must(len(parts) == 2, len(parts))
text_part, file_part = parts
must(b'Content-Disposition: form-data; name="parentPath"\r\n\r\n/logos\r\n' in text_part, text_part)
must(b'Content-Disposition: form-data; name="file"; filename="logo.png"\r\nContent-Type: image/png\r\n\r\n' + PNG + b"\r\n" in file_part, "the file part carries the bytes")
must(request._stream.read() == payload, "the stream the parser reads is the payload")
must(request.method == "POST" and request.META["QUERY_STRING"] == "" and "HTTP_AUTHORIZATION" not in request.META, request.META)
# the audit row records name, size and type only
row = ROWS[0]
must(row["action"] == "add" and row["after_value"] == {"parentPath": "/logos", "upload": {"file_name": "logo.png", "size": len(PNG), "content_type": "image/png"}}, row["after_value"])
must("SECRETBYTES" not in json.dumps(row, default=str) and "PNG" not in json.dumps(row["after_value"]).replace("image/png", "").replace("logo.png", ""), "no file content in the row")
# text parts carry non-strings as JSON, and a body is optional
run("asset-upload", upload=good)
must(b"name=\"parentPath\"" not in SEEN[0]._body, "no body, no text part")
register(UPLOAD, id="asset-upload2", route="reporting/assets/upload2/", body_fields=["parentPath", "flags"], audit={"action": "add", "object_type": "report_asset", "audit_fields": []})
ROUTES["/reporting/assets/upload2/"] = (seeing(FakeResponse(200, b'"ok"')), (), {})
run("asset-upload2", body={"parentPath": "a", "flags": {"x": [1, True]}}, upload=good)
must(b'\r\n\r\n{"x":[1,true]}\r\n' in SEEN[0]._body, SEEN[0]._body)
# the file name: no path, no control characters, at most 255 characters, an allowed extension
run("asset-upload", upload={**good, "name": "dir/sub\\evil.png"})
must(b'filename="evil.png"' in SEEN[0]._body and b"dir" not in SEEN[0]._body, SEEN[0]._body)
run("asset-upload", upload={**good, "name": 'a"b.png'})
must(b'filename="a_b.png"' in SEEN[0]._body, SEEN[0]._body)
run("asset-upload", upload={**good, "name": "LOGO.PNG"})  # extension matching ignores case
run("asset-upload", upload={**good, "name": "x" * 251 + ".png"})
for name in ("a\nb.png", "a\x00.png", "a\r.png", "x" * 252 + ".png", "", "   ", ".", "..", "dir/", "../", None, 5):
    refusal(lambda: run("asset-upload", upload={**good, "name": name}), 400, "invalid_upload")
for name in ("a.exe", "a.png.exe", "noextension", "a.", ".png.", "a.svgz", "a.html"):
    refusal(lambda: run("asset-upload", upload={**good, "name": name}), 400, "upload_type_not_allowed")
# a content type that is not a media type is replaced, never forwarded
run("asset-upload", upload={**good, "content_type": "image/png\r\nX-Evil: 1"})
must(b"Content-Type: image/png\r\nX-Evil" not in SEEN[0]._body, "no header injection")
run("asset-upload", upload={**good, "content_type": "garbage"})
must(b"Content-Type: application/octet-stream" in SEEN[0]._body, SEEN[0]._body)
# Tactical's report asset upload stores each file under the name of its multipart part, so Report Manager declares the part as the file name
register(UPLOAD, id="asset-upload-named", route="reporting/assets/uploadnamed/", upload={"field": ops.FILE_NAME_FIELD, "max_bytes": 1000, "extensions": ["png"]})
ROUTES["/reporting/assets/uploadnamed/"] = (seeing(FakeResponse(200, b'"ok"')), (), {})
must(ops.get_operation("reportmanager", "asset-upload-named")["upload"]["field"] == "{file_name}", "described")
run("asset-upload-named", body={"parentPath": "/logos"}, upload={**good, "name": "dir/logo.png"})
must(b'Content-Disposition: form-data; name="logo.png"; filename="logo.png"\r\n' in SEEN[0]._body and b'name="file"' not in SEEN[0]._body, SEEN[0]._body)
run("asset-upload-named", upload={**good, "name": "x.png", "field": "whatever"})  # the part key the browser chose does not matter
must(b'name="x.png"; filename="x.png"' in SEEN[0]._body, SEEN[0]._body)
refusal(lambda: run("asset-upload-named", upload={**good, "name": "a.exe"}), 400, "upload_type_not_allowed")
must(ROWS[-1]["after_value"] is not None and ROWS[-1]["after_value"]["upload"]["file_name"] == "x.png", ROWS[-1])
refused(UPLOAD, id="x11", upload={"field": "{other}", "max_bytes": 10, "extensions": ["png"]})
# size
must(run("asset-upload", upload={**good, "content": b"x" * 1000}).status == 200, "exactly the cap passes")
refusal(lambda: run("asset-upload", upload={**good, "content": b"x" * 1001}), 413, "upload_too_large")
must(not CALLS, "an oversize file never reaches Tactical")
register(UPLOAD, id="big", route="reporting/assets/big/", upload={"field": "file", "max_bytes": ops.MAX_UPLOAD_BYTES, "extensions": ["png"]})
refusal(lambda: run("big", upload={**good, "content": b"x" * (ops.MAX_UPLOAD_BYTES + 1)}), 413, "upload_too_large")
# shape: one file, the declared part, bytes
refusal(lambda: run("asset-upload", body={"parentPath": "/"}), 400, "invalid_upload")  # the operation needs its file
refusal(lambda: run("asset-upload", upload={**good, "field": "other"}), 400, "upload_not_allowed")
refusal(lambda: run("asset-upload", upload="logo.png"), 400, "invalid_upload")
refusal(lambda: run("asset-upload", upload={**good, "content": "text"}), 400, "invalid_upload")
refusal(lambda: run("asset-upload", upload={**good, "content": None}), 400, "invalid_upload")
refusal(lambda: run("asset-download", query={"path": "a"}, upload=good), 400, "upload_not_allowed")  # an operation that declares no file
refusal(lambda: ops.run_tactical_operation(Request(tech), "agents", "reboot", {"agent_id": AGENT}, {"mode": "x"}, upload=good), 400, "upload_not_allowed")
refusal(lambda: run("asset-upload", body={"parentPath": "/", "other": 1}, upload=good), 400, "body_field_not_allowed")
# audit rows for a failed upload: Tactical's 5xx gives the unknown-outcome row, and no content either
ROUTES["/reporting/assets/upload/"] = (seeing(FakeResponse(500, b'"boom"')), (), {})
del ROWS[:]
run("asset-upload", body={"parentPath": "/x"}, upload=good)
must(ROWS[0]["action"] == "custom:outcome-unknown" and "SECRETBYTES" not in json.dumps(ROWS, default=str), ROWS)
ROUTES["/reporting/assets/upload/"] = (seeing(FakeResponse(403, b'"no"')), (), {})
del ROWS[:]
run("asset-upload", body={"parentPath": "/x"}, upload=good)
must(ROWS[0]["action"] == "deny" and ROWS[0]["debug_info"]["metadata"]["reason"] == "tactical_denied", ROWS)
ROUTES["/reporting/assets/upload/"] = (seeing(FakeResponse(200, b'"uploaded"')), (), {})

# ------------------------------------------------------------------------------------------------ the HTTP view
view = views.TacticalOperationView()


class Files(dict):
    def getlist(self, name):
        return [self[name]] if name in self else []


class DRFRequest(G["HttpRequest"]):  # 1.17.16: a request the operation runner accepts, with Core's session proof
    def __init__(self, data, *, files=None, content_type="application/json", length=0, user=manager):
        self.tec_tac_session = SimpleNamespace(id="session-1")
        self.FILES = Files(files or {})
        # DRF 3.15.2 Request._load_data_and_files: _full_data = _data.copy(); _full_data.update(_files), so a multipart
        # request.data carries the file keys too. A JSON body has no files and stays as parsed.
        self.data = {**data, **self.FILES} if isinstance(data, dict) and files else data
        self.content_type, self.user = content_type, user
        self.META = {"CONTENT_LENGTH": str(length), "HTTP_AUTHORIZATION": "Token SECRET-KNOX", "REMOTE_ADDR": "10.0.0.9"}
        self.tec_tac_request_id = "req-1"


class Upload:
    def __init__(self, content, name="logo.png", content_type="image/png"):
        self.content, self.name, self.content_type, self.size, self.reads = content, name, content_type, len(content), 0

    def read(self):
        self.reads += 1
        return self.content


def post(request, module="reportmanager", operation="asset-upload"):
    del CALLS[:], SEEN[:]
    return view.post(request, module, operation)


# JSON form: query is accepted; the others are as before
response = post(DRFRequest({"query": {"path": "a.png"}}), operation="asset-download")
must(response.status_code == 200 and response.content == b"PNGDATA" and SEEN[0].META["QUERY_STRING"] == "path=a.png", (response.status_code, SEEN))
response = post(DRFRequest({"query": {"nope": "a"}}), operation="asset-download")
must(response.status_code == 400 and response.data["code"] == "query_field_not_allowed", response.data)
response = post(DRFRequest({"other": 1}), operation="asset-download")
must(response.status_code == 400 and response.data["code"] == "invalid_operation_request", response.data)
response = post(DRFRequest(["list"]), operation="asset-download")
must(response.status_code == 400, response.data)
# multipart form
data = {"params": "{}", "body": '{"parentPath": "/logos"}', "query": ""}
file = Upload(PNG)
response = post(DRFRequest(data, files={"file": file}, content_type="multipart/form-data; boundary=x", length=len(PNG) + 200))
must(response.status_code == 200 and b"parentPath" in SEEN[0]._body and PNG in SEEN[0]._body and file.reads == 1, (response.status_code, getattr(response, "data", None)))
must(response.headers.get("X-Tec-Tac-Audit") == "recorded", response.headers)
must("file" in DRFRequest(data, files={"file": Upload(PNG)}).data, "the stub mirrors DRF: request.data carries the file key")
# the size is checked before the file is read, against the operation's own cap
big = Upload(b"x" * 1001)
response = post(DRFRequest(data, files={"file": big}, content_type="multipart/form-data; boundary=x", length=1300))
must(response.status_code == 413 and response.data["code"] == "upload_too_large" and big.reads == 0 and not CALLS, (response.status_code, big.reads))
huge = Upload(b"x")
response = post(DRFRequest(data, files={"file": huge}, content_type="multipart/form-data; boundary=x", length=ops.MAX_UPLOAD_BYTES * 2))
must(response.status_code == 413 and huge.reads == 0, "an oversize declared length is refused before the content is looked at")
# a bad form
for form, files, code in (
    ({"params": "{}", "other": "{}"}, {"file": Upload(PNG)}, "invalid_operation_request"),
    ({"params": "not json"}, {"file": Upload(PNG)}, "invalid_operation_request"),
    ({"body": "[1]"}, {"file": Upload(PNG)}, "invalid_operation_request"),
    ({"body": "{}"}, {}, "invalid_upload"),
    ({"body": "{}"}, {"file": Upload(PNG), "second": Upload(PNG)}, "invalid_upload"),
    ({"body": "{}"}, {"wrongname": Upload(PNG)}, "upload_not_allowed"),
):
    response = post(DRFRequest(form, files=files, content_type="multipart/form-data; boundary=x", length=100))
    must(response.status_code == 400 and response.data["code"] == code and not CALLS, (form, response.data))
# a file sent to an operation that takes none
response = post(DRFRequest({"params": "{}"}, files={"file": Upload(PNG)}, content_type="multipart/form-data; boundary=x", length=300), operation="asset-download")
must(response.status_code == 400 and response.data["code"] == "upload_not_allowed" and not CALLS, response.data)
# the route still sits behind SessionAuthenticated with the same throttles, and accepts only JSON and multipart
view_source = (G["APP"] / "tactical_operation_views.py").read_text(encoding="utf-8")
must('_ALLOWED_FIELDS = {"params", "body", "query"}' in view_source and "SessionAuthenticated" in view_source and "TacticalOperationMinThrottle" in view_source, "view")
must("parser_classes = (JSONParser, MultiPartParser)" in view_source and "FormParser" not in view_source, "parsers")
src = (G["APP"] / "tactical_operations.py").read_text(encoding="utf-8")
must("from django.test" not in src and "import django.test" not in src and "urllib" not in src and "MultiPartEncoder" not in src and "def _encode_multipart" in src, "own encoder, no django.test")
must(re.search(r"secrets\.token_hex", src), "a random boundary")

print("[TEST] PASS tactical operations query and upload 1.17.13")
