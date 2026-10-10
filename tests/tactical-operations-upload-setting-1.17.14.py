#!/usr/bin/env python3
"""1.17.14 regression: the Tactical operation upload ceiling is a system setting (Johan CQ40, 9 October 2026). Executor and view.

``tactical_operation_upload_max_mib`` (whole MiB, 1 to 25, default 10) replaces the fixed 10 MiB ceiling. The executor
(``_clean_upload``) and the HTTP view use the smaller of the operation's declared ``max_bytes`` and the setting, read on every call, so
lowering the setting takes effect at once. Registration, which runs in AppConfig.ready() and must not read the database, checks a
fixed absolute ceiling of 25 MiB. ``MAX_UPLOAD_BYTES`` stays exported as the 10 MiB default.

The harness is tests/tactical-operations-query-upload-1.17.13.py, executed up to its final line (so those checks run too, and its
stubs, operations and view are reused). The setting is read through a stub ``tec_tac.runtime_settings`` that this test controls. The
validator, the getter and the PATCH permission split are in tests/runtime-settings-upload-1.17.14.py.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-query-upload-1.17.13.py"
source = BASE.read_text(encoding="utf-8")
source = source[:source.index('print("[TEST] PASS tactical operations query and upload 1.17.13")')]
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source, str(BASE), "exec"), G)
ops, fresh, must, register, refused, refusal = (G[k] for k in ("ops", "fresh", "must", "register", "refused", "refusal"))
UPLOAD, run, post, DRFRequest, Upload, CALLS, good = (G[k] for k in ("UPLOAD", "run", "post", "DRFRequest", "Upload", "CALLS", "good"))
MIB = 2**20

# The setting, as the executor reads it. A real read is the database; here the test sets it, or makes the read fail.
SETTING = {"mib": 10, "boom": False}


def get_tactical_upload_max_bytes():
    if SETTING["boom"]:
        raise RuntimeError("database is down")
    return SETTING["mib"] * MIB


stub = types.ModuleType("tec_tac.runtime_settings")
stub.get_tactical_upload_max_bytes = get_tactical_upload_max_bytes
sys.modules["tec_tac.runtime_settings"] = stub

# ------------------------------------------------------------------------------------------------ the constants
must(ops.MAX_UPLOAD_BYTES == 10 * MIB and ops.MAX_UPLOAD_ABSOLUTE_BYTES == 25 * MIB, "default 10 MiB, absolute 25 MiB")
must(ops.upload_ceiling_bytes() == 10 * MIB, "the default")
SETTING["mib"] = 15
must(ops.upload_ceiling_bytes() == 15 * MIB, "the setting")
SETTING["mib"] = 10

# ------------------------------------------------------------------------------------------------ registration: the absolute ceiling
big_spec = {"field": "file", "max_bytes": 25 * MIB, "extensions": ["png"]}
register(UPLOAD, id="max-ok", route="reporting/assets/max/", upload=big_spec)
must(ops.get_operation("reportmanager", "max-ok")["upload"]["max_bytes"] == 25 * MIB, "25 MiB registers")
for bad in (25 * MIB + 1, 26 * MIB, 10**12, 0, -5, True, 1.5, "100"):
    message = refused(UPLOAD, id="max-bad", route="reporting/assets/maxbad/", upload={"field": "file", "max_bytes": bad, "extensions": ["png"]})
    must("1 to 26214400" in message, message)
SETTING["boom"] = True
register(UPLOAD, id="no-db-at-registration", route="reporting/assets/nodb/", upload={"field": "file", "max_bytes": 20 * MIB, "extensions": ["png"]})
SETTING["boom"] = False

# ------------------------------------------------------------------------------------------------ the executor
register(UPLOAD, id="huge", route="reporting/assets/huge/", upload=big_spec)
G["ROUTES"]["/reporting/assets/huge/"] = G["ROUTES"]["/reporting/assets/upload/"]
eleven = {**good, "content": b"x" * (11 * MIB)}
ten = {**good, "content": b"x" * (10 * MIB)}
refusal(lambda: run("huge", upload=eleven), 413, "upload_too_large")  # the default stops 11 MiB
must(not CALLS, "an oversize file never reaches Tactical")
must(run("huge", upload=ten).status == 200, "exactly the default passes")
SETTING["mib"] = 15
must(run("huge", upload=eleven).status == 200, "accepted when the setting is 15")
refusal(lambda: run("huge", upload={**good, "content": b"x" * (15 * MIB + 1)}), 413, "upload_too_large")
SETTING["mib"] = 25
must(run("huge", upload={**good, "content": b"x" * (25 * MIB)}).status == 200, "25 MiB passes at the maximum")
refusal(lambda: run("huge", upload={**good, "content": b"x" * (25 * MIB + 1)}), 413, "upload_too_large")
# lowering the setting takes effect at once
SETTING["mib"] = 1
refusal(lambda: run("huge", upload={**good, "content": b"x" * (2 * MIB)}), 413, "upload_too_large")
must(run("huge", upload={**good, "content": b"x" * MIB}).status == 200, "1 MiB")
# an operation's own lower cap still wins
SETTING["mib"] = 25
must(run("asset-upload", upload={**good, "content": b"x" * 1000}).status == 200, "the operation cap of 1000 bytes: exactly the cap passes")
refusal(lambda: run("asset-upload", upload={**good, "content": b"x" * 1001}), 413, "upload_too_large")
register(UPLOAD, id="two", route="reporting/assets/two/", upload={"field": "file", "max_bytes": 2 * MIB, "extensions": ["png"]})
G["ROUTES"]["/reporting/assets/two/"] = G["ROUTES"]["/reporting/assets/upload/"]
refusal(lambda: run("two", upload={**good, "content": b"x" * (2 * MIB + 1)}), 413, "upload_too_large")
must(run("two", upload={**good, "content": b"x" * (2 * MIB)}).status == 200, "a 2 MiB cap with a 25 MiB setting")
# a setting that cannot be read falls back to the default, never to something looser
SETTING["mib"], SETTING["boom"] = 25, True
must(ops.upload_ceiling_bytes() == 10 * MIB, "a failing read gives 10 MiB")
refusal(lambda: run("huge", upload=eleven), 413, "upload_too_large")
SETTING["boom"] = False
for odd in (0, -1, 26, 10**6):
    SETTING["mib"] = odd
    must(ops.upload_ceiling_bytes() == 10 * MIB, f"a value of {odd} MiB from a bad row reads as the default")
SETTING["mib"] = 10
# a missing runtime_settings (no Django in this process) also gives the default
saved = sys.modules.pop("tec_tac.runtime_settings")
sys.modules["tec_tac.runtime_settings"] = None  # makes the import raise ImportError
must(ops.upload_ceiling_bytes() == 10 * MIB, "an import failure gives the default")
sys.modules["tec_tac.runtime_settings"] = saved

# ------------------------------------------------------------------------------------------------ the HTTP view
data = {"params": "{}", "body": '{"parentPath": "/logos"}', "query": ""}
SETTING["mib"] = 10
huge = Upload(b"x")
response = post(DRFRequest(data, files={"file": huge}, content_type="multipart/form-data; boundary=x", length=10 * MIB + 256 * 1024 + 1), operation="huge")
must(response.status_code == 413 and response.data["code"] == "upload_too_large" and huge.reads == 0, "the declared length follows the default")
SETTING["mib"] = 20
declared = 15 * MIB
small = Upload(b"x" * 100)
response = post(DRFRequest(data, files={"file": small}, content_type="multipart/form-data; boundary=x", length=declared), operation="huge")
must(response.status_code == 200 and small.reads == 1, (response.status_code, getattr(response, "data", None)))
response = post(DRFRequest(data, files={"file": Upload(b"x")}, content_type="multipart/form-data; boundary=x", length=20 * MIB + 256 * 1024 + 1), operation="huge")
must(response.status_code == 413, "the declared length follows the setting")
# the file's own size is checked against min(the operation's cap, the setting) before it is read
SETTING["mib"] = 12
over = Upload(b"x" * (13 * MIB))
response = post(DRFRequest(data, files={"file": over}, content_type="multipart/form-data; boundary=x", length=12 * MIB + 300), operation="huge")
must(response.status_code == 413 and over.reads == 0 and "12582912" in response.data["detail"], (response.status_code, response.data))
fits = Upload(b"x" * (12 * MIB))
response = post(DRFRequest(data, files={"file": fits}, content_type="multipart/form-data; boundary=x", length=12 * MIB + 300), operation="huge")
must(response.status_code == 200 and fits.reads == 1, response.status_code)
SETTING["mib"] = 25
over_op = Upload(b"x" * (3 * MIB))
response = post(DRFRequest(data, files={"file": over_op}, content_type="multipart/form-data; boundary=x", length=3 * MIB + 300), operation="two")
must(response.status_code == 413 and over_op.reads == 0, "the operation's own cap of 2 MiB wins over a 25 MiB setting")

# ------------------------------------------------------------------------------------------------ the capability and the text
meta = ops.tactical_operations_contract_metadata()
SETTING["mib"] = 15
meta = ops.tactical_operations_contract_metadata()
must(meta["limits"]["upload_bytes"] == 15 * MIB and meta["limits"]["upload_bytes_default"] == 10 * MIB and meta["limits"]["upload_bytes_max"] == 25 * MIB, meta["limits"])
SETTING["mib"] = 10
APP = Path(__file__).resolve().parents[1] / "framwork" / "tec_tac"
views_source = (APP / "tactical_operation_views.py").read_text(encoding="utf-8")
must("upload_ceiling_bytes" in views_source and "MAX_UPLOAD_BYTES" not in views_source, "the view reads the setting, not the constant")
ops_source = (APP / "tactical_operations.py").read_text(encoding="utf-8")
must("min(spec.max_bytes, upload_ceiling_bytes())" in ops_source and "min(spec.max_bytes, MAX_UPLOAD_BYTES)" not in ops_source, "the executor reads the setting")
docs = (Path(__file__).resolve().parents[1] / "docs/tactical-operations.md").read_text(encoding="utf-8")
must("tactical_operation_upload_max_mib" in docs and "body-size limit" in docs, "the docs name the setting and the web server body limit")

print("[TEST] PASS tactical operations upload setting 1.17.14")
