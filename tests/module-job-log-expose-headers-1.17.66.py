#!/usr/bin/env python3
"""1.17.66 regression (UI 0.12.118 request): the module job log route exposes its four headers to a browser on another origin.

The real ModuleV2JobLogView on the stub harness of the 1.17.58 licensing tests (Django is not installed on this PC), with a tempdir of stub job
folders. Covered: a 200 carries Access-Control-Expose-Headers naming exactly X-Tec-Tac-Log-Truncated, X-Tec-Tac-Log-Bytes, X-Tec-Tac-Log-Kept and
Content-Disposition, inline and as a download; the three X-Tec-Tac-Log headers, nosniff, no-store and Content-Disposition (download only) are as
in 1.17.60; a 404, a 400 and a refused caller carry no such header; no other route of Core sets the header; the contract row says so.
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT / "framwork" / "tec_tac"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "framwork"))

from tec_tac import module_job_logs as m  # noqa: E402


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


TMP = Path(tempfile.mkdtemp(prefix="tectac-joblog-expose-"))
m.JOBS_ROOT, m.LOGS_ROOT = TMP / "jobs", TMP / "logs"
m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT = TMP / "hf" / "jobs", TMP / "hf" / "logs"
for folder in (m.JOBS_ROOT, m.LOGS_ROOT, m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT):
    folder.mkdir(parents=True)
COUNTER = [0]


def make_job(text=None, **record):
    COUNTER[0] += 1
    job_id = f"00000000-0000-4000-8000-{COUNTER[0]:012d}"
    base = {"id": job_id, "status": "failed", "action": "install", "plugin_id": "reportmanager", "created_at": "2026-10-20T10:00:00+00:00"}
    base.update(record)
    (m.JOBS_ROOT / f"{job_id}.json").write_text(json.dumps(base), encoding="utf-8")
    if text is not None:
        (m.LOGS_ROOT / f"{job_id}.log").write_bytes(text.encode("utf-8"))
    return job_id


import licensing_harness_1_17_58 as harness  # noqa: E402

H = harness.install()
v2views = H.v2views


class HttpResponse:
    def __init__(self, content=b"", content_type=None, status=200):
        self.content, self.content_type, self.status_code, self.headers = content, content_type, status, {}

    def __setitem__(self, key, value):
        self.headers[key] = value


harness._stub("django.http", HttpResponse=HttpResponse)
sys.modules["django"].http = sys.modules["django.http"]


def call(job_id, download=None, user=None):
    request = SimpleNamespace(user=user or H.User("manager"), query_params={"download": download} if download is not None else {})
    return v2views.ModuleV2JobLogView().get(request, job_id)


v2views._require_module_manager = lambda user: None
H.reset()
NAMES = ["X-Tec-Tac-Log-Truncated", "X-Tec-Tac-Log-Bytes", "X-Tec-Tac-Log-Kept", "Content-Disposition"]

# ---- a 200, inline and as a download
for download in (None, "1"):
    resp = call(make_job("a log line\n"), download=download)
    must(resp.status_code == 200, resp.status_code)
    exposed = [part.strip() for part in resp.headers["Access-Control-Expose-Headers"].split(",")]
    must(exposed == NAMES, exposed)
    must(resp.headers["X-Content-Type-Options"] == "nosniff" and resp.headers["Cache-Control"] == "no-store", "nosniff and no-store are unchanged")
    must(resp.headers["X-Tec-Tac-Log-Truncated"] == "false" and resp.headers["X-Tec-Tac-Log-Kept"] == "all" and resp.headers["X-Tec-Tac-Log-Bytes"] == str(len(b"a log line\n")), "the three headers are unchanged")
    must(("Content-Disposition" in resp.headers) is (download == "1"), "Content-Disposition on a download only, as before")
    must(set(resp.headers) <= {"X-Content-Type-Options", "Cache-Control", "X-Tec-Tac-Log-Truncated", "X-Tec-Tac-Log-Bytes", "X-Tec-Tac-Log-Kept", "Access-Control-Expose-Headers", "Content-Disposition"}, sorted(resp.headers))
print("       a 200 names all four headers in Access-Control-Expose-Headers, inline and as a download; no other header changed")

# ---- a refusal or a 404 carries none
for label, response in (("unknown job", call("00000000-0000-4000-8000-0000000000ff")), ("no log kept", call(make_job())), ("bad id", call("not-a-uuid"))):
    must(not hasattr(response, "headers") or "Access-Control-Expose-Headers" not in getattr(response, "headers", {}), label)
H.audit_fail.on = True
refusal = call(make_job("x\n"))
must(refusal.status_code == 503 and "Access-Control-Expose-Headers" not in getattr(refusal, "headers", {}), "an audit failure gives a 503 with no exposed headers")
H.reset()
print("       a 404, a 400 and a 503 carry no exposed headers")

# ---- only this route sets it
hits = [p.name for p in APP.glob("*.py") if "Access-Control-Expose-Headers" in p.read_text(encoding="utf-8") and p.name != "contracts.py"]
# 1.17.67: the header is built in one shared helper (module_job_logs.log_response) that the module, system update and maintenance log routes call
must(hits == ["module_job_logs.py"], hits)
source = (APP / "module_job_logs.py").read_text(encoding="utf-8")
must(source.count("Access-Control-Expose-Headers") == 2 and source.index("def log_response(") < source.index("Access-Control-Expose-Headers"), "set once, inside the shared helper")
must("serve_log(" in (APP / "module_v2_views.py").read_text(encoding="utf-8").split("class ModuleV2JobLogView")[1], "the module log view uses it")
text = (APP / "contracts.py").read_text(encoding="utf-8")
must(re.search(r"Access-Control-Expose-Headers: X-Tec-Tac-Log-Truncated, X-Tec-Tac-Log-Bytes, X-Tec-Tac-Log-Kept, Content-Disposition", text), "the contract row names the header")
print("       only the log view sets the header, once; the contract row says so")
print("PASS module job log expose headers 1.17.66")
