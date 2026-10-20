#!/usr/bin/env python3
# ruff: noqa: E402
"""1.17.67 regression (Q83 part 1, UI 0.12.119 requests): open and download the System Updates job log and the server-maintenance job log, and
list system update jobs from history.

The real module_job_logs.py, system_update.py, server_maintenance.py and server_maintenance_views.py run against stubs and temp folders; the
two system update views are read from views.py with ast (that file needs Django) and run on the same stubs. Covered: both log routes return
scrubbed text (password=, a bearer token, a /etc/..secret path, and a maintenance job's own sensitive parameter value are redacted); the same
header set as the module route, with Access-Control-Expose-Headers on a 200 only; ?download=1 names the file safely; a 6 MB log is cut head and
tail at 5 MB; a symlinked log or folder is 404; a bad id is 400; a missing job is 404; a job found only in history works; one strict audit row
per read with no log text and a 503 with no body when it cannot be written; a job of an action that needs a permission is 404 for a caller
without it (also for ?download=1); ?part picks one file; the list pages, filters, merges jobs and history (history wins), carries no log text,
no backup path and no log path; the detail route falls back to history and keeps log_tail; the module route is unchanged.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import stat
import sys
import tempfile
import types
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


TMP = Path(tempfile.mkdtemp(prefix="tectac-joblog-routes-"))
SU_JOBS, SU_HISTORY, SU_LOGS = TMP / "su" / "jobs", TMP / "su" / "history", TMP / "su" / "logs"
SM_STATE = TMP / "sm"
SM_JOBS, SM_LOGS, SM_REGISTRY = SM_STATE / "jobs", SM_STATE / "logs", TMP / "registry"
for folder in (SU_JOBS, SU_HISTORY, SU_LOGS, SM_JOBS, SM_LOGS, SM_REGISTRY):
    folder.mkdir(parents=True)
AUDITS = []
AUDIT = {"fail": False}


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


class HttpResponse:
    def __init__(self, content=b"", content_type=None, status=200):
        self.content, self.content_type, self.status_code, self.headers = content, content_type, status, {}

    def __setitem__(self, key, value):
        self.headers[key] = value

    def __contains__(self, key):
        return key in self.headers


class DRFPermissionDenied(Exception):
    pass


class _Spec:
    def __call__(self, *a, **k):
        return lambda obj: obj


class User:
    is_authenticated = True

    def __init__(self, username, *grants, superuser=False, privileged=True):
        self.username, self.grants, self.is_superuser, self.privileged = username, set(grants), superuser, privileged


def record(**kw):
    if AUDIT["fail"]:
        raise RuntimeError("audit store down")
    AUDITS.append(kw)
    return {"recorded": True}


def atomic_json(path, payload, **kw):
    Path(path).write_text(json.dumps(payload, default=str), encoding="utf-8")


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.safe_files", atomic_json=atomic_json)
trust = mod("tec_tac.trusted_publishers", PublisherTrustError=type("PublisherTrustError", (Exception,), {}), verify_release_manifest_signature=lambda *a, **k: None, verify_release_tree=lambda *a, **k: None)
mod("tec_tac.trust_policy", TrustPolicyError=type("TrustPolicyError", (Exception,), {}), acceptance=lambda *a, **k: {}, get_policy=lambda: {}, require_accepted=lambda *a, **k: None)
if "pwd" not in sys.modules:
    try:
        import pwd  # noqa: F401
    except ImportError:
        mod("pwd")
mod("tec_tac.capabilities", build_operation_context=lambda *, source_module, source_action, source_run_id=None, requested_by=None, **extra: {
    "source_module": str(source_module or "").strip(), "source_action": str(source_action or "").strip(), "source_run_id": source_run_id,
    "requested_by": str(requested_by) if requested_by else None, **extra}, register_capability=lambda **kw: SimpleNamespace(**kw))
mod("tec_tac.config", load_layout=lambda: {"TEC_TAC_SERVER_MAINTENANCE_ROOT": str(SM_STATE), "TEC_TAC_SERVER_MAINTENANCE_REGISTRY_ROOT": str(SM_REGISTRY)})
mod("tec_tac.module_state", is_enabled=lambda module_id: True)
mod("tec_tac.rbac", has_extension_permission=lambda user, code: bool(user.is_superuser or code in user.grants), can_manage_privileged_operations=lambda user: user.privileged)
audit = mod("tec_tac.audit", record=record, service_audit_actor=lambda **kw: SimpleNamespace(kind="service", **kw))
pkg.audit = audit
mod("tec_tac.session_security", SessionAuthenticated=object)
mod("drf_spectacular")
mod("drf_spectacular.utils", extend_schema=_Spec(), extend_schema_view=_Spec())
mod("rest_framework")
mod("rest_framework.exceptions", PermissionDenied=DRFPermissionDenied)
mod("rest_framework.response", Response=Response)
mod("rest_framework.views", APIView=type("APIView", (), {}))
mod("django")
mod("django.http", HttpResponse=HttpResponse)
sys.modules["django"].http = sys.modules["django.http"]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


mj = load("tec_tac.module_job_logs", APP / "module_job_logs.py")
pkg.module_job_logs = mj
su = load("tec_tac.system_update", APP / "system_update.py")
su.JOBS_ROOT, su.HISTORY_ROOT, su.LOGS_ROOT = SU_JOBS, SU_HISTORY, SU_LOGS
sm = load("tec_tac.server_maintenance", APP / "server_maintenance.py")
smviews = load("tec_tac.server_maintenance_views", APP / "server_maintenance_views.py")

# the two system update views, read from views.py
tree = ast.parse((APP / "views.py").read_text(encoding="utf-8"))
wanted = {"SystemUpdateJobListView", "SystemUpdateJobLogView"}
nodes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name in wanted]
must({n.name for n in nodes} == wanted, "both views exist in views.py")
space = {
    "__name__": "tec_tac.views", "__package__": "tec_tac", "APIView": type("APIView", (), {}), "SessionAuthenticated": object, "extend_schema_view": _Spec(),
    "extend_schema": _Spec(), "Response": Response, "_require_module_manager": lambda user: None if user.privileged else (_ for _ in ()).throw(DRFPermissionDenied()),
    "list_system_update_jobs": su.list_jobs, "read_system_update_job_log": su.read_job_log, "logger": __import__("logging").getLogger("t"),
    "datetime": __import__("datetime").datetime, "timezone": __import__("datetime").timezone,
}
exec(compile(ast.Module(body=nodes, type_ignores=[]), "views_system_update_log", "exec"), space)  # noqa: S102 - the views' own source
UpdateList, UpdateLog = space["SystemUpdateJobListView"], space["SystemUpdateJobLogView"]
manager = User("manager")
NAMES = ["X-Tec-Tac-Log-Truncated", "X-Tec-Tac-Log-Bytes", "X-Tec-Tac-Log-Kept", "Content-Disposition"]
COUNTER = [0]


def new_id():
    COUNTER[0] += 1
    return f"00000000-0000-4000-8000-{COUNTER[0]:012d}"


def su_job(*, log=None, where="jobs", **record_):
    job_id = new_id()
    data = {"id": job_id, "status": "succeeded", "action": "install", "component": "framework", "version": "1.17.67", "installed_version": "1.17.66",
            "created_at": "2026-10-20T10:00:00+00:00", "finished_at": "2026-10-20T10:05:00+00:00", "backup_path": "/var/lib/tec-tac/x/backup", "requested_by": "alice"}
    data.update(record_)
    (SU_HISTORY if where == "history" else SU_JOBS).mkdir(exist_ok=True)
    (SU_HISTORY if where == "history" else SU_JOBS).joinpath(f"{job_id}.json").write_text(json.dumps(data), encoding="utf-8")
    if log is not None:
        (SU_LOGS / f"{job_id}.log").write_bytes(log if isinstance(log, bytes) else log.encode("utf-8"))
    return job_id


def register(action_id, **extra):
    manifest = {"id": action_id, "revision": "1", "description": action_id, "executable": "/x", "argv": [], "timeout_seconds": 60,
                "parameters": {"token": {"type": "string", "required": False, "sensitive": True}}}
    manifest.update(extra)
    (SM_REGISTRY / f"{action_id}.json").write_text(json.dumps(manifest), encoding="utf-8")


def sm_job(*, action="plain.run", logs=None, permission=None, secret="", **extra):
    job_id = new_id()
    data = {"schema": 1, "id": job_id, "action": action, "status": "succeeded", "stage": "done", "created_at": "2026-10-20T10:00:00+00:00",
            "finished_at": "2026-10-20T10:01:00+00:00", "context": {}, "parameters": {"token": secret} if secret else {},
            "public_parameters": {"token": "<redacted>"} if secret else {}, "lock": {}, "action_permission": permission}
    data.update(extra)
    (SM_JOBS / f"{job_id}.json").write_text(json.dumps(data), encoding="utf-8")
    for suffix, text in (logs or {}).items():
        (SM_LOGS / f"{job_id}{suffix}").write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
    return job_id


def req(download=None, part=None, user=None):
    q = {}
    if download is not None:
        q["download"] = download
    if part is not None:
        q["part"] = part
    return SimpleNamespace(user=user or manager, query_params=q, path="/x")


def update_log(job_id, **kw):
    return UpdateLog().get(req(**kw), job_id)


def maint_log(job_id, **kw):
    return smviews.ServerMaintenanceJobLogView().get(req(**kw), job_id)


def text_of(response):
    return response.content.decode("utf-8")


def reset():
    del AUDITS[:]
    AUDIT["fail"] = False


@contextmanager
def fake_type(path_ending, mode_bits):
    real = os.lstat
    ending = path_ending.replace("\\", "/")

    def lstat(path, *a, **k):
        info = real(path, *a, **k)
        if str(path).replace("\\", "/").endswith(ending):
            values = list(info)
            values[0] = mode_bits | 0o644
            return os.stat_result(values)
        return info

    os.lstat = lstat
    try:
        yield
    finally:
        os.lstat = real


register("plain.run")
register("vendor.rotate", permission="vendor.rotate", owner_module="vendor")
SECRET_LOG = "line one\npassword=hunter2hunter2\nAuthorization: Bearer abcdef0123456789abcdef\nread /etc/tec-tac/secret.key failed\nok\n"

# ---- system update log: text, scrub, headers
reset()
jid = su_job(log=SECRET_LOG)
resp = update_log(jid)
must(resp.status_code == 200 and resp.content_type == "text/plain; charset=utf-8", getattr(resp, "status_code", resp))
body = text_of(resp)
must("hunter2hunter2" not in body and "abcdef0123456789abcdef" not in body and "secret.key" not in body and "line one" in body and "ok" in body, body)
exposed = [p.strip() for p in resp.headers["Access-Control-Expose-Headers"].split(",")]
must(exposed == NAMES, exposed)
must(resp.headers["X-Content-Type-Options"] == "nosniff" and resp.headers["Cache-Control"] == "no-store", resp.headers)
must(resp.headers["X-Tec-Tac-Log-Truncated"] == "false" and resp.headers["X-Tec-Tac-Log-Kept"] == "all" and resp.headers["X-Tec-Tac-Log-Bytes"] == str(len(SECRET_LOG.encode())), resp.headers)
must("Content-Disposition" not in resp.headers, "inline by default")
must(set(resp.headers) == {"X-Content-Type-Options", "Cache-Control", "X-Tec-Tac-Log-Truncated", "X-Tec-Tac-Log-Bytes", "X-Tec-Tac-Log-Kept", "Access-Control-Expose-Headers"}, sorted(resp.headers))
print("       system update log: scrubbed text, nosniff, no-store, three log headers and Access-Control-Expose-Headers")

# ---- the module route's header set is the same (the shared helper)
inline = mj.log_response(body=b"x", size=1, truncated=False, kept="all")
for response in (inline, resp):
    must(set(response.headers) == set(inline.headers), "same header set")
must("Content-Disposition" in mj.log_response(body=b"x", size=1, truncated=False, kept="all", filename="a.log").headers, "attachment")
print("       the module, system update and maintenance routes build their answer in one helper (identical header set)")

# ---- download name
for _kind, make, call in (("system update", lambda: su_job(log="x\n", component="framework"), update_log), ("maintenance", lambda: sm_job(logs={".log": "x\n"}), maint_log)):
    reset()
    resp = call(make(), download="1")
    disposition = resp.headers["Content-Disposition"]
    must(disposition.startswith('attachment; filename="') and disposition.endswith('.log"') and "/" not in disposition and ".." not in disposition, disposition)
    must(resp.headers["Access-Control-Expose-Headers"].endswith("Content-Disposition"), "the name is readable by the browser")
reset()
must(update_log(su_job(log="x\n", component="framework"), download="1").headers["Content-Disposition"].startswith('attachment; filename="system-update-framework-20'), "system-update-<component>-<date>.log")
must(maint_log(sm_job(action="plain.run", logs={".log": "x"}), download="1").headers["Content-Disposition"].startswith('attachment; filename="server-maintenance-plain-run-20'), "server-maintenance-<action>-<date>.log")
hostile = su_job(log="x\n", component='../../etc/"x\r\nSet-Cookie: a=b')
must('"' not in update_log(hostile, download="1").headers["Content-Disposition"][len('attachment; filename="'):-1] and "\n" not in update_log(hostile, download="1").headers["Content-Disposition"], "a hostile component name cannot break out")
print("       ?download=1 sets Content-Disposition with system-update-<component>-<date>.log and server-maintenance-<action>-<date>.log, safe for hostile names")

# ---- the 5 MB cap
reset()
big = ("a line of ordinary log text that is long enough\n" * 140000).encode("utf-8")  # about 6.4 MB
must(len(big) > 6 * 1024 * 1024, len(big))
for call, make in ((update_log, lambda: su_job(log=big)), (maint_log, lambda: sm_job(logs={".log": big}))):
    resp = call(make())
    must(resp.status_code == 200 and resp.headers["X-Tec-Tac-Log-Truncated"] == "true" and resp.headers["X-Tec-Tac-Log-Kept"] == "head-and-tail", resp.headers)
    must(len(resp.content) <= mj.MAX_LOG_BYTES + 200 and b"were left out of the middle" in resp.content and resp.headers["X-Tec-Tac-Log-Bytes"] == str(len(big)), len(resp.content))
print("       a 6 MB log is cut head and tail at 5 MB, Truncated true, Kept head-and-tail, in both routes")

# the cap is shared between the non-empty parts of a maintenance log
reset()
part = ("stdout line of ordinary text for the cap\n" * 100000).encode("utf-8")  # about 4 MB each
resp = maint_log(sm_job(logs={".stdout.log": part, ".stderr.log": part, ".log": "short helper log\n"}))
must(resp.status_code == 200 and resp.headers["X-Tec-Tac-Log-Truncated"] == "true" and len(resp.content) <= mj.MAX_LOG_BYTES + 1000, len(resp.content))
must(b"short helper log" in resp.content and b"== stdout ==" in resp.content and b"== stderr ==" in resp.content, "a small part is kept whole, the big ones share the rest")
print("       the 5 MB cap is shared between the non-empty parts of a maintenance log")

# ---- errors
reset()
for call in (update_log, maint_log):
    r = call("not-a-uuid")
    must(r.status_code == 400 and r.data["code"] == "invalid_job_id" and "Access-Control-Expose-Headers" not in getattr(r, "headers", {}), r.data)
    r = call("00000000-0000-4000-8000-0000000000ff")
    must(r.status_code == 404 and r.data["code"] == "job_not_found", r.data)
r = update_log(su_job())
must(r.status_code == 404 and r.data["code"] == "no_log", r.data)
r = maint_log(sm_job())
must(r.status_code == 404 and r.data["code"] == "no_log", r.data)
must(not AUDITS, "a refusal writes no view row")
r = maint_log(sm_job(logs={".log": "x"}), part="nope")
must(r.status_code == 400 and r.data["code"] == "invalid_part", r.data)
for call, make in ((update_log, lambda: su_job(log="x\n")), (maint_log, lambda: sm_job(logs={".log": "x"}))):  # a caller without the manager right is refused before any file is read
    try:
        call(make(), user=User("nobody", privileged=False))
        raise AssertionError("a caller without core.privileged_operations read the log")
    except DRFPermissionDenied:
        pass
print("       a bad id is 400, an unknown job and a missing log are 404, a bad part is 400, a caller without the right is refused")

# ---- symlinks
for label, make, call, folder in (("system update", lambda: su_job(log="secret\n"), update_log, "/logs"), ("maintenance", lambda: sm_job(logs={".log": "secret\n"}), maint_log, "/logs")):
    jid = make()
    with fake_type(f"{jid}.log", stat.S_IFLNK):
        r = call(jid)
        must(r.status_code == 404 and r.data["code"] == "no_log", (label, r.data))
    with fake_type(folder, stat.S_IFLNK):
        r = call(jid)
        must(r.status_code == 404 and r.data["code"] == "no_log", (label, r.data))
print("       a symlinked log file or logs folder is 404 in both routes")

# ---- history
reset()
jid = su_job(log="from history\n", where="history")
must(not (SU_JOBS / f"{jid}.json").exists(), "only in history")
r = update_log(jid)
must(r.status_code == 200 and b"from history" in r.content, "a job found only in history works")
print("       a system update job found only in history works")

# ---- one strict audit row per read, no log text; a failed row means 503 and no body
reset()
jid = su_job(log=SECRET_LOG)
update_log(jid)
update_log(jid, download="1")
rows = [a for a in AUDITS if a["object_type"] == "system_update_job_log"]
must(len(rows) == 2 and all(a["action"] == "view" and a["strict"] is True and a["module_id"] == "core" and a["object_id"] == jid for a in rows), AUDITS)
must(rows[0]["metadata"] == {"job_id": jid, "component": "framework", "bytes": len(SECRET_LOG.encode()), "truncated": False, "download": False} and rows[1]["metadata"]["download"] is True, rows)
must("hunter2" not in repr(AUDITS) and "line one" not in repr(AUDITS), "no log text in the audit row")
reset()
mid = sm_job(action="plain.run", logs={".log": "a\n", ".stdout.log": "b\n"})
maint_log(mid, part="stdout")
rows = [a for a in AUDITS if a["object_type"] == "server_maintenance_job_log"]
must(len(rows) == 1 and rows[0]["strict"] is True and rows[0]["metadata"] == {"job_id": mid, "action": "plain-run", "part": "stdout", "bytes": 2, "truncated": False, "download": False}, rows)
for call, make in ((update_log, lambda: su_job(log="text\n")), (maint_log, lambda: sm_job(logs={".log": "text\n"}))):
    reset()
    AUDIT["fail"] = True
    r = call(make())
    must(r.status_code == 503 and not hasattr(r, "content") and "Access-Control-Expose-Headers" not in getattr(r, "headers", {}), "no body and no exposed headers")
    AUDIT["fail"] = False
print("       one strict audit row per read (job id, component or action, bytes, truncated, download; never text); an audit failure is 503 with no body")

# ---- server maintenance: scrub incl. the job's sensitive value, parts, permission
reset()
mid = sm_job(secret="s3cr3t-value-xyz", logs={".log": "helper started\nusing s3cr3t-value-xyz now\n", ".stdout.log": "out password=hunter2hunter2\n", ".stderr.log": "err line\n"})
r = maint_log(mid)
body = text_of(r)
must(r.status_code == 200 and "s3cr3t-value-xyz" not in body and "hunter2hunter2" not in body and "<redacted>" in body, body)
must(body.index("== log ==") < body.index("== stdout ==") < body.index("== stderr ==") and "helper started" in body and "err line" in body, body)
for part, present, absent in (("stdout", "out password", "helper started"), ("stderr", "err line", "out password"), ("log", "helper started", "err line")):
    r = maint_log(mid, part=part)
    b = text_of(r)
    must(present in b and absent not in b and "==" not in b.split("\n")[0], (part, b))
r = maint_log(sm_job(logs={".stdout.log": "only out\n"}))
must(r.status_code == 200 and "== stdout ==" in text_of(r) and "== log ==" not in text_of(r), "a part that does not exist is left out")
print("       maintenance log: three headed sections by default, ?part picks one, the job's own sensitive value and the usual secrets are redacted")

reset()
alice, root_user = User("alice"), User("root", superuser=True)
hidden = sm_job(action="vendor.rotate", permission="vendor.rotate", logs={".log": "private\n"})
for download in (None, "1"):
    r = maint_log(hidden, download=download, user=alice)
    must(r.status_code == 404 and r.data["code"] == "job_not_found" and not hasattr(r, "content"), (download, r.status_code))
    unknown = maint_log("00000000-0000-4000-8000-0000000000fe", download=download, user=alice)
    must(unknown.status_code == r.status_code and unknown.data["detail"].split(" ")[0:2] == r.data["detail"].split(" ")[0:2] and set(unknown.data) == set(r.data), "hidden looks like unknown")
must(not AUDITS, "a hidden job writes no view row")
must(maint_log(hidden, user=User("holder", "vendor.rotate")).status_code == 200 and maint_log(hidden, user=root_user).status_code == 200, "a holder and a superuser may read it")
legacy = sm_job(action="vendor.rotate", logs={".log": "legacy\n"})
data = json.loads((SM_JOBS / f"{legacy}.json").read_text(encoding="utf-8"))
data.pop("action_permission")
(SM_JOBS / f"{legacy}.json").write_text(json.dumps(data), encoding="utf-8")
must(maint_log(legacy, user=alice).status_code == 404, "a job written before 1.17.17 takes the registry's permission now")
print("       a job of an action that needs a permission is 404 (same as unknown) for a caller without it, also for ?download=1; holders and superusers read it")

# ---- the list route
for folder in (SU_JOBS, SU_HISTORY, SU_LOGS):
    for item in folder.iterdir():
        item.unlink()
ids = []
for n in range(7):
    ids.append(su_job(log=f"log {n}\n" if n % 2 == 0 else None, finished_at=f"2026-10-2{n}T10:00:00+00:00", component="framework" if n % 3 else "ui", status="failed" if n == 4 else "succeeded"))
dup_id = su_job(where="jobs", finished_at="2026-10-01T00:00:00+00:00", status="running")
(SU_HISTORY / f"{dup_id}.json").write_text(json.dumps({"id": dup_id, "status": "succeeded", "action": "install", "component": "framework", "finished_at": "2026-10-09T00:00:00+00:00", "backup_path": "/var/x"}), encoding="utf-8")
only_hist = su_job(where="history", finished_at="2026-10-30T00:00:00+00:00")
(SU_HISTORY / "not-a-job.json").write_text("{}", encoding="utf-8")
(SU_JOBS / "bad.txt").write_text("x", encoding="utf-8")
r = UpdateList().get(SimpleNamespace(user=manager, query_params={}))
must(r.status_code == 200 and r.data["total"] == 9, (r.status_code, r.data.get("total")))
rows = r.data["jobs"]
must(rows[0]["id"] == only_hist and [row["finished_at"] for row in rows] == sorted((row["finished_at"] for row in rows), reverse=True), "newest first")
must(sum(1 for row in rows if row["id"] == dup_id) == 1 and next(row for row in rows if row["id"] == dup_id)["status"] == "succeeded", "history wins over the jobs folder")
text = json.dumps(r.data)
must("log_tail" not in text and "backup_path" not in text and "/var/" not in text and "log 0" not in text and str(SU_LOGS) not in text, "no log text, no backup path, no path")
byid = {row["id"]: row for row in rows}
must(byid[ids[0]]["has_log"] is True and byid[ids[0]]["log_bytes"] == len(b"log 0\n") and byid[ids[1]]["has_log"] is False and byid[ids[1]]["log_bytes"] is None, "log_bytes and has_log")
page = UpdateList().get(SimpleNamespace(user=manager, query_params={"page": "2", "page_size": "4"})).data
must(page["page"] == 2 and page["page_size"] == 4 and page["pages"] == 3 and len(page["jobs"]) == 4 and page["previous_page"] == 1 and page["next_page"] == 3, page)
must([j["id"] for j in page["jobs"]] == [j["id"] for j in rows[4:8]], "paging keeps the order")
must(UpdateList().get(SimpleNamespace(user=manager, query_params={"page_size": "5000"})).data["page_size"] == 100, "page_size is capped at 100")
for bad in ({"page": "0"}, {"page": "x"}, {"page_size": "-1"}):
    must(UpdateList().get(SimpleNamespace(user=manager, query_params=bad)).status_code == 400, bad)
failed = UpdateList().get(SimpleNamespace(user=manager, query_params={"status": "failed"})).data
must(failed["total"] == 1 and failed["jobs"][0]["status"] == "failed", failed["total"])
comp = UpdateList().get(SimpleNamespace(user=manager, query_params={"component": "ui"})).data
must(comp["total"] == 3 and all(j["component"] == "ui" for j in comp["jobs"]), comp["total"])
try:
    UpdateList().get(SimpleNamespace(user=User("nobody", privileged=False), query_params={}))
    raise AssertionError("a non-manager listed the jobs")
except DRFPermissionDenied:
    pass
real_limit = su.LIST_SCAN_FILES
su.LIST_SCAN_FILES = 3
must(su.list_jobs()["total"] == 3, "only the newest files by modification time are read")
su.LIST_SCAN_FILES = real_limit
print("       list route: paging, page_size cap, filters, jobs and history merged (history wins), no log text or path, log_bytes and has_log, manager only")

# ---- the detail route falls back to history and keeps log_tail
only = su_job(where="history", log="one\ntwo\n")
detail = su.get_job(only)
must(detail["id"] == only and detail["log_tail"] == ["one", "two"] and detail["has_log"] is True and detail["log_bytes"] == 8 and "backup_path" in detail, detail)
live = su_job(log="live\n")
d2 = su.get_job(live)
must(d2["log_tail"] == ["live"] and d2["has_log"] is True and {"id", "status", "version", "installed_version", "requested_by"} <= set(d2), d2)
try:
    su.get_job("00000000-0000-4000-8000-0000000000aa")
    raise AssertionError("an unknown job was found")
except su.SystemUpdateError as exc:
    must("not found" in str(exc), exc)
no_log = su.get_job(su_job())
must(no_log["has_log"] is False and no_log["log_bytes"] is None and no_log["log_tail"] == [], no_log)
print("       the detail route falls back to history, keeps log_tail and every field, and adds log_bytes and has_log")

# ---- the existing routes and the contract
src = (APP / "module_v2_views.py").read_text(encoding="utf-8")
must("module_job_logs.serve_log(" in src and "download_filename(log) if download else None" in src, "the module route uses the shared helper")
urls = (APP / "urls.py").read_text(encoding="utf-8")
for needle in ('"system/updates/jobs/", SystemUpdateJobListView', '"system/updates/jobs/<uuid:job_id>/log/", SystemUpdateJobLogView', '"system/maintenance/jobs/<uuid:job_id>/log/", ServerMaintenanceJobLogView'):
    must(urls.count(needle) == 1, needle)
cap = (APP / "server_maintenance.py").read_text(encoding="utf-8")
must('CAPABILITY_VERSION = "1.1.0"' in cap or "1.1.0" in cap, "core.server_maintenance stays 1.1.0")
must(sm.get_server_maintenance_provider().__class__.__name__ == "ServerMaintenanceProvider" and not hasattr(sm.ServerMaintenanceProvider, "read_job_log"), "read_job_log is a module function, not a provider operation")
print("       the module route uses the shared helper; the three routes are registered once; the capability has no new operation")
print("PASS job log routes 1.17.67")
