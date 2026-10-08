#!/usr/bin/env python3
"""1.17.2 regression: remembered update source per component.

Django is not installed on the development PC, so the real runtime_settings.py and
system_update.py are loaded against stubs. The migration, the view wiring and the root
helper's source sanitiser are checked by loading or by AST. Style follows
tests/runtime-settings-1.17.1.py.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import tempfile
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
SHA_A = "a" * 40
SHA_B = "b" * 40


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------ stubs
class PermissionDenied(Exception):
    pass


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


class AtomicCtx:
    exited_with_error = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            AtomicCtx.exited_with_error += 1
        return False


def passthrough(*a, **k):
    return lambda fn: fn


mods = {n: types.ModuleType(n) for n in (
    "django", "django.db", "drf_spectacular", "drf_spectacular.utils", "rest_framework",
    "rest_framework.exceptions", "rest_framework.response", "rest_framework.views",
    "tec_tac.models", "tec_tac.rbac", "tec_tac.session_security", "tec_tac.throttles", "tec_tac.audit",
    "tec_tac.safe_files", "tec_tac.trusted_publishers", "tec_tac.trust_policy")}
mods["django.db"].transaction = types.SimpleNamespace(atomic=lambda: AtomicCtx())
mods["drf_spectacular.utils"].extend_schema = passthrough
mods["drf_spectacular.utils"].extend_schema_view = passthrough
mods["rest_framework.exceptions"].PermissionDenied = PermissionDenied
mods["rest_framework.response"].Response = Response
mods["rest_framework.views"].APIView = type("APIView", (), {})
mods["tec_tac.session_security"].SessionAuthenticated = type("SessionAuthenticated", (), {})
mods["tec_tac.throttles"].RuntimeSettingsWriteMinThrottle = type("Min", (), {})
mods["tec_tac.throttles"].RuntimeSettingsWriteDayThrottle = type("Day", (), {})
ALLOWED = {"ok": False}
mods["tec_tac.rbac"].can_manage_runtime_settings = lambda user: ALLOWED["ok"]
AUDITS: list[dict] = []
AUDIT_FAIL = {"on": False}


def record(**kwargs):
    if AUDIT_FAIL["on"]:
        raise RuntimeError("audit store down")
    AUDITS.append(kwargs)


mods["tec_tac.audit"].record = record


def _atomic_json(path, payload, **kw):
    Path(path).write_text(json.dumps(payload), encoding="utf-8")


mods["tec_tac.safe_files"].atomic_json = _atomic_json
mods["tec_tac.trusted_publishers"].PublisherTrustError = type("PublisherTrustError", (Exception,), {})
mods["tec_tac.trusted_publishers"].verify_release_manifest_signature = lambda *a, **k: None
mods["tec_tac.trusted_publishers"].verify_release_tree = lambda *a, **k: None
mods["tec_tac.trust_policy"].TrustPolicyError = type("TrustPolicyError", (Exception,), {})
mods["tec_tac.trust_policy"].acceptance = lambda *a, **k: {}
mods["tec_tac.trust_policy"].get_policy = lambda: {"minimum_level": "signed_development"}
mods["tec_tac.trust_policy"].require_accepted = lambda *a, **k: None
if "pwd" not in sys.modules:
    try:
        import pwd  # noqa: F401
    except ImportError:
        sys.modules["pwd"] = types.ModuleType("pwd")


class Config:
    pk = 1
    module_register_timeout_seconds = 30
    update_sources: object = {}
    updated_at = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    updated_by = None
    saved: list = []

    def save(self, update_fields=None):
        Config.saved.append(tuple(update_fields or ()))


CONFIG = Config()
CURRENT_FAILS = {"on": False}


class TecTacRuntimeConfig:
    @classmethod
    def current(cls):
        if CURRENT_FAILS["on"]:
            raise RuntimeError("database unavailable")
        return CONFIG

    class objects:
        @staticmethod
        def select_for_update():
            return types.SimpleNamespace(get=lambda pk: CONFIG)


mods["tec_tac.models"].TecTacRuntimeConfig = TecTacRuntimeConfig
pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(APP)]
sys.modules.update(mods)
sys.modules["tec_tac"] = pkg


def load(name):
    spec = importlib.util.spec_from_file_location(f"tec_tac.{name}", APP / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


rs = load("runtime_settings")
su = load("system_update")

# ------------------------------------------------------------------ default and reads
DEFAULT = {"type": "release", "ref": None}
must(rs.get_update_source("framework") == DEFAULT and rs.get_update_source("ui") == DEFAULT, "default must be release")
must(rs.get_update_source("nope") == DEFAULT, "unknown component reads as default")
for bad in (None, "x", [], {"type": "branch"}, {"type": "branch", "ref": "bad name"}, {"type": "tag", "ref": "v1"}, {"type": "branch", "ref": 5}):
    CONFIG.update_sources = {"framework": bad}
    must(rs.get_update_source("framework") == DEFAULT, f"{bad!r} must read as the default")
CONFIG.update_sources = "garbage"
must(rs.get_update_source("framework") == DEFAULT, "a non-dict column must read as the default")
CONFIG.update_sources = None
must(rs.get_update_source("ui") == DEFAULT, "a null column must read as the default")
CURRENT_FAILS["on"] = True
must(rs.get_update_source("framework") == DEFAULT, "a database error must read as the default")
CURRENT_FAILS["on"] = False
CONFIG.update_sources = {"framework": {"type": "branch", "ref": "dev"}}
must(rs.get_update_source("framework") == {"type": "branch", "ref": "dev"}, "stored branch must be returned")
must(rs.get_update_sources() == {"framework": {"type": "branch", "ref": "dev"}, "ui": DEFAULT}, "both components returned")
CONFIG.update_sources = {}

# ------------------------------------------------------------------ branch validation
for ok in ("dev", "main", "feature/x-1", "release/1.17.2", "a.b_c", "x" * 200):
    must(rs.validate_branch_ref(ok) == ok, f"{ok!r} must be accepted")
for bad in ("", " dev", "de v", "a\tb", "a..b", "-x", "/x", "x/", "x.lock", "x.", "a//b", "x" * 201, "a~b", "a^b", "a:b", "a?b", "a*b", "a[b", "a\\b", "a@{b", "dé", None, 5, True, ["dev"]):
    try:
        rs.validate_branch_ref(bad)
    except rs.UpdateSourceError:
        continue
    raise AssertionError(f"{bad!r} must be rejected")

# ------------------------------------------------------------------ GET and PATCH
view = rs.UpdateSourceView()
ALLOWED["ok"] = False
payload = view.get(types.SimpleNamespace(user=object())).data
must(payload["update_sources"] == {"framework": DEFAULT, "ui": DEFAULT}, payload)
must(payload["updated_at"] == "2026-10-08T12:00:00+00:00" and payload["updated_by"] is None, payload)

user = types.SimpleNamespace(username="alice")


def patch(body, who=user):
    return view.patch(types.SimpleNamespace(user=who, data=body))


try:
    patch({"component": "framework", "type": "branch", "ref": "dev"})
except PermissionDenied as exc:
    must("core.runtime_settings.manage" in str(exc) and "core.privileged_operations" in str(exc), "403 must name both rights")
else:
    raise AssertionError("a user with neither right must get 403")
must(CONFIG.update_sources == {} and not AUDITS, "a refused PATCH must change and audit nothing")

ALLOWED["ok"] = True
for body, why in (
    ({"component": "agents", "type": "release"}, "bad component"),
    ({"component": True, "type": "release"}, "bool component"),
    ({"type": "release"}, "missing component"),
    ({"component": "ui", "type": "tag", "ref": "v1"}, "bad type"),
    ({"component": "ui", "type": True}, "bool type"),
    ({"component": "ui", "type": None}, "null type"),
    ({"component": "ui"}, "missing type"),
    ({"component": "ui", "type": "branch"}, "branch without ref"),
    ({"component": "ui", "type": "branch", "ref": None}, "branch with null ref"),
    ({"component": "ui", "type": "branch", "ref": True}, "branch with bool ref"),
    ({"component": "ui", "type": "branch", "ref": "a..b"}, "bad ref"),
    ({"component": "ui", "type": "branch", "ref": "x" * 201}, "oversized ref"),
    ({"component": "ui", "type": "release", "extra": 1}, "unknown field"),
    (["ui"], "not an object"),
):
    resp = patch(body)
    must(resp.status_code == 400, f"{why} must give 400, gave {resp.status_code}")
must(CONFIG.update_sources == {} and not AUDITS, "rejected bodies must change and audit nothing")

resp = patch({"component": "framework", "type": "branch", "ref": "dev"})
must(resp.status_code == 200, resp.data)
must(resp.data["update_sources"]["framework"] == {"type": "branch", "ref": "dev"}, resp.data)
must(CONFIG.update_sources == {"framework": {"type": "branch", "ref": "dev"}}, CONFIG.update_sources)
must(Config.saved[-1] == ("update_sources", "updated_by", "updated_at"), Config.saved)
must(len(AUDITS) == 1, "exactly one audit row")
row = AUDITS[0]
must(row["module_id"] == "core" and row["object_type"] == "update_source" and row["object_id"] == "framework", row)
must(row["action"] == "modify" and row["strict"] is True, row)
must(row["before"] == DEFAULT and row["after"] == {"type": "branch", "ref": "dev"}, row)
must(row["actor"] is user, "the signed-in user is the actor")

# Unchanged value: no write and no audit row.
AUDITS.clear()
saves = len(Config.saved)
patch({"component": "framework", "type": "branch", "ref": "dev"})
must(not AUDITS and len(Config.saved) == saves, "an unchanged value must write nothing")

# release forces ref to null, whatever ref the body carries.
resp = patch({"component": "framework", "type": "release", "ref": "ignored"})
must(resp.data["update_sources"]["framework"] == DEFAULT, resp.data)
must(CONFIG.update_sources["framework"] == DEFAULT, CONFIG.update_sources)
must(AUDITS[-1]["before"] == {"type": "branch", "ref": "dev"} and AUDITS[-1]["after"] == DEFAULT, AUDITS[-1])
# The other component is untouched.
must(rs.get_update_source("ui") == DEFAULT, "the other component must not change")

# A failed audit write surfaces so the transaction rolls the change back.
AUDIT_FAIL["on"] = True
before_errors = AtomicCtx.exited_with_error
try:
    patch({"component": "ui", "type": "branch", "ref": "dev"})
except RuntimeError:
    pass
else:
    raise AssertionError("a failed audit write must not be swallowed")
must(AtomicCtx.exited_with_error == before_errors + 1, "the change and the audit row must share one transaction")
AUDIT_FAIL["on"] = False
CONFIG.update_sources = {}
AUDITS.clear()

# ------------------------------------------------------------------ online status
tmp = Path(tempfile.mkdtemp(prefix="update-source-test-"))
su.CACHE_ROOT = tmp / "cache"
su.RELEASE_CACHE = su.CACHE_ROOT / "release-cache.json"
su.HISTORY_ROOT = tmp / "history"
su.JOBS_ROOT = tmp / "jobs"
su.HISTORY_ROOT.mkdir()
su.JOBS_ROOT.mkdir()
su._read_config = lambda: {}
su._installed_version = lambda component: "1.17.1"
su._annotate_trust_acceptance = lambda trust: trust
su._release_signature_preview = lambda component, repo, commit: {"level": "signed_development"}

REPO = "jvz007/tac-net-rep"
GH = {"calls": [], "branch_fail": False, "head": SHA_A, "date": "2026-10-08T09:30:00Z"}


def fake_github(url):
    GH["calls"].append(url)
    if url.endswith("/releases/latest"):
        return {"tag_name": "v1.17.1", "name": "1.17.1", "published_at": "2026-10-01T00:00:00Z", "html_url": "https://example/r"}
    if "/commits/" in url:
        return {"sha": SHA_B}
    if "/branches/" in url:
        if GH["branch_fail"]:
            raise su.SystemUpdateError("GitHub request failed (404): Branch not found")
        return {"name": "dev", "commit": {"sha": GH["head"], "commit": {"committer": {"date": GH["date"]}}}}
    raise AssertionError(url)


su._github_json = fake_github
su._github_content_bytes = lambda repo, path, ref: None  # 1.17.3: the VERSION fallback reads nothing here, so these states stay unknown


def branch_calls():
    return [u for u in GH["calls"] if "/branches/" in u]


def write_job(name, *, component="framework", status="succeeded", finished="2026-10-08T10:00:00Z", source=None, action="install", where=None):
    job = {"id": name, "component": component, "status": status, "finished_at": finished, "action": action}
    if source is not None:
        job["source"] = source
    (where or su.HISTORY_ROOT).joinpath(f"{name}.json").write_text(json.dumps(job), encoding="utf-8")


BRANCH = {"type": "branch", "ref": "dev"}

# Release source: exactly today's answer, no new keys.
plain = su.online_status("framework", force=True)
via_release = su.online_status("framework", force=True, source=DEFAULT)
must(set(plain) == set(via_release) and "source" not in via_release and "branch" not in via_release and "branch_error" not in via_release,
     "a release source must give today's response")
must(plain["latest_release"]["tag"] == "v1.17.1", plain)

# Unknown: no history at all.
GH["calls"].clear()
out = su.online_status("framework", force=True, source=BRANCH)
must(out["source"] == BRANCH and out["branch_error"] is None, out)
# 1.17.3: a branch source no longer fetches the release, so latest_release is null; every key stays present.
must(out["latest_release"] is None and "installed_version" in out and "release_error" in out and "checked_at" in out and "cache" in out, "every existing key is kept")
b = out["branch"]
must(b["ref"] == "dev" and b["head_commit"] == SHA_A and b["head_short"] == SHA_A[:7] and b["head_date"] == "2026-10-08T09:30:00Z", b)
must(b["state"] == "unknown" and b["differs"] is None and b["installed_commit"] is None and b["installed_short"] is None, b)
must(any(u.endswith("/branches/dev") for u in branch_calls()), branch_calls())

# Same: the latest install recorded the head commit.
write_job("j1", source={"type": "branch", "repository": REPO, "ref": "dev", "commit": SHA_A})
out = su.online_status("framework", force=True, source=BRANCH)
b = out["branch"]
must(b["state"] == "same" and b["differs"] is False and b["installed_commit"] == SHA_A, b)
must(b["installed_source"] == {"type": "branch", "ref": "dev"}, b)

# Differs: the head moved on.
GH["head"] = SHA_B
out = su.online_status("framework", force=True, source=BRANCH)
b = out["branch"]
must(b["state"] == "differs" and b["differs"] is True and b["head_commit"] == SHA_B and b["installed_commit"] == SHA_A, b)

# The newest succeeded install decides. A later offline upload makes the installed commit unknown.
write_job("j2", finished="2026-10-08T11:00:00Z", source={"type": "offline"})
b = su.online_status("framework", force=True, source=BRANCH)["branch"]
must(b["state"] == "unknown" and b["differs"] is None and b["installed_commit"] is None, b)
# So does an install from before 1.17.2 (no source at all).
write_job("j3", finished="2026-10-08T12:00:00Z")
b = su.online_status("framework", force=True, source=BRANCH)["branch"]
must(b["state"] == "unknown" and b["differs"] is None, b)
# A matching install from another repository, another component, a failed job or a rollback is not counted.
write_job("j4", finished="2026-10-08T13:00:00Z", source={"type": "branch", "repository": "someone/else", "ref": "dev", "commit": SHA_B})
write_job("j5", finished="2026-10-08T14:00:00Z", component="ui", source={"type": "branch", "repository": REPO, "ref": "dev", "commit": SHA_B})
write_job("j6", finished="2026-10-08T15:00:00Z", status="failed", source={"type": "branch", "repository": REPO, "ref": "dev", "commit": SHA_B})
b = su.online_status("framework", force=True, source=BRANCH)["branch"]
must(b["state"] == "unknown", b)
# A job with no commit gives unknown, not a guess.
write_job("j7", finished="2026-10-08T16:00:00Z", source={"type": "branch", "repository": REPO, "ref": "dev"})
b = su.online_status("framework", force=True, source=BRANCH)["branch"]
must(b["state"] == "unknown" and b["differs"] is None, b)
# A newer matching install with a commit restores an exact answer.
write_job("j8", finished="2026-10-08T17:00:00Z", source={"type": "branch", "repository": REPO, "ref": "dev", "commit": SHA_B.upper()})
b = su.online_status("framework", force=True, source=BRANCH)["branch"]
must(b["state"] == "same" and b["installed_commit"] == SHA_B, b)

# branch_error leaves the release data intact.
GH["branch_fail"] = True
out = su.online_status("framework", force=True, source={"type": "branch", "ref": "nope"})
must("Branch not found" in out["branch_error"], out)
# 1.17.3: no release data is fetched for a branch source, so a branch failure leaves latest_release null and release_error null.
must(out["latest_release"] is None and out["release_error"] is None, "a branch failure sets branch_error only")
must(out["branch"]["state"] == "unknown" and out["branch"]["head_commit"] is None and out["branch"]["differs"] is None, out["branch"])
GH["branch_fail"] = False

# Cache: 5 minutes, bypassed by force.
GH["head"] = SHA_A
GH["calls"].clear()
su.online_status("framework", force=True, source=BRANCH)
must(len(branch_calls()) == 1, "force must hit GitHub")
su.online_status("framework", source=BRANCH)
su.online_status("framework", source=BRANCH)
must(len(branch_calls()) == 1, "a fresh branch cache must serve the next calls")
GH["head"] = SHA_B
must(su.online_status("framework", source=BRANCH)["branch"]["head_commit"] == SHA_A, "cached head is served within 5 minutes")
must(su.online_status("framework", force=True, source=BRANCH)["branch"]["head_commit"] == SHA_B, "force bypasses the branch cache")
must(len(branch_calls()) == 2, branch_calls())
# Expire it.
doc = json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))
doc["branches"]["framework"]["checked_at"] = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
su.RELEASE_CACHE.write_text(json.dumps(doc), encoding="utf-8")
GH["head"] = SHA_A
must(su.online_status("framework", source=BRANCH)["branch"]["head_commit"] == SHA_A, "an expired cache must refetch")
# A different ref does not reuse the cached row.
n = len(branch_calls())
su.online_status("framework", source={"type": "branch", "ref": "other"})
must(len(branch_calls()) == n + 1, "a different ref must not be served from the cache")
# The release cache keys survive the branch write.
doc = json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))
must("framework" in doc["components"] and "branches" in doc, doc.keys())

# ------------------------------------------------------------------ system_status
su._signed_release_min_version = lambda component: None
su.cached_online_status = lambda component: {"component": component}
su._recent_history = lambda limit=12: []
CONFIG.update_sources = {"ui": {"type": "branch", "ref": "dev"}}
status = su.system_status()
must(status["update_sources"] == {"framework": DEFAULT, "ui": {"type": "branch", "ref": "dev"}}, status["update_sources"])
must(all(k in status for k in ("framework", "ui", "release_cache", "history", "advanced_sources")), "existing keys must stay")
CONFIG.update_sources = {}

# ------------------------------------------------------------------ queue_install records the source
captured = {}
su._load_stage = lambda upload_id: {"preview": {"component": "framework", "operation": "upgrade", "version": "1.17.2", "installable": True,
                                                  "source": {"type": "branch", "repository": REPO, "ref": "dev", "commit": SHA_A}}}
su._accept_update_trust = lambda trust, subject: {}
su._new_job = lambda payload: captured.update(payload) or {"id": "job-1", **payload}
su._dispatch = lambda job_id: None
su.public_job = lambda job: job
su.queue_install("upload-1", requested_by="alice")
must(captured["source"] == {"type": "branch", "repository": REPO, "ref": "dev", "commit": SHA_A}, captured)
su._load_stage = lambda upload_id: {"preview": {"component": "framework", "operation": "upgrade", "version": "1.17.2", "installable": True}}
su.queue_install("upload-2", requested_by="alice")
must(captured["source"] == {"type": "offline"}, "a preview with no source is recorded as offline")

# ------------------------------------------------------------------ the root helper's sanitiser
helper_src = (ROOT / "scripts" / "system-update-helper.py").read_text(encoding="utf-8")
tree = ast.parse(helper_src)
wanted = []
for node in tree.body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in {"SOURCE_TYPES", "SOURCE_TEXT_MAX"} for t in node.targets):
        wanted.append(node)
    if isinstance(node, ast.FunctionDef) and node.name == "sanitise_source":
        wanted.append(node)
must(len(wanted) == 3, "helper must define SOURCE_TYPES, SOURCE_TEXT_MAX and sanitise_source")
ns = {"re": re}
exec(compile(ast.Module(body=wanted, type_ignores=[]), "helper-sanitiser", "exec"), ns)  # noqa: S102 - test-only extraction
clean = ns["sanitise_source"]
must(clean({"type": "branch", "repository": REPO, "ref": "dev", "commit": SHA_A.upper()}) == {"type": "branch", "repository": REPO, "ref": "dev", "commit": SHA_A}, "valid source kept, commit lower-cased")
must(clean({"type": "release", "repository": REPO, "ref": "v1.17.1"}) == {"type": "release", "repository": REPO, "ref": "v1.17.1"}, "release without commit")
must("commit" not in clean({"type": "branch", "commit": "z" * 40}), "a non-hex commit must be dropped")
must("commit" not in clean({"type": "branch", "commit": "a" * 39}), "a short commit must be dropped")
must("commit" not in clean({"type": "branch", "commit": SHA_A + "0"}), "a long commit must be dropped")
for bad in ({"type": "tag"}, {"type": None}, {}, None, "branch", ["branch"], {"type": ["release"]}):
    must(clean(bad) == {"type": "offline"}, f"{bad!r} must read as offline")
out = clean({"type": "branch", "repository": "x" * 201, "ref": "bad\nref", "extra": "drop", "commit": SHA_A})
must(out == {"type": "branch", "commit": SHA_A}, out)
must(clean({"type": "branch", "repository": 5, "ref": ["dev"]}) == {"type": "branch"}, "non-string repository and ref are dropped")
claim = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "claim_job")
claim_src = ast.get_source_segment(helper_src, claim)
must('"source": sanitise_source(request.get("source"))' in claim_src, "claim_job must copy a sanitised source into the immutable job")

# ------------------------------------------------------------------ view wiring (stage default)
views_src = (APP / "views.py").read_text(encoding="utf-8")
vtree = ast.parse(views_src)


def method_of(class_name, method_name):
    cls = next(n for n in vtree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method_name)
    fn.decorator_list = []
    return fn


stage_fn = method_of("SystemUpdateOnlineStageView", "post")
stage_fn.name = "stage_post"
staged = []


class SystemUpdateError(Exception):
    pass


vns = {
    "Response": Response,
    "SystemUpdateError": SystemUpdateError,
    "_require_module_manager": lambda user: None,
    "get_update_source": rs.get_update_source,
    "stage_online_package": lambda component, source_type, ref=None: staged.append((component, source_type, ref)) or {"ok": True},
    "logger": types.SimpleNamespace(exception=lambda *a, **k: None),
}
exec(compile(ast.Module(body=[stage_fn], type_ignores=[]), "stage-view", "exec"), vns)  # noqa: S102 - test-only extraction
stage_post = vns["stage_post"]


def stage(data):
    staged.clear()
    resp = stage_post(object(), types.SimpleNamespace(user=user, data=data))
    return resp.status_code, (staged[0] if staged else None)


CONFIG.update_sources = {}
must(stage({"component": "framework"}) == (201, ("framework", "release", None)), "no saved source: default stays release")
CONFIG.update_sources = {"framework": {"type": "branch", "ref": "dev"}}
must(stage({"component": "framework"}) == (201, ("framework", "branch", "dev")), "the saved branch is the default")
must(stage({"component": "ui"}) == (201, ("ui", "release", None)), "the other component keeps its own source")
must(stage({"component": "framework", "source_type": "release"}) == (201, ("framework", "release", None)), "an explicit source_type wins")
must(stage({"component": "framework", "source_type": "branch", "ref": "feature/x"}) == (201, ("framework", "branch", "feature/x")), "an explicit branch and ref win")
must(stage({"component": "framework", "source_type": "branch"}) == (201, ("framework", "branch", None)), "an explicit branch with no ref keeps today's error path")
CONFIG.update_sources = {}

status_fn = method_of("SystemUpdateOnlineStatusView", "get")
status_src = ast.get_source_segment(views_src, next(n for n in vtree.body if isinstance(n, ast.ClassDef) and n.name == "SystemUpdateOnlineStatusView"))
must("system_update_online_status(component, force=force, source=source)" in status_src and "get_update_source(component)" in status_src, "the online status view must pass the saved source")
must("from .runtime_settings import get_module_register_timeout_seconds, get_update_source" in views_src, "views.py must import get_update_source")

# ------------------------------------------------------------------ wiring by source
urls = (APP / "urls.py").read_text(encoding="utf-8")
must('path("system/update-source/", UpdateSourceView.as_view(), name="tec-tac-update-source")' in urls, "route missing")
must("UpdateSourceView" in urls.split("from .runtime_settings import")[1].split("\n")[0], "urls.py must import the view")
openapi = (APP / "openapi.py").read_text(encoding="utf-8")
must('("/api/tfd/system/update-source/", "Tec-Tac · Runtime Settings")' in openapi, "openapi grouping missing")
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
for needle in ('"/api/tfd/system/update-source/"', '"/api/tfd/system/updates/online/"', '"/api/tfd/system/updates/": {', '"update_sources"',
               '"branch_error"', '"get_update_source"', "update_source"):
    must(needle in contracts, f"contracts.py lacks {needle}")
install = (ROOT / "install.sh").read_text(encoding="utf-8")
must("('/api/tfd/system/update-source/','tec-tac-update-source')" in install, "install.sh must verify the route")
must((ROOT / "docs" / "update-source.md").is_file(), "docs/update-source.md missing")

# Held Low from the 1.17.2 review: the stage route has a contract entry (read by AST, as contracts.py needs Django).
ctree = ast.parse(contracts)
details = next(ast.literal_eval(n.value) for n in ctree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in n.targets))
stage_entry = details["/api/tfd/system/updates/online/stage/"]["POST"]
stage_text = json.dumps(stage_entry)
for needle in ("component", "source_type", "ref", "remembered", "core.privileged_operations"):
    must(needle in stage_text, f"stage contract entry lacks {needle}")
must(set(stage_entry["errors"]) == {"400", "403", "500"} and "201" in stage_entry["response"], "stage contract entry must list 201, 400, 403 and 500")

# ------------------------------------------------------------------ model and migration
model_src = (APP / "models.py").read_text(encoding="utf-8")
cls = next(n for n in ast.parse(model_src).body if isinstance(n, ast.ClassDef) and n.name == "TecTacRuntimeConfig")
must("update_sources = models.JSONField(default=dict, blank=True)" in ast.unparse(cls), "model field missing")


class Rec:
    def __init__(self, *a, **k):
        self.a, self.k = a, k


class Migration:
    pass


dmig = types.ModuleType("django.db.migrations")
dmig.Migration = Migration
dmig.AddField = Rec
dmodels = types.ModuleType("django.db.models")
dmodels.JSONField = Rec
ddb = types.ModuleType("django.db")
ddb.migrations, ddb.models = dmig, dmodels
sys.modules.update({"django.db": ddb, "django.db.migrations": dmig, "django.db.models": dmodels})
spec = importlib.util.spec_from_file_location("mig0025", APP / "migrations" / "0025_runtime_update_sources.py")
m25 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m25)
must(m25.Migration.dependencies == [("tec_tac", "0024_retire_tfdreporting_poc")], m25.Migration.dependencies)
must(len(m25.Migration.operations) == 1, "0025 adds one column only")
op = m25.Migration.operations[0]
must(op.k["model_name"] == "tectacruntimeconfig" and op.k["name"] == "update_sources", op.k)
must(op.k["field"].k == {"blank": True, "default": dict}, op.k["field"].k)
latest = sorted(p.name for p in (APP / "migrations").glob("0*.py"))[-1]
must(latest == "0025_runtime_update_sources.py", f"0025 must be the newest migration, found {latest}")

print("[TEST] PASS 1.17.2 remembered update source")
