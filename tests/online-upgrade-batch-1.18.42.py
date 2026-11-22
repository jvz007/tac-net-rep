#!/usr/bin/env python3
"""Regression: Core 1.18.42 Upgrade selected = the single Upgrade for every selected module.
Part 1: POST modules/catalog/online/stage/batch/ (module_repository.stage_online_batch and the helpers shared with stage_multiple_packages).
Part 2: purpose "upgrade" is gone from the plan and install run (purpose "install" stays for Welcome); select_release stays pinned.
Django-free. The functions of module_repository.py and module_manager_v2.py (both need Django) are taken from their source with ast and run with fake
collaborators, as online-upgrade-release-1.18.38.py does. Views, urls, contract and docs are checked at source level; the real stage, the real queue,
the views and systemd-run run only on dev02."""
import ast
import contextlib
import copy
import importlib
import inspect
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "framwork" / "tec_tac"
package_stub = types.ModuleType("tec_tac")
package_stub.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package_stub
plan = importlib.import_module("tec_tac.module_install_plan")
run_mod = importlib.import_module("tec_tac.module_install_run")


def must(condition, message=""):
    if not condition:
        raise AssertionError(message)


def read(name):
    return (ROOT / name).read_bytes().decode("utf-8").replace("\r\n", "\n")


def func_src(path, name):
    text = read(path)
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(text, node)
    raise AssertionError(name)


def raises(exc_type, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exc_type as exc:
        return exc
    raise AssertionError(f"{call} did not raise {exc_type.__name__}")


REPO = "framwork/tec_tac/module_repository.py"
MGR = "framwork/tec_tac/module_manager_v2.py"


# ====================================================================================================== part 1: the batch stage
class RepoError(RuntimeError):
    pass


class MgrError(RuntimeError):
    pass


class V2Error(RuntimeError):
    pass


class LicError(V2Error):
    pass


class FakeClock:
    def __init__(self):
        self.t = 100.0

    def monotonic(self):
        return self.t


class FakePath:
    def __init__(self, name=""):
        self.name = name

    def mkdir(self, **kwargs):
        pass

    def __truediv__(self, other):
        return FakePath(str(other))


class World:
    """Fake collaborators shared by stage_online_batch and the helpers it uses."""

    def __init__(self):
        self.clock = FakeClock()
        self.stage_calls, self.discards, self.writes = [], [], []
        self.fail = {}  # module id -> exception raised by stage_repository_package
        self.step = 0.0  # clock seconds one stage call takes
        self.write_fail = None
        self.bundles = {}  # module id -> list of child previews (a bundle stage)
        ns = {
            "time": types.SimpleNamespace(monotonic=self.clock.monotonic), "contextlib": contextlib,
            "ModuleRepositoryError": RepoError, "ModuleManagerError": MgrError, "ModuleManagerV2Error": V2Error,
            "ONLINE_BATCH_DEADLINE_SECONDS": 240,
            "stage_repository_package": self.stage_repository_package, "discard_v2_stage": self.discard_v2_stage,
            "_flatten_staged": None, "_write_batch": None,
        }
        # the shared helpers, from the source of module_manager_v2.py
        mgr_ns = {
            "ModuleManagerV2Error": V2Error, "Path": Path, "_load_stage": lambda upload_id: {"package_path": "/x/" + upload_id},
            "_package_metadata": lambda path: {"id": "from-metadata"}, "resolve_install_plan": self.resolve_install_plan,
            "uuid": types.SimpleNamespace(uuid4=lambda: "batch-1"), "BATCHES_ROOT": FakePath("batches"), "_utcnow": lambda: "2026-11-22T00:00:00+00:00",
            "_atomic_json": self.atomic_json,
        }
        for name in ("_flatten_staged", "_write_batch"):
            exec(func_src(MGR, name), mgr_ns)  # noqa: S102 - the repo's own source, as the other source-extracting tests do
        ns["_flatten_staged"], ns["_write_batch"] = mgr_ns["_flatten_staged"], mgr_ns["_write_batch"]
        exec(func_src(REPO, "stage_online_batch"), ns)  # noqa: S102
        self.stage_online_batch = ns["stage_online_batch"]
        self.mgr_ns = mgr_ns

    def stage_repository_package(self, repository_id, module_id, version=None, allow_source_change=False, request=None, correlation_id=None):
        self.stage_calls.append({"args": (repository_id, module_id, version), "allow_source_change": allow_source_change, "request": request,
                                 "correlation_id": correlation_id})
        self.clock.t += self.step
        if module_id in self.fail:
            raise self.fail[module_id]
        upload_id = f"up-{module_id}"
        if module_id in self.bundles:
            return {"upload_id": upload_id, "kind": "bundle", "preview": {"id": "bundle", "kind": "bundle", "packages": self.bundles[module_id]}}
        return {"upload_id": upload_id, "kind": "package", "filename": f"{module_id}.zip", "preview": {"id": module_id, "extension_version": version},
                "source": {"repository_id": repository_id}}

    def discard_v2_stage(self, upload_id):
        self.discards.append(upload_id)

    def resolve_install_plan(self, previews):
        return {"valid": True, "problems": [], "order": [p["id"] for p in previews]}

    def atomic_json(self, path, payload):
        if self.write_fail:
            raise self.write_fail
        self.writes.append((path.name, payload))


def items(*ids):
    return [{"repository_id": "repo-1", "module_id": m, "version": "1.2.0"} for m in ids]


REQUEST = object()

# ---- (a) one stage_repository_package call per item, with the arguments the single route passes
w = World()
w.stage_online_batch(items("a", "b", "c"), request=REQUEST)
must([c["args"] for c in w.stage_calls] == [("repo-1", "a", "1.2.0"), ("repo-1", "b", "1.2.0"), ("repo-1", "c", "1.2.0")], w.stage_calls)
must(all(c["request"] is REQUEST for c in w.stage_calls), "the request is kept")
must(all(c["allow_source_change"] is False and c["correlation_id"] is None for c in w.stage_calls), "no source change, no correlation id")

# ---- (b) three good items give one batch
w = World()
payload = w.stage_online_batch(items("a", "b", "c"), request=REQUEST)
must(payload["kind"] == "batch" and payload["upload_id"] == "batch-1" and payload["created_at"], payload)
must(len(payload["artifacts"]) == 3 and len(payload["packages"]) == 3 and payload["plan"]["order"] == ["a", "b", "c"], payload)
must(len(w.writes) == 1 and w.writes[0][0] == "batch-1.json" and w.writes[0][1] is payload, "written once")
must(set(payload) == {"kind", "upload_id", "created_at", "artifacts", "packages", "plan"}, "the payload shape of stage_multiple_packages")
must(payload["packages"][0]["source_kind"] == "package" and payload["packages"][0]["source_upload_id"] == "up-a" and payload["packages"][0]["source_filename"] == "a.zip", payload["packages"][0])
must(not w.discards, "nothing is discarded on success")

# a bundle item is flattened exactly as in stage_multiple_packages
w = World()
w.bundles["pack"] = [{"id": "x"}, {"id": "y"}]
payload = w.stage_online_batch(items("pack", "a"), request=REQUEST)
must([p["preview"]["id"] for p in payload["packages"]] == ["x", "y", "a"], payload["packages"])
must(payload["packages"][0]["source_kind"] == "bundle" and payload["packages"][0]["source_bundle_id"] == "bundle" and payload["packages"][0]["source_upload_id"] == "up-pack", payload["packages"][0])
must(len(payload["artifacts"]) == 2 and payload["artifacts"][0]["kind"] == "bundle", "artifacts keep one row per staged upload")

# ---- (c) one item (also a one-item list) is still a batch
w = World()
payload = w.stage_online_batch(items("a"), request=REQUEST)
must(payload["kind"] == "batch" and len(payload["artifacts"]) == 1 and len(payload["packages"]) == 1 and len(w.writes) == 1, payload)

# ---- (d) the second item is refused: the first is discarded, nothing is written, the message starts with the module id
for failure, text in ((RepoError("Repository is disabled."), "Repository is disabled."), (MgrError("bad package"), "bad package"),
                      (V2Error("plan failed"), "plan failed"), (LicError("The licence does not cover this module."), "The licence does not cover this module.")):
    w = World()
    w.fail["b"] = failure
    exc = raises(RepoError, w.stage_online_batch, items("a", "b", "c"), request=REQUEST)
    must(str(exc) == f"b: {text}", str(exc))
    must(w.discards == ["up-a"], w.discards)
    must(not w.writes, "nothing is written after a refusal")
    must(len(w.stage_calls) == 2, "the third module is never staged")

# ---- (e) the batch write fails: every staged item is discarded
w = World()
w.write_fail = OSError("disk full")
raises(OSError, w.stage_online_batch, items("a", "b"), request=REQUEST)
must(w.discards == ["up-a", "up-b"], w.discards)
w = World()
w.bundles["pack"] = []
exc = raises(RepoError, w.stage_online_batch, items("a", "pack"), request=REQUEST)
must(str(exc).startswith("pack: ") and w.discards == ["up-a", "up-pack"], (str(exc), w.discards))

# ---- (f) the 240 second deadline (fake clock) refuses and discards
w = World()
w.step = 100.0
exc = raises(RepoError, w.stage_online_batch, items("a", "b", "c", "d"), request=REQUEST)
must(str(exc) == "The batch took too long to download. Select fewer modules.", str(exc))
must(w.discards == ["up-a", "up-b", "up-c"] and len(w.stage_calls) == 3 and not w.writes, (w.discards, len(w.stage_calls)))
w = World()
w.step = 100.0
w.stage_online_batch(items("a", "b", "c"), request=REQUEST)  # the third starts at 200 s, still inside 240 s
must(len(w.writes) == 1, "inside the deadline it works")
must("ONLINE_BATCH_DEADLINE_SECONDS = 240" in read(REPO), "the deadline is 240 seconds")

# ---- (g) body validation
ok = [{"repository_id": "r", "module_id": "a", "version": "1.0.0"}]
clean = plan.clean_batch_items([{"repository_id": " r ", "module_id": "a-b_1", "version": "1.0.0", "extra": "dropped"}])
must(clean == [{"repository_id": "r", "module_id": "a-b_1", "version": "1.0.0"}], clean)
must(len(plan.clean_batch_items([{"repository_id": "r", "module_id": f"m{i}", "version": "1"} for i in range(50)])) == 50, "50 items are fine")
bad = [
    None, "a", {"items": ok}, [], [{"repository_id": "r", "module_id": f"m{i}", "version": "1"} for i in range(51)],
    ["a"], [{"module_id": "a", "version": "1"}], [{"repository_id": "r", "version": "1"}], [{"repository_id": "r", "module_id": "a"}],
    [{"repository_id": "r", "module_id": "a", "version": ""}], [{"repository_id": "r", "module_id": "a", "version": 1}],
    [{"repository_id": "", "module_id": "a", "version": "1"}], [{"repository_id": "r", "module_id": "../x", "version": "1"}],
    [{"repository_id": "r", "module_id": "A", "version": "1"}], [{"repository_id": "r", "module_id": "a b", "version": "1"}],
    [{"repository_id": "r", "module_id": "a", "version": "1"}, {"repository_id": "r2", "module_id": "a", "version": "2"}],
]
for value in bad:
    raises(plan.BadSelection, plan.clean_batch_items, value)
for name in ("licence_override_reason", "license_override_reason", "disable_replaced"):
    must(run_mod.refused_fields({"items": ok, name: "x"}) == [name], name)
must(run_mod.refused_fields({"items": ok}) == [], "a clean body is not refused")

# ---- (h) stage_multiple_packages produces the same payload through the shared helpers
w = World()
mgr_src = func_src(MGR, "stage_multiple_packages")
calls = []


def stage_uploaded_artifact(upload, signature_upload=None, metadata_upload=None):
    calls.append(upload.name)
    return {"upload_id": f"u-{upload.name}", "kind": "package", "preview": {"id": upload.name, "extension_version": "1.0.0"}}


multi_ns = dict(w.mgr_ns)
multi_ns.update({"stage_uploaded_artifact": stage_uploaded_artifact, "pair_intake_sidecars": None, "discard_v2_stage": w.discard_v2_stage,
                 "ModuleManagerError": MgrError})
exec(mgr_src, multi_ns)  # noqa: S102
uploads = [types.SimpleNamespace(name="a.zip"), types.SimpleNamespace(name="b.zip")]
manual = multi_ns["stage_multiple_packages"](uploads)
must(manual["kind"] == "batch" and len(manual["artifacts"]) == 2 and len(manual["packages"]) == 2 and manual["plan"]["order"] == ["a.zip", "b.zip"], manual)
must(set(manual) == set(payload) and manual["packages"][0]["source_filename"] == "a.zip", "the same payload shape as the online batch")
must(not w.discards, "no discard on success")
multi_ns["stage_uploaded_artifact"] = lambda upload, **kw: (_ for _ in ()).throw(MgrError("broken")) if upload.name == "b.zip" else stage_uploaded_artifact(upload)
exc = raises(V2Error, multi_ns["stage_multiple_packages"], uploads)
must(str(exc) == "b.zip: broken" and w.discards == ["u-a.zip"], (str(exc), w.discards))
mgr_text = read(MGR)
for name in ("stage_multiple_packages",):
    body = func_src(MGR, name)
    must("_flatten_staged(" in body and "_write_batch(" in body, "stage_multiple_packages calls both helpers")
    must("resolve_install_plan" not in body and "BATCHES_ROOT" not in body, "the tail now lives in _write_batch")
must("_flatten_staged(" in func_src(REPO, "stage_online_batch") and "_write_batch(" in func_src(REPO, "stage_online_batch"), "the online batch uses both helpers")
must("_flatten_staged" in read(REPO).split("def stage_online_batch")[0] and "_write_batch" in read(REPO).split("def stage_online_batch")[0], "module_repository imports both helpers")

# ---- (i) source-level wiring
urls = read("framwork/tec_tac/urls.py")
must('path("modules/catalog/online/stage/batch/", ModuleOnlineStageBatchView.as_view(), name="tec-tac-module-online-stage-batch")' in urls, "urls.py path")
must(urls.index("online/stage/batch/") > urls.index('"modules/catalog/online/stage/"'), "the batch path is listed beside the stage path")
views = read("framwork/tec_tac/module_repository_views.py")
view = views[views.index("class ModuleOnlineStageBatchView"):]
must("_require_module_manager(request.user)" in view and view.index("_require_module_manager") < view.index("clean_batch_items"), "permission is checked first")
must("refused_fields(data)" in view and "clean_batch_items(data.get(\"items\"))" in view and "stage_online_batch(items, request=request)" in view and "status=201" in view, "the view wiring")
must("LicensingRequirementError" in views and "ModuleManagerV2Error" in view and "ModuleManagerError" in view and "ModuleRepositoryError" in view, "every refusal type answers 400")
must("allow_source_change" not in view and "override_scope" not in view and "read_override" not in view, "no source change and no licence override in the batch route")
contracts = read("framwork/tec_tac/contracts.py")
entry = contracts[contracts.index('"/api/tfd/modules/catalog/online/stage/batch/"'):]
entry = entry[:entry.index('"/api/tfd/modules/catalog/allowed/"')]
for needle in ("authorization", "request", "response", "errors", '"400"', '"403"', "Added 1.18.42", "items", "batch"):
    must(needle in entry, "contract entry has " + needle)
must('"/api/tfd/modules/catalog/online/stage/": {' in contracts and "Added 1.17.58 (additive)" in contracts, "the contract text of the old stage route stays")
docs = read("docs/module-repositories.md")
must("`POST /api/tfd/modules/catalog/online/stage/batch/`" in docs and "Added 1.18.42" in docs, "docs row")
helper = read("scripts/module-v2-job-helper.py")

# ====================================================================================================== part 2: purpose upgrade is gone
must(plan.PURPOSES == ("install",), plan.PURPOSES)
must(plan.clean_purpose(None) == "install" and plan.clean_purpose("install") == "install", "install and a missing purpose are accepted")
for value in ("upgrade", "Install", "", "x", 1, True, [], {}):
    raises(plan.BadSelection, plan.clean_purpose, value)
must(str(raises(plan.BadSelection, plan.clean_purpose, "upgrade")) == 'purpose must be "install"', "the plain sentence")
parameters = list(inspect.signature(plan.build_plan).parameters)
must("upgrade_release" not in parameters and "licensing_repo_ids" not in parameters and parameters[-1] == "purpose", parameters)
must("purpose" in inspect.signature(plan.plan_online_install).parameters, "plan_online_install keeps the purpose argument")
must("not_installed" not in plan.TEXT and "other_source" not in plan.TEXT, "the upgrade-only texts are gone")


def ver(text):
    return tuple(int(x) for x in text.split("."))


def satisfies(version, constraint):
    constraint = (constraint or "").strip()
    if not constraint or constraint == "*":
        return True
    for part in constraint.split(","):
        m = re.fullmatch(r"(==|>=|<=|>|<)?\s*(\d+\.\d+\.\d+)", part.strip())
        op, want, got = m.group(1) or "==", ver(m.group(2)), ver(version)
        if not {"==": got == want, ">=": got >= want, "<=": got <= want, ">": got > want, "<": got < want}[op]:
            return False
    return True


def resolver(installed):
    def resolve(candidates):
        ids = [c["id"] for c in candidates]
        actions = [{"id": c["id"], "version": c["extension_version"], "action": "replace" if c["id"] in installed else "install",
                    "current_version": installed.get(c["id"], {}).get("extension_version")} for c in candidates]
        return {"valid": True, "problems": [], "optional_dependencies": [], "order": ids, "actions": actions, "will_disable": []}
    return resolve


def build(version, installed_version):
    allowed = {"state": "ok", "plan_state": "active", "plan_revision": 1, "fetched_at": "t", "modules": [
        {"id": "m", "name": "M", "selected": True, "entitled": True, "availability": "available", "release": {"release_id": "r1", "version": version}}]}
    cache = {("m", "r1"): {"version": version, "name": "M", "dependencies": {}, "requires": {}, "category": "premium"}}
    installed = {"m": {"id": "m", "extension_version": installed_version}} if installed_version else {}
    return plan.build_plan(["m"], allowed, cache, installed, resolver(installed), satisfies, lambda p: "problem", lambda c: None, frozenset(), lambda r: [])


body = build("1.1.0", "1.0.0")
must(body["ok"] and body["valid"] and body["purpose"] == "install" and body["order"][0]["action"] == "replace" and body["order"][0]["current_version"] == "1.0.0", body)
body = build("1.0.0", "1.0.0")
must(not body["valid"] and body["blocked"][0]["code"] == "already_installed", body)
body = build("0.9.0", "1.0.0")
must(not body["valid"] and body["blocked"][0]["code"] == "older_than_installed", body)
body = build("1.0.0", None)
must(body["valid"] and body["order"][0]["action"] == "install" and body["purpose"] == "install", body)


class Env:
    """The smallest collaborators of module_install_run: a Welcome style run still stages and queues through env.stage and env.repo_for."""

    def __init__(self):
        self.runs, self.locked, self.t = {}, set(), 1000.0
        self.audits, self.stage_calls, self.queue_calls, self.repo_calls, self.jobs = [], [], [], [], {}
        self.known_errors = (RuntimeError,)

    def now(self):
        return self.t

    def load(self, run_id):
        return copy.deepcopy(self.runs.get(run_id))

    def save(self, run):
        self.runs[run["run_id"]] = copy.deepcopy(run)

    def ids(self):
        return list(self.runs)

    def forget(self, run_id):
        self.runs.pop(run_id, None)

    @contextlib.contextmanager
    def lock(self, run_id):
        yield True

    @contextlib.contextmanager
    def start_lock(self):
        yield True

    def plan(self, selection):
        return {"ok": True, "state": "ok", "message": "x", "blocked": [], "order": [
            {"id": m, "name": m.title(), "version": "1.0.0", "action": "install", "dependencies": {}} for m in selection]}

    def allowed(self):
        return {"state": "ok", "modules": [{"id": "m", "selected": True, "release": {"version": "1.0.0", "release_id": "r"}}]}

    def repo_for(self, module_id, version):
        self.repo_calls.append((module_id, version))
        return "repo-1"

    def stage(self, repository_id, module_id, version):
        self.stage_calls.append((repository_id, module_id, version))
        return {"upload_id": f"up-{module_id}"}

    def queue(self, upload_id, requested_by):
        self.queue_calls.append((upload_id, requested_by))
        self.jobs["job-m"] = {"status": "queued", "stage": "queued", "error": None}
        return {"id": "job-m"}

    def discard(self, upload_id):
        pass

    def job_status(self, job_id):
        return copy.deepcopy(self.jobs.get(job_id))

    def audit(self, run, kind, message, metadata, strict=False, request=None):
        self.audits.append({"kind": kind, "message": message, "metadata": metadata})

    def enqueue_tick(self, run_id, countdown, seq=None):
        return True


env = Env()
status, started = run_mod.start_run(env, ["m"], "alice", lambda state: 200)
must(status == 202 and started["purpose"] == "install", (status, started))
must(env.audits[0]["message"] == "Module install run started" and env.audits[0]["metadata"]["purpose"] == "install", env.audits[0])
run_id = started["run_id"]
must(run_mod.advance_run(env, run_id) is False, "first tick queues the module")
must(env.repo_calls == [("m", "1.0.0")] and env.stage_calls == [("repo-1", "m", "1.0.0")] and env.queue_calls == [("up-m", "alice")], (env.repo_calls, env.stage_calls, env.queue_calls))
env.jobs["job-m"] = {"status": "succeeded", "stage": "done", "error": None}
must(run_mod.advance_run(env, run_id) is True and env.runs[run_id]["status"] == "completed", env.runs[run_id])
# a run file written by 1.18.35 to 1.18.41 with purpose upgrade still reads, and is checked against the allowed list from now on
old = copy.deepcopy(env.runs[run_id])
old["purpose"] = "upgrade"
env.runs["old"] = {**old, "run_id": "old"}
must(run_mod.public_run(env, env.runs["old"])["purpose"] == "upgrade", "an old run file still reads upgrade")
older = {**old, "run_id": "older"}
del older["purpose"]
must(run_mod.public_run(env, older)["purpose"] == "install", "a run file without purpose reads install")

# source level: nothing of the upgrade path is left
banned = ("upgrade_release", "_recheck_upgrade", "upgrade_selector", 'purpose == "upgrade"', "Module upgrade run started", "licensing_repo_ids")
for name in ("module_install_plan.py", "module_install_run.py", "module_install_run_views.py", "module_allowed_views.py", "module_repository.py"):
    text = read("framwork/tec_tac/" + name)
    for needle in banned:
        must(needle not in text, f"{needle} is still in {name}")
must("def select_release(" in read(REPO), "select_release stays (online_catalog uses it)")
must("select_release(choices, source_repo)" in read(REPO), "online_catalog still calls select_release")
must('"upgrade"' not in func_src("framwork/tec_tac/module_install_plan.py", "clean_purpose").split('"""')[2], "clean_purpose no longer names upgrade as a value")
for name in ("framwork/tec_tac/contracts.py", "docs/module-repositories.md"):
    text = read(name)
    for line in text.split("\n"):
        if "/online/plan/" in line or "/online/install/" in line and "stage" not in line:
            must('"install" or "upgrade"' not in line and "install or upgrade" not in line and '\\"install\\" (default) or \\"upgrade\\"' not in line, "still offers upgrade: " + line[:100])
must("install or upgrade (1.18.35)" not in contracts and "not_installed and other_source (purpose upgrade only" not in contracts, "contract text of the removed purpose")
must("removed in 1.18.42" in contracts.lower() or "Removed in 1.18.42" in contracts, "the contract notes the removal")
views_run = read("framwork/tec_tac/module_install_run_views.py")
must("clean_purpose(data.get(\"purpose\"))" in views_run and "clean_purpose(data.get(\"purpose\"))" in read("framwork/tec_tac/module_allowed_views.py"), "both views still read the purpose and clean_purpose refuses upgrade")
must("module_install_plan.plan_online_install(selection, purpose=purpose)" in read("framwork/tec_tac/module_allowed_views.py"), "no purpose-dependent plan call")

# ---- select_release cases lifted from online-upgrade-release-1.18.38.py (retired to tests/legacy): the behaviour stays pinned
namespace = {"version_satisfies": satisfies}
exec(func_src(REPO, "select_release"), namespace)  # noqa: S102
select_release = namespace["select_release"]


def rel(repo, version, priority=100, **extra):
    return {"id": "m", "repository_id": repo, "version": version, "repository_priority": priority, **extra}


must(select_release([]) is None, "nothing to select")
must(select_release([rel("a", "1.0.0"), rel("a", "1.2.0"), rel("a", "1.1.0")])["version"] == "1.2.0", "highest version")
chosen = select_release([rel("a", "9.0.0", 200), rel("b", "1.0.0", 10)])
must(chosen["repository_id"] == "b", "priority comes before version")
chosen = select_release([rel("a", "1.0.0", 100), rel("b", "5.0.0", 100)])
must(chosen["repository_id"] == "a", "same priority: repository id decides, not the higher version")
chosen = select_release([rel("a", "9.0.0", 10), rel("b", "1.0.0", 200)], "b")
must(chosen["repository_id"] == "b" and chosen["version"] == "1.0.0", "the pinned repository is the pool first")
chosen = select_release([rel("a", "2.0.0", 10)], "gone")
must(chosen["repository_id"] == "a", "a pin with no release falls back to every choice")
original = [rel("a", "1.0.0"), rel("a", "1.2.0")]
snapshot = copy.deepcopy(original)
select_release(original)
must(original == snapshot, "the input list is not reordered")

# ====================================================================================================== line endings
CRLF = ("framwork/tec_tac/module_repository.py", "framwork/tec_tac/module_manager_v2.py", "framwork/tec_tac/contracts.py", "docs/module-repositories.md")
LF = ("framwork/tec_tac/module_repository_views.py", "framwork/tec_tac/urls.py", "framwork/tec_tac/module_install_plan.py", "framwork/tec_tac/module_install_run.py",
      "framwork/tec_tac/module_install_run_views.py", "framwork/tec_tac/module_allowed_views.py", "scripts/module-v2-job-helper.py", "tests/online-upgrade-batch-1.18.42.py",
      "tests/module-dispatch-unit-1.18.42.py")
for name in CRLF:
    data = (ROOT / name).read_bytes()
    must(b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must stay all CRLF")
for name in LF:
    must(b"\r" not in (ROOT / name).read_bytes(), name + " must stay all LF")
print("online upgrade batch 1.18.42 regression: PASS")
