#!/usr/bin/env python3
"""Regression: Core 1.18.38 bulk upgrade takes its release from the selection the single Upgrade uses, not from Licensing's allowed list.
Django-free, fake collaborators, in the style of online-upgrade-run-1.18.35.py. select_release is taken from the source of module_repository.py
(the module needs Django); the real selection over live caches, FileStore (fcntl), stage and queue run only on dev02."""
import ast
import contextlib
import copy
import importlib
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


REPO = "framwork/tec_tac/module_repository.py"
namespace = {"version_satisfies": satisfies}
exec(func_src(REPO, "select_release"), namespace)  # noqa: S102 - the repo's own source, as the other source-extracting tests do
select_release = namespace["select_release"]


def rel(repo, version, priority=100, **extra):
    return {"id": "m", "repository_id": repo, "version": version, "repository_priority": priority, **extra}


# ---- (b) select_release: the selection online_catalog makes
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

catalog_src = func_src(REPO, "online_catalog")
must("select_release(choices, source_repo)" in catalog_src and "winning_repo" not in catalog_src, "online_catalog calls the shared helper")
selector_src = func_src(REPO, "upgrade_selector")
must("select_release(" in selector_src and "_cached_modules(repo, development=development)" in selector_src and "download_unavailable" in selector_src, "selector uses the helper and the cache")
must(selector_src.count("_development_for(") == 1 and selector_src.count("installed_catalog_v2(") == 1, "development test and installed list are read once")
must("read_allowed" not in selector_src and "licensing_catalogue_source" not in selector_src, "the selector never reads the allowed list")


# ---- (a), (c), (d), (e): the plan
def resolver_for(installed):
    def resolve(candidates):
        ids = [c["id"] for c in candidates]
        actions = [{"id": m, "version": next(c["extension_version"] for c in candidates if c["id"] == m), "action": "replace" if m in installed else "install",
                    "current_version": installed.get(m, {}).get("extension_version")} for m in ids]
        return {"valid": True, "problems": [], "optional_dependencies": [], "order": ids, "actions": actions, "will_disable": []}
    return resolve


def arow(mid, version, **kw):
    return {"id": mid, "selected": True, "entitled": True, "availability": "available", "name": mid, "category": "core",
            "release": {"release_id": f"rel-{mid}", "version": version}, **kw}


def crow(mid, version, repo="lic", **kw):
    return {"id": mid, "name": mid, "version": version, "release_id": f"rel-{mid}", "repository_id": repo, "dependencies": {}, "requires": {}, "category": "core", **kw}


def inst(mid, version, repo="lic"):
    return {"id": mid, "extension_version": version, "source": {"repository_id": repo} if repo else {}}


def make(selection, rows, installed, picks=None, caches=(), **kw):
    body = {"state": "ok", "message": "ok", "plan_state": "valid", "plan_revision": 1, "fetched_at": "x", "modules": rows}
    return plan.build_plan(selection, body, {(c["id"], c["release_id"]): c for c in caches}, installed, resolver_for(installed), satisfies,
                           lambda p: "fake " + str(p.get("type")), lambda cand: None, frozenset({"example"}), lambda requires: [], **kw)


LIC = frozenset({"lic"})
codes = lambda out: {b["id"]: b["code"] for b in out["blocked"]}  # noqa: E731

# (a) a development-channel release that the allowed list does not carry is planned, including an allowed row that would refuse it
installed = {"sentinelone": inst("sentinelone", "0.4.0"), "unticked": inst("unticked", "1.0.0"), "norelease": inst("norelease", "1.0.0"), "notentitled": inst("notentitled", "1.0.0")}
picks = {"sentinelone": crow("sentinelone", "0.5.0"), "unticked": crow("unticked", "1.1.0"), "norelease": crow("norelease", "1.2.0"), "notentitled": crow("notentitled", "1.3.0")}
rows = [arow("unticked", "1.1.0", selected=False), arow("norelease", "1.2.0", release=None), arow("notentitled", "1.3.0", entitled=False, availability="not_entitled")]
calls = []


def upgrade_release(module_id):
    calls.append(module_id)
    return picks.get(module_id)


out = make(["sentinelone", "unticked", "norelease", "notentitled"], rows, installed, purpose="upgrade", licensing_repo_ids=LIC, upgrade_release=upgrade_release)
must(out["valid"] and not out["blocked"], out["blocked"])
must([(i["id"], i["action"], i["current_version"], i["version"]) for i in out["order"]] ==
     [("sentinelone", "replace", "0.4.0", "0.5.0"), ("unticked", "replace", "1.0.0", "1.1.0"), ("norelease", "replace", "1.0.0", "1.2.0"), ("notentitled", "replace", "1.0.0", "1.3.0")], out["order"])
must(sorted(calls) == sorted(["sentinelone", "unticked", "norelease", "notentitled"]), "one selection call per module")
must(out["plan_state"] == "valid" and out["plan_revision"] == 1, "state fields still come from the allowed body")
out = make(["sentinelone"], [], installed, purpose="upgrade", licensing_repo_ids=LIC, upgrade_release=upgrade_release)
must(out["valid"] and out["order"][0]["version"] == "0.5.0", "an empty allowed list does not stop an upgrade")
# the allowed list is still read for its state: a bad state fails closed as before
bad = plan.build_plan(["sentinelone"], {"state": "licensing_unavailable", "message": "x", "modules": []}, {}, installed, None, None, None, None, frozenset(), None,
                      purpose="upgrade", upgrade_release=upgrade_release)
must(bad["ok"] is False and bad["state"] == "licensing_unavailable" and not bad["order"], bad)

# (c) blocks that stay
installed = {"a": inst("a", "1.0.0"), "b": inst("b", "1.0.0", "index-1"), "c": inst("c", "2.0.0"), "d": inst("d", "3.0.0"), "e": inst("e", "1.0.0"), "f": inst("f", "1.0.0"), "example": inst("example", "1.0.0")}
picks = {"a": crow("a", "1.1.0"), "b": crow("b", "1.1.0", "index-1"), "c": crow("c", "2.0.0"), "d": crow("d", "2.9.0"), "e": crow("e", "1.1.0", "elsewhere"),
         "f": crow("f", "1.1.0", "lic"), "example": crow("example", "1.1.0"), "z": crow("z", "1.0.0")}
installed["f"] = inst("f", "1.0.0", "other")  # pinned to another repository than the selected row
out = make(["a", "b", "c", "d", "e", "f", "example", "z", "gone"], [], installed, purpose="upgrade", licensing_repo_ids=LIC, upgrade_release=lambda m: picks.get(m))
must(codes(out) == {"b": "other_source", "c": "already_installed", "d": "older_than_installed", "e": "other_source", "f": "other_source", "example": "protected",
                    "z": "not_installed", "gone": "not_installed"}, codes(out))
must([i["id"] for i in out["order"]] == ["a"], out["order"])
installed = {"a": inst("a", "1.0.0")}
out = make(["a"], [], installed, purpose="upgrade", licensing_repo_ids=LIC, upgrade_release=lambda m: None)
must(codes(out) == {"a": "not_in_catalogue_cache"} and "no saved catalogue entry" in out["blocked"][0]["message"], out)
out = make(["a"], [], installed, purpose="upgrade", licensing_repo_ids=LIC, upgrade_release=lambda m: crow("a", "1.1.0", download_unavailable=True))
must(codes(out) == {"a": "not_in_catalogue_cache"}, "a download_unavailable row is never offered")
out = make(["a"], [], installed, purpose="upgrade", licensing_repo_ids=LIC, upgrade_release=lambda m: crow("a", "not-a-version"))
must(codes(out) == {"a": "bad_version"}, codes(out))

# (d) install purpose is exactly as in 1.18.19
rows = [arow("a", "1.0.0"), arow("b", "1.0.0", selected=False), arow("c", "1.0.0", release=None)]
caches = [crow("a", "1.0.0"), crow("b", "1.0.0"), crow("c", "1.0.0")]
out = make(["a", "b", "c", "dev"], rows, {}, caches=caches)
must(codes(out) == {"b": "not_selected", "c": "no_release", "dev": "not_in_allowed_list"} and [i["id"] for i in out["order"]] == ["a"], out)
out = make(["a"], [arow("a", "1.0.0", availability="gone")], {}, caches=caches)
must(codes(out) == {"a": "not_available"}, out)
out = make(["a"], rows, {}, caches=[])
must(codes(out) == {"a": "not_in_catalogue_cache"}, out)
out = make(["a"], rows, {}, caches=caches, upgrade_release=lambda m: picks["z"])  # an upgrade_release given to an install is ignored
must(out["valid"] and out["order"][0]["version"] == "1.0.0", out)

# (e) no silent fallback
for kwargs in ({}, {"upgrade_release": None}):
    try:
        make(["a"], rows, {}, caches=caches, purpose="upgrade", licensing_repo_ids=LIC, **kwargs)
    except ValueError:
        pass
    else:
        raise AssertionError("purpose upgrade without upgrade_release must raise")

plan_src = read("framwork/tec_tac/module_install_plan.py")
wiring = plan_src[plan_src.index("def plan_online_install"):]
must("upgrade_release=module_repository.upgrade_selector() if upgrade else None" in wiring, "plan_online_install wires the selector for upgrade only")
must('purpose == "upgrade"' in wiring, "wiring tells the purposes apart")
offer_src = func_src("framwork/tec_tac/module_install_plan.py", "build_plan")
upgrade_branch = offer_src[offer_src.index("if upgrade:\n            have"):offer_src.index("        else:\n            row = allowed.get(module_id)")]
must("upgrade_release(module_id)" in upgrade_branch and "cache_rows" not in upgrade_branch and "not_selected" not in upgrade_branch and "no_release" not in upgrade_branch
     and "not_available" not in upgrade_branch and "entitled" not in upgrade_branch, "(g) the upgrade branch of offer reads neither allowed rows nor release ids")


# ---- (f) the run
class FakeError(RuntimeError):
    pass


class Env:
    def __init__(self, order, purpose_rows):
        self.runs, self.t = {}, 1000.0
        self.order, self.rows = list(order), purpose_rows
        self.stage_calls, self.queue_calls, self.allowed_calls, self.upgrade_calls, self.repo_for_calls, self.jobs = [], [], 0, [], 0, {}
        self.known_errors = (FakeError,)

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

    def plan(self, selection, purpose="install"):
        return {"ok": True, "state": "ok", "message": "x", "blocked": [], "order": [
            {"id": m, "name": m, "version": "2.0.0", "action": "replace", "current_version": "1.0.0", "dependencies": {}} for m in self.order]}

    def allowed(self):  # an allowed list that names nothing
        self.allowed_calls += 1
        return {"state": "ok", "modules": []}

    def upgrade_release(self, module_id):
        self.upgrade_calls.append(module_id)
        return copy.deepcopy(self.rows.get(module_id))

    def repo_for(self, module_id, version):
        self.repo_for_calls += 1
        return "first-licensing"

    def stage(self, repository_id, module_id, version):
        self.stage_calls.append((repository_id, module_id, version))
        return {"upload_id": f"up-{module_id}"}

    def queue(self, upload_id, requested_by):
        self.queue_calls.append(upload_id)
        self.jobs[f"job-{upload_id[3:]}"] = {"status": "queued", "stage": "queued", "error": None}
        return {"id": f"job-{upload_id[3:]}"}

    def discard(self, upload_id):
        pass

    def job_status(self, job_id):
        return copy.deepcopy(self.jobs.get(job_id))

    def audit(self, run, kind, message, metadata, strict=False, request=None):
        pass

    def enqueue_tick(self, run_id, countdown, seq=None):
        return True


http = lambda state: 200  # noqa: E731
env = Env(["sentinelone", "moved"], {"sentinelone": {"id": "sentinelone", "version": "2.0.0", "repository_id": "dev-channel"},
                                      "moved": {"id": "moved", "version": "2.1.0", "repository_id": "dev-channel"}})
status, body = run_mod.start_run(env, ["sentinelone", "moved"], "alice", http, purpose="upgrade")
must(status == 202, body)
run_id = body["run_id"]
must(run_mod.advance_run(env, run_id) is False, "first tick stages sentinelone")
must(env.stage_calls == [("dev-channel", "sentinelone", "2.0.0")], "staged from the selected row's repository, not repo_for(): " + str(env.stage_calls))
env.jobs["job-sentinelone"] = {"status": "succeeded", "stage": "done", "error": None}
must(run_mod.advance_run(env, run_id) is True, "the second tick ends the run")
states = {m["id"]: (m["state"], m["code"]) for m in env.runs[run_id]["modules"]}
must(states == {"sentinelone": ("succeeded", None), "moved": ("skipped", "version_changed")}, states)
must(env.allowed_calls == 0 and env.repo_for_calls == 0, "(g) the upgrade run never reads the allowed list or the licensing-first repository")
# a module the selection no longer offers
env = Env(["a"], {})
status, body = run_mod.start_run(env, ["a"], "alice", http, purpose="upgrade")
run_mod.advance_run(env, body["run_id"])
m = env.runs[body["run_id"]]["modules"][0]
must(m["state"] == "skipped" and m["code"] == "not_in_catalogue_cache" and not env.stage_calls and env.allowed_calls == 0, m)
# a selected row without a repository id is not staged
env = Env(["a"], {"a": {"id": "a", "version": "2.0.0"}})
status, body = run_mod.start_run(env, ["a"], "alice", http, purpose="upgrade")
run_mod.advance_run(env, body["run_id"])
must(env.runs[body["run_id"]]["modules"][0]["code"] == "not_in_catalogue_cache" and not env.stage_calls, "no repository, no stage")

# an install run keeps the allowed-list recheck
env = Env(["a"], {"a": {"id": "a", "version": "2.0.0", "repository_id": "dev-channel"}})
status, body = run_mod.start_run(env, ["a"], "alice", http)
run_mod.advance_run(env, body["run_id"])
m = env.runs[body["run_id"]]["modules"][0]
must(m["code"] == "not_selected" and env.allowed_calls == 1 and not env.upgrade_calls and not env.stage_calls, m)


class InstallEnv(Env):
    def allowed(self):
        self.allowed_calls += 1
        return {"state": "ok", "modules": [{"id": "a", "selected": True, "release": None}]}


env = InstallEnv(["a"], {})
status, body = run_mod.start_run(env, ["a"], "alice", http)
run_mod.advance_run(env, body["run_id"])
must(env.runs[body["run_id"]]["modules"][0]["code"] == "no_release" and not env.upgrade_calls, "an install run still skips no_release")

# the live wiring and the docs
live = read("framwork/tec_tac/module_install_run.py")
must("upgrade_release=lambda module_id: module_repository.upgrade_selector()(module_id)" in live, "live env wires the same selector")
advance_src = func_src("framwork/tec_tac/module_install_run.py", "_advance")
must('run.get("purpose") == "upgrade"' in advance_src and "_recheck_upgrade(env, nxt)" in advance_src, "the tick picks the recheck by purpose")
recheck_src = func_src("framwork/tec_tac/module_install_run.py", "_recheck_upgrade")
must("allowed" not in recheck_src.replace("the allowed list is not read", ""), "the upgrade recheck does not touch allowed()")
for needle in ("From 1.18.38 an upgrade takes its release from the repository the single Upgrade uses",):
    must(needle in read("framwork/tec_tac/contracts.py") and needle in read("docs/module-repositories.md"), needle)
print("online upgrade release 1.18.38 regression: PASS")
