#!/usr/bin/env python3
"""Regression: Core 1.18.35 upgrade of several licensed modules at once (optional ``purpose`` on the online plan and install routes, current_version
and purpose in the progress body, one correlation id per run). Django-free, in the fake-collaborator style of online-install-plan-1.18.19.py and
online-install-run-1.18.20.py. The views, the contract, the docs and the repository wiring are checked at source level; the real resolver, the
FileStore (fcntl) and the stage and queue path run only on dev02."""
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


# ---------------------------------------------------------------- 1. the plan
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


def resolver_for(installed):
    def resolve(candidates):
        ids = [c["id"] for c in candidates]
        future = {k: v["extension_version"] for k, v in installed.items()}
        future.update({c["id"]: c["extension_version"] for c in candidates})
        problems = [{"module": c["id"], "type": "missing_dependency", "dependency": d, "constraint": k}
                    for c in candidates for d, k in c["dependencies"].items() if d not in future]
        actions = [{"id": m, "version": next(c["extension_version"] for c in candidates if c["id"] == m), "action": "replace" if m in installed else "install",
                    "current_version": installed.get(m, {}).get("extension_version")} for m in ids]
        return {"valid": not problems, "problems": problems, "optional_dependencies": [], "order": ids, "actions": actions, "will_disable": []}
    return resolve


def arow(mid, version):
    return {"id": mid, "selected": True, "entitled": True, "availability": "available", "name": mid, "category": "core",
            "release": {"release_id": f"rel-{mid}", "version": version}}


def centry(mid, version, deps=None):
    return (mid, f"rel-{mid}"), {"id": mid, "name": mid, "version": version, "release_id": f"rel-{mid}", "dependencies": deps or {}, "requires": {}, "category": "core"}


def inst(mid, version, repo="lic"):
    return {"id": mid, "extension_version": version, "source": {"repository_id": repo} if repo else {}}


def fake_upgrade_release(caches, installed):
    """1.18.38: what module_repository.upgrade_selector gives the plan, built from the fake cache rows (the module's own repository, else lic)."""
    by_id = {key[0]: dict(row) for key, row in caches}

    def select(module_id):
        row = by_id.get(module_id)
        if row is None:
            return None
        pinned = ((installed.get(module_id) or {}).get("source") or {}).get("repository_id")
        row["repository_id"] = pinned or "lic"
        return row
    return select


def make(selection, rows, caches, installed, **kw):
    if kw.get("purpose") == "upgrade" and "upgrade_release" not in kw:
        kw["upgrade_release"] = fake_upgrade_release(caches, installed)
    body = {"state": "ok", "message": "ok", "plan_state": "valid", "plan_revision": 1, "fetched_at": "x", "modules": rows}
    return plan.build_plan(selection, body, dict(caches), installed, resolver_for(installed), satisfies, lambda p: "fake " + str(p.get("type")),
                           lambda cand: None, frozenset({"example"}), lambda requires: [], **kw)


def codes(out):
    return {b["id"]: b["code"] for b in out["blocked"]}


LIC = frozenset({"lic"})

# purpose parsing
must(plan.clean_purpose(None) == "install" and plan.clean_purpose("install") == "install" and plan.clean_purpose("upgrade") == "upgrade", "purpose values")
for bad in ("", "Upgrade", "remove", 1, True, ["upgrade"], {}):
    try:
        plan.clean_purpose(bad)
    except plan.BadSelection:
        pass
    else:
        raise AssertionError(f"purpose {bad!r} must be refused")

# an installed older module is in order with action replace and current_version
rows = [arow("a", "1.2.0"), arow("b", "2.0.0"), arow("c", "1.1.0")]
caches = [centry("a", "1.2.0"), centry("b", "2.0.0"), centry("c", "1.1.0")]
installed = {"a": inst("a", "1.1.0"), "b": inst("b", "1.0.0"), "c": inst("c", "1.0.0")}
out = make(["a", "b", "c"], rows, caches, installed, purpose="upgrade", licensing_repo_ids=LIC)
must(out["purpose"] == "upgrade" and out["valid"] and not out["blocked"], out)
must([(i["id"], i["action"], i["current_version"], i["version"]) for i in out["order"]] ==
     [("a", "replace", "1.1.0", "1.2.0"), ("b", "replace", "1.0.0", "2.0.0"), ("c", "replace", "1.0.0", "1.1.0")], out["order"])

# the default purpose is the 1.18.19 behaviour: same body plus purpose install, and a not-installed module is planned as an install
out = make(["a", "z"], rows + [arow("z", "1.0.0")], caches + [centry("z", "1.0.0")], installed)
must(out["purpose"] == "install" and not out["blocked"] and [i["action"] for i in out["order"]] == ["replace", "install"], out)
positional = plan.build_plan(["a"], {"state": "ok", "modules": rows}, dict(caches), installed, resolver_for(installed), satisfies, str, lambda c: None, frozenset(), lambda r: [])
must(positional["purpose"] == "install" and positional["valid"], "an old positional call still works")

# not installed
out = make(["a", "z"], rows + [arow("z", "1.0.0")], caches + [centry("z", "1.0.0")], installed, purpose="upgrade", licensing_repo_ids=LIC)
must(codes(out) == {"z": "not_installed"} and not out["valid"] and [i["id"] for i in out["order"]] == ["a"], out)
must("nothing to upgrade" in out["blocked"][0]["message"], out["blocked"])

# a missing new dependency adds nothing and is reported by the resolver
caches2 = [centry("a", "1.2.0", {"newdep": ">=1.0.0"}), centry("newdep", "1.0.0")]
rows2 = [arow("a", "1.2.0"), arow("newdep", "1.0.0")]
out = make(["a"], rows2, caches2, {"a": inst("a", "1.1.0")}, purpose="upgrade", licensing_repo_ids=LIC)
must(out["added_dependencies"] == [] and codes(out) == {"a": "missing_dependency"} and not out["order"], out)
out = make(["a"], rows2, caches2, {"a": inst("a", "1.1.0")})
must({i["id"] for i in out["order"]} == {"a", "newdep"}, "install mode still adds the dependency")

# other source
out = make(["a", "b"], rows[:2], caches[:2], {"a": inst("a", "1.1.0", "index-1"), "b": inst("b", "1.0.0")}, purpose="upgrade", licensing_repo_ids=LIC)
must(codes(out) == {"a": "other_source"} and [i["id"] for i in out["order"]] == ["b"], out)
must("another repository" in out["blocked"][0]["message"], out["blocked"])
out = make(["a"], rows[:1], caches[:1], {"a": inst("a", "1.1.0", "index-1")}, purpose="upgrade", licensing_repo_ids=None)
must(not out["blocked"], "None skips the source check")
out = make(["a"], rows[:1], caches[:1], {"a": inst("a", "1.1.0", None)}, purpose="upgrade", licensing_repo_ids=LIC)
must(not out["blocked"], "a module with no recorded repository is not refused by the stage step either")

# same version and older release
out = make(["a", "b"], [arow("a", "1.1.0"), arow("b", "1.0.0")], [centry("a", "1.1.0"), centry("b", "1.0.0")],
           {"a": inst("a", "1.1.0"), "b": inst("b", "1.5.0")}, purpose="upgrade", licensing_repo_ids=LIC)
must(codes(out) == {"a": "already_installed", "b": "older_than_installed"}, out)


# ---------------------------------------------------------------- 2. the run
class FakeError(RuntimeError):
    pass


class Env:
    def __init__(self, order, deps=None, current=None):
        self.runs, self.locked, self.t = {}, set(), 1000.0
        self.audits, self.stage_calls, self.corr_calls, self.queue_calls, self.ticks, self.jobs, self.plan_calls = [], [], [], [], [], {}, []
        self.deps, self.current, self.order = deps or {}, current or {}, list(order)
        self.stage_fail, self.known_errors = {}, (FakeError,)

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
        yield run_id not in self.locked

    @contextlib.contextmanager
    def start_lock(self):
        yield True

    def plan(self, selection, purpose="install"):
        self.plan_calls.append((list(selection), purpose))
        return {"ok": True, "state": "ok", "message": "x", "blocked": [], "order": [
            {"id": m, "name": m, "version": "2.0.0", "action": "replace", "current_version": self.current.get(m, "1.0.0"),
             "dependencies": dict(self.deps.get(m, {}))} for m in self.order]}

    def upgrade_release(self, module_id):
        return {"id": module_id, "version": "2.0.0", "repository_id": "lic"} if module_id in self.order else None

    def allowed(self):
        return {"state": "ok", "modules": [{"id": m, "selected": True, "release": {"version": "2.0.0", "release_id": m}} for m in self.order]}

    def repo_for(self, module_id, version):
        return "lic"

    def stage_in_run(self, repository_id, module_id, version, run_id):
        self.corr_calls.append((module_id, run_id))
        return self.stage(repository_id, module_id, version)

    def stage(self, repository_id, module_id, version):
        self.stage_calls.append(module_id)
        if module_id in self.stage_fail:
            raise self.stage_fail[module_id]
        return {"upload_id": f"up-{module_id}"}

    def queue(self, upload_id, requested_by):
        self.jobs[f"job-{upload_id[3:]}"] = {"status": "queued", "stage": "queued", "error": None}
        return {"id": f"job-{upload_id[3:]}"}

    def discard(self, upload_id):
        pass

    def job_status(self, job_id):
        return copy.deepcopy(self.jobs.get(job_id))

    def audit(self, run, kind, message, metadata, strict=False, request=None):
        self.audits.append({"kind": kind, "message": message, "metadata": metadata, "run_id": run["run_id"]})

    def enqueue_tick(self, run_id, countdown, seq=None):
        self.ticks.append((run_id, countdown, seq))
        return True

    def done(self, module_id):
        self.jobs[f"job-{module_id}"] = {"status": "succeeded", "stage": "done", "error": None}


def http(state):
    return 200


def states(env, run_id):
    return {m["id"]: m["state"] for m in env.runs[run_id]["modules"]}


# three modules, the second fails at stage, a dependant of the second is skipped, the third still runs
env = Env(["a", "b", "c", "d"], deps={"d": {"b": ">=1.0.0"}}, current={"a": "1.1.0"})
env.stage_fail["b"] = FakeError("Core refused b")
status, body = run_mod.start_run(env, ["a", "b", "c", "d"], "alice", http, purpose="upgrade")
must(status == 202 and body["purpose"] == "upgrade", body)
must(env.plan_calls == [(["a", "b", "c", "d"], "upgrade")], env.plan_calls)
run_id = body["run_id"]
must([(m["id"], m["current_version"]) for m in body["modules"]] == [("a", "1.1.0"), ("b", "1.0.0"), ("c", "1.0.0"), ("d", "1.0.0")], body["modules"])
must(env.runs[run_id]["purpose"] == "upgrade", "stored in the run file")
start_row = next(a for a in env.audits if a["kind"] == "start")
must(start_row["metadata"]["purpose"] == "upgrade" and "upgrade" in start_row["message"], start_row)
must(run_mod.advance_run(env, run_id) is False and env.stage_calls == ["a"], "one module at a time, plan order")
must(run_mod.advance_run(env, run_id) is False and env.stage_calls == ["a"], "waits while a runs")
env.done("a")
must(run_mod.advance_run(env, run_id) is False and env.stage_calls == ["a", "b", "c"], env.stage_calls)  # b fails, the loop goes on to c
must(states(env, run_id) == {"a": "succeeded", "b": "failed", "c": "installing", "d": "skipped"}, states(env, run_id))
must([m for m in env.runs[run_id]["modules"] if m["id"] == "d"][0]["code"] == "dependency_failed", "dependant skipped")
env.done("c")
must(run_mod.advance_run(env, run_id) is True and env.runs[run_id]["status"] == "completed", "completed")
progress = run_mod.public_run(env, env.runs[run_id])
must(progress["purpose"] == "upgrade" and progress["modules"][0]["current_version"] == "1.1.0", progress)
must(set(env.corr_calls) == {("a", run_id), ("b", run_id), ("c", run_id)}, env.corr_calls)
must({a["run_id"] for a in env.audits} == {run_id} and [a["kind"] for a in env.audits].count("end") == 1, env.audits)

# Stop ends the rest skipped
env = Env(["a", "b"])
status, body = run_mod.start_run(env, ["a", "b"], "alice", http, purpose="upgrade")
run_id = body["run_id"]
run_mod.advance_run(env, run_id)
stopped = []
status, _ = run_mod.request_stop(env, run_id, lambda run: stopped.append(run["run_id"]))
must(status == 200 and stopped == [run_id] and env.runs[run_id]["stop_requested"], "stop flag set")
env.done("a")
must(run_mod.advance_run(env, run_id) is True and states(env, run_id) == {"a": "succeeded", "b": "skipped"} and env.runs[run_id]["status"] == "stopped", states(env, run_id))

# default purpose: plan called with the selection only, body says install
env = Env(["a"])
status, body = run_mod.start_run(env, ["a"], "alice", http)
must(body["purpose"] == "install" and env.plan_calls == [(["a"], "install")] and "upgrade" not in next(a for a in env.audits if a["kind"] == "start")["message"], body)

# an old run file with no purpose and no current_version reads as install
old = copy.deepcopy(env.runs[body["run_id"]])
old.pop("purpose")
for m in old["modules"]:
    m.pop("current_version")
shown = run_mod.public_run(env, old)
must(shown["purpose"] == "install" and shown["modules"][0]["current_version"] is None, shown)
env.runs[old["run_id"]] = old
must(run_mod.advance_run(env, old["run_id"]) is False, "an old run file still advances")


# ---------------------------------------------------------------- 3. source-level wiring
def func_src(path, name):
    text = read(path)
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(text, node)
    raise AssertionError(name)


REPO = "framwork/tec_tac/module_repository.py"
must("correlation_id=None) -> dict:" in func_src(REPO, "stage_repository_package").splitlines()[0], "stage takes correlation_id")
must('{"correlation_id": correlation_id} if correlation_id else {}' in func_src(REPO, "stage_repository_package") and "**extra" in func_src(REPO, "stage_repository_package"), "stage forwards it when given")
must(func_src(REPO, "_stage_licensing_release").count("correlation_id=correlation_id") == 2, "both grant rows carry it")
must('{"correlation_id": correlation_id} if correlation_id else {}' in func_src(REPO, "_licensing_audit") and "**extra" in func_src(REPO, "_licensing_audit"), "audit.record gets it only when one is passed")
must("correlation_id" not in read("framwork/tec_tac/module_repository_views.py"), "the single stage route is unchanged")
live = read("framwork/tec_tac/module_install_run.py")
must('correlation_id=run["run_id"]' in live and "stage_in_run=" in live, "live wiring links every row to the run id")
allowed_views = read("framwork/tec_tac/module_allowed_views.py")
must("**extra" in func_src("framwork/tec_tac/module_allowed_views.py", "_audit_allowed") and "correlation_id=None" in func_src("framwork/tec_tac/module_allowed_views.py", "_audit_allowed"), "_audit_allowed keyword, passed on only when given")
must('clean_purpose(data.get("purpose"))' in allowed_views and "purpose=purpose" in allowed_views, "plan view reads purpose")
run_views = read("framwork/tec_tac/module_install_run_views.py")
must('clean_purpose(data.get("purpose"))' in run_views and "purpose=purpose" in run_views and 'correlation_id=run["run_id"]' in run_views, "install and stop views")
must("licensing_repo_ids=frozenset(" in read("framwork/tec_tac/module_install_plan.py"), "plan_online_install fills the licensing repositories")
contract = read("framwork/tec_tac/contracts.py")
for needle in ("not_installed and other_source", "current_version (1.18.35", "correlation_id equal to the run_id", "install or upgrade (1.18.35)"):
    must(needle in contract, needle)
docs = read("docs/module-repositories.md")
for needle in ('"purpose": "install" or "upgrade"', "not_installed", "other_source", "correlation id"):
    must(needle in docs, needle)
print("online upgrade run 1.18.35 regression: PASS")
