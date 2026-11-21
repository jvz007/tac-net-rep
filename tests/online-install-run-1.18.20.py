#!/usr/bin/env python3
"""Regression: Core 1.18.20 batch install run (POST/GET/stop under /api/tfd/modules/catalog/online/install/) and the two held Mediums of the 1.18.19
review. Django-free: the run logic gets injected collaborators (stage, queue, job status, allowed list, audit, lock, clock) and an in-memory store, so
it also runs on a PC with no fcntl. The views, the Celery task, the urls, the contract and the docs are checked at source level; the real stage and
queue path (module_repository, module_manager_v2) runs only on dev02."""
import ast
import contextlib
import copy
import importlib
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "framwork" / "tec_tac"
package_stub = types.ModuleType("tec_tac")
package_stub.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package_stub
run_mod = importlib.import_module("tec_tac.module_install_run")
plan_mod = importlib.import_module("tec_tac.module_install_plan")


def must(condition, message):
    if not condition:
        raise AssertionError(message)


class FakeError(RuntimeError):
    pass


class Env:
    """The collaborators of module_install_run, recording every call."""

    def __init__(self, order=(), blocked=(), deps=None, plan_state="ok"):
        self.runs, self.locked, self.t = {}, set(), 1000.0
        self.audits, self.stage_calls, self.queue_calls, self.discards, self.ticks, self.jobs = [], [], [], [], [], {}
        self.deps, self.plan_calls = deps or {}, []
        self.plan_body = self.make_plan(order, blocked, plan_state)
        self.allowed_body = self.make_allowed(list(order))
        self.stage_fail, self.queue_fail, self.audit_fail, self.start_busy = {}, {}, False, False
        self.known_errors = (FakeError,)

    def make_plan(self, order, blocked=(), state="ok"):
        return {"ok": state == "ok", "state": state, "message": "x", "order": [
            {"id": m, "name": m.title(), "version": "1.0.0", "action": "install", "dependencies": dict(self.deps.get(m, {}))} for m in order],
            "blocked": [{"id": b[0], "code": b[1], "message": f"blocked {b[1]}"} for b in blocked]}

    @staticmethod
    def make_allowed(ids, state="ok"):
        return {"state": state, "modules": [{"id": m, "selected": True, "release": {"version": "1.0.0", "release_id": m}} for m in ids]}

    # collaborators
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
        if run_id in self.locked:
            yield False
            return
        self.locked.add(run_id)
        try:
            yield True
        finally:
            self.locked.discard(run_id)

    @contextlib.contextmanager
    def start_lock(self):
        yield not self.start_busy

    def plan(self, selection):
        self.plan_calls.append(list(selection))
        return copy.deepcopy(self.plan_body)

    def allowed(self):
        return copy.deepcopy(self.allowed_body)

    def repo_for(self, module_id, version):
        return "repo-1"

    def stage(self, repository_id, module_id, version):
        self.stage_calls.append((repository_id, module_id, version))
        if module_id in self.stage_fail:
            raise self.stage_fail[module_id]
        return {"upload_id": f"up-{module_id}"}

    def queue(self, upload_id, requested_by):
        self.queue_calls.append((upload_id, requested_by))
        module_id = upload_id[3:]
        if module_id in self.queue_fail:
            raise self.queue_fail[module_id]
        job_id = f"job-{module_id}"
        self.jobs[job_id] = {"status": "queued", "stage": "queued", "error": None}
        return {"id": job_id}

    def discard(self, upload_id):
        self.discards.append(upload_id)

    def job_status(self, job_id):
        return copy.deepcopy(self.jobs.get(job_id))

    def audit(self, run, kind, message, metadata, strict=False, request=None):
        if strict and self.audit_fail:
            raise run_mod.AuditNotSaved()
        self.audits.append({"kind": kind, "message": message, "metadata": metadata, "run_id": run["run_id"], "strict": strict})

    def enqueue_tick(self, run_id, countdown, seq=None):
        self.ticks.append((run_id, countdown, seq))
        return True

    # helpers
    def kinds(self, kind):
        return [a for a in self.audits if a["kind"] == kind]

    def finish_job(self, module_id, status="succeeded", error=None):
        self.jobs[f"job-{module_id}"] = {"status": status, "stage": "done", "error": error}


def http(state):
    return {"licensing_unavailable": 503, "invalid_response": 502}.get(state, 200)


def start(env, selection=None, user="alice"):
    status, body = run_mod.start_run(env, selection or [m["id"] for m in env.plan_body["order"]], user, http)
    return status, body


def states(env, run_id):
    return {m["id"]: m["state"] for m in env.runs[run_id]["modules"]}


def module(env, run_id, module_id):
    return next(m for m in env.runs[run_id]["modules"] if m["id"] == module_id)


# ---------------------------------------------------------------- 1. two modules with a dependency, plan order, one job each, one run
env = Env(order=["a", "b"], deps={"b": {"a": ">=1.0.0"}})
status, body = start(env, ["b"], user="alice")
must(status == 202 and body["status"] == "running" and len(env.runs) == 1, (status, body))
run_id = body["run_id"]
must(env.plan_calls == [["b"]], "the run plans on the server from the ids only")
must(len(env.kinds("start")) == 1 and env.kinds("start")[0]["strict"] is True, "one strict start row")
must(env.kinds("start")[0]["metadata"]["order"] == ["a", "b"], env.kinds("start")[0])
must(env.ticks == [(run_id, 0, 0)], env.ticks)
must(run_mod.advance_run(env, run_id) is False, "first tick queues a")
must(env.stage_calls == [("repo-1", "a", "1.0.0")] and env.queue_calls == [("up-a", "alice")], (env.stage_calls, env.queue_calls))
must(states(env, run_id) == {"a": "installing", "b": "pending"}, states(env, run_id))
must(run_mod.advance_run(env, run_id) is False and len(env.stage_calls) == 1, "a tick while the job runs stages nothing")
env.jobs["job-a"]["status"] = "running"
must(run_mod.advance_run(env, run_id) is False and len(env.stage_calls) == 1, "still waiting while running")
env.finish_job("a")
must(run_mod.advance_run(env, run_id) is False, "a done, b queued")
must(states(env, run_id) == {"a": "succeeded", "b": "installing"} and env.stage_calls[1][1] == "b", states(env, run_id))
env.finish_job("b")
must(run_mod.advance_run(env, run_id) is True, "run ends")
must(env.runs[run_id]["status"] == "completed" and states(env, run_id) == {"a": "succeeded", "b": "succeeded"}, env.runs[run_id])
must(len(env.kinds("outcome")) == 2 and len(env.kinds("end")) == 1, [a["message"] for a in env.audits])
must(run_mod.advance_run(env, run_id) is True and len(env.kinds("end")) == 1, "a tick after the end changes nothing")
must(len(env.stage_calls) == 2 and len(env.queue_calls) == 2, "one job per module")
status, body = run_mod.progress(env, run_id)
must(status == 200 and body["counts"]["succeeded"] == 2 and body["counts"]["total"] == 2 and body["finished_at"], body)
text = repr(body).lower()
for word in ("sha256", "url", "publisher", "key_id", "token", "log_tail", "path"):
    must(word not in text, "progress leaks " + word)
# a start after the end is accepted
status, body2 = start(env, ["b"])
must(status == 202 and body2["run_id"] != run_id, (status, body2))

# ---------------------------------------------------------------- 2. a failed dependency skips its dependant, an unrelated module installs
env = Env(order=["a", "b", "c"], deps={"b": {"a": ">=1.0.0"}})
_, body = start(env)
run_id = body["run_id"]
run_mod.advance_run(env, run_id)
env.finish_job("a", "failed", "The package   failed\nits checks. " + "x" * 600)
final = run_mod.advance_run(env, run_id)
must(states(env, run_id) == {"a": "failed", "b": "skipped", "c": "installing"}, states(env, run_id))
must(module(env, run_id, "b")["code"] == "dependency_failed" and "(a)" in module(env, run_id, "b")["reason"], module(env, run_id, "b"))
must(len(module(env, run_id, "a")["reason"]) <= 400 and "\n" not in module(env, run_id, "a")["reason"], "job error cut to 400 chars, one line")
must(("repo-1", "b", "1.0.0") not in env.stage_calls, "the dependant is never staged")
env.finish_job("c")
must(run_mod.advance_run(env, run_id) is True and env.runs[run_id]["status"] == "completed", env.runs[run_id])
must(len(env.kinds("outcome")) == 3 and len(env.kinds("end")) == 1, len(env.audits))
must(env.kinds("end")[0]["metadata"]["counts"] == {"failed": 1, "skipped": 1, "succeeded": 1}, env.kinds("end")[0])
# dispatch_failed counts as failed
env = Env(order=["a"])
_, body = start(env)
run_mod.advance_run(env, body["run_id"])
env.finish_job("a", "dispatch_failed", "helper down")
must(run_mod.advance_run(env, body["run_id"]) is True and states(env, body["run_id"]) == {"a": "failed"}, "dispatch_failed")

# ---------------------------------------------------------------- 3. stop mid-run
env = Env(order=["a", "b", "c"])
_, body = start(env)
run_id = body["run_id"]
run_mod.advance_run(env, run_id)
stops = []
status, sbody = run_mod.request_stop(env, run_id, lambda run: stops.append(run["run_id"]))
must(status == 200 and sbody["status"] == "stopping" and sbody["stop_requested"] and stops == [run_id], (status, sbody))
job_before = copy_job = dict(env.jobs["job-a"])
must(run_mod.advance_run(env, run_id) is False and len(env.stage_calls) == 1, "nothing starts while the job is in flight")
must(env.jobs["job-a"] == job_before, "a job in flight is never touched")
env.finish_job("a")
must(run_mod.advance_run(env, run_id) is True, "ends stopped")
must(env.runs[run_id]["status"] == "stopped" and states(env, run_id) == {"a": "succeeded", "b": "skipped", "c": "skipped"}, env.runs[run_id])
must(module(env, run_id, "b")["code"] == "stopped" and len(env.stage_calls) == 1 and len(env.kinds("end")) == 1, "pending skipped 'stopped'")
status, fbody = run_mod.request_stop(env, run_id, lambda run: stops.append("again"))
must(status == 409 and fbody["state"] == "already_finished" and stops == [run_id], (status, fbody))
status, ubody = run_mod.request_stop(env, "00000000-0000-4000-8000-000000000000", lambda run: None)
must(status == 404, status)
status, _ = run_mod.progress(env, "00000000-0000-4000-8000-000000000000")
must(status == 404, status)
# stop before anything is in flight ends the run with no module started
env = Env(order=["a", "b"])
_, body = start(env)
run_mod.request_stop(env, body["run_id"], lambda run: None)
must(env.runs[body["run_id"]]["status"] == "running", "no module in flight: status stays running until the next tick")
must(run_mod.advance_run(env, body["run_id"]) is True and env.stage_calls == [] and env.runs[body["run_id"]]["status"] == "stopped", "stopped, nothing staged")
# a busy lock makes stop wait and then answer 503
env = Env(order=["a"])
_, body = start(env)
env.locked.add(body["run_id"])
orig_sleep = run_mod.time.sleep
run_mod.time.sleep = lambda s: None
try:
    status, _ = run_mod.request_stop(env, body["run_id"], lambda run: None)
finally:
    run_mod.time.sleep = orig_sleep
must(status == 503, status)

# ---------------------------------------------------------------- 4. second start while a run is going
env = Env(order=["a"])
_, body = start(env)
status, again = start(env)
must(status == 409 and again["state"] == "run_in_progress" and again["run_id"] == body["run_id"] and len(env.runs) == 1, (status, again))
env.start_busy = True
env2 = Env(order=["a"])
env2.start_busy = True
status, busy = start(env2)
must(status == 409 and busy["state"] == "run_in_progress" and not env2.runs, (status, busy))

# ---------------------------------------------------------------- 5. deselected or re-versioned between start and its turn
env = Env(order=["a", "b", "c"])
_, body = start(env)
run_id = body["run_id"]
env.allowed_body["modules"][1]["selected"] = False  # b unticked
env.allowed_body["modules"][2]["release"]["version"] = "2.0.0"  # c re-versioned
run_mod.advance_run(env, run_id)
env.finish_job("a")
must(run_mod.advance_run(env, run_id) is True, "b and c are skipped, run ends")
must(module(env, run_id, "b")["code"] == "not_selected" and module(env, run_id, "c")["code"] == "version_changed", env.runs[run_id]["modules"])
must([c[1] for c in env.stage_calls] == ["a"], "never staged: " + repr(env.stage_calls))
env = Env(order=["a"])
_, body = start(env)
env.allowed_body = Env.make_allowed([], state="licensing_unavailable")
must(run_mod.advance_run(env, body["run_id"]) is True and module(env, body["run_id"], "a")["code"] == "allowed_unavailable" and env.stage_calls == [], "fail closed")
env = Env(order=["a"])
_, body = start(env)
env.allowed_body["modules"][0]["release"] = None
must(run_mod.advance_run(env, body["run_id"]) is True and module(env, body["run_id"], "a")["code"] == "no_release" and env.stage_calls == [], "no release")

# ---------------------------------------------------------------- 6. plan-blocked modules are skipped with their code and never staged
env = Env(order=["b"], blocked=[("x", "not_selected"), ("y", "dependency_blocked"), ("z", "already_installed")], deps={"b": {"z": ">=1.0.0"}})
_, body = start(env, ["x", "y", "z", "b"])
run_id = body["run_id"]
must(states(env, run_id) == {"x": "skipped", "y": "skipped", "z": "skipped", "b": "pending"}, states(env, run_id))
must(module(env, run_id, "y")["code"] == "dependency_blocked" and module(env, run_id, "x")["reason"] == "blocked not_selected", env.runs[run_id])
run_mod.advance_run(env, run_id)
must([c[1] for c in env.stage_calls] == ["b"], "an already installed (plan-blocked) dependency does not skip its dependant: " + repr(env.stage_calls))
must(env.kinds("start")[0]["metadata"]["skipped"] == [{"id": "x", "code": "not_selected"}, {"id": "y", "code": "dependency_blocked"}, {"id": "z", "code": "already_installed"}], "start row lists the skipped")

# ---------------------------------------------------------------- 7. refused fields, plan not ok, empty order, audit not saved
must(run_mod.refused_fields({"modules": ["a"], "licence_override_reason": "x"}) == ["licence_override_reason"], "override refused")
must(run_mod.refused_fields({"modules": ["a"], "disable_replaced": ["m"]}) == ["disable_replaced"], "replacement confirmation refused")
must(run_mod.refused_fields({"modules": ["a"]}) == [], "clean body")
env = Env(order=["a"], plan_state="licensing_unavailable")
status, body = start(env)
must(status == 503 and not env.runs and not env.audits and not env.stage_calls, (status, body))
env = Env(order=["a"], plan_state="not_fetched")
status, body = start(env)
must(status == 200 and body["ok"] is False and not env.runs, "plan state not ok creates no run")
env = Env(order=[], blocked=[("a", "not_selected")])
status, body = start(env, ["a"])
must(status == 400 and body["state"] == "nothing_to_install" and body["blocked"] and not env.runs and not env.audits, (status, body))
env = Env(order=["a"])
env.audit_fail = True
status, body = start(env)
must(status == 503 and body["state"] == "audit_not_saved" and not env.runs and not env.ticks, "no row, no run")

# ---------------------------------------------------------------- 8. crashed tick, stale run, busy lock
env = Env(order=["a", "b"])
_, body = start(env)
run_id = body["run_id"]
run = env.runs[run_id]
run["modules"][0]["state"] = "downloading"  # an earlier tick died here, the lock is free
run_mod.advance_run(env, run_id)
must(module(env, run_id, "a")["state"] == "failed" and "download was interrupted" in module(env, run_id, "a")["reason"].lower(), module(env, run_id, "a"))
must(module(env, run_id, "b")["state"] == "installing", "the run goes on after the recovered module")
env.locked.add(run_id)
stages = len(env.stage_calls)
must(run_mod.advance_run(env, run_id) is False and len(env.stage_calls) == stages, "a busy lock returns at once with no second start")
env.locked.clear()
# stale run, no active job: closed interrupted exactly once
env = Env(order=["a", "b"])
_, body = start(env)
run_id = body["run_id"]
env.t += 20
must(run_mod.progress(env, run_id)[1]["status"] == "running", "20 seconds: not stale yet")
must(len(env.ticks) >= 1, "ticks queued")
ticks_before = len(env.ticks)
env.t += 20  # 40 s with no heartbeat: queue a tick again
run_mod.progress(env, run_id)
must(len(env.ticks) == ticks_before + 1 and not env.stage_calls, "progress queues a tick but never stages")
env.t += 900
status, pbody = run_mod.progress(env, run_id)
must(pbody["status"] == "interrupted" and all(m["state"] == "skipped" for m in pbody["modules"]), pbody)
must(module(env, run_id, "a")["code"] == "interrupted" and len(env.kinds("end")) == 1 and not env.stage_calls, "closed once")
run_mod.progress(env, run_id)
run_mod.close_if_stale(env, run_id)
must(len(env.kinds("end")) == 1 and len(env.kinds("outcome")) == 2, "exactly one end row")
# a stale run with a job still running is never closed
env = Env(order=["a", "b"])
_, body = start(env)
run_mod.advance_run(env, body["run_id"])
env.jobs["job-a"]["status"] = "running"
env.t += 5000
must(run_mod.progress(env, body["run_id"])[1]["status"] in ("running", "stopping") and not env.kinds("end"), "an active job is always waited for")
# a vanished job record fails the module after 20 ticks
env = Env(order=["a"])
_, body = start(env)
run_mod.advance_run(env, body["run_id"])
del env.jobs["job-a"]
for _ in range(25):
    if run_mod.advance_run(env, body["run_id"]):
        break
must(module(env, body["run_id"], "a")["code"] == "job_unreadable" and env.runs[body["run_id"]]["status"] == "completed", env.runs[body["run_id"]])
# the progress route reconciles a finished job without staging
env = Env(order=["a", "b"])
_, body = start(env)
run_mod.advance_run(env, body["run_id"])
env.finish_job("a")
status, pbody = run_mod.progress(env, body["run_id"])
must(pbody["modules"][0]["state"] == "succeeded" and len(env.stage_calls) == 1, "reconciled, b not staged by a GET")

# ---------------------------------------------------------------- 9. replacement confirmation, licence and unexpected errors fail one module with its sentence
for label, error, expect in (
        ("replacement", FakeError("Installing it would disable the module 'old'. Confirm it on its own."), "would disable the module"),
        ("licence", FakeError("The licence check refused this module."), "licence check refused"),
        ("unexpected", ValueError("secret /var/lib/path"), run_mod.TEXT["unexpected"])):
    env = Env(order=["a", "b"])
    env.queue_fail["a"] = error
    _, body = start(env)
    run_id = body["run_id"]
    run_mod.advance_run(env, run_id)
    must(module(env, run_id, "a")["state"] == "failed" and expect in module(env, run_id, "a")["reason"], (label, module(env, run_id, "a")))
    must("secret" not in module(env, run_id, "a")["reason"], "an unexpected error never shows its text")
    must(env.discards == ["up-a"], (label, "staged package discarded when queueing raises", env.discards))
    must(module(env, run_id, "b")["state"] == "installing" and env.runs[run_id]["status"] == "running", (label, "the run goes on"))
env = Env(order=["a", "b"], deps={"b": {"a": ">=1.0.0"}})
env.stage_fail["a"] = FakeError("Core has no saved catalogue entry.")
_, body = start(env)
run_mod.advance_run(env, body["run_id"])
must(states(env, body["run_id"]) == {"a": "failed", "b": "skipped"} and env.runs[body["run_id"]]["status"] == "completed" and env.discards == [], "stage error: failed, dependant skipped, nothing to discard")

# ---------------------------------------------------------------- 10. broker failure and a crashing tick never raise
env = Env(order=["a"])
_, body = start(env)
run_mod.advance_and_requeue(env, body["run_id"], 0)
must(env.ticks[-1] == (body["run_id"], 3, 1), "next tick in 3 seconds, next seq: " + repr(env.ticks))
env.finish_job("a")
count = len(env.ticks)
run_mod.advance_and_requeue(env, body["run_id"], 1)
must(len(env.ticks) == count, "a final run queues no more ticks")
env = Env(order=["a"])
env.load = lambda run_id: (_ for _ in ()).throw(OSError("disk"))
run_mod.advance_and_requeue(env, "00000000-0000-4000-8000-000000000001")
must(env.ticks == [("00000000-0000-4000-8000-000000000001", 3, None)], "a crashed tick is retried with the same seq, never raised")

# ---------------------------------------------------------------- 11. only the last 20 runs are kept
env = Env(order=["a"])
for index in range(23):
    env.t += 1
    status, body = start(env)
    must(status == 202, status)
    run_mod.advance_run(env, body["run_id"])
    env.finish_job("a")
    run_mod.advance_run(env, body["run_id"])
must(len(env.runs) <= run_mod.MAX_RUNS_KEPT + 1, len(env.runs))

# ---------------------------------------------------------------- 12. held Medium of the 1.18.19 review (module_install_plan)
RID = "00000000-0000-4000-8000-000000000001"


def plan_for(cache_version, resolver):
    allowed = {"state": "ok", "message": "ok", "plan_state": "valid", "plan_revision": 1, "fetched_at": "x", "modules": [
        {"id": "m", "name": "M", "category": "premium", "entitled": True, "availability": "available", "selected": True,
         "release": {"release_id": RID, "version": "1.0.0"}}]}
    cache = {("m", RID): {"id": "m", "name": "M", "version": cache_version, "release_id": RID, "dependencies": {}, "optional_dependencies": {}, "requires": {},
                          "category": "premium"}}
    return plan_mod.build_plan(["m"], allowed, cache, {}, resolver, lambda v, c: True, lambda p: "fake", lambda c: None, frozenset(), lambda r: [])


ok_resolver = lambda candidates: {"problems": [], "order": [c["id"] for c in candidates], "actions": [], "will_disable": [], "optional_dependencies": []}
good = plan_for("1.0.0", ok_resolver)
must(good["ok"] and [o["id"] for o in good["order"]] == ["m"], good)
differ = plan_for("1.1.0", ok_resolver)
must(differ["blocked"] and differ["blocked"][0]["code"] == "not_in_catalogue_cache" and not differ["order"], differ)


for exc in (FakeError("The installed module state is damaged."), ValueError("bad"), KeyError("x"), TypeError("t")):
    def raising(candidates, exc=exc):
        raise exc
    body = plan_for("1.0.0", raising)
    must(body["ok"] is True and body["valid"] is False and not body["order"], body)
    must(body["conflicts"] and body["conflicts"][0]["type"] == "plan_conflict" and body["conflicts"][0]["message"], body)
    must(body["blocked"] and body["blocked"][0]["code"] == "plan_conflict", body)

# ---------------------------------------------------------------- 13. source level
run_src = (PKG_DIR / "module_install_run.py").read_text(encoding="utf-8")
tree = ast.parse(run_src)
called = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func = node.func
        called.add(func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", ""))
for needed in ("stage_repository_package", "queue_v2_install", "discard_v2_stage"):
    must(needed in run_src, needed + " is the existing path")
for forbidden in ("remove", "uninstall", "queue_remove", "queue_uninstall", "queue_set_enabled", "set_enabled", "sha256", "hexdigest", "_fetch", "urlopen",
                  "verify_release_files", "resolve_install_plan", "queue_batch_install"):
    must(forbidden not in called, "module_install_run calls " + forbidden)
for banned in ("hashlib", "urllib", "subprocess", "import requests", "disable_replaced=", "licence_override_reason="):
    must(banned not in run_src, banned + " must not appear in module_install_run.py")
must("stage_repository_package(repository_id, module_id, version, request=None)" in run_src and "queue_v2_install(upload_id, requested_by=requested_by)" in run_src,
    "stage and queue calls are exactly the single-install ones, no disable_replaced")
must("fcntl" in run_src and "import fcntl" not in run_src.split("class FileStore")[0], "fcntl is imported lazily")

views_src = (PKG_DIR / "module_install_run_views.py").read_text(encoding="utf-8")
views_tree = ast.parse(views_src)
for cls_name, method in (("ModuleOnlineInstallRunView", "post"), ("ModuleOnlineInstallProgressView", "get"), ("ModuleOnlineInstallStopView", "post")):
    cls = next(n for n in views_tree.body if isinstance(n, ast.ClassDef) and n.name == cls_name)
    fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method)
    first = fn.body[0]
    must(isinstance(first, ast.Expr) and isinstance(first.value, ast.Call) and getattr(first.value.func, "id", "") == "_require_module_manager",
         cls_name + " must call _require_module_manager first")
    must("SessionAuthenticated" in ast.unparse(cls), cls_name + " needs SessionAuthenticated")
run_view = next(n for n in views_tree.body if isinstance(n, ast.ClassDef) and n.name == "ModuleOnlineInstallRunView")
reads = [n.args[0].value for n in ast.walk(run_view) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get" and n.args
         and isinstance(n.args[0], ast.Constant)]
must(reads == ["modules", "purpose"], "the start view reads only the module ids and (1.18.35) the purpose from the body: " + repr(reads))

urls_src = (PKG_DIR / "urls.py").read_text(encoding="utf-8")
contracts_src = (PKG_DIR / "contracts.py").read_text(encoding="utf-8")
docs_src = (ROOT / "docs" / "module-repositories.md").read_text(encoding="utf-8")
for route in ("modules/catalog/online/install/\"", "modules/catalog/online/install/<uuid:run_id>/\"", "modules/catalog/online/install/<uuid:run_id>/stop/\""):
    must(route in urls_src, "urls.py lacks " + route)
for route in ("/api/tfd/modules/catalog/online/install/\"", "/api/tfd/modules/catalog/online/install/<uuid:run_id>/\"",
              "/api/tfd/modules/catalog/online/install/<uuid:run_id>/stop/\""):
    must(route in contracts_src, "contracts.py lacks " + route)
for needle in ("online/install/", "online/install/<run_id>/", "tec_tac.advance_module_install_run", "interrupted", "Installing several licensed modules in one run (1.18.20)"):
    must(needle in docs_src, "docs lack " + needle)
must(docs_src.rstrip().endswith("techxflow.co.za"), "the footer stays last")
tasks_src = (PKG_DIR / "tasks.py").read_text(encoding="utf-8")
must('@app.task(name="tec_tac.advance_module_install_run", ignore_result=True, acks_late=True, reject_on_worker_lost=True, time_limit=900)' in tasks_src, "task registered")
must("advance_and_requeue" in tasks_src, "task body")
must('"tec_tac.module_install_run_views": "Tec-Tac · Module Repository"' in (PKG_DIR / "openapi.py").read_text(encoding="utf-8"), "openapi group")
plan_src = (PKG_DIR / "module_install_plan.py").read_text(encoding="utf-8")
must('cache.get("version")' in plan_src and "except (RuntimeError, ValueError, KeyError, TypeError)" in plan_src, "held Medium fix in the plan")
for name in ("framwork/tec_tac/module_install_run.py", "framwork/tec_tac/module_install_run_views.py", "framwork/tec_tac/tasks.py", "framwork/tec_tac/urls.py",
             "framwork/tec_tac/module_install_plan.py", "tests/online-install-run-1.18.20.py"):
    must(b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings")
for name in ("framwork/tec_tac/contracts.py", "docs/module-repositories.md", "docs/troubleshooting-diagnostics.md"):
    data = (ROOT / name).read_bytes()
    must(data.count(b"\r\n") == data.count(b"\n"), name + " must keep CRLF line endings")
# Rebuild fix: the run folder must be writable by the Tactical user (FileStore.root is MODULE_STATE_ROOT/install-runs).
lib_src = (ROOT / "scripts" / "recovery" / "lib.sh").read_text(encoding="utf-8")
must("${MODULE_ROOT}/install-runs|root:${group}|2770" in lib_src, "install-runs permission spec missing in lib.sh")
must('"${MODULE_ROOT}/install-runs" "${MODULE_ROOT}/hotfixes/staged"' in lib_src, "install-runs missing from the recovery runtime-write check")
install_src = (ROOT / "install.sh").read_text(encoding="utf-8")
must('"${MODULE_STATE_ROOT}/install-runs"' in install_src, "install-runs missing from the install.sh writable verification")
# Review round 1 (rewritten in 1.18.21): a busy run lock must not multiply tick chains on Celery. A busy tick requeues itself with the same seq and
# a delay; a poll never queues while the lock is held; the dead-chain recovery queues exactly one tick.
env = Env(order=["a"])
_, body = start(env, ["a"])
run_id = body["run_id"]
env.ticks.clear()
env.locked.add(run_id)  # a tick is staging a download and holds the flock
for _ in range(10):
    env.t += 40  # past STALE_TICK_SECONDS, the heartbeat is not refreshed while the lock holder works
    run_mod.progress(env, run_id)
must(env.ticks == [], "progress queues nothing while the lock is held: " + repr(env.ticks))
run_mod.advance_and_requeue(env, run_id, 0)
must(env.ticks == [(run_id, run_mod.BUSY_DELAY_SECONDS, 0)], "a tick on a busy lock requeues itself with the same seq: " + repr(env.ticks))
env.ticks.clear()
must(run_mod.advance_run(env, run_id) is False, "advance_run still reports not final on a busy lock")
env.locked.discard(run_id)  # the holder died: the flock is released
env.t += 40
run_mod.progress(env, run_id)
must(len(env.ticks) == 1, "one new tick once the lock is free and the heartbeat is stale")
outstanding = list(env.ticks)
env.ticks.clear()
for _ in range(5):
    for tick in outstanding:
        run_mod.advance_and_requeue(env, tick[0], tick[2])
    outstanding = list(env.ticks)
    env.ticks.clear()
    must(len(outstanding) <= 1, "outstanding ticks stay at 1 or less")
print("online install run 1.18.20 regression: PASS")
