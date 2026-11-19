#!/usr/bin/env python3
"""Regression: Core 1.18.21 install run chain (the review 1.18.20-1 findings). One live tick chain per run through a tick token (seq), a busy tick
requeues itself with the same seq, Stop only sets the flag, a dead chain is restarted by one poll, and raw helper or stage errors never reach an
audit row or the progress body. Django-free: the same injected collaborators as online-install-run-1.18.20.py, with a fake broker that the test pumps
like Celery (pop a queued tick, run it). FileStore locking (fcntl), the Celery task and the real stage and queue path run only on dev02."""
import contextlib
import copy
import importlib
import json
import logging
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



class BrokerEnv(Env):
    """Env plus a broker: ``broker`` holds the queued ticks (run_id, countdown, seq); ``history`` keeps every enqueue. A stage hook runs while the
    run lock is held, like a long download."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.broker, self.history, self.broker_down, self.stage_hook = [], [], False, None

    def enqueue_tick(self, run_id, countdown, seq=None):
        if self.broker_down:
            return False
        self.history.append((run_id, countdown, seq))
        self.broker.append((run_id, countdown, seq))
        return True

    def stage(self, repository_id, module_id, version):
        if self.stage_hook:
            self.stage_hook(self, module_id)
        return super().stage(repository_id, module_id, version)


def pump(env):
    """Run the oldest queued tick like a Celery worker. False when the broker is empty."""
    if not env.broker:
        return False
    run_id, _countdown, seq = env.broker.pop(0)
    run_mod.advance_and_requeue(env, run_id, seq)
    return True


def begin(env):
    status, body = start(env)
    must(status == 202, (status, body))
    return body["run_id"]


# ---------------------------------------------------------------- 1. a poll racing a tick
env = BrokerEnv(order=["a", "b"])
run_id = begin(env)
must(env.broker == [(run_id, 0, 0)], env.broker)
tick = env.broker.pop(0)
env.locked.add(run_id)  # a poll (or stop) holds the lock for a moment
run_mod.advance_and_requeue(env, run_id, tick[2])
must(env.broker == [(run_id, run_mod.BUSY_DELAY_SECONDS, 0)], "the busy tick requeues itself with the same seq and a delay: " + repr(env.broker))
must(run_mod.BUSY_DELAY_SECONDS > 0 and not env.stage_calls, "nothing was staged while busy")
env.locked.discard(run_id)
must(pump(env), "the requeued tick runs")
must(states(env, run_id)["a"] == "installing" and len(env.broker) == 1 and env.broker[0][2] == 1, "the run moved on, one tick outstanding: " + repr(env.broker))
must(run_mod.advance_run(env, run_id) is False, "advance_run keeps its meaning")

# ---------------------------------------------------------------- 2. 20 polls across a 60 second download: never more than one tick outstanding
env = BrokerEnv(order=["a"])
run_id = begin(env)
seen = []


def download(e, module_id):
    for _ in range(20):
        e.t += 3
        status, _ = run_mod.progress(e, run_id)  # the lock is held by this tick, so these polls cannot start a tick
        must(status == 200, status)
        seen.append(len(e.broker))


env.stage_hook = download
env.broker.pop(0)  # the start tick, run below as the worker
run_mod.advance_and_requeue(env, run_id, 0)
must(max(seen) == 0 and len(seen) == 20, "no poll queued a tick during the download: " + repr(seen))
must(len(env.broker) == 1 and env.broker[0][2] == 1, "the tick itself queued the next one: " + repr(env.broker))
env.stage_hook = None
must(env.t - env.runs[run_id]["heartbeat"] < run_mod.STALE_TICK_SECONDS, "the heartbeat was refreshed after the download")
for _ in range(20):
    env.t += 0.1
    run_mod.progress(env, run_id)
must(len(env.broker) == 1, "polls right after the download queue nothing: " + repr(env.broker))

# ---------------------------------------------------------------- 3. a poll in the 3 s gap after a long download queues nothing
env = BrokerEnv(order=["a", "b"])
run_id = begin(env)
env.stage_hook = lambda e, m: setattr(e, "t", e.t + 100)  # a 100 s download
env.broker.pop(0)
run_mod.advance_and_requeue(env, run_id, 0)
env.stage_hook = None
env.t += 2  # inside the 3 s gap before the next tick
before = len(env.history)
for _ in range(5):
    run_mod.progress(env, run_id)
must(len(env.history) == before and len(env.broker) == 1, "no tick queued from a poll in the gap: " + repr(env.broker))
env.t += 1
env.finish_job("a")
must(pump(env), "the live tick runs")
must(len(env.broker) == 1 and env.broker[0][2] == 2, repr(env.broker))

# ---------------------------------------------------------------- 4. a dead chain is restarted by exactly one poll
env = BrokerEnv(order=["a"])
run_id = begin(env)
old_tick = env.broker.pop(0)  # the chain is lost: the tick never ran, but a copy is still somewhere in the broker
env.t += 40
run_mod.progress(env, run_id)
must(len(env.broker) == 1 and env.broker[0][1] == 0 and env.broker[0][2] == 1, "the first poll queues exactly one tick: " + repr(env.broker))
for _ in range(10):
    run_mod.progress(env, run_id)
must(len(env.broker) == 1, "ten more polls queue none: " + repr(env.broker))
run_mod.advance_and_requeue(env, old_tick[0], old_tick[2])
must(not env.stage_calls and len(env.broker) == 1, "the older tick ends on the seq check")
must(pump(env) and env.stage_calls == [("repo-1", "a", "1.0.0")], "the recovery tick installs")

# ---------------------------------------------------------------- 5. a duplicate tick with a consumed seq does nothing
env = BrokerEnv(order=["a", "b"])
run_id = begin(env)
first = env.broker.pop(0)
run_mod.advance_and_requeue(env, run_id, first[2])
must(len(env.stage_calls) == 1 and len(env.broker) == 1, "first tick staged one module")
queued = list(env.broker)
run_mod.advance_and_requeue(env, run_id, first[2])
must(len(env.stage_calls) == 1 and len(env.queue_calls) == 1 and env.broker == queued, "the redelivered duplicate stages and queues nothing")

# ---------------------------------------------------------------- 6. a tick queued by 1.18.20 (no seq) is accepted once
env = BrokerEnv(order=["a", "b"])
run_id = begin(env)
env.broker.clear()
del env.runs[run_id]["seq"]  # a run file written by 1.18.20
run_mod.advance_and_requeue(env, run_id)  # the old message carries no seq
must(len(env.stage_calls) == 1 and len(env.broker) == 1 and env.broker[0][2] == 1, "the legacy tick runs once and the chain gets a seq: " + repr(env.broker))
run_mod.advance_and_requeue(env, run_id)  # a duplicate legacy message
must(len(env.stage_calls) == 1 and len(env.broker) == 1, "a second legacy tick dies")

# ---------------------------------------------------------------- 7. a broker failure never raises and a poll recovers after 30 s
env = BrokerEnv(order=["a"])
run_id = begin(env)
env.broker.pop(0)
env.broker_down = True
run_mod.advance_and_requeue(env, run_id, 0)  # stages, but the next tick cannot be queued
must(states(env, run_id)["a"] == "installing" and not env.broker, "the module is installing, no tick queued")
env.broker_down = False
env.t += 10
run_mod.progress(env, run_id)
must(not env.broker, "10 s: heartbeat still fresh")
env.t += 25
run_mod.progress(env, run_id)
must(len(env.broker) == 1, "after 30 s one poll recovers: " + repr(env.broker))
run_mod.progress(env, run_id)
must(len(env.broker) == 1, "and only one")
env.finish_job("a")
pump(env)
must(env.runs[run_id]["status"] == "completed" and not env.broker, "the recovered chain ends the run with no tick queued")

# ---------------------------------------------------------------- 8. every sequence ends final with no tick queued
env = BrokerEnv(order=["a", "b", "c"], deps={"b": {"a": ">=1.0.0"}})
run_id = begin(env)
guard = 0
while env.broker and guard < 100:
    guard += 1
    for module_id in ("a", "b", "c"):
        if f"job-{module_id}" in env.jobs and env.jobs[f"job-{module_id}"]["status"] == "queued" and guard % 3 == 0:
            env.finish_job(module_id)
    env.t += 3
    run_mod.progress(env, run_id)
    must(len(env.broker) <= 1, "never more than one outstanding tick: " + repr(env.broker))
    pump(env)
must(env.runs[run_id]["status"] == "completed" and not env.broker, (env.runs[run_id]["status"], env.broker))
must(len(env.kinds("end")) == 1, "one end audit row")

# ---------------------------------------------------------------- 9. Stop only sets the flag
env = BrokerEnv(order=["a", "b"])
run_id = begin(env)
pump(env)  # one tick: module a installing, one tick queued
must(states(env, run_id) == {"a": "installing", "b": "pending"}, states(env, run_id))
history = len(env.history)
stops = []
for _ in range(5):
    status, body = run_mod.request_stop(env, run_id, lambda run: stops.append(1))
    must(status == 200 and body["status"] == "stopping" and body["stop_requested"], (status, body))
must(len(env.history) == history and len(env.broker) == 1, "five Stop clicks queued no tick")
must(stops == [1], "a repeated Stop is not audited again")
env.finish_job("a")
must(pump(env), "the one outstanding tick runs")
must(env.runs[run_id]["status"] == "stopped" and states(env, run_id) == {"a": "succeeded", "b": "skipped"}, env.runs[run_id])
must(module(env, run_id, "b")["code"] == "stopped" and len(env.kinds("end")) == 1 and not env.broker, "stopped once, no tick queued")
history = len(env.history)
status, body = run_mod.request_stop(env, run_id, lambda run: None)
must(status == 409 and body["state"] == "already_finished" and len(env.history) == history, (status, body))
# stop racing a tick (the lock is held): 503 and nothing queued
env = BrokerEnv(order=["a"])
run_id = begin(env)
env.locked.add(run_id)
history = len(env.history)
real_sleep = run_mod.time.sleep
run_mod.time.sleep = lambda s: None  # request_stop waits up to 2 s for the lock
try:
    status, body = run_mod.request_stop(env, run_id, lambda run: None)
finally:
    run_mod.time.sleep = real_sleep
env.locked.discard(run_id)
must(status == 503 and body["state"] == "busy" and len(env.history) == history and not env.runs[run_id]["stop_requested"], (status, body))

# ---------------------------------------------------------------- 10. raw helper and stage errors never reach an audit row or the progress body
records = []


class Capture(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())


handler = Capture()
run_mod.logger.addHandler(handler)
run_mod.logger.setLevel(logging.WARNING)
env = BrokerEnv(order=["a"])
run_id = begin(env)
pump(env)
env.finish_job("a", "failed", "refusing non-root-owned or writable lifecycle script: /usr/local/x")
pump(env)
a = module(env, run_id, "a")
must(a["state"] == "failed" and a["reason"] == run_mod.TEXT["job_failed_detail"].format(stage="done"), a)
must('"done"' in a["reason"], "the stage word is named")
must("/usr/local" not in json.dumps(env.audits) and "/usr/local" not in json.dumps(run_mod.progress(env, run_id)[1]), "no path in audit rows or the body")
must(any("/usr/local/x" in r and "job-a" in r for r in records), "the raw text is in the log with the job id: " + repr(records))
word = run_mod._stage_word("../../etc/PASSWD x" + "y" * 80)
must(word == "etcpasswd x" + "y" * 29, word)
env = BrokerEnv(order=["a"])
env.stage_fail["a"] = FakeError("Repository configuration is unreadable: /etc/tec-tac/repositories.json")
run_id = begin(env)
pump(env)
must(module(env, run_id, "a")["reason"] == run_mod.TEXT["install_refused"], module(env, run_id, "a"))
must("/etc/tec-tac" not in json.dumps(env.audits) and any("/etc/tec-tac/repositories.json" in r for r in records), "stage path only in the log")
for text in ("Installing it would disable the module 'old'. Confirm it on its own.", "The licence check refused this module."):
    env = BrokerEnv(order=["a"])
    env.stage_fail["a"] = FakeError(text)
    run_id = begin(env)
    pump(env)
    must(module(env, run_id, "a")["reason"] == text, "Core's own sentence passes through: " + text)
for bad in ("see C:\\temp\\x", "https://x.example/y", "a" * 241, "a\\b"):
    must(run_mod._safe_sentence(bad) is None, bad)
must(run_mod._safe_sentence("Note: this module needs Core 1.18.") is not None, "a colon in a sentence is fine")
run_mod.logger.removeHandler(handler)

# ---------------------------------------------------------------- 11. source checks
task_src = (PKG_DIR / "tasks.py").read_text(encoding="utf-8")
must("def advance_module_install_run(run_id: str, seq=None):" in task_src and "advance_and_requeue(live_env(), run_id, seq)" in task_src, "task takes an optional seq")
run_src = (PKG_DIR / "module_install_run.py").read_text(encoding="utf-8")
must("def enqueue_tick(run_id, countdown, seq=None):" in run_src and "[run_id] if seq is None else [run_id, seq]" in run_src, "live enqueue passes the seq")
must(b"\r" not in (PKG_DIR / "module_install_run.py").read_bytes() and b"\r" not in (PKG_DIR / "tasks.py").read_bytes(), "LF kept")
print("online install chain 1.18.21 regression: PASS")
