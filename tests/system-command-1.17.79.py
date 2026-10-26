#!/usr/bin/env python3
"""1.17.79 regression: a refused send-command route leaves no claim. run_one checks the route BEFORE count_run and claim, so the command_id is not burned
and a retry is not read as duplicate_command. Runs without Django: tactical_operations.py and system_commands.py load as one small package with fakes.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent / "framwork" / "tec_tac"
FAILED = []


def must(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        FAILED.append(label)


store = {}


class FakeCache:
    def add(self, key, value, timeout=None):
        if key in store:
            return False
        store[key] = value
        return True

    def incr(self, key):
        store[key] = store.get(key, 0) + 1
        return store[key]

    def delete(self, key):
        store.pop(key, None)


cache_mod = types.ModuleType("django.core.cache")
cache_mod.cache = FakeCache()
sys.modules.update({"django": types.ModuleType("django"), "django.core": types.ModuleType("django.core"), "django.core.cache": cache_mod})
pkg = types.ModuleType("tt79")
pkg.__path__ = [str(ROOT)]
sys.modules["tt79"] = pkg


def load(name):
    spec = importlib.util.spec_from_file_location(f"tt79.{name}", ROOT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"tt79.{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


load("module_category")
to = load("tactical_operations")
sc = load("system_commands")

AID = "x" * 20 + "ABCDEFG"
sc._service_user = lambda: object()
sc.route_agent_id = lambda pk: AID
sa = types.ModuleType("tt79.system_actions")
audits = []


class FakeAudit:
    def record(self, **kw):
        audits.append(kw)


sa._actor_for = lambda owner: "actor"
sa._audit = lambda: FakeAudit()
sys.modules["tt79.system_actions"] = sa
pkg.system_actions = sa
sched = types.ModuleType("tt79.scheduler")


class Transient(Exception):
    pass


sched.SchedulerTransientError = Transient
sys.modules["tt79.scheduler"] = sched
pkg.scheduler = sched
sc._already_recorded = lambda a, c: False
sent = []
sc._send = lambda *a, **k: sent.append(a) or "ok"

definition = types.SimpleNamespace(function="agent.command", id="agent.command", module_id="communicator")
run = types.SimpleNamespace(id="run-1")
verified = types.SimpleNamespace(schedule_id="s1")
call = {"command_id": "c1", "template_id": "t", "template_hash": "h", "shell": "cmd", "timeout": 5, "command": "x"}


def go():
    return sc.run_one(definition=definition, run=run, verified=verified, owner=None, provenance={}, extra={}, agent_pk=5, call=call)


sc.OWNER_MODULE = "premium-other"
try:
    go()
    must(False, "a refused route refuses run_one")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable", "a refused route refuses run_one with function_unavailable")
must(store == {}, "a refused route leaves no claim and no run count behind")
must(audits == [] and sent == [], "a refused route writes no audit row and sends nothing")

sc.OWNER_MODULE = "remote-background"
result = go()
must(result["outcome"] == "ran" and len(sent) == 1, "the retry with the same command_id runs: it is not read as duplicate_command")
try:
    go()
    must(False, "a second run of the same command_id is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "duplicate_command", "a second run of the same command_id is still duplicate_command")

print(("\nFAILED: " + ", ".join(FAILED)) if FAILED else "\nAll passed")
sys.exit(1 if FAILED else 0)
