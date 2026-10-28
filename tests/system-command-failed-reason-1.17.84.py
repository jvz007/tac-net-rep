#!/usr/bin/env python3
"""1.17.84 regression: the route guard of _send reads the view's CLASS name (Django 4+ and DRF leave the function called `view`), works in a fresh worker (no warmed urlconf), still fails closed, and a Core refusal reaches the caller with its code. Runs without Django: system_commands.py is loaded alone with small fakes."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "framwork" / "tec_tac"
FAILED = []


def must(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        FAILED.append(label)


class Cache:
    def add(self, *a, **k):
        return True

    def delete(self, *a, **k):
        pass

    def incr(self, key):
        return 1


cache_mod = types.ModuleType("django.core.cache")
cache_mod.cache = Cache()
sys.modules.update({"django": types.ModuleType("django"), "django.core": types.ModuleType("django.core"), "django.core.cache": cache_mod})
pkg = types.ModuleType("tt84")
pkg.__path__ = [str(ROOT)]
sys.modules["tt84"] = pkg
for _name in ("module_category", "tactical_operations"):
    spec = importlib.util.spec_from_file_location(f"tt84.{_name}", ROOT / f"{_name}.py")
    _mod = importlib.util.module_from_spec(spec)
    sys.modules[f"tt84.{_name}"] = _mod
    spec.loader.exec_module(_mod)
AUDITS = []
audit = types.SimpleNamespace(record=lambda **kw: AUDITS.append(kw))
sa = types.ModuleType("tt84.system_actions")
sa._actor_for = lambda owner: "actor"
sa._audit = lambda: audit
sys.modules["tt84.system_actions"] = sa
sched = types.ModuleType("tt84.scheduler")
sched.SchedulerTransientError = RuntimeError
sys.modules["tt84.scheduler"] = sched
spec = importlib.util.spec_from_file_location("tt84.system_commands", ROOT / "system_commands.py")
sc = importlib.util.module_from_spec(spec)
sys.modules["tt84.system_commands"] = sc
spec.loader.exec_module(sc)


import types as T


def view_func(cls_name, module="agents.views", via="cls"):
    cls = type(cls_name, (), {"__module__": module})
    f = T.SimpleNamespace(__name__="view", args=(), kwargs={})
    setattr(f, via, cls)
    return f

WARM = {"loaded": False}
CURRENT = {"func": view_func("send_raw_cmd")}

def resolve(path):
    # a worker process: the root urlconf is imported by resolve() itself on the first call, nothing was warmed by a request
    WARM["loaded"] = True
    if CURRENT["func"] is None:
        raise RuntimeError("urlconf import failed")
    return T.SimpleNamespace(func=CURRENT["func"], args=(), kwargs={"agent_id": "x"})

urls = T.ModuleType("django.urls")
urls.resolve = resolve
sys.modules["django.urls"] = urls

must(WARM["loaded"] is False, "fresh worker: nothing resolved before the first call")
m = sc._resolve_view("/agents/abc/cmd/")
must(WARM["loaded"] and m.func.__name__ == "view" and sc._view_name(m.func) == "send_raw_cmd", "a view whose function is called 'view' is read by its class name (DRF cls)")
CURRENT["func"] = view_func("send_raw_cmd", via="view_class")
must(sc._resolve_view("/x/").func is CURRENT["func"], "Django's view_class works too")
CURRENT["func"] = T.SimpleNamespace(__name__="send_raw_cmd", __module__="agents.views", args=(), kwargs={})
must(sc._resolve_view("/x/") is not None, "a plain function named send_raw_cmd (no class) in the agents app still passes")
for label, func in (("another view", view_func("other_view")), ("another app", view_func("send_raw_cmd", module="evil.views")), ("no __module__ (1.17.86)", T.SimpleNamespace(__name__="send_raw_cmd", args=(), kwargs={})), ("plain view name", T.SimpleNamespace(__name__="view", args=(), kwargs={})), ("no resolve", None)):
    CURRENT["func"] = func
    try:
        sc._resolve_view("/x/")
        must(False, f"{label} is refused")
    except sc.CommandRefused as exc:
        must(exc.reason == "function_unavailable", f"{label} is refused (fail closed)")

sc._service_user = lambda: object()
sc.route_agent_id = lambda pk: "x" * 27
sc._check_route = lambda path: None
sc.count_run = lambda run_id: 1
sc.claim = lambda *a, **k: True
sc.release = lambda *a, **k: None
definition = T.SimpleNamespace(function="agent.command", module_id="remote-background", id="a")
call = {"command_id": "c1", "template_id": "t", "template_hash": "h", "shell": "powershell", "timeout": 20, "command": "X"}
def run():
    return sc.run_one(definition=definition, run=T.SimpleNamespace(id="r1"), verified=T.SimpleNamespace(schedule_id="s"), owner=None, provenance={"creator": "johan"}, extra={}, agent_pk=5, call=call)
CURRENT["func"] = view_func("other_view")
AUDITS.clear()
try:
    run()
    must(False, "run_one refuses a wrong view")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable" and not AUDITS, "a wrong view is refused with its code before the claim and the audit row")
CURRENT["func"] = view_func("send_raw_cmd")
sc._dispatch_view = lambda match, request: T.SimpleNamespace(status_code=200, content=b'"done"')
sc._build_view_request = lambda *a, **k: object()
r = run()
must(r["outcome"] == "ran" and r["output"] == "done", "with the worker-style match the command goes through")
# a refusal raised after the claim (inside _send) is reported with its code, not as failed
sc._send = lambda *a, **k: (_ for _ in ()).throw(sc.CommandRefused("function_unavailable", "late"))
AUDITS.clear()
try:
    run()
    must(False, "late refusal raises")
except sc.CommandRefused as exc:
    closed = [a for a in AUDITS if a.get("metadata", {}).get("phase") == "closed"]
    must(exc.reason == "function_unavailable" and closed and closed[0]["metadata"]["outcome"] == "refused", "a Core refusal reaches the caller with its code and the closing row says refused")
sys.exit(1 if FAILED else 0)
