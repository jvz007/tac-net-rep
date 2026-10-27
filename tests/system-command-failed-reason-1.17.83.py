#!/usr/bin/env python3
"""1.17.83 regression (adds error and tactical_detail to 1.17.82's status and reason): a failed run_one reply carries `status` and a short `reason` (additive); outcome, output and message are unchanged; the reason is logged at info
without the command or the output. Runs without Django: system_commands.py is loaded alone with small fakes."""
from __future__ import annotations

import importlib.util
import logging
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
pkg = types.ModuleType("tt82")
pkg.__path__ = [str(ROOT)]
sys.modules["tt82"] = pkg
for _name in ("module_category", "tactical_operations"):
    spec = importlib.util.spec_from_file_location(f"tt82.{_name}", ROOT / f"{_name}.py")
    _mod = importlib.util.module_from_spec(spec)
    sys.modules[f"tt82.{_name}"] = _mod
    spec.loader.exec_module(_mod)
AUDITS = []
audit = types.SimpleNamespace(record=lambda **kw: AUDITS.append(kw))
sa = types.ModuleType("tt82.system_actions")
sa._actor_for = lambda owner: "actor"
sa._audit = lambda: audit
sys.modules["tt82.system_actions"] = sa
sched = types.ModuleType("tt82.scheduler")
sched.SchedulerTransientError = RuntimeError
sys.modules["tt82.scheduler"] = sched
spec = importlib.util.spec_from_file_location("tt82.system_commands", ROOT / "system_commands.py")
sc = importlib.util.module_from_spec(spec)
sys.modules["tt82.system_commands"] = sc
spec.loader.exec_module(sc)

must([sc.failure_reason(s) for s in (None, 401, 403, 404, 400, 422, 500, 502)] ==
     ["tactical_view_raised", "tactical_permission_denied", "tactical_permission_denied", "tactical_not_found", "tactical_bad_request", "tactical_bad_request", "tactical_error", "tactical_error"],
     "failure_reason maps the HTTP status to a short code")
e = sc.SendFailed(403)
must(e.status == 403 and e.reason == "tactical_permission_denied" and isinstance(e, RuntimeError), "SendFailed keeps the status and reason and is still a RuntimeError")

sc._service_user = lambda: object()
sc.route_agent_id = lambda pk: "x" * 27
sc._check_route = lambda path: None
sc.count_run = lambda run_id: 1
sc.claim = lambda *a, **k: True
sc.release = lambda *a, **k: None
definition = types.SimpleNamespace(function="agent.command", module_id="remote-background", id="a")
run = types.SimpleNamespace(id="r1")
verified = types.SimpleNamespace(schedule_id="s1")
call = {"command_id": "c1", "template_id": "t", "template_hash": "h", "shell": "powershell", "timeout": 20, "command": "SECRET-COMMAND-TEXT"}


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append((record.levelno, record.getMessage()))


cap = Capture()
logging.getLogger("tec_tac.system_actions").addHandler(cap)
logging.getLogger("tec_tac.system_actions").setLevel(logging.DEBUG)


def go(send):
    sc._send = send
    sc._RECORDED.clear() if hasattr(sc._RECORDED, "clear") else None
    return sc.run_one(definition=definition, run=run, verified=verified, owner=None, provenance={"creator": "johan"}, extra={}, agent_pk=5, call=call)


def refuse_403(*a, **k):
    raise sc.SendFailed(403, "You do not have permission to perform this action.")


r = go(refuse_403)
must(r["outcome"] == "failed" and r["output"] == "" and r["message"] == "The command could not be sent." and r["truncated"] is False, "failed keeps outcome, output, truncated and message")
must(r["status"] == 403 and r["reason"] == "tactical_permission_denied", "a 403 from the view gives status 403 and tactical_permission_denied")
must(r["tactical_detail"].startswith("You do not have") and r["error"] == "SendFailed", "the reply holds Tactical's own detail sentence and the exception class name")
must(any(level == logging.INFO and "status=403" in text and "tactical_permission_denied" in text for level, text in cap.lines), "the cause is logged at info")
must(not any("SECRET-COMMAND-TEXT" in text for _, text in cap.lines), "the log never holds the command")


def boom(*a, **k):
    raise ValueError("nats down")


r = go(boom)
must(r["outcome"] == "failed" and r["status"] is None and r["reason"] == "tactical_view_raised" and r["error"] == "ValueError" and "nats down" not in str(r), "a view that raised gives status None, tactical_view_raised and the class name only")


def refused(*a, **k):
    raise sc.CommandRefused("function_unavailable", "long detail text")


r = go(refused)
must(r["status"] is None and r["reason"] == "function_unavailable" and "long detail" not in str(r), "a Core refusal gives its code, not its detail")
r = go(lambda *a, **k: "timeout")
must(r["outcome"] == "unreachable" and "status" not in r and "reason" not in r, "unreachable and ran replies are unchanged")
r = go(lambda *a, **k: "hello")
must(r["outcome"] == "ran" and r["output"] == "hello" and "status" not in r, "a ran reply is unchanged")
sys.exit(1 if FAILED else 0)
