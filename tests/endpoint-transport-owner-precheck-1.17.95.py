#!/usr/bin/env python3
"""1.17.95 regression (held Medium and Low of the 1.17.94 review): nats-comms is refused before any owner is registered while endpoint-comms is
installed and enabled; the except branch of _verified_owner_id answers None.

Uses the real _owner_folder with a stubbed plugin registry and module state (as tests/endpoint-transport-owner-1.17.94.py). Covered: nats-comms
refused at request, send_many and presence before registration while endpoint-comms is installed and enabled; accepted when endpoint-comms is
absent, disabled or legacy; endpoint-comms accepted before registration; registered owner rules unchanged (the registered nats-comms keeps
working until the process restarts); register_owner still answers with a reason; an exception inside the walk gives None, and _caller_is_owner is
False; the answer is cached inside its window (one scan) and read again after it; a read fault refuses nats-comms and is kept one second only.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must, reset, CACHE = H.et, H.must, H.reset, H.CACHE
REQ = {"v": 1, "type": "request", "id": "r1", "func": "status.get", "payload": {}}
EVT = {"v": 1, "type": "event", "id": "e1", "func": "notice.show", "payload": {"text": "hi"}}
IDS = ("endpoint-comms", "nats-comms")
FOLDERS = {i: os.path.normcase(os.path.realpath(str(Path(H.ROOT) / "fake-owner-folders" / i))) for i in IDS}
INSTALLED = {}
LEGACY = set()
SCANS = [0]
FAULT = [False]


def _plugins():
    SCANS[0] += 1
    if FAULT[0]:
        raise RuntimeError("registry unreadable")
    return [SimpleNamespace(plugin_id=i, plugin_type="extension", legacy=i in LEGACY, root=FOLDERS[i]) for i in INSTALLED]


registry = types.ModuleType("tec_tac.registry")
registry.discover_plugins = _plugins
state = types.ModuleType("tec_tac.module_state")
state.load_state = dict
state.is_enabled = lambda module_id, st=None: INSTALLED.get(module_id, False)
sys.modules["tec_tac.registry"], sys.modules["tec_tac.module_state"] = registry, state
sys.modules["tec_tac"].registry, sys.modules["tec_tac"].module_state = registry, state

NOW = [1000.0]
et._clock = lambda: NOW[0]


def fresh(installed, caller):
    reset()
    INSTALLED.clear()
    INSTALLED.update(installed)
    LEGACY.clear()
    FAULT[0] = False
    SCANS[0] = 0
    NOW[0] += 100  # past every cache window
    H.CALLER["module_id"] = caller
    CACHE.set(et.presence_key("a1"), {"connected": True, "since": "2026-10-29T10:00:00+00:00", "owner": "o"}, 150)


def denied(label):
    must(et.request("nats-comms", "a1", REQ, 1)["outcome"] == "denied", label + " request")
    must(et.send_many("nats-comms", ["a1"], EVT)["outcome"] == "denied", label + " send_many")
    must(et.presence("nats-comms", ["a1"])["outcome"] == "denied", label + " presence")


def works(who, label):
    must(et.request(who, "a1", REQ, 1)["outcome"] in ("timeout", "ok"), label + " request")
    must(et.send_many(who, ["a1"], EVT)["outcome"] == "ok", label + " send_many")
    must(et.presence(who, ["a1"])["outcome"] == "ok", label + " presence")


et.MIN_REQUEST_TIMEOUT = 0.1

# nats-comms refused before registration while endpoint-comms is installed and enabled
fresh({"endpoint-comms": True, "nats-comms": True}, "nats-comms")
denied("nats-comms before registration, endpoint-comms enabled")
must(not et.get_owner(), "nothing registered")
fresh({"endpoint-comms": True}, "nats-comms")
denied("nats-comms with only endpoint-comms installed")

# accepted when endpoint-comms is absent, disabled or legacy
for installed, legacy in (({"nats-comms": True}, False), ({"endpoint-comms": False, "nats-comms": True}, False), ({"endpoint-comms": True, "nats-comms": True}, True)):
    fresh(installed, "nats-comms")
    if legacy:
        LEGACY.add("endpoint-comms")
    works("nats-comms", f"nats-comms with {installed} legacy={legacy}")

# endpoint-comms is accepted before registration, with or without nats-comms installed
fresh({"endpoint-comms": True, "nats-comms": True}, "endpoint-comms")
works("endpoint-comms", "endpoint-comms before registration")
must(SCANS[0] == 0, "endpoint-comms needs no scan on the hot path")

# register_owner still answers with a reason for nats-comms, and a registered owner's rules are unchanged
fresh({"endpoint-comms": True, "nats-comms": True}, "nats-comms")
refused = et.register_owner("nats-comms", "x_tasks.handle")
must(refused["outcome"] == "denied" and "endpoint-comms" in refused["reason"], refused)
fresh({"nats-comms": True}, "nats-comms")
tasks = types.ModuleType("nats_tasks95")


class _Task:
    name = "nats-comms.handle"
    run = SimpleNamespace(__code__=SimpleNamespace(co_filename=str(Path(FOLDERS["nats-comms"]) / "tasks.py")))

    def apply_async(self, *a, **k):
        return None


tasks.handle = _Task()
sys.modules["nats_tasks95"] = tasks
must(et.register_owner("nats-comms", "nats_tasks95.handle")["outcome"] == "ok", "nats-comms registers alone")
INSTALLED["endpoint-comms"] = True  # endpoint-comms appears later: the registered owner keeps working until the process restarts
NOW[0] += 100
works("nats-comms", "registered nats-comms")
H.CALLER["module_id"] = "endpoint-comms"
must(et.request("endpoint-comms", "a1", REQ, 1)["outcome"] == "denied", "endpoint-comms after nats-comms registered: unchanged 1.17.94 rule")

# an exception inside the walk gives None, and _caller_is_owner is False
fresh({"nats-comms": True}, "nats-comms")
import tec_tac.caller_identity as ci  # noqa: E402

real = ci.calling_module_for_core_provider


def boom(**kwargs):
    raise RuntimeError("walk failed")


ci.calling_module_for_core_provider = boom
must(et._verified_owner_id() is None, "an exception gives None")
must(et._caller_is_owner() is False, "_caller_is_owner is False")
must(et.request("nats-comms", "a1", REQ, 1)["outcome"] == "denied", "an exception refuses")
for bad in (0, False):
    must(et.request(bad, "a1", REQ, 1)["outcome"] in ("denied", "invalid"), f"module_id {bad!r}")
ci.calling_module_for_core_provider = real

# the cache: one scan inside the window, a new read after it
fresh({"endpoint-comms": True, "nats-comms": True}, "nats-comms")
for _ in range(5):
    must(et._verified_owner_id() is None, "refused")
must(SCANS[0] == 1, SCANS)
NOW[0] += et.PREFERRED_OWNER_SECONDS - 0.5
et._verified_owner_id()
must(SCANS[0] == 1, "still inside the window")
INSTALLED["endpoint-comms"] = False
NOW[0] += 1
must(et._verified_owner_id() == "nats-comms" and SCANS[0] == 2, "read again after the window; endpoint-comms is now disabled")

# a read fault counts as endpoint-comms present, and is kept one second only
fresh({"nats-comms": True}, "nats-comms")
FAULT[0] = True
must(et._verified_owner_id() is None, "a read fault refuses nats-comms")
scans = SCANS[0]
must(et._verified_owner_id() is None and SCANS[0] == scans, "the fault is kept inside its second")
FAULT[0] = False
NOW[0] += et.PREFERRED_OWNER_FAULT_SECONDS + 0.1
must(et._verified_owner_id() == "nats-comms", "read again after one second")

docs = (HERE.parent / "docs/endpoint-transport.md").read_text(encoding="utf-8")
must("Before any owner is registered" in docs and "1.17.95" in docs, "docs sentence")
print("PASS endpoint transport owner precheck 1.17.95")
