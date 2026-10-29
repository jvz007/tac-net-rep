#!/usr/bin/env python3
"""1.17.94 regression: endpoint-comms is accepted as the transport owner, nats-comms until dev02 has moved; exactly one owner at runtime.

Uses the real _owner_folder with a stubbed plugin registry and module state. Covered for each id: register, request, send_many and presence work;
the other id is then refused everywhere (both orders); both installed and enabled means endpoint-comms wins at register_owner; idempotent
re-registration, different path, task outside the folder, not installed or disabled; module_id argument not equal to the verified id, a foreign
module, Core itself and an unverifiable caller are denied.
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
INSTALLED = {}  # id -> enabled
LEGACY = set()


def _plugins():
    return [SimpleNamespace(plugin_id=i, plugin_type="extension", legacy=i in LEGACY, root=FOLDERS[i]) for i in INSTALLED]


registry = types.ModuleType("tec_tac.registry")
registry.discover_plugins = _plugins
state = types.ModuleType("tec_tac.module_state")
state.load_state = dict
state.is_enabled = lambda module_id, st=None: INSTALLED.get(module_id, False)
sys.modules["tec_tac.registry"], sys.modules["tec_tac.module_state"] = registry, state
sys.modules["tec_tac"].registry, sys.modules["tec_tac"].module_state = registry, state


class _Task:
    def __init__(self, name, folder):
        self.name = name
        self.run = SimpleNamespace(__code__=SimpleNamespace(co_filename=str(Path(folder) / "tasks.py")))

    def apply_async(self, *a, **k):
        return None


def make_task_module(module_name, task_name, folder):
    module = types.ModuleType(module_name)
    module.handle = _Task(task_name, folder)
    sys.modules[module_name] = module
    return f"{module_name}.handle"


PATH = {i: make_task_module(i.replace("-", "_") + "_tasks", i + ".handle", FOLDERS[i]) for i in IDS}
PATH_ROGUE = make_task_module("rogue94_tasks", "rogue.handle", str(Path(H.ROOT).resolve() / "elsewhere"))
PATH_OTHER = {i: make_task_module(i.replace("-", "_") + "_other", i + ".other", FOLDERS[i]) for i in IDS}


def fresh(installed=None, caller="endpoint-comms"):
    reset()
    INSTALLED.clear()
    INSTALLED.update(installed if installed is not None else {})
    LEGACY.clear()
    H.CALLER["module_id"] = caller
    CACHE.set(et.presence_key("a1"), {"connected": True, "since": "2026-10-29T10:00:00+00:00", "owner": "o"}, 150)


def operations_work(who, label):
    must(et.request(who, "a1", REQ, 1)["outcome"] in ("timeout", "ok"), label + " request")
    must(et.send_many(who, ["a1"], EVT)["outcome"] == "ok", label + " send_many")
    must(et.presence(who, ["a1"])["outcome"] == "ok", label + " presence")


def operations_denied(who, label):
    must(et.request(who, "a1", REQ, 1)["outcome"] == "denied", label + " request")
    must(et.send_many(who, ["a1"], EVT)["outcome"] == "denied", label + " send_many")
    must(et.presence(who, ["a1"])["outcome"] == "denied", label + " presence")
    must(et.register_owner(who, PATH.get(who, PATH["nats-comms"]))["outcome"] == "denied", label + " register_owner")


orig_min = et.MIN_REQUEST_TIMEOUT
et.MIN_REQUEST_TIMEOUT = 0.1
must(et.OWNER_MODULES == ("endpoint-comms", "nats-comms") and et.OWNER_MODULE == "endpoint-comms", "the owner ids")

# (1) and (2) each id alone registers and works
for who in IDS:
    fresh({who: True}, caller=who)
    done = et.register_owner(who, PATH[who])
    must(done["outcome"] == "ok" and not done["idempotent"], (who, done))
    must(et.get_owner() == {"module_id": who, "path": PATH[who], "task_name": who + ".handle"}, et.get_owner())
    operations_work(who, who)

# (3) the other id is refused once an owner is registered, in both orders; the owner stays
for first, second in (("endpoint-comms", "nats-comms"), ("nats-comms", "endpoint-comms")):
    fresh({first: True}, caller=first)
    must(et.register_owner(first, PATH[first])["outcome"] == "ok", "first owner")
    INSTALLED[second] = True
    H.CALLER["module_id"] = second
    operations_denied(second, f"{second} after {first}")
    refused = et.register_owner(second, PATH[second])
    must(refused["outcome"] == "denied", refused)
    must(et.get_owner()["module_id"] == first, "owner unchanged")
    must(et.register_owner(second, PATH[first])["outcome"] == "denied", "same path from the other id")
    must(et.get_owner()["module_id"] == first, "owner unchanged after the same-path attempt")
    H.CALLER["module_id"] = first
    operations_work(first, first + " still works")

# (4) both installed and enabled: endpoint-comms wins at register_owner, nats-comms is refused naming endpoint-comms
fresh({"endpoint-comms": True, "nats-comms": True}, caller="nats-comms")
refused = et.register_owner("nats-comms", PATH["nats-comms"])
must(refused["outcome"] == "denied" and "endpoint-comms" in refused["reason"] and not et.get_owner(), refused)
H.CALLER["module_id"] = "endpoint-comms"
must(et.register_owner("endpoint-comms", PATH["endpoint-comms"])["outcome"] == "ok", "endpoint-comms wins")
# endpoint-comms installed but disabled: nats-comms may register
fresh({"endpoint-comms": False, "nats-comms": True}, caller="nats-comms")
must(et.register_owner("nats-comms", PATH["nats-comms"])["outcome"] == "ok", "nats-comms when endpoint-comms is disabled")

# (5) idempotent, different path, outside folder, not installed, disabled, legacy: for each id
for who in IDS:
    fresh({who: True}, caller=who)
    must(et.register_owner(who, PATH[who])["outcome"] == "ok", "first")
    again = et.register_owner(who, PATH[who])
    must(again["outcome"] == "ok" and again["idempotent"], again)
    must(et.register_owner(who, PATH_OTHER[who])["outcome"] == "invalid" and et.get_owner()["path"] == PATH[who], "different path")
    fresh({who: True}, caller=who)
    must(et.register_owner(who, PATH_ROGUE)["outcome"] == "invalid" and not et.get_owner(), "task outside the folder")
    must(et.register_owner(who, "missing94_tasks.handle")["outcome"] == "invalid", "import fault")
    must(et.register_owner(who, "not a path!")["outcome"] == "invalid", "bad path")
    fresh({}, caller=who)
    must(et.register_owner(who, PATH[who])["outcome"] == "denied", "not installed")
    fresh({who: False}, caller=who)
    must(et.register_owner(who, PATH[who])["outcome"] == "denied", "disabled")
    fresh({who: True}, caller=who)
    LEGACY.add(who)
    must(et.register_owner(who, PATH[who])["outcome"] == "denied", "legacy plugin")

# (6) argument mismatch, foreign module, Core itself, unverifiable caller
for who in IDS:
    other = IDS[1 - IDS.index(who)]
    fresh({who: True}, caller=who)
    must(et.register_owner(other, PATH[who])["outcome"] == "denied", "module_id is the other owner id")
    must(et.register_owner("someone-else", PATH[who])["outcome"] == "denied", "module_id foreign")
    must(et.request(other, "a1", REQ)["outcome"] == "invalid", "request module_id mismatch")
    must(et.send_many(other, ["a1"], EVT)["outcome"] == "invalid", "send_many module_id mismatch")
    must(et.presence(other, ["a1"])["outcome"] == "invalid", "presence module_id mismatch")
    for bad in ("halopsa", "core", None):
        fresh({who: True}, caller=bad)
        operations_denied(who, f"{who} claimed by caller {bad}")
        must(not et.get_owner(), "a refused caller changed nothing")

et.MIN_REQUEST_TIMEOUT = orig_min
print("PASS endpoint transport owner 1.17.94")
