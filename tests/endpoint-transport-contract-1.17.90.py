#!/usr/bin/env python3
"""1.17.90 regression: the contract core.endpoint_transport 1.0.0 (register_owner, request, send_many, presence).

Stubbed caller identity, cache and channel layer (tests/endpoint_transport_harness.py); the real endpoint_transport.py. Covered: a caller that
is not nats-comms (another module, Core itself, an unverifiable frame) gets denied from all four operations; register_owner refuses a task
outside nats-comms' folder and a second different path and accepts an identical one; request to an agent with no presence returns offline
at once without touching the channel layer, returns timeout within timeout + 1 s and frees the reply channel, returns ok with the right
reply; invalid frames and timeouts are refused; send_many over 2000 ids sends nothing, lists offline ids, uses one event loop and de-duplicates;
presence reads the cache once; the metadata names version 1.0.0 and matches the CORE_CONTRACTS rows.
"""
from __future__ import annotations

import ast
import asyncio
import importlib.util
import sys
import threading
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must, reset, CACHE, LAYER = H.et, H.must, H.reset, H.CACHE, H.LAYER
REQ = {"v": 1, "type": "request", "id": "r1", "func": "status.get", "payload": {}}
EVT = {"v": 1, "type": "event", "id": "e1", "func": "notice.show", "payload": {"text": "hi"}}


def connected(*ids):
    for agent_id in ids:
        CACHE.set(et.presence_key(agent_id), {"connected": True, "since": "2026-10-28T10:00:00+00:00", "owner": "o"}, 150)


def all_denied(label):
    must(et.register_owner("nats-comms", "nats_comms.tasks.handle")["outcome"] == "denied", label + " register_owner")
    must(et.request("nats-comms", "a1", REQ)["outcome"] == "denied", label + " request")
    must(et.send_many("nats-comms", ["a1"], EVT)["outcome"] == "denied", label + " send_many")
    must(et.presence("nats-comms", ["a1"])["outcome"] == "denied", label + " presence")
    provider = et._PROVIDER
    must(provider.request(module_id="nats-comms", agent_id="a1", frame=REQ)["outcome"] == "denied", label + " provider.request")


# ---------------------------------------------------------------- the caller is verified, never taken from the argument
for who in ("halopsa", "core", None):
    reset()
    H.CALLER["module_id"] = who
    connected("a1")
    all_denied(f"caller {who}")
    must(LAYER.group_calls == 0 and not et.get_owner(), "a refused caller changed nothing")

# ---------------------------------------------------------------- register_owner
reset()
import os  # noqa: E402

FOLDER = os.path.normcase(os.path.realpath(str(Path(H.ROOT) / "nats-comms-folder")))
et._owner_folder = lambda module_id=None: None
must(et.register_owner("nats-comms", "nats_comms.tasks.handle")["outcome"] == "denied", "owner not installed or not enabled")
et._owner_folder = lambda module_id=None: FOLDER if module_id in (None, "nats-comms") else None
must(et.register_owner("someone-else", "nats_comms.tasks.handle")["outcome"] == "denied", "module_id must equal the verified caller")
must(et.register_owner("nats-comms", "not a path!")["outcome"] == "invalid", "bad path text")


class _Task:
    name = "nats_comms.handle"

    def apply_async(self, *a, **k):
        return None

    def run(self):
        return None


def _make_module(name, file_name, task):
    module = types.ModuleType(name)
    module.handle = task
    sys.modules[name] = module
    return module


inside = _Task()
inside.run = types.SimpleNamespace(__code__=types.SimpleNamespace(co_filename=str(Path(FOLDER) / "tasks.py")))
outside = _Task()
outside.run = types.SimpleNamespace(__code__=types.SimpleNamespace(co_filename=str(Path(H.ROOT).resolve() / "elsewhere" / "tasks.py")))
not_celery = types.SimpleNamespace(run=lambda: None)
_make_module("nats_comms_tasks", "", inside)
_make_module("rogue_tasks", "", outside)
_make_module("plain_tasks", "", not_celery)
must(et.register_owner("nats-comms", "rogue_tasks.handle")["outcome"] == "invalid" and not et.get_owner(), "a task outside nats-comms' folder")
must(et.register_owner("nats-comms", "plain_tasks.handle")["outcome"] == "invalid" and not et.get_owner(), "not a Celery task")
must(et.register_owner("nats-comms", "missing_tasks.handle")["outcome"] == "invalid", "an import fault")
done = et.register_owner("nats-comms", "nats_comms_tasks.handle")
must(done["outcome"] == "ok" and not done["idempotent"], done)
must(et.get_owner() == {"module_id": "nats-comms", "path": "nats_comms_tasks.handle", "task_name": "nats_comms.handle"}, et.get_owner())
again = et.register_owner("nats-comms", "nats_comms_tasks.handle")
must(again["outcome"] == "ok" and again["idempotent"], "an identical re-registration is idempotent")
must(et.register_owner("nats-comms", "rogue_tasks.handle")["outcome"] == "invalid" and et.get_owner()["path"] == "nats_comms_tasks.handle", "a different path is refused")

# ---------------------------------------------------------------- request
reset()
before = LAYER.group_calls


class _NoLayer:
    def __getattr__(self, name):
        raise AssertionError("the channel layer was touched: " + name)


real_layer = et._channel_layer
et._channel_layer = lambda: _NoLayer()
must(et.request("nats-comms", "a1", REQ) == {"outcome": "offline", "reply": None}, "offline at once")
et._channel_layer = real_layer
must(LAYER.group_calls == before and not LAYER.channels, "offline touched nothing")
connected("a1")
for bad in ({**REQ, "type": "event"}, {**REQ, "v": 2}, {**REQ, "payload": 3}, "frame", None, {**REQ, "payload": {"x": "y" * 70000}}):
    must(et.request("nats-comms", "a1", bad)["outcome"] == "invalid", bad if not isinstance(bad, dict) else list(bad))
must(et.request("nats-comms", "bad id", REQ)["outcome"] == "invalid", "bad agent id")
must(et.request("other", "a1", REQ)["outcome"] == "invalid", "module id must equal the verified caller")
for bad_timeout in ("5", None, True, float("nan")):
    must(et.request("nats-comms", "a1", REQ, bad_timeout)["outcome"] == "invalid", repr(bad_timeout))
must(et._clamp_timeout(0) == 1.0 and et._clamp_timeout(99) == 30.0 and et._clamp_timeout(7) == 7.0, "clamped to 1 to 30")

# no reply: timeout within timeout + 1 s, the reply channel is freed, the group got the request with the reply channel
orig_min = et.MIN_REQUEST_TIMEOUT
et.MIN_REQUEST_TIMEOUT = 0.1
started = time.monotonic()
result = et.request("nats-comms", "a1", REQ, 0.2)
elapsed = time.monotonic() - started
must(result == {"outcome": "timeout", "reply": None} and elapsed < 1.2, (result, elapsed))
must(not LAYER.channels, "the reply channel was freed")
group, message = LAYER.sent[-1]
must(group == "tectac-ea-a1" and message["type"] == "endpoint.request" and message["frame"] == REQ and message["reply_channel"].startswith("specific."), (group, message))
must(message["timeout"] == 0.2, message)

# the right reply comes back
ANSWER = {"v": 1, "type": "reply", "id": "r1", "func": "status.get", "payload": {"ok": True}}
real_group_send = LAYER.group_send


async def answering_group_send(group, message):
    await real_group_send(group, message)
    await LAYER.send(message["reply_channel"], {"type": "endpoint.reply", "frame": ANSWER})


LAYER.group_send = answering_group_send
result = et.request("nats-comms", "a1", REQ, 5)
must(result == {"outcome": "ok", "reply": ANSWER}, result)
must(not LAYER.channels, "freed after a reply")
LAYER.group_send = real_group_send
et.MIN_REQUEST_TIMEOUT = orig_min
# a layer that hangs in group_send is still bounded
LAYER_BAK = et._channel_layer


class _Hang:
    async def new_channel(self):
        return "specific.hang"

    async def group_send(self, group, message):
        await asyncio.sleep(10)

    async def receive(self, channel):
        await asyncio.sleep(10)


et._channel_layer = lambda: _Hang()
started = time.monotonic()
must(et.request("nats-comms", "a1", REQ, 1)["outcome"] == "timeout" and time.monotonic() - started < 2.0, "bounded")
et._channel_layer = LAYER_BAK
H.LAYER_ENABLED[0] = False
must(et.request("nats-comms", "a1", REQ)["outcome"] == "offline", "no channel layer reads as offline")
H.LAYER_ENABLED[0] = True
CACHE.down = True
must(et.request("nats-comms", "a1", REQ)["outcome"] == "offline", "a cache fault reads as offline")
CACHE.down = False

# ---------------------------------------------------------------- send_many
reset()
connected("a1", "a3")
LAYER.group_calls = 0
result = et.send_many("nats-comms", ["a1", "a2", "a3", "a1"], EVT)
must(result == {"outcome": "ok", "queued": 2, "offline": ["a2"]}, result)
must(LAYER.group_calls == 2 and [g for g, _ in LAYER.sent] == ["tectac-ea-a1", "tectac-ea-a3"], LAYER.sent)
must(all(m == {"type": "endpoint.push", "frame": EVT} for _, m in LAYER.sent), "event pushed")
must(CACHE.get_many_calls == 1, "presence read with one get_many")
# many ids: one event loop for the batch, not one per agent
many = [f"agent{n}" for n in range(1500)]
connected(*many)
LAYER.sent.clear()
LAYER.group_calls = 0
calls = []
orig_a2s = None
import asgiref.sync as _sync  # noqa: E402

orig_a2s = _sync.async_to_sync


def counting(func, *args, **kwargs):
    calls.append(func)
    return orig_a2s(func, *args, **kwargs)


_sync.async_to_sync = counting
CACHE.get_many_calls = 0
result = et.send_many("nats-comms", many, EVT)
_sync.async_to_sync = orig_a2s
must(result["queued"] == 1500 and not result["offline"] and LAYER.group_calls == 1500, result)
must(len(calls) == 1 and CACHE.get_many_calls == 1, f"one event loop and one get_many for the batch ({len(calls)})")
# the cap
LAYER.sent.clear()
over = et.send_many("nats-comms", [f"x{n}" for n in range(2001)], EVT)
must(over == {"outcome": "invalid", "queued": 0, "offline": []} and not LAYER.sent, over)
must(et.send_many("nats-comms", [f"y{n}" for n in range(2000)], EVT)["outcome"] == "ok", "2000 is allowed")
must(et.send_many("nats-comms", ["bad id"], EVT)["outcome"] == "invalid", "bad id")
must(et.send_many("nats-comms", "a1", EVT)["outcome"] == "invalid", "ids must be a list")
must(et.send_many("nats-comms", ["a1"], REQ)["outcome"] == "invalid", "only events are fanned out")
must(et.send_many("other", ["a1"], EVT)["outcome"] == "invalid", "module id must equal the verified caller")

# ---------------------------------------------------------------- presence
reset()
connected("a1")
CACHE.get_many_calls = 0
result = et.presence("nats-comms", ["a1", "a2"])
must(result == {"outcome": "ok", "presence": {"a1": {"connected": True, "since": "2026-10-28T10:00:00+00:00"}, "a2": {"connected": False, "since": None}}}, result)
must(CACHE.get_many_calls == 1 and LAYER.group_calls == 0, "cache only, one get_many")
must(et.presence("nats-comms", [f"z{n}" for n in range(2001)])["outcome"] == "invalid", "cap")
must(et.presence("nats-comms", "a1")["outcome"] == "invalid", "ids must be a list")
CACHE.down = True
must(et.presence("nats-comms", ["a1"])["outcome"] == "offline", "a cache fault never raises")
CACHE.down = False

# ---------------------------------------------------------------- a request from another thread does not need the caller's event loop
reset()
connected("a1")
holder = {}
thread = threading.Thread(target=lambda: holder.update(r=et.request("nats-comms", "a1", REQ, 1.0)))
thread.start()
thread.join(5)
must(holder["r"]["outcome"] == "timeout", holder)

# ---------------------------------------------------------------- the metadata and the CORE_CONTRACTS rows
meta = et.endpoint_transport_contract_metadata()
must(meta["id"] == "core.endpoint_transport" and meta["version"] == "1.0.0", meta["version"])
must(meta["operations"] == ["register_owner", "request", "send_many", "presence"], meta["operations"])
must("framework >=1.17.90" in meta["added_in"] and "nats-comms" in meta["owner"], "version and owner named")
for word in ("4401", "4429", "4409", "4503", "1013", "2000", "1 to 30"):
    must(word in repr(meta), word)
tree = ast.parse((H.APP / "contracts.py").read_text(encoding="utf-8"))
rows = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CORE_CONTRACTS")
mine = [r for r in rows if r["area"] == "endpoint-transport"]
must(sorted(r["name"] for r in mine) == ["presence", "register_owner", "request", "send_many"], mine)
for row in mine:
    must(row["import_path"] == "tec_tac.endpoint_transport" and hasattr(et, row["name"]) and "framework >=1.17.90" in row["purpose"], row["name"])
    must("1.0.0" in row["purpose"] and row["audience"] == "backend/premium-owner", row["name"])
# the provider registers exactly the four operations
must(et.EndpointTransportProvider.__dict__.keys() >= {"register_owner", "request", "send_many", "presence"}, "provider methods")
src = (H.APP / "endpoint_transport.py").read_text(encoding="utf-8")
must('operations=("register_owner", "request", "send_many", "presence")' in src and 'module_id="core"' in src, "registration")
apps = (H.APP / "apps.py").read_text(encoding="utf-8")
must("register_core_endpoint_transport_capability" in apps and "install_endpoint_agent_route" in apps, "apps.py wires both")
must(apps.index("install_endpoint_agent_route") > apps.index("install_tactical_websocket_route") and apps.count("try:") >= 2, "own guarded blocks")
print("PASS endpoint transport contract 1.17.90")
