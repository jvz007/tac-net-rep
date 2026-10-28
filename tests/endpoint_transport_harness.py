"""Shared fixtures of the 1.17.90 endpoint transport tests (imported by file path, not a test itself).

Stubs the boundaries that are not on this PC (channels, Django's cache, Tactical's Token model, Celery, the audit writer, the caller identity)
and loads the REAL framwork/tec_tac/endpoint_transport.py and endpoint_transport_consumer.py under a stub ``tec_tac`` package. Nothing here
touches a database, a network or Redis.
"""
from __future__ import annotations

import asyncio
import copy
import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "framwork" / "tec_tac"
sys.dont_write_bytecode = True

TOKEN = "a" * 40
TOKEN2 = "b" * 40
SECRET_MARKERS = (TOKEN, TOKEN2, "Token " + TOKEN)


def must(condition, message="check failed"):
    if not condition:
        raise AssertionError(message)


def stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


# ------------------------------------------------------------------------------------------------ cache
class FakeCache:
    def __init__(self):
        self.data, self.timeouts, self.down = {}, {}, False

    def _check(self):
        if self.down:
            raise ConnectionError("cache down")

    def get(self, key, default=None):
        self._check()
        return copy.deepcopy(self.data.get(key, default))

    def get_many(self, keys):
        self._check()
        self.get_many_calls = getattr(self, "get_many_calls", 0) + 1
        return {k: copy.deepcopy(self.data[k]) for k in keys if k in self.data}

    def set(self, key, value, timeout=None):
        self._check()
        self.data[key] = copy.deepcopy(value)
        self.timeouts[key] = timeout

    def add(self, key, value, timeout=None):
        self._check()
        if key in self.data:
            return False
        self.set(key, value, timeout)
        return True

    def incr(self, key):
        self._check()
        if key not in self.data:
            raise ValueError("missing")
        self.data[key] += 1
        return self.data[key]

    def delete(self, key):
        self._check()
        return self.data.pop(key, None) is not None


CACHE = FakeCache()


# ------------------------------------------------------------------------------------------------ Tactical's token model
class FakeAgent:
    def __init__(self, pk, agent_id):
        self.pk, self.agent_id = pk, agent_id


class FakeUser:
    def __init__(self, name, agent=None, active=True):
        self.username, self.agent, self.is_active = name, agent, active
        self.agent_id = None if agent is None else agent.pk


class FakeTokenRow:
    def __init__(self, key, user):
        self.key, self.user = key, user


TOKENS: dict = {}


class _TokenQuery:
    def __init__(self, key):
        self.key = key

    def select_related(self, *a):
        return self

    def filter(self, **kw):
        return _TokenQuery(kw.get("key"))

    def first(self):
        return TOKENS.get(self.key)


class FakeToken:
    class objects:  # noqa: N801 - mirrors Django's manager attribute
        @staticmethod
        def select_related(*a):
            return _TokenQuery(None)


# ------------------------------------------------------------------------------------------------ celery, audit, caller identity
class FakeCelery:
    def __init__(self):
        self.sent, self.fail, self.on_send = [], False, None

    def send_task(self, name, args=(), **kw):
        if self.on_send:
            self.on_send(name, args)
        if self.fail:
            raise ConnectionError("broker down")
        self.sent.append((name, args))


CELERY = FakeCelery()
AUDITS: list = []
ORDER: list = []
CALLER = {"module_id": "nats-comms"}  # None means unverifiable
audit_stub = stub("tec_tac.audit")
audit_stub._record_endpoint_transport = lambda **kw: (ORDER.append("audit"), AUDITS.append(kw))


def _caller(*, provider_file):
    return None if CALLER["module_id"] is None else SimpleNamespace(module_id=CALLER["module_id"], kind="module", module_version="1")


stub("tec_tac.caller_identity", calling_module_for_core_provider=_caller)


# ------------------------------------------------------------------------------------------------ channels
class FakeLayer:
    """An in-memory channel layer: groups, per-channel queues, and direct delivery of group messages to registered consumers."""

    def __init__(self):
        self.groups, self.channels, self.consumers, self.counter = {}, {}, {}, 0
        self.sent = []
        self.group_calls = 0

    async def new_channel(self):
        self.counter += 1
        name = f"specific.{self.counter}"
        self.channels[name] = asyncio.Queue()
        return name

    async def group_add(self, group, channel):
        self.groups.setdefault(group, set()).add(channel)

    async def group_discard(self, group, channel):
        self.groups.get(group, set()).discard(channel)

    async def group_send(self, group, message):
        self.group_calls += 1
        self.sent.append((group, message))
        for channel in sorted(self.groups.get(group, ())):
            consumer = self.consumers.get(channel)
            if consumer is not None:
                await getattr(consumer, message["type"].replace(".", "_"))(message)

    async def send(self, channel, message):
        self.channels.setdefault(channel, asyncio.Queue()).put_nowait(message)

    async def receive(self, channel):
        return await self.channels.setdefault(channel, asyncio.Queue()).get()


LAYER = FakeLayer()
LAYER_ENABLED = [True]


class FakeBase:
    """channels' AsyncWebsocketConsumer, reduced to what the consumer uses. ``dispatch`` is not needed: tests call handlers directly."""

    def __init__(self, *args, **kwargs):
        self.scope = {}
        self.channel_layer = LAYER if LAYER_ENABLED[0] else None
        self.channel_name = None
        self.accepted, self.closed, self.out = False, [], []

    @classmethod
    def as_asgi(cls):
        async def app(scope, receive, send):
            raise AssertionError("driven directly")

        return app

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000):
        self.closed.append(code)

    async def send(self, text_data=None, bytes_data=None):
        self.out.append(text_data)


def _db_sync(func):
    async def run(*args, **kwargs):
        return func(*args, **kwargs)

    return run


stub("channels")
stub("channels.db", database_sync_to_async=_db_sync)
stub("channels.generic")
stub("channels.generic.websocket", AsyncWebsocketConsumer=FakeBase)
stub("channels.layers", get_channel_layer=lambda: LAYER if LAYER_ENABLED[0] else None)
stub("rest_framework")
stub("rest_framework.authtoken")
stub("rest_framework.authtoken.models", Token=FakeToken)
stub("celery", current_app=CELERY)
stub("django.core.cache", cache=CACHE)

# the stub package: real files, lazily imported collaborators are the stubs above
package = sys.modules.get("tec_tac") or types.ModuleType("tec_tac")
package.__path__ = [str(APP)]
sys.modules["tec_tac"] = package
WALL = [1_000_000.0]
et = importlib.import_module("tec_tac.endpoint_transport")
et.time = SimpleNamespace(time=lambda: WALL[0])
consumer_module = importlib.import_module("tec_tac.endpoint_transport_consumer")


def reset():
    CACHE.data.clear()
    CACHE.timeouts.clear()
    CACHE.down = False
    CACHE.get_many_calls = 0
    TOKENS.clear()
    CELERY.sent.clear()
    CELERY.fail = False
    CELERY.on_send = None
    AUDITS.clear()
    ORDER.clear()
    CALLER["module_id"] = "nats-comms"
    LAYER.groups.clear()
    LAYER.channels.clear()
    LAYER.consumers.clear()
    LAYER.sent.clear()
    LAYER.group_calls = 0
    LAYER_ENABLED[0] = True
    et.clear_owner_for_tests()
    WALL[0] = 1_000_000.0


def add_agent(agent_id="agentone", token=TOKEN, pk=1, active=True):
    TOKENS[token] = FakeTokenRow(token, FakeUser(f"u-{agent_id}", FakeAgent(pk, agent_id), active))


def headers_for(token=TOKEN, agent_id="agentone", real_ip="203.0.113.9", extra=()):
    rows = []
    if token is not None:
        rows.append((b"authorization", f"Token {token}".encode()))
    if agent_id is not None:
        rows.append((b"x-agent-id", agent_id.encode()))
    if real_ip:
        rows.append((b"x-real-ip", real_ip.encode()))
    rows.extend(extra)
    return rows


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_consumer(headers=None, clock=None, channel="specific.c1"):
    c = consumer_module.EndpointAgentConsumer()
    c.scope = {"headers": headers if headers is not None else headers_for(), "client": ("10.0.0.1", 5000)}
    c.channel_name = channel
    if clock is not None:
        c._clock = clock
        c._bucket = consumer_module._Bucket(clock)
    LAYER.consumers[channel] = c
    return c


def run(coro):
    return asyncio.run(coro)


def frames(consumer):
    import json

    return [json.loads(x) for x in consumer.out]
