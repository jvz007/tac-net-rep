"""Shared fixtures of the 1.18.46 and 1.18.47 probe transport tests (imported by file path, not a test itself).

Stubs the boundaries that are not on this PC (channels, Django's cache, Celery, the audit writer, the caller identity, the module registry)
and loads the REAL framwork/tec_tac/probe_transport.py and probe_transport_consumer.py under a stub ``tec_tac`` package. Nothing here touches
a database, a network or Redis.
"""
from __future__ import annotations

import asyncio
import copy
import importlib
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "framwork" / "tec_tac"
sys.dont_write_bytecode = True

PROBE = "probe-one-0001"
PROBE2 = "probe-two-0002"
KEY = "k" * 32
KEY2 = "j" * 32
SECRET_MARKERS = (KEY, KEY2, f"Probe {PROBE}.{KEY}")
ENGINEER = 5
PERMISSION = "networkprobe.tunnel"


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

    def touch(self, key, timeout=None):
        self._check()
        self.touched = getattr(self, "touched", []) + [key]
        if key not in self.data:
            return False
        self.timeouts[key] = timeout
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


# ------------------------------------------------------------------------------------------------ the owner's authenticator (a stub)
PROBES: dict = {}  # probe id -> (key, client_id, site_id) or a refusal string for that id
AUTH = {"mode": "normal", "calls": []}  # mode: normal | fault | slow | junk | mismatch | refuse_all


def _authenticate(probe_id, key):
    AUTH["calls"].append((probe_id, key))
    mode = AUTH["mode"]
    if mode == "fault":
        raise RuntimeError("owner database down")
    if mode == "junk":
        return {"ok": True}
    if mode == "mismatch":
        return {"probe_id": "someone-else-1", "client_id": 1, "site_id": 1}
    row = PROBES.get(probe_id)
    if row is None:
        return "probe_unknown"
    if isinstance(row, str):
        return row
    if row[0] != key:
        return "probe_key_invalid"
    return {"probe_id": probe_id, "client_id": row[1], "site_id": row[2]}


stub("nprobe_stub")
stub("nprobe_stub.auth", authenticate=_authenticate)


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
audit_stub = stub("tec_tac.audit")
audit_stub._record_probe_transport = lambda **kw: AUDITS.append(kw)
CALLER = {"module_id": "networkprobe"}  # None means unverifiable


def _caller(*, provider_file):
    return None if CALLER["module_id"] is None else SimpleNamespace(module_id=CALLER["module_id"], kind="module", module_version="1")


stub("tec_tac.caller_identity", calling_module_for_core_provider=_caller)

# the registry and the module state (register_owner reads them)
REGISTRY = {"plugins": [], "enabled": True}
stub("tec_tac.registry", discover_plugins=lambda: list(REGISTRY["plugins"]))
stub("tec_tac.module_state", load_state=dict, is_enabled=lambda module_id, state=None: REGISTRY["enabled"])


# ------------------------------------------------------------------------------------------------ channels
class FakeLayer:
    """An in-memory channel layer: groups, per-channel queues, and direct delivery of group messages to registered consumers."""

    def __init__(self):
        self.groups, self.channels, self.consumers, self.counter = {}, {}, {}, 0
        self.sent = []
        self.fail = None  # 1.18.47: a function (group, message) -> an exception to raise, or None (ChannelFull, a slow layer)
        self.fail_send = None  # 1.18.49: the same for send(channel, message)
        self.drop_send = None  # 1.18.49: a function (channel, message) -> True to lose the message silently (an expired message, a Redis flush)
        self.direct = []  # 1.18.49: every send() to a channel, in order: (channel, message)
        self.held = {}  # 1.18.49: channel -> messages held for a stalled consumer; hold(channel) starts it, release(channel) delivers them
        self.capacity = 100  # channels_redis' default channel capacity

    async def new_channel(self):
        self.counter += 1
        name = f"specific.{self.counter}"
        self.channels[name] = asyncio.Queue()
        return name

    async def group_add(self, group, channel):
        self.groups.setdefault(group, set()).add(channel)

    async def group_discard(self, group, channel):
        self.groups.get(group, set()).discard(channel)

    def hold(self, channel):
        """A stalled consumer: messages to this channel wait in its queue (up to the capacity) instead of being dispatched."""
        self.held.setdefault(channel, [])

    async def release(self, channel):
        """The consumer wakes up and handles what waited, in order."""
        queued = self.held.pop(channel, [])
        for message in queued:
            consumer = self.consumers.get(channel)
            if consumer is not None:
                await getattr(consumer, message["type"].replace(".", "_"))(message)
        return len(queued)

    async def _deliver(self, channel, message):
        if channel in self.held:
            if len(self.held[channel]) >= self.capacity:
                return False  # a full channel
            self.held[channel].append(message)
            return True
        consumer = self.consumers.get(channel)
        if consumer is not None:
            await getattr(consumer, message["type"].replace(".", "_"))(message)
        return True

    async def group_send(self, group, message):
        if self.fail is not None:
            problem = self.fail(group, message)
            if problem is not None:
                raise problem
        self.sent.append((group, message))
        for channel in sorted(self.groups.get(group, ())):
            await self._deliver(channel, message)  # channels_redis: a full channel is skipped without an error

    async def send(self, channel, message):
        if self.fail_send is not None:
            problem = self.fail_send(channel, message)
            if problem is not None:
                raise problem
        self.direct.append((channel, message))
        if self.drop_send is not None and self.drop_send(channel, message):
            return
        if channel in self.held:
            if len(self.held[channel]) >= self.capacity:
                raise ChannelFull()
            self.held[channel].append(message)
            return
        consumer = self.consumers.get(channel)
        if consumer is not None:
            await getattr(consumer, message["type"].replace(".", "_"))(message)
            return
        self.channels.setdefault(channel, asyncio.Queue()).put_nowait(message)

    async def receive(self, channel):
        return await self.channels.setdefault(channel, asyncio.Queue()).get()


LAYER = FakeLayer()
LAYER_ENABLED = [True]


class FakeBase:
    """channels' AsyncWebsocketConsumer, reduced to what the consumer uses. Tests call handlers directly."""

    def __init__(self, *args, **kwargs):
        self.scope = {}
        self.channel_layer = LAYER if LAYER_ENABLED[0] else None
        self.channel_name = None
        self.accepted, self.closed, self.out = False, [], []
        self.close_reasons, self.out_bytes = [], []

    @classmethod
    def as_asgi(cls):
        async def app(scope, receive, send):
            raise AssertionError("driven directly")

        return app

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000, reason=None):
        self.closed.append(code)
        self.close_reasons.append(reason)

    async def send(self, text_data=None, bytes_data=None):
        if bytes_data is not None:
            self.out_bytes.append(bytes_data)
        if text_data is not None:
            self.out.append(text_data)


class ChannelFull(Exception):
    """channels.exceptions.ChannelFull."""


stub("channels")
stub("channels.exceptions", ChannelFull=ChannelFull)
stub("channels.generic")
stub("channels.generic.websocket", AsyncWebsocketConsumer=FakeBase)
stub("channels.layers", get_channel_layer=lambda: LAYER if LAYER_ENABLED[0] else None)
stub("celery", current_app=CELERY)
DB = {"old": 0, "closed": 0}
# 1.18.50: django.db.transaction as access_events reads it: an atomic block is open or not, and on_commit runs a callback when it commits
TXN = SimpleNamespace(in_atomic_block=False, pending=[])
stub("django.db", close_old_connections=lambda: DB.__setitem__("old", DB["old"] + 1),
     connections=SimpleNamespace(close_all=lambda: DB.__setitem__("closed", DB["closed"] + 1)),
     transaction=SimpleNamespace(get_connection=lambda: TXN, on_commit=lambda func: TXN.pending.append(func)))
stub("django.core.cache", cache=CACHE)

# 1.18.47: the sign-in, the permission and the user model behind a tunnel ticket (stubs; the real ones need Django)
SIGNIN = {"refusal": None, "calls": []}  # tactical_websocket.session_refusal: None while the sign-in holds
PERMS = {"granted": True, "calls": []}
USERS = {}


def _session_refusal(value, activity_at=None):
    SIGNIN["calls"].append((dict(value), activity_at))
    return SIGNIN["refusal"]


def _has_permission(user, codename):
    PERMS["calls"].append((getattr(user, "pk", None), codename))
    return PERMS["granted"]


class _Users:
    def filter(self, pk=None, **kw):
        return SimpleNamespace(first=lambda: USERS.get(pk))


# 1.18.50: tec_tac.resources.get_site, the question the owner asks at open and Core asks again for a live session
class ResourceNotFound(Exception):
    pass


class ResourcePermissionDenied(Exception):
    pass


SITES = {"visible": {}, "mode": "normal", "calls": []}  # visible: user pk -> set of site ids; mode: normal | fault | denied


def _get_site(site_id, *, context):
    SITES["calls"].append((getattr(context.user, "pk", None), site_id))
    if SITES["mode"] == "fault":
        raise RuntimeError("database down")
    if SITES["mode"] == "denied":
        raise ResourcePermissionDenied("no")
    if site_id not in SITES["visible"].get(context.user.pk, ()):
        raise ResourceNotFound("no")
    return {"id": site_id}


stub("tec_tac.resources", get_site=_get_site, user_context=lambda user: SimpleNamespace(user=user), ResourceNotFound=ResourceNotFound,
     ResourcePermissionDenied=ResourcePermissionDenied)


class FakeSignal:
    """django.dispatch.Signal reduced to connect and send_robust (a receiver that raises is returned, never raised)."""

    def __init__(self):
        self.receivers = []
        self.sent = []

    def connect(self, receiver, **kw):
        self.receivers.append(receiver)

    def send_robust(self, sender, **named):
        self.sent.append(named)
        out = []
        for receiver in self.receivers:
            try:
                out.append((receiver, receiver(signal=self, sender=sender, **named)))
            except Exception as error:
                out.append((receiver, error))
        return out


stub("django.dispatch", Signal=FakeSignal)
stub("tec_tac.tactical_websocket", session_refusal=_session_refusal)
stub("tec_tac.rbac", has_extension_permission=_has_permission)
stub("tec_tac.session_security", request_knox_digest=lambda request: getattr(request, "digest", ""))
stub("django.contrib")
stub("django.contrib.auth", get_user_model=lambda: SimpleNamespace(objects=_Users()))

# the stub package: real files, lazily imported collaborators are the stubs above
package = sys.modules.get("tec_tac") or types.ModuleType("tec_tac")
package.__path__ = [str(APP)]
sys.modules["tec_tac"] = package
WALL = [1_000_000.0]
pt = importlib.import_module("tec_tac.probe_transport")
pt.time = SimpleNamespace(time=lambda: WALL[0])
consumer_module = importlib.import_module("tec_tac.probe_transport_consumer")
tun = importlib.import_module("tec_tac.probe_tunnel")
tun.time = SimpleNamespace(time=lambda: WALL[0], sleep=lambda seconds: None)
tun_consumer = importlib.import_module("tec_tac.probe_tunnel_consumer")
ae = importlib.import_module("tec_tac.access_events")
ae.time = SimpleNamespace(time=lambda: WALL[0])


def reset():
    CACHE.data.clear()
    CACHE.timeouts.clear()
    CACHE.down = False
    CACHE.get_many_calls = 0
    CACHE.touched = []
    DB.update(old=0, closed=0)
    pt.reset_pools_for_tests()
    pt._TRANSIENT_LAST[0] = 0.0
    PROBES.clear()
    AUTH.update(mode="normal", calls=[])
    CELERY.sent.clear()
    CELERY.fail = False
    CELERY.on_send = None
    AUDITS.clear()
    CALLER["module_id"] = "networkprobe"
    LAYER.groups.clear()
    LAYER.channels.clear()
    LAYER.consumers.clear()
    LAYER.sent.clear()
    LAYER.direct.clear()
    LAYER.held.clear()
    LAYER.fail_send = LAYER.drop_send = None
    LAYER_ENABLED[0] = True
    REGISTRY["plugins"] = []
    REGISTRY["enabled"] = True
    pt.clear_owner_for_tests()
    WALL[0] = 1_000_000.0
    LAYER.fail = None
    SIGNIN.update(refusal=None, calls=[])
    PERMS.update(granted=True, calls=[])
    USERS.clear()
    USERS[ENGINEER] = SimpleNamespace(pk=ENGINEER, is_active=True)
    SITES.update(visible={ENGINEER: {7}}, mode="normal", calls=[])  # the engineer sees site 7, the site add_probe gives the probe
    TXN.in_atomic_block = False
    TXN.pending.clear()
    ae.access_changed.receivers.clear()
    ae.access_changed.sent.clear()


def set_owner():
    """Register the stub authenticator as the owner, as register_owner would after its checks."""
    pt._OWNER = {"module_id": "networkprobe", "authenticator_path": "nprobe_stub.auth.authenticate",
                 "event_task_path": "nprobe_stub.tasks.handle", "task_name": "networkprobe.handle"}


def add_probe(probe_id=PROBE, key=KEY, client_id=3, site_id=7):
    PROBES[probe_id] = (key, client_id, site_id)


def headers_for(probe_id=PROBE, key=KEY, real_ip="203.0.113.9", scheme="Probe", extra=(), raw=None):
    rows = []
    if raw is not None:
        rows.append((b"authorization", raw))
    elif probe_id is not None:
        value = f"{scheme} {probe_id}.{key}" if scheme == "Probe" else f"{scheme} {key}"
        rows.append((b"authorization", value.encode()))
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
    c = consumer_module.ProbeConsumer()
    c.scope = {"headers": headers if headers is not None else headers_for(), "client": ("10.0.0.1", 5000)}
    c.channel_name = channel
    c._random = lambda: 0.0  # no jitter unless a test asks for it
    if clock is not None:
        c._clock = clock
        c._bucket = consumer_module._Bucket(clock)
    LAYER.consumers[channel] = c
    return c


async def settle(consumer):
    """Wait for the background tasks of a connection (the connect audit row is written off the connect path)."""
    while consumer._bg:
        await asyncio.gather(*list(consumer._bg))
        await asyncio.sleep(0)


def run(coro):
    return asyncio.run(coro)


def frames(consumer):
    import json

    return [json.loads(x) for x in consumer.out]


# ------------------------------------------------------------------------------------------------ an owner folder on disk (register_owner)
def make_owner_folder(task_inside=True, auth_inside=True, task_is_celery=True, auth_is_function=True):
    """Write a real owner folder and an outside folder, import their modules and return (folder, auth path, task path). Used to check
    that register_owner reads the code file of the authenticator and the task, not the path text."""
    base = Path(tempfile.mkdtemp(prefix="tectac-probe-owner-")).resolve()
    inside, outside = base / "networkprobe", base / "elsewhere"
    inside.mkdir()
    outside.mkdir()
    sys.path.insert(0, str(base))
    (inside / "__init__.py").write_text("", encoding="utf-8")
    (outside / "__init__.py").write_text("", encoding="utf-8")
    auth_text = "def authenticate(probe_id, key):\n    return 'probe_unknown'\n"
    if not auth_is_function:
        auth_text = "class _A:\n    def __call__(self, probe_id, key):\n        return 'probe_unknown'\n\n\nauthenticate = _A()\n"
    task_text = ("class _Task:\n    name = 'networkprobe.handle'\n\n    def apply_async(self, *a, **k):\n        return None\n\n"
                 "    def run(self, probe_id, frame):\n        return None\n\n\nhandle = _Task()\n")
    if not task_is_celery:
        task_text = "def handle(probe_id, frame):\n    return None\n"
    (inside if auth_inside else outside).joinpath("auth.py").write_text(auth_text, encoding="utf-8")
    (inside if task_inside else outside).joinpath("tasks.py").write_text(task_text, encoding="utf-8")
    auth_pkg = "networkprobe" if auth_inside else "elsewhere"
    task_pkg = "networkprobe" if task_inside else "elsewhere"
    for name in [n for n in sys.modules if n.split(".")[0] in ("networkprobe", "elsewhere")]:
        del sys.modules[name]
    importlib.invalidate_caches()
    REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=inside)]
    return inside, f"{auth_pkg}.auth.authenticate", f"{task_pkg}.tasks.handle"


# ------------------------------------------------------------------------------------------------ 1.18.47: the tunnel
def engineer_request(user_id=ENGINEER, host="tec.example.com", digest="digest-1", authenticated=True, session=True):
    user = SimpleNamespace(pk=user_id, is_authenticated=authenticated)
    return SimpleNamespace(user=user, tec_tac_session=SimpleNamespace(id="trust-1") if session else None, digest=digest, get_host=lambda: host)


def new_session_id():
    import uuid

    return str(uuid.uuid4())


def tunnel_spec(**over):
    spec = {"session_id": new_session_id(), "probe_id": PROBE, "permission": PERMISSION, "target_label": "server-one"}
    spec.update(over)
    return spec


def probe_online(probe_id=PROBE):
    pt.set_presence(probe_id, "2026-11-25T08:00:00+00:00", "owner-x", 3, 7)


def issue(spec=None, request=None):
    """Issue a ticket through the provider function of probe_transport (the caller stub says networkprobe)."""
    spec = spec if spec is not None else tunnel_spec()
    return pt.issue_tunnel_ticket(request if request is not None else engineer_request(), "networkprobe", spec)


def ticket_headers(ticket, real_ip="203.0.113.50", scheme="Ticket", extra=()):
    rows = [(b"authorization", f"{scheme} {ticket}".encode())]
    if real_ip:
        rows.append((b"x-real-ip", real_ip.encode()))
    rows.extend(extra)
    return rows


def make_console(ticket, clock=None, channel="specific.console", headers=None):
    c = tun_consumer.ProbeTunnelConsoleConsumer()
    c.scope = {"headers": headers if headers is not None else ticket_headers(ticket), "client": ("10.0.0.2", 5001)}
    c.channel_name = channel
    c._random = lambda: 0.0
    c._wall = lambda: WALL[0]
    if clock is not None:
        c._clock = clock
    LAYER.consumers[channel] = c
    return c


def make_tunnel_probe(session_id, probe_id=PROBE, key=KEY, clock=None, channel="specific.tprobe", headers=None, real_ip="203.0.113.9"):
    c = tun_consumer.ProbeTunnelProbeConsumer()
    rows = headers if headers is not None else headers_for(probe_id, key, real_ip=real_ip, extra=[(b"x-tunnel-session", session_id.encode())])
    c.scope = {"headers": rows, "client": ("10.0.0.3", 5002)}
    c.channel_name = channel
    c._random = lambda: 0.0
    c._wall = lambda: WALL[0]
    if clock is not None:
        c._clock = clock
    LAYER.consumers[channel] = c
    return c


def frame(ftype, stream=1, payload=b""):
    return bytes([ftype]) + stream.to_bytes(4, "big") + payload


async def settle_all(*consumers):
    for consumer in consumers:
        await settle(consumer)
