"""Core's Network Probe transport (Core 1.18.46, C1 of the probe channel plan): one websocket per probe, one identity check, one contract.

The Network Probe is a native client that connects to /ws/tfd/network-probe/ with its own key (``Authorization: Probe <probe_id>.<key>``,
the same secret it already uses over HTTPS). Core does not know probes. It hands the pair to the one owning module (networkprobe), which
checks it against its own table through an authenticator it registered, and keeps one live connection per probe, answers ping, checks the
frame shape, hands an event to the owner's task and routes a reply back to the request that is waiting. Core never interprets ``func``.

This file is a sibling of endpoint_transport.py and imports nothing from it (AD-54): its own prefixes, groups, pools, audit actions,
credential parser and owner registry. An agent token never reaches the authenticator and a probe key never reaches Tactical.

This file holds what has no channels import: the header parser, the failure limits, the owner registry, the identity check, the frame
checks, the presence keys, the route class and the public contract (core.probe_transport 1.0.0). The consumer lives in
probe_transport_consumer and is imported on the first connection, so a fault there closes the socket 4503 and never stops Tactical.

Secrets: the key is read from the Authorization header of the scope and from nowhere else. It is never in a URL, a log line, an audit
row, a refusal text or a return value. Refusals carry a reason code only.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import importlib
import ipaddress
import json
import logging
import math
import os
import re
import threading
import time
import types
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("tec_tac.probe_transport")

CAPABILITY_ID = "core.probe_transport"
CAPABILITY_VERSION = "1.1.0"  # 1.1.0 (Core 1.18.47) adds the tunnel operations; the five 1.0.0 operations are unchanged
OWNER_MODULES = ("networkprobe",)
OWNER_MODULE = OWNER_MODULES[0]
ROUTE_PATTERN = "ws/tfd/network-probe/"
SOCKET_PATH = "/ws/tfd/network-probe/"

GROUP_PREFIX = "tectac-pn-"
PRESENCE_PREFIX = "tec-tac:pt:presence:"
FAILURE_PREFIX = "tec-tac:pt:fail:"
PROBE_FAILURE_PREFIX = "tec-tac:pt:failprobe:"
PROBE_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{8,64}$")
KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")

CLOSE_UNAUTHORIZED = 4401
CLOSE_PLAINTEXT = 4403
CLOSE_BAD_FRAME = 4400
CLOSE_SUPERSEDED = 4409
CLOSE_PING_TIMEOUT = 4408
CLOSE_RATE_LIMITED = 4429
CLOSE_UNAVAILABLE = 4503
CLOSE_TOO_BIG = 1009
CLOSE_RETRY_LATER = 1013  # a server-side fault, a busy server or a stale re-check: the probe backs off and tries again (never an identity answer)

FAILURES_PER_ADDRESS_PER_MINUTE = 10  # the numbers AD-54 signed for the agent route; nothing is widened here (IPv6 grouped by its /64)
FAILURES_PER_PROBE_PER_MINUTE = 10  # failed checks naming one probe id, read only after a failed check
RECHECK_SECONDS = 300
RECHECK_RETRY_SECONDS = 30  # after a transient fault at the re-check
RECHECK_JITTER_SECONDS = 30
RECHECK_GRACE_SECONDS = 300  # past RECHECK_SECONDS + jitter + this without an identity answer, the socket closes 1013
PING_SECONDS = 30
PING_JITTER_SECONDS = 5
AUTH_TIMEOUT_SECONDS = 10.0
TRANSIENT_ROW_SECONDS = 10
MAX_UNANSWERED_PINGS = 2
PRESENCE_SECONDS = 90
MAX_FRAME_BYTES = 16 * 1024
MAX_FRAMES_PER_SECOND = 20
MAX_BAD_FRAMES = 20
MAX_PENDING_REQUESTS = 64
MAX_INFLIGHT_EVENTS = 32
ENQUEUE_TIMEOUT_SECONDS = 5.0
MAX_PROBES_PER_CALL = 2000
MIN_REQUEST_TIMEOUT = 1.0
MAX_REQUEST_TIMEOUT = 30.0

FRAME_TYPES = ("request", "reply", "event", "ping", "pong")  # no ack: events are best effort on this route
_NEEDS_FUNC = ("request", "reply", "event")
_NEEDS_PAYLOAD = ("request", "reply", "event")
_FRAME_FIELD_MAX = 128

REFUSAL_CODES = ("probe_unknown", "probe_disabled", "probe_key_invalid")  # the strings an authenticator may return
DISCONNECT_REASONS = ("disabled", "revoked", "key_rotated", "module_disabled")
OPERATIONS_1_0_0 = ("register_owner", "request", "send", "presence", "disconnect")
TUNNEL_OPERATIONS = ("issue_tunnel_ticket", "end_tunnel", "end_tunnels_for_probe", "tunnel_status")  # added in 1.1.0 (Core 1.18.47)
OPERATIONS = OPERATIONS_1_0_0 + TUNNEL_OPERATIONS

REFUSAL_MESSAGES = {
    "malformed_header": "the Authorization header is missing, duplicated or not 'Probe <probe_id>.<key>'",
    "wrong_scheme": "the Authorization header is not a probe credential",
    "malformed_probe_id": "the probe id in the Authorization header is not valid",
    "malformed_key": "the probe key in the Authorization header is not valid",
    "probe_unknown": "no probe matches",
    "probe_disabled": "the probe is disabled",
    "probe_key_invalid": "no probe matches",
    "unavailable": "the probe could not be checked just now; try again shortly",
    "busy": "the server is busy; try again shortly",
    "identity_stale": "the probe could not be re-checked in time; connect again",
    "rate_limited_probe": "too many failed checks naming this probe id in a minute",
}


# ------------------------------------------------------------------------------------------------ headers
def _scope_headers(scope) -> dict:
    """Header name (lower-case bytes) to a list of values. A name that appears twice is kept twice, so it can be refused."""
    found: dict = {}
    for name, value in scope.get("headers") or []:
        found.setdefault(bytes(name).lower(), []).append(bytes(value))
    return found


def parse_probe_headers(scope) -> tuple[str | None, str | None, str | None]:
    """(probe_id, key, reason). Exactly one Authorization header of the form 'Probe <probe_id>.<key>'. A 'Token ...' header (an agent
    token) gives wrong_scheme. A missing, duplicated, over-long or non-ASCII header gives malformed_header. A bad id or key gives its own
    reason. When the id is readable and valid it is returned with a reason too, so a failure can be counted against it. Nothing here logs or
    returns the key on a refusal."""
    values = _scope_headers(scope).get(b"authorization") or []
    if len(values) != 1 or len(values[0]) > 400:
        return None, None, "malformed_header"
    try:
        text = values[0].decode("ascii")
    except UnicodeDecodeError:
        return None, None, "malformed_header"
    scheme, space, rest = text.partition(" ")
    if not space:
        return None, None, "malformed_header"
    if scheme.lower() != "probe":
        return None, None, "wrong_scheme"
    probe_id, dot, key = rest.partition(".")
    if not dot or not PROBE_ID_PATTERN.fullmatch(probe_id):
        return None, None, "malformed_probe_id"
    if not KEY_PATTERN.fullmatch(key):
        return probe_id, None, "malformed_key"
    return probe_id, key, None


def client_ip(scope) -> str:
    """The address failures are counted against: X-Real-IP (set by nginx from $remote_addr, so a client cannot choose it), else the ASGI
    client address. The leftmost X-Forwarded-For is client controlled and is never used."""
    for value in _scope_headers(scope).get(b"x-real-ip", [])[:1]:
        try:
            return str(ipaddress.ip_address(value.decode("ascii").strip()))
        except (ValueError, UnicodeDecodeError):
            break
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and client and isinstance(client[0], str) and client[0]:
        return client[0][:64]
    return "unknown"


def forwarded_plaintext(scope) -> bool:
    """True when the proxy says the client used a plain-text connection (X-Forwarded-Proto http or ws). Absent header: TLS is left to nginx."""
    values = _scope_headers(scope).get(b"x-forwarded-proto", [])
    if not values:
        return False
    return values[0].decode("latin-1").split(",")[0].strip().lower() in ("http", "ws")


# ------------------------------------------------------------------------------------------------ failure limits
def _cache():
    from django.core.cache import cache

    return cache


def _address_key(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return str(ip)
    if address.version == 6:
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


def _minute() -> int:
    return int(time.time() // 60)


def _failure_key(ip: str) -> str:
    return f"{FAILURE_PREFIX}{_address_key(ip)}:{_minute()}"


def _probe_failure_key(probe_id: str) -> str:
    return f"{PROBE_FAILURE_PREFIX}{probe_id}:{_minute()}"


def _bump(key: str) -> int:
    cache = _cache()
    cache.add(key, 0, timeout=120)
    try:
        return int(cache.incr(key))
    except ValueError:
        cache.add(key, 1, timeout=120)
        return 1


def _count(key: str) -> int:
    return int(_cache().get(key, 0) or 0)


def rate_limited(ip: str) -> bool:
    """True when this address (an IPv6 address by its /64) has had FAILURES_PER_ADDRESS_PER_MINUTE failed attempts this minute. A cache
    fault reads as not limited and is logged: a probe key has at least 96 bits, so a missing counter does not make guessing possible."""
    try:
        return _count(_failure_key(ip)) >= FAILURES_PER_ADDRESS_PER_MINUTE
    except Exception:
        logger.warning("The probe failure counter could not be read.", exc_info=True)
        return False


def note_failure(ip: str) -> None:
    try:
        _bump(_failure_key(ip))
    except Exception:
        logger.warning("The probe failure counter could not be written.", exc_info=True)


def probe_limited(probe_id) -> bool:
    """True when failed checks naming this probe id have reached FAILURES_PER_PROBE_PER_MINUTE this minute. Read only AFTER a failed check,
    never before one, so a person who presents a real probe's id can never lock that probe out. A fault reads as not limited."""
    if not isinstance(probe_id, str) or not PROBE_ID_PATTERN.fullmatch(probe_id):
        return False
    try:
        return _count(_probe_failure_key(probe_id)) >= FAILURES_PER_PROBE_PER_MINUTE
    except Exception:
        logger.warning("The probe id failure counter could not be read.", exc_info=True)
        return False


def note_probe_failure(probe_id) -> None:
    if not isinstance(probe_id, str) or not PROBE_ID_PATTERN.fullmatch(probe_id):
        return
    try:
        _bump(_probe_failure_key(probe_id))
    except Exception:
        logger.warning("The probe id failure counter could not be written.", exc_info=True)


def note_failed_check(ip: str, probe_id) -> bool:
    """One call for a failed identity check: True when this probe id is over its limit (read BEFORE this failure is counted, so the 11th
    failure is the first one refused with 4429), then counts the failure against the address and the id. Sync."""
    limited = probe_limited(probe_id)
    note_failure(ip)
    note_probe_failure(probe_id)
    return limited


_TRANSIENT_LAST = [0.0]


def transient_row_allowed() -> bool:
    """One 'unavailable' audit row per TRANSIENT_ROW_SECONDS per process, so a database fault under a burst cannot flood the table."""
    now = time.time()
    if now - _TRANSIENT_LAST[0] >= TRANSIENT_ROW_SECONDS:
        _TRANSIENT_LAST[0] = now
        return True
    return False


# ------------------------------------------------------------------------------------------------ dedicated worker pools
class PoolFull(Exception):
    """A dedicated pool has its backlog cap in flight: the caller answers at once instead of queueing."""


class _BoundedPool:
    """A small ThreadPoolExecutor, created on first use, with an in-flight counter (queued plus running) so a full pool refuses at once."""

    def __init__(self, name: str, workers: int, backlog: int):
        self.name, self.workers, self.backlog = name, workers, backlog
        self._lock = threading.Lock()
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self.inflight = 0

    def submit(self, func, /, *args, **kwargs) -> concurrent.futures.Future:
        with self._lock:
            if self.inflight >= self.backlog:
                raise PoolFull(self.name)
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix=f"tectac-pn-{self.name}")
            self.inflight += 1
            executor = self._executor
        try:
            future = executor.submit(func, *args, **kwargs)
        except Exception:
            with self._lock:
                self.inflight -= 1
            raise
        future.add_done_callback(self._done)
        return future

    def _done(self, _future) -> None:
        with self._lock:
            self.inflight -= 1

    def shutdown(self) -> None:
        with self._lock:
            executor, self._executor = self._executor, None
            self.inflight = 0
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)


# name: (threads, backlog cap). Sized like the endpoint route for the fleet note in docs/probe-transport.md (up to 500 connected probes, a reconnect
# storm spread by the probe's jittered back-off) and for the two tunnel routes, which use these same pools.
POOL_SPECS = {"auth": (6, 256), "recheck": (2, 4096), "cache": (6, 2000), "audit": (3, 800), "handover": (2, 64)}
UNAUTHENTICATED_IN_FLIGHT = 64  # connects between the first byte and the identity answer: over this a connect is answered 1013 and counted nowhere
_POOLS = {name: _BoundedPool(name, *spec) for name, spec in POOL_SPECS.items()}


async def run_in_pool(name: str, func, /, *args, **kwargs):
    """Run a blocking call on one of the probe route's own pools and await it. Never uses the event loop's default executor, which
    Tactical's own sockets share, and never a pool of the agent route. Raises PoolFull at once when the backlog is full."""
    future = _POOLS[name].submit(func, *args, **kwargs)
    return await asyncio.wrap_future(future)


def pool_inflight(name: str) -> int:
    return _POOLS[name].inflight


def reset_pools_for_tests() -> None:
    for pool in _POOLS.values():
        pool.shutdown()
    _UNAUTH.count = 0


class _InFlight:
    """A non-blocking ceiling on connects that have not been identified yet, so a flood spread over many addresses cannot make real probes
    queue behind it. Taken before the identity check and released when the connect decision is made."""

    def __init__(self, limit: int):
        self.limit, self.count = limit, 0
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            if self.count >= self.limit:
                return False
            self.count += 1
            return True

    def release(self) -> None:
        with self._lock:
            self.count = max(0, self.count - 1)


_UNAUTH = _InFlight(UNAUTHENTICATED_IN_FLIGHT)


def acquire_unauth() -> bool:
    return _UNAUTH.acquire()


def release_unauth() -> None:
    _UNAUTH.release()


def unauth_in_flight() -> int:
    return _UNAUTH.count


def _close_db(final: bool) -> None:
    """Drop stale or broken Django connections held by this pool thread; after a job also close its connection. Guarded: the test stubs
    may have no django.db."""
    try:
        from django.db import close_old_connections, connections
    except ImportError:
        return
    try:
        close_old_connections()
        if final:
            connections.close_all()
    except Exception:
        logger.warning("The probe pool connection could not be closed.", exc_info=True)


# ------------------------------------------------------------------------------------------------ the owner of identity and events
_OWNER_LOCK = threading.Lock()
_OWNER: dict[str, str] | None = None


def get_owner() -> dict[str, str] | None:
    """The registered owner in this process: {module_id, authenticator_path, event_task_path, task_name}, or None. The consumer reads it."""
    with _OWNER_LOCK:
        return dict(_OWNER) if _OWNER else None


def clear_owner_for_tests() -> None:
    global _OWNER
    with _OWNER_LOCK:
        _OWNER = None


def _owner_folder(module_id: str = OWNER_MODULE) -> str | None:
    """The real path of the installed, enabled, non-legacy extension folder of the owner module id, or None."""
    from . import module_state, registry

    if module_id not in OWNER_MODULES:
        return None
    plugin = next((p for p in registry.discover_plugins() if p.plugin_id == module_id), None)
    if plugin is None or plugin.plugin_type != "extension" or plugin.legacy:
        return None
    state = module_state.load_state()
    if isinstance(state, dict) and state.get("_corrupt"):
        return None
    if not module_state.is_enabled(module_id, state):
        return None
    return os.path.normcase(os.path.realpath(str(plugin.root)))


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


_DOTTED = re.compile(r"[A-Za-z_][\w.]{0,200}")


def _load_attr(path: str):
    module_name, _, attr = path.rpartition(".")
    if not module_name or not attr:
        raise ValueError("a dotted path to a callable is needed.")
    return getattr(importlib.import_module(module_name), attr)


def _code_file(func) -> str:
    code = getattr(getattr(func, "__func__", func), "__code__", None)
    filename = getattr(code, "co_filename", None)
    if not isinstance(filename, str) or not filename or filename.startswith("<"):
        raise ValueError("the code is not a file.")
    return os.path.normcase(os.path.realpath(filename))


def _task_name_and_file(task) -> tuple[str, str]:
    name = getattr(task, "name", None)
    if not isinstance(name, str) or not name or not (hasattr(task, "apply_async") or hasattr(task, "delay")):
        raise ValueError("event_task_path is not a Celery task.")
    return name, _code_file(getattr(task, "run", None) or task)


def _authenticator_file(func) -> str:
    if not isinstance(func, types.FunctionType):
        raise TypeError("authenticator_path is not a plain function.")
    return _code_file(func)


def _register_owner(module_id: str, authenticator_path, event_task_path) -> dict:
    global _OWNER
    if module_id not in OWNER_MODULES:
        return {"outcome": "denied", "reason": "module_id must be the verified caller"}
    for value in (authenticator_path, event_task_path):
        if not isinstance(value, str) or not _DOTTED.fullmatch(value):
            return {"outcome": "invalid", "reason": "authenticator_path and event_task_path must be dotted paths"}
    with _OWNER_LOCK:
        current = dict(_OWNER) if _OWNER else None
    if current is not None:
        if current["module_id"] != module_id:
            return {"outcome": "denied", "reason": f"another module already owns the transport ({current['module_id']})"}
        if current["authenticator_path"] == authenticator_path and current["event_task_path"] == event_task_path:
            return {"outcome": "ok", "registered": True, "idempotent": True}
        return {"outcome": "invalid", "reason": "an owner is already registered with different paths"}
    try:
        folder = _owner_folder(module_id)
        if folder is None:
            return {"outcome": "denied", "reason": f"{module_id} is not an installed, enabled extension"}
        auth_file = _authenticator_file(_load_attr(authenticator_path))
        name, task_file = _task_name_and_file(_load_attr(event_task_path))
    except Exception:
        logger.warning("The probe owner paths could not be checked.", exc_info=True)
        return {"outcome": "invalid", "reason": "authenticator_path or event_task_path could not be loaded"}
    if not _inside(auth_file, folder) or not _inside(task_file, folder):
        return {"outcome": "invalid", "reason": "the authenticator and the task must lie inside the owner module's own folder"}
    with _OWNER_LOCK:
        if _OWNER is not None:
            if _OWNER["module_id"] != module_id:
                return {"outcome": "denied", "reason": f"another module already owns the transport ({_OWNER['module_id']})"}
            if _OWNER["authenticator_path"] != authenticator_path or _OWNER["event_task_path"] != event_task_path:
                return {"outcome": "invalid", "reason": "an owner is already registered with different paths"}
            return {"outcome": "ok", "registered": True, "idempotent": True}
        _OWNER = {"module_id": module_id, "authenticator_path": authenticator_path, "event_task_path": event_task_path, "task_name": name}
    return {"outcome": "ok", "registered": True, "idempotent": False}


# ------------------------------------------------------------------------------------------------ identity
@dataclass(frozen=True)
class ProbeAuthResult:
    """The answer of ``authenticate_probe``. ``ok`` is True only when the owner accepted the probe. ``reason`` is a code from
    REFUSAL_MESSAGES when it is not. The key is never part of it."""

    ok: bool
    reason: str | None = None
    probe_id: str | None = None
    client_id: int | None = None
    site_id: int | None = None
    transient: bool = False  # a server-side fault, not an answer about identity: never counted, never closes 4401


def _refused(reason: str) -> ProbeAuthResult:
    return ProbeAuthResult(False, reason)


def _transient(reason: str = "unavailable") -> ProbeAuthResult:
    return ProbeAuthResult(False, reason, transient=True)


def _optional_id(value) -> bool:
    return value is None or (isinstance(value, int) and not isinstance(value, bool))


def authenticate_probe(probe_id, key) -> ProbeAuthResult:
    """Ask the owner's registered authenticator whether this probe id and key are good. Sync: the consumer runs it on the auth pool.

    Accepted only when the authenticator returns a dict {probe_id (equal to the one presented), client_id, site_id} (ints or None). A
    string from REFUSAL_CODES is a refusal. Anything else, a fault or no registered owner is a transient result (never 4401)."""
    if not isinstance(probe_id, str) or not PROBE_ID_PATTERN.fullmatch(probe_id):
        return _refused("malformed_probe_id")
    if not isinstance(key, str) or not KEY_PATTERN.fullmatch(key):
        return _refused("malformed_key")
    owner = get_owner()
    if owner is None:
        return _transient("unavailable")
    try:
        answer = _load_attr(owner["authenticator_path"])(probe_id, key)
    except Exception:
        logger.exception("The probe authenticator failed; answering retry-later.")
        return _transient("unavailable")
    if isinstance(answer, str) and answer in REFUSAL_CODES:
        return _refused(answer)
    if (isinstance(answer, dict) and answer.get("probe_id") == probe_id
            and _optional_id(answer.get("client_id")) and _optional_id(answer.get("site_id"))):
        return ProbeAuthResult(True, None, probe_id, answer.get("client_id"), answer.get("site_id"))
    logger.warning("The probe authenticator gave an answer Core does not accept; answering retry-later.")
    return _transient("unavailable")


def _auth_job(probe_id, key) -> ProbeAuthResult:
    _close_db(False)
    try:
        return authenticate_probe(probe_id, key)
    finally:
        _close_db(True)


async def authenticate_async(probe_id, key, pool: str = "auth") -> ProbeAuthResult:
    """The identity check on the auth pool (the re-check passes pool="recheck"), bounded by AUTH_TIMEOUT_SECONDS. A full pool, a timeout
    or any fault is a transient result: the consumer answers 1013 and counts nothing."""
    try:
        return await asyncio.wait_for(run_in_pool(pool, _auth_job, probe_id, key), timeout=AUTH_TIMEOUT_SECONDS)
    except PoolFull:
        return _transient("busy")
    except asyncio.TimeoutError:
        return _transient("unavailable")
    except Exception:
        logger.warning("The probe auth pool failed.", exc_info=True)
        return _transient("unavailable")


def enqueue_event(probe_id: str, frame: dict) -> str:
    """Hand a probe event to the owner's Celery task with (probe_id, frame). Sync and blocking (a broker call): the consumer runs it on the
    handover pool under a timeout. No publish retry. Returns ok, no_owner or failed. Never raises."""
    owner = get_owner()
    if owner is None:
        return "no_owner"
    try:
        from celery import current_app

        current_app.send_task(owner["task_name"], args=(probe_id, frame), retry=False)
        return "ok"
    except Exception:
        logger.warning("The probe event could not be queued for its owner.", exc_info=True)
        return "failed"


# ------------------------------------------------------------------------------------------------ frames
def validate_frame(frame, *, allowed_types=FRAME_TYPES) -> str | None:
    """A JSON object, v == 1, a known type, id and func strings, payload an object. Returns a reason code, or None when acceptable.
    Core never looks at ``func`` beyond its type and length."""
    if not isinstance(frame, dict):
        return "not_an_object"
    version = frame.get("v")
    if version != 1 or isinstance(version, bool):
        return "bad_version"
    ftype = frame.get("type")
    if not isinstance(ftype, str) or ftype not in FRAME_TYPES:
        return "unknown_type"
    if ftype not in allowed_types:
        return "type_not_allowed"
    fid = frame.get("id")
    if not isinstance(fid, str) or not fid or len(fid) > _FRAME_FIELD_MAX:
        return "bad_id"
    func = frame.get("func", "")
    if not isinstance(func, str) or len(func) > _FRAME_FIELD_MAX or (ftype in _NEEDS_FUNC and not func):
        return "bad_func"
    if "payload" in frame:
        if not isinstance(frame["payload"], dict):
            return "bad_payload"
    elif ftype in _NEEDS_PAYLOAD:
        return "bad_payload"
    return None


def frame_size_ok(frame) -> bool:
    try:
        return len(json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) <= MAX_FRAME_BYTES
    except (TypeError, ValueError):
        return False


def clean_label(value, limit: int = _FRAME_FIELD_MAX) -> str:
    return "".join(ch for ch in str(value or "") if ch.isprintable())[:limit]


# ------------------------------------------------------------------------------------------------ presence
def group_name(probe_id: str) -> str:
    return f"{GROUP_PREFIX}{probe_id}"


def presence_key(probe_id: str) -> str:
    return f"{PRESENCE_PREFIX}{probe_id}"


def set_presence(probe_id: str, since: str, owner: str = "", client_id=None, site_id=None) -> None:
    """Mark the probe connected. ``owner`` is a random id of this connection, so a newer connection is never mistaken for this one. Sync."""
    _cache().set(presence_key(probe_id), {"connected": True, "since": since, "owner": owner, "client_id": client_id, "site_id": site_id},
                 timeout=PRESENCE_SECONDS)


def refresh_presence(probe_id: str, owner: str = "", since: str | None = None, client_id=None, site_id=None) -> None:
    """Keep this connection's presence alive. The cached owner is this connection: touch the key, or rewrite it when the client or site the
    owner reported has changed. The key is missing: cache.add re-creates it (atomic). A different live owner is left alone. The consumer never
    calls this for a superseded connection."""
    cache = _cache()
    key = presence_key(probe_id)
    current = cache.get(key)
    if isinstance(current, dict):
        if current.get("owner") == owner:
            if current.get("client_id") != client_id or current.get("site_id") != site_id:
                cache.set(key, {**current, "client_id": client_id, "site_id": site_id}, timeout=PRESENCE_SECONDS)
            else:
                cache.touch(key, PRESENCE_SECONDS)
        return
    if since is not None:
        cache.add(key, {"connected": True, "since": since, "owner": owner, "client_id": client_id, "site_id": site_id}, timeout=PRESENCE_SECONDS)


def clear_presence(probe_id: str, owner: str = "") -> bool:
    """Delete the key only when this connection still owns it. Sync. True when it was deleted."""
    cache = _cache()
    current = cache.get(presence_key(probe_id))
    if isinstance(current, dict) and current.get("owner") == owner:
        cache.delete(presence_key(probe_id))
        return True
    return False


def _presence_row(value) -> dict:
    if isinstance(value, dict) and value.get("connected"):
        return {"connected": True, "since": value.get("since"), "client_id": value.get("client_id"), "site_id": value.get("site_id")}
    return {"connected": False, "since": None, "client_id": None, "site_id": None}


def presence_many(probe_ids) -> dict:
    """Probe id to {connected, since, client_id, site_id}, from the cache only, with one get_many. Sync."""
    ids = list(probe_ids)
    found = _cache().get_many([presence_key(p) for p in ids]) or {}
    return {p: _presence_row(found.get(presence_key(p))) for p in ids}


# ------------------------------------------------------------------------------------------------ audit
TUNNEL_AUDIT_KEYS = ("engineer", "session_id", "side", "ended_by", "detail", "duration", "bytes_up", "bytes_down", "permission")


def _tunnel_extra(extra) -> dict:
    """The tunnel fields of a row: only the names in TUNNEL_AUDIT_KEYS, an int or a short clean text. Never a ticket, a key or traffic."""
    found: dict = {}
    for name in TUNNEL_AUDIT_KEYS:
        value = (extra or {}).get(name)
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, int):
            found[name] = value
        elif isinstance(value, str) and value:
            found[name] = clean_label(value, 128)
    return found


def record_probe_event(action: str, probe_id: str | None = None, *, reason: str | None = None, ip: str | None = None,
                       client_id=None, site_id=None, code=None, refusal: bool = False, extra: dict | None = None) -> None:
    """One non-strict Core audit row for the socket. Sync (a database write). Never raises. Holds only the fields named here: never a key,
    an Authorization header or a payload. A probe id that is not valid is written without one. Runs on the audit pool."""
    _close_db(False)
    try:
        from . import audit as audit_core

        safe_probe = probe_id if isinstance(probe_id, str) and PROBE_ID_PATTERN.fullmatch(probe_id) else None
        metadata = {k: v for k, v in {
            "reason": reason, "ip": ip, "code": None if code is None else str(code)[:16],
            "client_id": client_id if isinstance(client_id, int) and not isinstance(client_id, bool) else None,
            "site_id": site_id if isinstance(site_id, int) and not isinstance(site_id, bool) else None,
        }.items() if v is not None and v != ""}
        metadata.update(_tunnel_extra(extra))
        audit_core._record_probe_transport(
            action=action, probe_id=safe_probe, message=f"Network probe socket: {action.split(':', 1)[-1]}.", metadata=metadata, refusal=refusal,
        )
    except Exception:
        logger.warning("The probe transport audit row could not be written (%s).", action, exc_info=True)
    finally:
        _close_db(False)


# ------------------------------------------------------------------------------------------------ route
class _ProbeRoute:
    """The ASGI app of ws/tfd/network-probe/. Imports the consumer on the first connection, so a fault there closes the socket 4503 and
    never stops Tactical from starting (rule 1.15)."""

    async def __call__(self, scope, receive, send):
        try:
            from .probe_transport_consumer import ProbeConsumer

            app = ProbeConsumer.as_asgi()
        except Exception:
            logger.exception("The probe consumer could not be loaded; closing the socket.")
            await send({"type": "websocket.close", "code": CLOSE_UNAVAILABLE})
            return
        await app(scope, receive, send)


def probe_route():
    return _ProbeRoute()


def install_probe_route() -> bool:
    """Append ws/tfd/network-probe/ to Tactical's ws_urlpatterns, once. Returns True when this call added it."""
    from django.urls import path
    from tacticalrmm import urls as tactical_urls

    routes = tactical_urls.ws_urlpatterns
    if ROUTE_PATTERN in {str(getattr(pattern, "pattern", "")) for pattern in routes}:
        return False
    routes.append(path(ROUTE_PATTERN, probe_route()))
    return True


# ------------------------------------------------------------------------------------------------ the contract
def _verified_owner_id() -> str | None:
    """The verified calling module id when it is networkprobe and, once an owner is registered in this process, the registered one; else
    None. Never from an argument. Every frame of this file is skipped by the walk, so this may be called from any depth of the provider."""
    from .caller_identity import calling_module_for_core_provider

    try:
        identity = calling_module_for_core_provider(provider_file=__file__)
    except Exception:
        logger.debug("A call failed and was handled (see the caller).", exc_info=True)
        return None
    if identity is None or identity.module_id not in OWNER_MODULES:
        return None
    with _OWNER_LOCK:
        registered = _OWNER["module_id"] if _OWNER else None
    if registered is not None and registered != identity.module_id:
        return None
    return identity.module_id


_DENIED = {"outcome": "denied"}


def _channel_layer():
    from channels.layers import get_channel_layer

    return get_channel_layer()


def _clamp_timeout(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or math.isnan(value):
        return None
    return float(min(MAX_REQUEST_TIMEOUT, max(MIN_REQUEST_TIMEOUT, value)))


def _probe_ids(probe_ids) -> list[str] | None:
    if not isinstance(probe_ids, (list, tuple, set, frozenset)):
        return None
    seen: dict[str, None] = {}
    for item in probe_ids:
        if not isinstance(item, str) or not PROBE_ID_PATTERN.fullmatch(item):
            return None
        seen[item] = None
    if len(seen) > MAX_PROBES_PER_CALL:
        return None
    return list(seen)


def _free_channel(layer, channel: str) -> None:
    channels = getattr(layer, "channels", None)
    if isinstance(channels, dict):
        channels.pop(channel, None)


def _connected(probe_id: str) -> bool:
    return _presence_row(_cache().get(presence_key(probe_id)))["connected"]


def register_owner(module_id, authenticator_path, event_task_path) -> dict:
    """Register the authenticator and the Celery task that receive probe identity checks and events. Only networkprobe, verified by Core,
    may call it. See docs/probe-transport.md."""
    caller = _verified_owner_id()
    if caller is None:
        return dict(_DENIED)
    if module_id != caller:
        return {"outcome": "denied", "reason": "module_id must be the verified caller"}
    return _register_owner(module_id, authenticator_path, event_task_path)


def request(module_id, probe_id, frame, timeout=10) -> dict:
    """Send a request frame to one connected probe and wait for its reply. Returns {outcome: ok|timeout|offline|denied|invalid, reply}.
    Sync (async_to_sync): call it from a Celery task or a request thread. Returns within timeout + 1 second."""
    caller = _verified_owner_id()
    if caller is None:
        return {**_DENIED, "reply": None}
    if module_id != caller or not isinstance(probe_id, str) or not PROBE_ID_PATTERN.fullmatch(probe_id):
        return {"outcome": "invalid", "reply": None}
    wait = _clamp_timeout(timeout)
    if wait is None or validate_frame(frame, allowed_types=("request",)) is not None or not frame_size_ok(frame):
        return {"outcome": "invalid", "reply": None}
    try:
        if not _connected(probe_id):
            return {"outcome": "offline", "reply": None}
        layer = _channel_layer()
    except Exception:
        logger.warning("The probe presence could not be read.", exc_info=True)
        return {"outcome": "offline", "reply": None}
    if layer is None:
        return {"outcome": "offline", "reply": None}
    from asgiref.sync import async_to_sync

    async def go():
        channel = await layer.new_channel()
        try:
            await layer.group_send(group_name(probe_id), {"type": "probe.request", "frame": frame, "reply_channel": channel, "timeout": wait})
            message = await layer.receive(channel)
            return {"outcome": "ok", "reply": message.get("frame")}
        finally:
            _free_channel(layer, channel)

    async def bounded():
        try:
            return await asyncio.wait_for(go(), timeout=wait)
        except asyncio.TimeoutError:
            return {"outcome": "timeout", "reply": None}

    try:
        return async_to_sync(bounded)()
    except Exception:
        logger.warning("The probe request failed.", exc_info=True)
        return {"outcome": "offline", "reply": None}


def _group_send(probe_id: str, message: dict) -> str:
    """Send one group message to a probe that has presence. Returns ok or offline. Sync."""
    try:
        if not _connected(probe_id):
            return "offline"
        layer = _channel_layer()
    except Exception:
        logger.warning("The probe presence could not be read.", exc_info=True)
        return "offline"
    if layer is None:
        return "offline"
    from asgiref.sync import async_to_sync

    async def go():
        await asyncio.wait_for(layer.group_send(group_name(probe_id), message), timeout=MAX_REQUEST_TIMEOUT)

    try:
        async_to_sync(go)()
    except Exception:
        logger.warning("The probe group message failed.", exc_info=True)
        return "offline"
    return "ok"


def send(module_id, probe_id, frame) -> dict:
    """Fire and forget one event or reply frame to one probe (a reply carries the id of the probe's own event, so the owner can answer
    probe.hello with probe.welcome). Returns {outcome: ok|offline|denied|invalid}. Sync."""
    caller = _verified_owner_id()
    if caller is None:
        return dict(_DENIED)
    if (module_id != caller or not isinstance(probe_id, str) or not PROBE_ID_PATTERN.fullmatch(probe_id)
            or validate_frame(frame, allowed_types=("event", "reply")) is not None or not frame_size_ok(frame)):
        return {"outcome": "invalid"}
    return {"outcome": _group_send(probe_id, {"type": "probe.push", "frame": frame})}


def presence(module_id, probe_ids) -> dict:
    """Per probe {connected, since, client_id, site_id}, from the cache only (one get_many), at most 2000 ids. Sync."""
    caller = _verified_owner_id()
    if caller is None:
        return {**_DENIED, "presence": {}}
    ids = _probe_ids(probe_ids)
    if module_id != caller or ids is None:
        return {"outcome": "invalid", "presence": {}}
    try:
        return {"outcome": "ok", "presence": presence_many(ids)}
    except Exception:
        logger.warning("The probe presence could not be read.", exc_info=True)
        return {"outcome": "offline", "presence": {}}


def disconnect(module_id, probe_id, reason) -> dict:
    """Close one probe's socket with 4401 (the probe then stops the channel and keeps its 5-minute HTTPS check). ``reason`` is one of
    DISCONNECT_REASONS. Returns {outcome: ok|offline|denied|invalid}. Sync."""
    caller = _verified_owner_id()
    if caller is None:
        return dict(_DENIED)
    if (module_id != caller or not isinstance(probe_id, str) or not PROBE_ID_PATTERN.fullmatch(probe_id)
            or not isinstance(reason, str) or reason not in DISCONNECT_REASONS):
        return {"outcome": "invalid"}
    return {"outcome": _group_send(probe_id, {"type": "probe.disconnect", "reason": reason})}


def issue_tunnel_ticket(request, module_id, spec) -> dict:
    """Mint one single-use Console ticket for one tunnel session (1.1.0, Core 1.18.47). The caller must be the verified owner and
    module_id must equal it. Returns {outcome: ok, ticket, launch_url, expires_in: 60, session_id} or {outcome: denied|invalid|
    rate_limited|limit_reached|probe_offline|session_exists|unavailable, code, message}. Sync. See docs/probe-transport.md."""
    caller = _verified_owner_id()
    if caller is None:
        return dict(_DENIED)
    if module_id != caller:
        return {"outcome": "denied", "reason": "module_id must be the verified caller"}
    from . import probe_tunnel

    return probe_tunnel.issue_ticket(request, caller, spec)


def end_tunnel(module_id, session_id, ended_by) -> dict:
    """End one tunnel session (1.1.0). ended_by is engineer, admin or core. Returns {outcome: ok|invalid|denied, ...}. The first end
    wins: a second changes nothing and answers already_ended. Sync."""
    caller = _verified_owner_id()
    if caller is None:
        return dict(_DENIED)
    from . import probe_tunnel as tun

    if module_id != caller or not isinstance(ended_by, str) or ended_by not in tun.ENDED_BY_VALUES or tun._clean_session_id(session_id) is None:
        return {"outcome": "invalid"}
    try:
        record = tun.get_record(session_id)
        if record is None or record.get("module_id") != caller:
            return {"outcome": "invalid"}
        return tun.end_session(session_id, tun.ENDED_BY_REASON[ended_by], ended_by)
    except Exception:
        logger.warning("A tunnel session could not be ended.", exc_info=True)
        return {"outcome": "unavailable"}


def end_tunnels_for_probe(module_id, probe_id, reason) -> dict:
    """End every live tunnel session of one probe, and only that probe (1.1.0). reason is ended_by_core, probe_offline or server_restart,
    or one of the 1.0.0 disconnect reasons (disabled, revoked, key_rotated, module_disabled), which end the sessions ended_by_core and keep
    the reason in the audit row. Returns {outcome: ok|invalid|denied, ended: [session ids]}. Sync."""
    caller = _verified_owner_id()
    if caller is None:
        return {**_DENIED, "ended": []}
    from . import probe_tunnel as tun

    allowed = tun.PROBE_END_REASONS + DISCONNECT_REASONS
    if (module_id != caller or not isinstance(probe_id, str) or not PROBE_ID_PATTERN.fullmatch(probe_id)
            or not isinstance(reason, str) or reason not in allowed):
        return {"outcome": "invalid", "ended": []}
    stored, detail = (reason, "") if reason in tun.PROBE_END_REASONS else ("ended_by_core", reason)
    try:
        return {"outcome": "ok", "ended": tun.end_for_probe(probe_id, stored, "core", detail)}
    except Exception:
        logger.warning("The tunnel sessions of a probe could not be ended.", exc_info=True)
        return {"outcome": "unavailable", "ended": []}


def tunnel_status(module_id, session_ids=None, probe_id=None) -> dict:
    """The state of tunnel sessions (1.1.0), from the cache only. Name up to 200 session ids, or one probe id for its live sessions.
    Returns {outcome: ok|invalid|denied|unavailable, sessions: {session_id: {state: pending|open|ended|unknown, probe_id, started, last_data,
    console_connected, probe_connected, bytes_up, bytes_down, reason, ended_by}}}. Sync."""
    caller = _verified_owner_id()
    if caller is None:
        return {**_DENIED, "sessions": {}}
    from . import probe_tunnel as tun

    if module_id != caller or (session_ids is None) == (probe_id is None):
        return {"outcome": "invalid", "sessions": {}}
    try:
        if probe_id is not None:
            if not isinstance(probe_id, str) or not PROBE_ID_PATTERN.fullmatch(probe_id):
                return {"outcome": "invalid", "sessions": {}}
            ids = [sid for sid, entry in tun.read_index().items() if entry.get("probe_id") == probe_id][:tun.MAX_STATUS_IDS]
        else:
            if not isinstance(session_ids, (list, tuple, set, frozenset)) or len(session_ids) > tun.MAX_STATUS_IDS:
                return {"outcome": "invalid", "sessions": {}}
            ids = list(dict.fromkeys(session_ids))
            if any(tun._clean_session_id(item) is None for item in ids):
                return {"outcome": "invalid", "sessions": {}}
        return {"outcome": "ok", "sessions": tun.status_rows(ids)}
    except Exception:
        logger.warning("The tunnel status could not be read.", exc_info=True)
        return {"outcome": "unavailable", "sessions": {}}


class ProbeTransportProvider:
    """The capability provider. Every operation verifies the calling module from the call stack, never from ``module_id``."""

    def register_owner(self, *, module_id, authenticator_path, event_task_path):
        return register_owner(module_id, authenticator_path, event_task_path)

    def request(self, *, module_id, probe_id, frame, timeout=10):
        return request(module_id, probe_id, frame, timeout)

    def send(self, *, module_id, probe_id, frame):
        return send(module_id, probe_id, frame)

    def presence(self, *, module_id, probe_ids):
        return presence(module_id, probe_ids)

    def disconnect(self, *, module_id, probe_id, reason):
        return disconnect(module_id, probe_id, reason)

    def issue_tunnel_ticket(self, *, request, module_id, spec):
        return issue_tunnel_ticket(request, module_id, spec)

    def end_tunnel(self, *, module_id, session_id, ended_by):
        return end_tunnel(module_id, session_id, ended_by)

    def end_tunnels_for_probe(self, *, module_id, probe_id, reason):
        return end_tunnels_for_probe(module_id, probe_id, reason)

    def tunnel_status(self, *, module_id, session_ids=None, probe_id=None):
        return tunnel_status(module_id, session_ids, probe_id)


_PROVIDER = ProbeTransportProvider()


def tunnel_contract_metadata() -> dict[str, Any]:
    from . import probe_tunnel as tun

    return {
        "since": "1.1.0",
        "routes": {
            "console": "wss://<host>/ws/tfd/probe-tunnel/ (the engineer's Console). Header: Authorization: Ticket <43 characters>. Binary frames only.",
            "probe": "wss://<host>/ws/tfd/network-probe/tunnel/ (the probe). Headers: Authorization: Probe <probe_id>.<key> and X-Tunnel-Session: <uuid>. Binary frames only.",
        },
        "launch_url": "tectac-console://open?host=<server host>&ticket=<ticket>",
        "frame": "[type u8][stream u32 BE][payload]: OPEN 1, DATA 2 (1 to 32 KiB), ACK 3, CLOSE 4. Core reads byte 0 and the length only (5 up to 5 + 32 KiB); a text frame, an unknown type or any other length ends the session with close 1002.",
        "limits": {
            "sessions": tun.MAX_SESSIONS, "sessions_per_probe": tun.MAX_SESSIONS_PER_PROBE, "sessions_per_engineer": tun.MAX_SESSIONS_PER_ENGINEER,
            "tickets_per_engineer_per_minute": tun.TICKETS_PER_MINUTE, "ticket_seconds": tun.TICKET_TTL_SECONDS, "idle_seconds": tun.IDLE_SECONDS_MAX,
            "hard_cap_seconds": tun.CAP_SECONDS_MAX, "buffer_bytes": tun.BUFFER_CAP_BYTES, "pair_wait_seconds": tun.PAIR_WAIT_SECONDS,
            "recheck_seconds": tun.RECHECK_SECONDS,
        },
        "close_reasons": list(tun.ALL_REASONS),
        "close_codes": {
            "4401": "ticket unknown, used or expired, or the account, permission or module check failed; the probe side's identity was refused",
            "4403": "plain-text connection", "4404": "no pending session of that name for this ticket or probe",
            "4409": "that side of the session is already attached", "1002": "protocol error: a text frame, an unknown type byte or a bad length",
            "1013": "retry later: a busy or faulty server, or a relay that cannot keep up (relay_overloaded)", "1001": "the server is going away (server_restart)",
            "4503": "no owner registered, or the tunnel consumer could not be loaded",
        },
        "closed_event": "One tunnel.closed event per session reaches the owner's event task as (probe_id, frame) with func tunnel.closed and payload {session_id, reason, ended_by, bytes_up, bytes_down, source: core}. bytes_up is Console to probe. The probe's own tunnel.closed arrives through the normal event path; source tells them apart.",
        "audit": "custom:probe-tunnel-ticket, custom:probe-tunnel-connect, custom:probe-tunnel-end and custom:probe-tunnel-refused (non-strict, module core, provenance probe-transport, object type probe). No per-frame rows; never a ticket, a key, a header, a payload or a target address.",
        "shared_cache": "Limits, tickets and session state live in the shared Django cache (Redis). With no shared cache Core refuses to issue a ticket (unavailable).",
    }


def probe_transport_contract_metadata() -> dict[str, Any]:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": list(OPERATIONS),
        "owner": f"One module only: {OWNER_MODULE}. Core verifies the caller from the call stack (core.caller_identity), never from the module_id argument, which must equal the verified id. Any other caller, Core itself and an unverifiable caller get outcome denied from every operation. Core checks nothing about people: the owner checks the person's scope before it calls.",
        "socket": "wss://<host>/ws/tfd/network-probe/ for the Network Probe (a native client). Header: Authorization: Probe <probe_id>.<key>. No key in the URL, no Origin rule. TLS is terminated by nginx; Core refuses a connection the proxy reports as plain text (X-Forwarded-Proto http or ws). Until the owner has registered, every connection closes 4503.",
        "identity": "Core passes the probe id and key to the authenticator the owner registered. The authenticator returns {probe_id, client_id, site_id} for an accepted probe or one of probe_unknown, probe_disabled, probe_key_invalid for a refusal. Any other answer, a fault or a timeout (10 seconds) is a server fault: close 1013, counted nowhere. Checked on connect and again every 5 minutes. A Token header (an agent token) is refused with 4401 (wrong_scheme).",
        "frame": {
            "shape": "A JSON text frame: {v: 1, type, id, func, payload}. type is request, reply, event, ping or pong (there is no ack). id and func are strings (func at most 128 characters), payload an object (required for request, reply and event). Binary frames are refused.",
            "limits": {"bytes_per_frame": MAX_FRAME_BYTES, "frames_per_second": MAX_FRAMES_PER_SECOND, "bad_frames_before_close": MAX_BAD_FRAMES},
            "func": "Core never interprets func. It is the owner's.",
        },
        "operations_detail": {
            "register_owner": "register_owner(module_id, authenticator_path, event_task_path) -> {outcome: ok|denied|invalid}. authenticator_path is the dotted path of a plain function authenticate(probe_id, key) in the owner's own folder. event_task_path is the dotted path of a Celery task in the owner's own folder; Core calls it by its Celery name with (probe_id, frame) for every probe event. Identical re-registration is accepted (idempotent); different paths are refused. Call it from AppConfig.ready().",
            "request": "request(module_id, probe_id, frame, timeout=10) -> {outcome: ok|timeout|offline|denied|invalid, reply}. frame.type must be request. timeout is clamped to 1 to 30 seconds; the call returns within timeout + 1. offline is decided at once from presence. Sync: call it from a Celery task or a request thread, not from async code.",
            "send": "send(module_id, probe_id, frame) -> {outcome: ok|offline|denied|invalid}. frame.type must be event or reply. Fire and forget: no reply and no ack. The owner answers probe.hello with a reply frame that carries the hello's id.",
            "presence": "presence(module_id, probe_ids) -> {outcome, presence: {probe_id: {connected, since, client_id, site_id}}}. At most 2000 ids. Reads the cache only.",
            "disconnect": "disconnect(module_id, probe_id, reason) -> {outcome: ok|offline|denied|invalid}. reason is one of " + ", ".join(DISCONNECT_REASONS) + ". Closes that probe's socket with 4401.",
            "issue_tunnel_ticket": "issue_tunnel_ticket(request, module_id, spec) -> {outcome: ok, ticket, launch_url, expires_in: 60, session_id} or {outcome: denied|invalid|rate_limited|limit_reached|probe_offline|session_exists|unavailable, code, message} (1.1.0). request is the signed-in Tec-Tac request of the engineer. spec is {session_id (a uuid4 string), probe_id, permission (a networkprobe. permission the engineer must hold), target_label (audit text only), idle_s (default 900, 60 to 900), cap_s (default 14400, 60 to 14400)}. Core re-checks the account and the permission; the owner checks the person's scope and port rules before it calls, then asks the probe for tunnel.open.",
            "end_tunnel": "end_tunnel(module_id, session_id, ended_by) -> {outcome: ok|invalid|denied|unavailable, already_ended} (1.1.0). ended_by is engineer, admin or core. The first end wins; both data sockets close at once and the probe is sent tunnel.close.",
            "end_tunnels_for_probe": "end_tunnels_for_probe(module_id, probe_id, reason) -> {outcome: ok|invalid|denied|unavailable, ended: [session ids]} (1.1.0). reason is ended_by_core, probe_offline, server_restart, or a disconnect reason (kept in the audit row; the session ends ended_by_core). Call it when a probe is disabled or revoked.",
            "tunnel_status": "tunnel_status(module_id, session_ids=None, probe_id=None) -> {outcome, sessions: {session_id: {state: pending|open|ended|unknown, probe_id, started, last_data, console_connected, probe_connected, bytes_up, bytes_down, reason, ended_by}}} (1.1.0). Name up to 200 session ids, or one probe id for its live sessions. Reads the cache only.",
        },
        "events": "A probe event frame is handed to the owner's registered task with (probe_id, frame). There is no ack: delivery is best effort, and bulk data and the outbox stay on HTTPS. Core writes no per-event audit row; the owner writes its own.",
        "one_connection": "One live connection per probe, across processes. A new connection closes the older one with 4409.",
        "reconnect": "The probe waits a random time that starts at 1 second and doubles up to 5 minutes. After 4409 it waits 60 seconds. After 4401 it stops the channel and keeps its 5-minute HTTPS check.",
        "close_codes": {
            "4401": "identity refused (reason in the audit row), the owner no longer accepts the probe at a re-check, or the owner called disconnect. Never a server-side fault",
            "1013": "retry later: a server-side fault while checking the key (owner fault, pool full or timeout), a cache pool that is full at connect, or a re-check that got no identity answer for 10 minutes. Not an identity answer and never counted",
            "4403": "the proxy reports a plain-text connection",
            "4400": "20 invalid frames",
            "4408": "two pings went unanswered",
            "4409": "another connection for the same probe took over",
            "4429": "more than 10 failed attempts from one address in a minute (an IPv6 address counts by its /64), more than 10 failed checks naming one probe id in a minute (read only after a failed check, so a valid key is never refused for this), or more than 20 frames in a second",
            "1009": "a frame over 16 KiB",
            "4503": "no owner has registered, or the probe consumer could not be loaded; Tactical itself still runs",
            "tunnel": "The tunnel routes add 4404, 4409 (that side is attached), 1002 and 1001; see the tunnel section.",
        },
        "limits": {
            "ping_seconds": PING_SECONDS, "unanswered_pings": MAX_UNANSWERED_PINGS, "recheck_seconds": RECHECK_SECONDS,
            "recheck_jitter_seconds": RECHECK_JITTER_SECONDS, "recheck_grace_seconds": RECHECK_GRACE_SECONDS, "presence_seconds": PRESENCE_SECONDS,
            "failures_per_address_per_minute": FAILURES_PER_ADDRESS_PER_MINUTE, "failures_per_probe_per_minute": FAILURES_PER_PROBE_PER_MINUTE,
        },
        "audit": "Non-strict Core rows (module core, provenance probe-transport, object type probe): connect, disconnect and refusals (probe id when valid, reason code, address). Never a key, an Authorization header or a payload.",
        "core_does_not": "Core does not interpret messages, keep a probe record, store events, check a person's scope or port rules, read tunnel stream ids, windows or payloads, or run module code. Agent and probe credentials never cross.",
        "added_in": "1.0.0 (Core 1.18.46): the control channel and its five operations. 1.1.0 (Core 1.18.47, framework >=1.18.47): the tunnel operations (issue_tunnel_ticket, end_tunnel, end_tunnels_for_probe, tunnel_status) and the two tunnel routes. Additive: nothing in 1.0.0 changed.",
        "tunnel": tunnel_contract_metadata(),
    }


def register_core_probe_transport_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="The Network Probe websocket and tunnel: identity through the owner's authenticator, presence, requests, events, disconnect, and (1.1.0) the Console ticket, the tunnel relay and its end and status, for the owning module (networkprobe) only.",
        operations=OPERATIONS,
        metadata=probe_transport_contract_metadata(),
    )
