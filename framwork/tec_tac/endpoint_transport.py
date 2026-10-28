"""Core's endpoint agent transport (Core 1.17.90, AD-54, plan section 9A): one websocket, one identity check, one contract.

The endpoint agent is a native client that connects to /ws/tfd/endpoint-agent/ with Tactical's own agent token (the DRF token Tactical
created at install) and its agent id. Core checks that pair against Tactical's own tables, keeps one live connection per agent, answers
ping, checks the frame shape, hands an event to the one owning module (nats-comms) and routes a reply back to the request that is waiting.
Core never interprets ``func``. Meaning, the agent record and the page are the owner's.

This file holds what has no channels import: the identity check, the failure rate limit, the header and frame checks, the presence keys,
the owner registry, the route class and the public contract (core.endpoint_transport 1.0.0). The consumer lives in
endpoint_transport_consumer and is imported on the first connection, so a fault there closes the socket 4503 and never stops Tactical.

There is no enrolment, no revoke call and no model. Tactical deleting the agent (or issuing it a new token) is the revoke: the next
re-check, at most 10 minutes later, closes the socket 4401.

Secrets: the token is read from the Authorization header of the scope and from nowhere else. It is never in a URL, a log line, an audit
row, a refusal text or a return value. Refusals carry a reason code only.
"""
from __future__ import annotations

import asyncio
import hmac
import importlib
import ipaddress
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("tec_tac.endpoint_transport")

CAPABILITY_ID = "core.endpoint_transport"
CAPABILITY_VERSION = "1.0.0"
OWNER_MODULE = "nats-comms"  # the one module that may use the contract; a constant of Core's table, like OWNER_MODULE of remote-background
ROUTE_PATTERN = "ws/tfd/endpoint-agent/"
SOCKET_PATH = "/ws/tfd/endpoint-agent/"

GROUP_PREFIX = "tectac-ea-"
PRESENCE_PREFIX = "tec-tac:ea:presence:"
FAILURE_PREFIX = "tec-tac:ea:fail:"
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,80}$")  # a Tactical agent id, within the channel group name alphabet
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9]{16,128}$")  # a DRF token is 40 hex characters; the bound is loose, the lookup is exact

CLOSE_UNAUTHORIZED = 4401
CLOSE_PLAINTEXT = 4403
CLOSE_BAD_FRAME = 4400
CLOSE_SUPERSEDED = 4409
CLOSE_PING_TIMEOUT = 4408
CLOSE_RATE_LIMITED = 4429
CLOSE_UNAVAILABLE = 4503
CLOSE_TOO_BIG = 1009

FAILURES_PER_MINUTE = 10
RECHECK_SECONDS = 600
PING_SECONDS = 60
MAX_UNANSWERED_PINGS = 2
PRESENCE_SECONDS = 150
MAX_FRAME_BYTES = 64 * 1024
MAX_FRAMES_PER_SECOND = 20
MAX_BAD_FRAMES = 20
MAX_PENDING_REQUESTS = 256
MAX_INFLIGHT_EVENTS = 32
ENQUEUE_TIMEOUT_SECONDS = 5.0
MAX_AGENTS_PER_CALL = 2000
MIN_REQUEST_TIMEOUT = 1.0
MAX_REQUEST_TIMEOUT = 30.0

FRAME_TYPES = ("request", "reply", "event", "ack", "ping", "pong")
_NEEDS_FUNC = ("request", "reply", "event")
_NEEDS_PAYLOAD = ("request", "reply", "event")
_FRAME_FIELD_MAX = 128

REFUSAL_MESSAGES = {
    "malformed_agent_id": "the X-Agent-Id header is missing or not a valid agent id",
    "malformed_token": "the Authorization header is missing or is not 'Token <key>'",
    "unknown_token": "no agent token matches",
    "token_mismatch": "no agent token matches",
    "no_agent": "the token does not belong to an agent",
    "agent_mismatch": "the token belongs to a different agent",
    "inactive": "the agent account is inactive",
    "lookup_failed": "the agent token could not be checked",
}


# ------------------------------------------------------------------------------------------------ identity
@dataclass(frozen=True)
class EndpointAuthResult:
    """The answer of ``authenticate_endpoint_agent``. ``ok`` is True only when every check passed. ``reason`` is a code from
    REFUSAL_MESSAGES when it is not. The token is never part of it."""

    ok: bool
    reason: str | None = None
    agent_pk: int | None = None
    agent_id: str | None = None


def _refused(reason: str) -> EndpointAuthResult:
    return EndpointAuthResult(False, reason)


def authenticate_endpoint_agent(token, agent_id) -> EndpointAuthResult:
    """Check an agent token and agent id against Tactical's own tables (AD-54 E5). Sync: call it through database_sync_to_async.

    Accepted only when ALL hold: the token is a Tactical agent token (rest_framework.authtoken Token), its user is linked to an agent
    (a dashboard user's token or a Knox session token has no agent or is not in this table), that agent's agent_id equals the one
    presented exactly, and the user is active. Every other case is a refusal with a reason code. Reads Tactical's tables only."""
    if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
        return _refused("malformed_agent_id")
    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
        return _refused("malformed_token")
    try:
        from rest_framework.authtoken.models import Token

        row = Token.objects.select_related("user").filter(key=token).first()
        if row is None:
            return _refused("unknown_token")
        if not hmac.compare_digest(str(row.key).encode("utf-8"), token.encode("utf-8")):
            return _refused("token_mismatch")
        user = row.user
        if getattr(user, "agent_id", None) is None:
            return _refused("no_agent")
        agent = user.agent
        stored = str(getattr(agent, "agent_id", "") or "")
        if not hmac.compare_digest(stored.encode("utf-8"), agent_id.encode("utf-8")):
            return _refused("agent_mismatch")
        if not getattr(user, "is_active", False):
            return _refused("inactive")
        return EndpointAuthResult(True, None, getattr(agent, "pk", None), stored)
    except Exception:
        logger.exception("The endpoint agent token could not be checked; refusing.")
        return _refused("lookup_failed")


# ------------------------------------------------------------------------------------------------ headers, address, failure limit
def _scope_headers(scope) -> dict:
    """Header name (lower-case bytes) to a list of values. A name that appears twice is kept twice, so it can be refused."""
    found: dict = {}
    for name, value in scope.get("headers") or []:
        found.setdefault(bytes(name).lower(), []).append(bytes(value))
    return found


def parse_endpoint_headers(scope) -> tuple[str | None, str | None, str | None]:
    """(token, agent_id, reason). The token is read from the Authorization header ('Token <key>') and the agent id from X-Agent-Id.
    A missing, duplicated, over-long or malformed header gives a reason and no value. Nothing here logs or returns the header."""
    headers = _scope_headers(scope)
    agent_values = headers.get(b"x-agent-id") or []
    if len(agent_values) != 1:
        return None, None, "malformed_agent_id"
    try:
        agent_id = agent_values[0].decode("ascii").strip()
    except UnicodeDecodeError:
        return None, None, "malformed_agent_id"
    if not AGENT_ID_PATTERN.fullmatch(agent_id):
        return None, None, "malformed_agent_id"
    auth_values = headers.get(b"authorization") or []
    if len(auth_values) != 1:
        return None, agent_id, "malformed_token"
    try:
        text = auth_values[0].decode("ascii")
    except UnicodeDecodeError:
        return None, agent_id, "malformed_token"
    scheme, _, key = text.partition(" ")
    if scheme.lower() != "token" or not TOKEN_PATTERN.fullmatch(key):
        return None, agent_id, "malformed_token"
    return key, agent_id, None


def client_ip(scope) -> str:
    """The address failures are counted against. nginx sets X-Real-IP from $remote_addr (Tactical's install.sh), so a client cannot
    choose it. The leftmost X-Forwarded-For is client controlled (nginx appends to it, uvicorn trusts every proxy), so it is never used.
    Falls back to the ASGI client address."""
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
    """True when the proxy says the client used a plain-text connection (X-Forwarded-Proto http or ws). Absent header: Core cannot tell,
    and TLS is left to nginx."""
    values = _scope_headers(scope).get(b"x-forwarded-proto", [])
    if not values:
        return False
    return values[0].decode("latin-1").split(",")[0].strip().lower() in ("http", "ws")


def _cache():
    from django.core.cache import cache

    return cache


def _failure_key(ip: str) -> str:
    return f"{FAILURE_PREFIX}{ip}:{int(time.time() // 60)}"


def rate_limited(ip: str) -> bool:
    """True when this address has had FAILURES_PER_MINUTE failed attempts in the current minute. Sync (reads the cache). A cache fault
    reads as not limited and is logged: a token has 160 bits, so a missing counter does not make guessing possible."""
    try:
        return int(_cache().get(_failure_key(ip), 0) or 0) >= FAILURES_PER_MINUTE
    except Exception:
        logger.warning("The endpoint failure counter could not be read.", exc_info=True)
        return False


def note_failure(ip: str) -> None:
    """Count one failed attempt for this address (failures only: a good connect never counts). Sync."""
    try:
        cache = _cache()
        key = _failure_key(ip)
        cache.add(key, 0, timeout=120)
        try:
            cache.incr(key)
        except ValueError:
            cache.add(key, 1, timeout=120)
    except Exception:
        logger.warning("The endpoint failure counter could not be written.", exc_info=True)


# ------------------------------------------------------------------------------------------------ frames
def validate_frame(frame, *, allowed_types=FRAME_TYPES) -> str | None:
    """The frame checks of plan 7.2 and nothing more: a JSON object, v == 1, a known type, id and func strings, payload an object.
    Returns a reason code, or None when the frame is acceptable. Core never looks at ``func`` beyond its type and length."""
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
    """A frame id or func as an audit row or a log line may carry it: printable characters only, bounded."""
    return "".join(ch for ch in str(value or "") if ch.isprintable())[:limit]


# ------------------------------------------------------------------------------------------------ presence
def group_name(agent_id: str) -> str:
    return f"{GROUP_PREFIX}{agent_id}"


def presence_key(agent_id: str) -> str:
    return f"{PRESENCE_PREFIX}{agent_id}"


def set_presence(agent_id: str, since: str, owner: str = "") -> None:
    """Mark the agent connected. Called on connect. ``owner`` is a random id of this connection, so a newer connection is never mistaken
    for this one even when both start in the same instant. Sync (the cache)."""
    _cache().set(presence_key(agent_id), {"connected": True, "since": since, "owner": owner}, timeout=PRESENCE_SECONDS)


def refresh_presence(agent_id: str, owner: str = "") -> None:
    """Keep the key alive without taking it over: only while the cached owner is this connection. Sync."""
    cache = _cache()
    current = cache.get(presence_key(agent_id))
    if isinstance(current, dict) and current.get("owner") == owner:
        cache.set(presence_key(agent_id), current, timeout=PRESENCE_SECONDS)


def clear_presence(agent_id: str, owner: str = "") -> bool:
    """Delete the key only when this connection still owns it. Sync. True when it was deleted."""
    cache = _cache()
    current = cache.get(presence_key(agent_id))
    if isinstance(current, dict) and current.get("owner") == owner:
        cache.delete(presence_key(agent_id))
        return True
    return False


def _presence_row(value) -> dict:
    if isinstance(value, dict) and value.get("connected"):
        return {"connected": True, "since": value.get("since")}
    return {"connected": False, "since": None}


def presence_many(agent_ids) -> dict:
    """Agent id to {connected, since}, from the cache only, with one get_many. Sync."""
    ids = list(agent_ids)
    found = _cache().get_many([presence_key(a) for a in ids]) or {}
    return {a: _presence_row(found.get(presence_key(a))) for a in ids}


# ------------------------------------------------------------------------------------------------ the owner of events
_OWNER_LOCK = threading.Lock()
_OWNER: dict[str, str] | None = None


def get_owner() -> dict[str, str] | None:
    """The registered owner of events in this process: {module_id, path, task_name}, or None. The consumer reads it."""
    with _OWNER_LOCK:
        return dict(_OWNER) if _OWNER else None


def clear_owner_for_tests() -> None:
    global _OWNER
    with _OWNER_LOCK:
        _OWNER = None


def _owner_folder() -> str | None:
    """The real path of the installed, enabled nats-comms extension folder, or None."""
    from . import module_state, registry

    plugin = next((p for p in registry.discover_plugins() if p.plugin_id == OWNER_MODULE), None)
    if plugin is None or plugin.plugin_type != "extension" or plugin.legacy:
        return None
    state = module_state.load_state()
    if isinstance(state, dict) and state.get("_corrupt"):
        return None
    if not module_state.is_enabled(OWNER_MODULE, state):
        return None
    return os.path.normcase(os.path.realpath(str(plugin.root)))


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _load_task(path: str):
    module_name, _, attr = path.rpartition(".")
    if not module_name or not attr:
        raise ValueError("event_task_path must be a dotted path to a Celery task.")
    return getattr(importlib.import_module(module_name), attr)


def _task_name_and_file(task) -> tuple[str, str]:
    name = getattr(task, "name", None)
    if not isinstance(name, str) or not name or not (hasattr(task, "apply_async") or hasattr(task, "delay")):
        raise ValueError("event_task_path is not a Celery task.")
    func = getattr(task, "run", None) or task
    code = getattr(getattr(func, "__func__", func), "__code__", None)
    filename = getattr(code, "co_filename", None)
    if not isinstance(filename, str) or not filename or filename.startswith("<"):
        raise ValueError("the task's code is not a file.")
    return name, os.path.normcase(os.path.realpath(filename))


def _register_owner(module_id: str, event_task_path: str) -> dict:
    global _OWNER
    if module_id != OWNER_MODULE:
        return {"outcome": "denied", "reason": "module_id must be the verified caller"}
    if not isinstance(event_task_path, str) or not re.fullmatch(r"[A-Za-z_][\w.]{0,200}", event_task_path or ""):
        return {"outcome": "invalid", "reason": "event_task_path must be a dotted path to a Celery task"}
    with _OWNER_LOCK:
        current = dict(_OWNER) if _OWNER else None
    if current is not None:
        if current["path"] == event_task_path:
            return {"outcome": "ok", "registered": True, "idempotent": True}
        return {"outcome": "invalid", "reason": "an owner is already registered with a different task path"}
    try:
        folder = _owner_folder()
        if folder is None:
            return {"outcome": "denied", "reason": f"{OWNER_MODULE} is not an installed, enabled extension"}
        name, filename = _task_name_and_file(_load_task(event_task_path))
    except Exception:
        logger.warning("The endpoint event task could not be checked.", exc_info=True)
        return {"outcome": "invalid", "reason": "event_task_path could not be loaded as a Celery task"}
    if not _inside(filename, folder):
        return {"outcome": "invalid", "reason": "the task's code must lie inside the owner module's own folder"}
    with _OWNER_LOCK:
        if _OWNER is not None and _OWNER["path"] != event_task_path:
            return {"outcome": "invalid", "reason": "an owner is already registered with a different task path"}
        _OWNER = {"module_id": OWNER_MODULE, "path": event_task_path, "task_name": name}
    return {"outcome": "ok", "registered": True, "idempotent": False}


def enqueue_event(agent_id: str, frame: dict) -> str:
    """Hand an agent event to the owner's Celery task with (agent_id, frame). Sync and blocking (a broker call): the consumer runs it in a
    worker thread under a timeout. Returns ok, no_owner or failed. Never raises."""
    owner = get_owner()
    if owner is None:
        return "no_owner"
    try:
        from celery import current_app

        current_app.send_task(owner["task_name"], args=(agent_id, frame))
        return "ok"
    except Exception:
        logger.warning("The endpoint event could not be queued for its owner.", exc_info=True)
        return "failed"


def record_endpoint_event(action: str, agent_id: str | None = None, *, reason: str | None = None, ip: str | None = None,
                          func: str | None = None, frame_id: str | None = None, refusal: bool = False) -> None:
    """One non-strict Core audit row for the socket. Sync (a database write). Never raises. Holds only the fields named here: never a
    token, an Authorization header or a payload. A refusal whose agent id is not valid is written without one."""
    try:
        from . import audit as audit_core

        safe_agent = agent_id if isinstance(agent_id, str) and AGENT_ID_PATTERN.fullmatch(agent_id) else None
        metadata = {k: v for k, v in {
            "reason": reason, "ip": ip, "func": clean_label(func) if func else None, "frame_id": clean_label(frame_id) if frame_id else None,
        }.items() if v}
        audit_core._record_endpoint_transport(
            action=action, agent_id=safe_agent, message=f"Endpoint agent socket: {action.split(':', 1)[-1]}.",
            metadata=metadata, refusal=refusal,
        )
    except Exception:
        logger.warning("The endpoint transport audit row could not be written (%s).", action, exc_info=True)


# ------------------------------------------------------------------------------------------------ route
class _EndpointAgentRoute:
    """The ASGI app of ws/tfd/endpoint-agent/. Imports the consumer on the first connection, so a fault there closes the socket 4503 and
    never stops Tactical from starting (rule 1.15)."""

    async def __call__(self, scope, receive, send):
        try:
            from .endpoint_transport_consumer import EndpointAgentConsumer

            app = EndpointAgentConsumer.as_asgi()
        except Exception:
            logger.exception("The endpoint agent consumer could not be loaded; closing the socket.")
            await send({"type": "websocket.close", "code": CLOSE_UNAVAILABLE})
            return
        await app(scope, receive, send)


def endpoint_agent_route():
    return _EndpointAgentRoute()


def install_endpoint_agent_route() -> bool:
    """Append ws/tfd/endpoint-agent/ to Tactical's ws_urlpatterns, once. Returns True when this call added it."""
    from django.urls import path
    from tacticalrmm import urls as tactical_urls

    routes = tactical_urls.ws_urlpatterns
    if ROUTE_PATTERN in {str(getattr(pattern, "pattern", "")) for pattern in routes}:
        return False
    routes.append(path(ROUTE_PATTERN, endpoint_agent_route()))
    return True


# ------------------------------------------------------------------------------------------------ the contract
def _caller_is_owner() -> bool:
    """True only when the verified calling module is nats-comms (an enabled, installed extension). Never from an argument. Every frame of
    this file is skipped by the walk, so this helper may be called from any depth of the provider."""
    from .caller_identity import calling_module_for_core_provider

    try:
        identity = calling_module_for_core_provider(provider_file=__file__)
    except Exception:
        return False
    return identity is not None and identity.module_id == OWNER_MODULE


_DENIED = {"outcome": "denied"}


def _channel_layer():
    from channels.layers import get_channel_layer

    return get_channel_layer()


def _clamp_timeout(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return None
    return float(min(MAX_REQUEST_TIMEOUT, max(MIN_REQUEST_TIMEOUT, value)))


def _agent_ids(agent_ids) -> list[str] | None:
    """The agent ids de-duplicated in order, or None when the list is not a list of valid ids or is over the cap."""
    if not isinstance(agent_ids, (list, tuple, set, frozenset)):
        return None
    seen: dict[str, None] = {}
    for item in agent_ids:
        if not isinstance(item, str) or not AGENT_ID_PATTERN.fullmatch(item):
            return None
        seen[item] = None
    if len(seen) > MAX_AGENTS_PER_CALL:
        return None
    return list(seen)


def _free_channel(layer, channel: str) -> None:
    """Drop the reply channel's queue where the layer keeps one in memory. A Redis layer lets the unused key expire on its own."""
    channels = getattr(layer, "channels", None)
    if isinstance(channels, dict):
        channels.pop(channel, None)


def register_owner(module_id, event_task_path) -> dict:
    """Register the Celery task that receives agent events. Only nats-comms (verified by Core) may call it. See docs/endpoint-transport.md."""
    if not _caller_is_owner():
        return dict(_DENIED)
    return _register_owner(module_id, event_task_path)


def request(module_id, agent_id, frame, timeout=10) -> dict:
    """Send a request frame to one connected agent and wait for its reply. Returns {outcome: ok|timeout|offline|denied|invalid, reply}.
    Sync (async_to_sync): call it from a Celery task or a request thread, never from async code. Returns within timeout + 1 second."""
    if not _caller_is_owner():
        return dict(_DENIED)
    if module_id != OWNER_MODULE or not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
        return {"outcome": "invalid", "reply": None}
    wait = _clamp_timeout(timeout)
    if wait is None or validate_frame(frame, allowed_types=("request",)) is not None or not frame_size_ok(frame):
        return {"outcome": "invalid", "reply": None}
    try:
        if not _presence_row(_cache().get(presence_key(agent_id)))["connected"]:
            return {"outcome": "offline", "reply": None}
        layer = _channel_layer()
    except Exception:
        logger.warning("The endpoint presence could not be read.", exc_info=True)
        return {"outcome": "offline", "reply": None}
    if layer is None:
        return {"outcome": "offline", "reply": None}
    from asgiref.sync import async_to_sync

    async def go():
        channel = await layer.new_channel()
        try:
            await layer.group_send(group_name(agent_id), {"type": "endpoint.request", "frame": frame, "reply_channel": channel, "timeout": wait})
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
        logger.warning("The endpoint request failed.", exc_info=True)
        return {"outcome": "offline", "reply": None}


def send_many(module_id, agent_ids, frame) -> dict:
    """Fire and forget one event frame to many agents (at most 2000 ids). Returns {outcome, queued, offline}. Agents with no presence key are
    listed in ``offline`` and not sent. One event loop for the whole batch. Sync."""
    if not _caller_is_owner():
        return {**_DENIED, "queued": 0, "offline": []}
    ids = _agent_ids(agent_ids)
    if module_id != OWNER_MODULE or ids is None or validate_frame(frame, allowed_types=("event",)) is not None or not frame_size_ok(frame):
        return {"outcome": "invalid", "queued": 0, "offline": []}
    try:
        live = presence_many(ids)
        layer = _channel_layer()
    except Exception:
        logger.warning("The endpoint presence could not be read.", exc_info=True)
        return {"outcome": "offline", "queued": 0, "offline": list(ids)}
    online = [a for a in ids if live[a]["connected"]]
    offline = [a for a in ids if not live[a]["connected"]]
    if layer is None or not online:
        return {"outcome": "ok", "queued": 0, "offline": offline if layer is not None else list(ids)}
    from asgiref.sync import async_to_sync

    async def go():
        sent = 0
        for start in range(0, len(online), 100):
            batch = online[start:start + 100]
            results = await asyncio.gather(
                *(layer.group_send(group_name(a), {"type": "endpoint.push", "frame": frame}) for a in batch), return_exceptions=True,
            )
            sent += sum(1 for r in results if not isinstance(r, BaseException))
        return sent

    async def bounded():
        return await asyncio.wait_for(go(), timeout=MAX_REQUEST_TIMEOUT)

    try:
        queued = async_to_sync(bounded)()
    except Exception:
        logger.warning("The endpoint send failed.", exc_info=True)
        return {"outcome": "offline", "queued": 0, "offline": list(ids)}
    return {"outcome": "ok", "queued": queued, "offline": offline}


def presence(module_id, agent_ids) -> dict:
    """Per agent {connected, since}, from the cache only (one get_many), at most 2000 ids. Sync."""
    if not _caller_is_owner():
        return {**_DENIED, "presence": {}}
    ids = _agent_ids(agent_ids)
    if module_id != OWNER_MODULE or ids is None:
        return {"outcome": "invalid", "presence": {}}
    try:
        return {"outcome": "ok", "presence": presence_many(ids)}
    except Exception:
        logger.warning("The endpoint presence could not be read.", exc_info=True)
        return {"outcome": "offline", "presence": {}}


class EndpointTransportProvider:
    """The capability provider. Every operation verifies the calling module from the call stack, never from ``module_id``."""

    def register_owner(self, *, module_id, event_task_path):
        return register_owner(module_id, event_task_path)

    def request(self, *, module_id, agent_id, frame, timeout=10):
        return request(module_id, agent_id, frame, timeout)

    def send_many(self, *, module_id, agent_ids, frame):
        return send_many(module_id, agent_ids, frame)

    def presence(self, *, module_id, agent_ids):
        return presence(module_id, agent_ids)


_PROVIDER = EndpointTransportProvider()


def endpoint_transport_contract_metadata() -> dict[str, Any]:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["register_owner", "request", "send_many", "presence"],
        "owner": f"One module only: {OWNER_MODULE}. Core verifies the caller from the call stack (core.caller_identity), never from the module_id argument, which must equal the verified id. Any other caller, Core itself and an unverifiable caller get outcome denied from every operation. Core checks nothing about people: the owner checks the person's scope before it calls.",
        "socket": "wss://<host>/ws/tfd/endpoint-agent/ for the endpoint agent (a native client). Headers: Authorization: Token <Tactical agent token>, X-Agent-Id: <Tactical agent id>. No token in the URL, no Origin rule. TLS is terminated by nginx; Core refuses a connection the proxy reports as plain text (X-Forwarded-Proto http or ws).",
        "identity": "The token must be a Tactical agent token whose user is linked to the agent named in X-Agent-Id, and the user must be active. A dashboard user's token or a Knox session token is refused. Checked on connect and again every 10 minutes. There is no enrolment and no revoke call: Tactical deleting the agent or issuing a new token is the revoke.",
        "frame": {
            "shape": "A JSON text frame: {v: 1, type, id, func, payload}. type is request, reply, event, ack, ping or pong. id and func are strings (func at most 128 characters), payload an object (required for request, reply and event). Binary frames are refused.",
            "limits": {"bytes_per_frame": MAX_FRAME_BYTES, "frames_per_second": MAX_FRAMES_PER_SECOND},
            "func": "Core never interprets func. It is the owner's.",
        },
        "operations_detail": {
            "register_owner": "register_owner(module_id, event_task_path) -> {outcome: ok|denied|invalid}. event_task_path is the dotted import path of a Celery task defined in the owner's own folder; Core calls it by its Celery name with (agent_id, frame) for every agent event. Identical re-registration is accepted (idempotent, every process runs ready()); a different path is refused. Call it from AppConfig.ready().",
            "request": "request(module_id, agent_id, frame, timeout=10) -> {outcome: ok|timeout|offline|denied|invalid, reply}. frame.type must be request. timeout is clamped to 1 to 30 seconds; the call returns within timeout + 1. offline is decided at once from presence. Sync: call it from a Celery task or a request thread, not from async code.",
            "send_many": "send_many(module_id, agent_ids, frame) -> {outcome, queued, offline}. frame.type must be event. At most 2000 agent ids (more is invalid and nothing is sent). Ids are de-duplicated. Offline agents are listed and not sent. Fire and forget: no reply and no ack.",
            "presence": "presence(module_id, agent_ids) -> {outcome, presence: {agent_id: {connected, since}}}. At most 2000 ids. Reads the cache only.",
        },
        "events": "An agent event frame is handed to the owner's registered task with (agent_id, frame), one audit row is written (agent, func, id; never the payload) and only then does Core send the ack (type ack, same id). With no owner registered, or when the hand-over fails, Core sends no ack: the agent keeps the event and resends after it reconnects.",
        "one_connection": "One live connection per agent, across processes. A new connection closes the older one with 4409.",
        "close_codes": {
            "4401": "identity refused (reason in the audit row), or the Tactical agent or token is gone at a re-check",
            "4403": "the proxy reports a plain-text connection",
            "4408": "two pings went unanswered",
            "4409": "another connection for the same agent took over",
            "4429": "more than 10 failed attempts from one address in a minute, or more than 20 frames in a second",
            "1009": "a frame over 64 KB",
            "4503": "the endpoint consumer could not be loaded; Tactical itself still runs",
        },
        "audit": "Non-strict Core rows (module core, provenance endpoint-transport): connect, disconnect, refusals (agent id presented, reason code, address), and each event (agent, func, frame id). The owner registration is memory only and writes no row. Never a token, an Authorization header or a payload.",
        "core_does_not": "Core does not interpret messages, keep an agent record, store events, check a person's scope or run module code.",
        "added_in": "1.0.0 (Core 1.17.90). Needs framework >=1.17.90. Additive: nothing existing changed.",
    }


def register_core_endpoint_transport_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="The endpoint agent websocket: identity, presence, requests, events and fan-out, for the owning module (nats-comms) only.",
        operations=("register_owner", "request", "send_many", "presence"),
        metadata=endpoint_transport_contract_metadata(),
    )
