"""The endpoint agent socket (Core 1.17.90; burst handling and limiter order 1.17.92; re-check deadline and busy cache 1.17.93). Loaded lazily by endpoint_transport._EndpointAgentRoute.

Connect: headers from the scope, the address ceiling, the identity check, and only then any per-agent decision (a valid token is never
refused because someone else failed). Then the group tectac-ea-<agent_id>, the takeover message and the presence key. A watcher task
re-checks the token every 10 minutes, pings every 60 seconds and closes after two unanswered pings (the first ping and the re-check are
jittered, so a fleet that connected in one ramp does not hit the database together). The receive loop never touches the database, the
cache or the broker: every blocking call runs on one of Core's own small pools (auth, recheck, cache, audit, hand-over; see endpoint_transport)
and never on the event loop's default executor, which Tactical's own sockets share. A full pool answers at once.

A server-side fault while checking the token closes 1013 (retry later) and counts nothing. 4401 is an identity answer only. A cache pool that
is full closes 1013 too (the limiter could not be read or written, so it must not read as off). A re-check that gets no identity answer for
RECHECK_SECONDS + jitter + RECHECK_GRACE_SECONDS closes 1013, so a long fault never keeps a socket open for good.

The socket is accepted before a refusal is closed, so the native client can read the close code (4401, 4429, 1013). Core logs no
frame, no payload, no token and no Authorization header. Close codes and limits: docs/endpoint-transport.md.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone

from channels.generic.websocket import AsyncWebsocketConsumer

from . import endpoint_transport as et

logger = logging.getLogger("tec_tac.endpoint_transport")

WATCH_TICK_SECONDS = 5
LOG_THROTTLE_SECONDS = 60


class _Bucket:
    """Token bucket: MAX_FRAMES_PER_SECOND frames, refilled continuously. In memory, per connection."""

    def __init__(self, clock):
        self._clock = clock
        self.tokens = float(et.MAX_FRAMES_PER_SECOND)
        self.at = clock()

    def take(self) -> bool:
        now = self._clock()
        self.tokens = min(float(et.MAX_FRAMES_PER_SECOND), self.tokens + (now - self.at) * et.MAX_FRAMES_PER_SECOND)
        self.at = now
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


class EndpointAgentConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._clock = time.monotonic  # replaced in tests
        self._sleep = asyncio.sleep
        self._random = random.random  # replaced in tests
        self._bg: set = set()
        self.agent_id = None
        self._token = None
        self._ip = "unknown"
        self._since = None
        self._owner = uuid.uuid4().hex
        self._connected = False
        self._superseded = False
        self._watch = None
        self._events: set = set()
        self._pending: dict = {}  # request id -> (reply channel, expires at)
        self._bucket = _Bucket(self._clock)
        self._bad_frames = 0
        self._dropped_replies = 0
        self._unanswered_pings = 0
        self._ping_count = 0
        self._next_recheck = 0.0
        self._identity_ok_at = 0.0  # the last time the token passed a check (connect or re-check)
        self._next_ping = 0.0
        self._last_log = {}

    # -------------------------------------------------------------------------------------------- helpers
    async def _cache_call(self, func, *args, default=None, busy_raises=False):
        """A blocking cache call on the CACHE pool. A fault or a full pool is logged (throttled) and gives ``default``. With
        ``busy_raises`` a full pool raises PoolFull instead, so the limiter never reads as off because the pool is busy; a real cache
        error still gives ``default`` (the signed fail-open for a cache that is down)."""
        try:
            return await et.run_in_pool("cache", func, *args)
        except et.PoolFull:
            self._throttled_log("cache", "An endpoint cache call could not be made (%s).", getattr(func, "__name__", "call"))
            if busy_raises:
                raise
            return default
        except Exception:
            logger.debug("An endpoint cache call failed.", exc_info=True)
            self._throttled_log("cache", "An endpoint cache call could not be made (%s).", getattr(func, "__name__", "call"))
            return default

    async def _audit(self, action, **kwargs):
        """One non-strict audit row on the AUDIT pool. A full pool drops the row (throttled log line): rows are not a gate."""
        try:
            await et.run_in_pool("audit", et.record_endpoint_event, action, **kwargs)
        except et.PoolFull:
            self._throttled_log("audit_full", "The endpoint audit pool is full; an audit row was not written.")
        except Exception:
            logger.warning("The endpoint audit row could not be written.", exc_info=True)

    def _spawn(self, coro):
        task = asyncio.ensure_future(coro)
        self._bg.add(task)
        task.add_done_callback(self._bg.discard)
        return task

    async def _refusal_row(self, **kwargs):
        """A refusal row, inside the global budget of REFUSAL_ROWS_PER_MINUTE."""
        if await self._cache_call(et.refusal_row_allowed, default=True):
            await self._audit("custom:endpoint-refused", ip=self._ip, refusal=True, **kwargs)

    def _throttled_log(self, key, message, *args, **kwargs):
        now = self._clock()
        if now - self._last_log.get(key, -1e9) >= LOG_THROTTLE_SECONDS:
            self._last_log[key] = now
            logger.warning(message, *args, **kwargs)

    async def _send_frame(self, frame):
        await self.send(text_data=json.dumps(frame, separators=(",", ":")))

    async def _refuse(self, code, reason, *, agent_id=None, audit=True):
        """Accept, close with the code (so the client can read it, and is not held by the audit write), then write the refusal row unless
        audit is False or the row budget is spent. The token is never in the row."""
        await self.accept()
        await self.close(code)
        if audit:
            await self._refusal_row(agent_id=agent_id, reason=reason)

    async def _unavailable(self, result, agent_id):
        """A server-side fault or a full pool: close 1013, count nothing, write at most a throttled non-strict row."""
        await self.accept()
        await self.close(et.CLOSE_RETRY_LATER)
        if et.transient_row_allowed():
            await self._audit("custom:endpoint-refused", agent_id=agent_id, reason=result.reason, ip=self._ip)

    # -------------------------------------------------------------------------------------------- connect and disconnect
    async def connect(self):
        scope = self.scope
        self._ip = et.client_ip(scope)
        # The address ceiling is a NAT-sized pre-auth bound. An address over it is closed 4429 with no audit row.
        try:
            limited = await self._cache_call(et.rate_limited, self._ip, default=False, busy_raises=True)
        except et.PoolFull:
            await self._unavailable(et._transient("busy"), None)  # the limiter could not be read: retry later, count nothing
            return
        if limited:
            await self._refuse(et.CLOSE_RATE_LIMITED, "rate_limited", audit=False)
            return
        if et.forwarded_plaintext(scope):
            await self._cache_call(et.note_failure, self._ip)
            await self._refuse(et.CLOSE_PLAINTEXT, "plaintext_refused")
            return
        token, agent_id, reason = et.parse_endpoint_headers(scope)
        result = None
        if reason is None:
            # The identity check comes before any per-agent decision, so a valid token is never refused because someone else failed.
            result = await et.authenticate_async(token, agent_id)
            if result.transient:
                await self._unavailable(result, agent_id)
                return
            reason = None if result.ok else result.reason
        if reason is not None:
            try:
                over = await self._cache_call(et.note_failed_check, self._ip, agent_id, default=False, busy_raises=True)
            except et.PoolFull:
                await self._unavailable(et._transient("busy"), agent_id)  # the failure could not be counted: never an uncounted 4401
                return
            if over:
                await self._refuse(et.CLOSE_RATE_LIMITED, "rate_limited_agent", agent_id=agent_id)
            else:
                await self._refuse(et.CLOSE_UNAUTHORIZED, reason, agent_id=agent_id)
            return
        if self.channel_layer is None:
            await self._refuse(et.CLOSE_UNAVAILABLE, "no_channel_layer", agent_id=agent_id)
            return
        self.agent_id = result.agent_id
        self._token = token  # kept in memory only, for the re-check
        self._since = datetime.now(timezone.utc).isoformat()
        await self.accept()
        self._connected = True
        group = et.group_name(self.agent_id)
        await self.channel_layer.group_add(group, self.channel_name)
        await self._cache_call(et.set_presence, self.agent_id, self._since, self._owner)
        await self.channel_layer.group_send(group, {"type": "endpoint.takeover", "channel": self.channel_name})
        now = self._clock()
        self._identity_ok_at = now
        self._next_recheck = now + et.RECHECK_SECONDS + self._random() * et.RECHECK_JITTER_SECONDS
        self._next_ping = now + et.PING_SECONDS + self._random() * et.PING_JITTER_SECONDS
        self._spawn(self._audit("custom:endpoint-connect", agent_id=self.agent_id, ip=self._ip))
        self._watch = asyncio.ensure_future(self._watch_loop())

    async def disconnect(self, close_code):
        watch, self._watch = self._watch, None
        if watch is not None and not watch.done():
            watch.cancel()
        for task in list(self._events):
            task.cancel()
        self._events.clear()
        self._pending.clear()
        if not self._connected:
            return
        self._connected = False
        try:
            await self.channel_layer.group_discard(et.group_name(self.agent_id), self.channel_name)
        except Exception:
            logger.warning("The endpoint group could not be left.", exc_info=True)
        if not self._superseded:
            await self._cache_call(et.clear_presence, self.agent_id, self._owner)
        await self._audit("custom:endpoint-disconnect", agent_id=self.agent_id, ip=self._ip, reason=str(close_code))

    # -------------------------------------------------------------------------------------------- the watcher
    async def _watch_loop(self):
        while True:
            await self._sleep(WATCH_TICK_SECONDS)
            if not await self._tick():
                return

    async def _tick(self) -> bool:
        """One pass of the watcher. False when the socket was closed. Tests drive it with an injected clock."""
        now = self._clock()
        if now >= self._next_recheck:
            result = await et.authenticate_async(self._token, self.agent_id, pool="recheck")
            if result.transient:
                # Not an answer about identity: the socket stays up and the re-check retries on a later tick, until the last good
                # answer is older than the deadline. Then it closes 1013 and the agent reconnects through a fresh check.
                if now - self._identity_ok_at > et.RECHECK_SECONDS + et.RECHECK_JITTER_SECONDS + et.RECHECK_GRACE_SECONDS:
                    await self.close(et.CLOSE_RETRY_LATER)
                    if et.transient_row_allowed():
                        await self._audit("custom:endpoint-refused", agent_id=self.agent_id, reason="identity_stale", ip=self._ip)
                    return False
                self._throttled_log("recheck", "The endpoint token re-check could not be made (%s); it will be retried.", result.reason)
                self._next_recheck = now + et.RECHECK_RETRY_SECONDS
            elif not result.ok:
                await self.close(et.CLOSE_UNAUTHORIZED)
                await self._refusal_row(agent_id=self.agent_id, reason=result.reason)
                return False
            else:
                self._identity_ok_at = now
                self._next_recheck = now + et.RECHECK_SECONDS + self._random() * et.RECHECK_JITTER_SECONDS
        if now >= self._next_ping:
            if self._unanswered_pings >= et.MAX_UNANSWERED_PINGS:
                await self.close(et.CLOSE_PING_TIMEOUT)
                return False
            self._ping_count += 1
            self._unanswered_pings += 1
            self._next_ping = now + et.PING_SECONDS
            await self._rejoin_group()
            await self._send_frame({"v": 1, "type": "ping", "id": f"core-{self._ping_count}", "func": "", "payload": {}})
            await self._refresh_presence()
        return True

    async def _rejoin_group(self):
        """channels_redis drops a group member after group_expiry (86400 s by default). group_add is idempotent, so every ping renews it,
        well inside the expiry: requests, fan-out and takeover keep reaching this connection."""
        try:
            await self.channel_layer.group_add(et.group_name(self.agent_id), self.channel_name)
        except Exception:
            logger.warning("The endpoint group could not be renewed.", exc_info=True)

    async def _refresh_presence(self):
        """touch the key while this connection owns it, re-create it (atomic add) when it is gone; never for a superseded connection."""
        if self._superseded:
            return
        await self._cache_call(et.refresh_presence, self.agent_id, self._owner, self._since)

    # -------------------------------------------------------------------------------------------- frames from the agent
    async def receive(self, text_data=None, bytes_data=None):
        if not self._bucket.take():
            await self.close(et.CLOSE_RATE_LIMITED)
            return
        if text_data is None:
            await self._bad_frame("binary_frame")
            return
        if len(text_data.encode("utf-8", "surrogatepass")) > et.MAX_FRAME_BYTES:
            await self.close(et.CLOSE_TOO_BIG)
            return
        try:
            frame = json.loads(text_data)
        except ValueError:
            await self._bad_frame("not_json")
            return
        reason = et.validate_frame(frame)
        if reason is not None:
            await self._bad_frame(reason)
            return
        ftype = frame["type"]
        if ftype == "ping":
            await self._send_frame({"v": 1, "type": "pong", "id": frame["id"], "func": "", "payload": {}})
            await self._refresh_presence()
        elif ftype == "pong":
            self._unanswered_pings = 0
            await self._refresh_presence()
        elif ftype == "event":
            self._start_event(frame)
        elif ftype == "reply":
            await self._route_reply(frame)
        else:  # request from the agent, or an ack Core has no use for: dropped
            self._throttled_log(("drop", ftype), "An endpoint agent sent a %s frame; dropped.", ftype)

    async def _bad_frame(self, reason):
        self._bad_frames += 1
        self._throttled_log(("bad", reason), "An endpoint agent sent an invalid frame (%s); dropped.", reason)
        if self._bad_frames >= et.MAX_BAD_FRAMES:
            await self.close(et.CLOSE_BAD_FRAME)

    # -------------------------------------------------------------------------------------------- events
    def _start_event(self, frame):
        if len(self._events) >= et.MAX_INFLIGHT_EVENTS:
            self._throttled_log("busy", "Endpoint events are arriving faster than they can be handed over; one was left unacknowledged.")
            return
        task = asyncio.ensure_future(self._handle_event(frame))
        self._events.add(task)
        task.add_done_callback(self._events.discard)

    async def _handle_event(self, frame):
        try:
            outcome = await asyncio.wait_for(et.run_in_pool("handover", et.enqueue_event, self.agent_id, frame), timeout=et.ENQUEUE_TIMEOUT_SECONDS)
        except (asyncio.TimeoutError, et.PoolFull):
            outcome = "failed"
        if outcome != "ok":
            # No ack: the agent keeps the event in its outbox and resends after it reconnects.
            self._throttled_log("owner", "An endpoint event was not handed to its owner (%s); no ack was sent.", outcome)
            return
        await self._audit("custom:endpoint-event", agent_id=self.agent_id, func=frame.get("func"), frame_id=frame["id"])
        if self._connected:
            await self._send_frame({"v": 1, "type": "ack", "id": frame["id"], "func": frame.get("func", ""), "payload": {}})

    # -------------------------------------------------------------------------------------------- replies
    def _expire_pending(self):
        now = self._clock()
        for key in [k for k, (_, until) in self._pending.items() if until <= now]:
            del self._pending[key]

    async def _route_reply(self, frame):
        self._expire_pending()
        entry = self._pending.pop(frame["id"], None)
        if entry is None:
            self._dropped_replies += 1
            self._throttled_log("reply", "An endpoint agent sent a reply that matches no request delivered to it; dropped.")
            return
        await self.channel_layer.send(entry[0], {"type": "endpoint.reply", "frame": frame})

    # -------------------------------------------------------------------------------------------- group messages
    async def endpoint_takeover(self, event):
        if event.get("channel") == self.channel_name:
            return
        self._superseded = True  # the newer connection owns the presence key now
        await self.close(et.CLOSE_SUPERSEDED)

    async def endpoint_request(self, event):
        frame, reply_channel = event.get("frame"), event.get("reply_channel")
        if not isinstance(reply_channel, str) or et.validate_frame(frame, allowed_types=("request",)) is not None:
            return
        self._expire_pending()
        if len(self._pending) >= et.MAX_PENDING_REQUESTS or frame["id"] in self._pending:
            self._throttled_log("pending", "An endpoint request was not delivered: too many open requests, or the id is in use.")
            return
        wait = event.get("timeout")
        wait = float(wait) if isinstance(wait, (int, float)) and not isinstance(wait, bool) else et.MAX_REQUEST_TIMEOUT
        self._pending[frame["id"]] = (reply_channel, self._clock() + min(max(wait, et.MIN_REQUEST_TIMEOUT), et.MAX_REQUEST_TIMEOUT) + 1)
        await self._send_frame(frame)

    async def endpoint_push(self, event):
        frame = event.get("frame")
        if et.validate_frame(frame, allowed_types=("event",)) is None:
            await self._send_frame(frame)
