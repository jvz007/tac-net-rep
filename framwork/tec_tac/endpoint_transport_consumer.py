"""The endpoint agent socket (Core 1.17.90). Loaded lazily by endpoint_transport._EndpointAgentRoute.

Connect: headers from the scope, the failure limit, the identity check (once, in a worker thread), then the group tectac-ea-<agent_id>,
the takeover message and the presence key. A watcher task re-checks the token every 10 minutes, pings every 60 seconds and closes after
two unanswered pings. The receive loop never touches the database or the broker: the identity check, audit rows and the Celery hand-over
run in worker threads and every wait is bounded.

The socket is accepted before an identity refusal is closed, so the native client can read the close code (4401, 4429). Core logs no
frame, no payload, no token and no Authorization header. Close codes and limits: docs/endpoint-transport.md.
"""
from __future__ import annotations

import asyncio
import functools
import json
import logging
import time
import uuid
from datetime import datetime, timezone

from channels.db import database_sync_to_async
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
        self._next_ping = 0.0
        self._last_log = {}

    # -------------------------------------------------------------------------------------------- helpers
    async def _off(self, func, *args, **kwargs):
        """A plain blocking call (the cache, the broker) in a worker thread, never in the event loop."""
        return await asyncio.get_running_loop().run_in_executor(None, functools.partial(func, *args, **kwargs))

    async def _audit(self, action, **kwargs):
        try:
            await database_sync_to_async(et.record_endpoint_event)(action, **kwargs)
        except Exception:
            logger.warning("The endpoint audit row could not be written.", exc_info=True)

    def _throttled_log(self, key, message, *args):
        now = self._clock()
        if now - self._last_log.get(key, -1e9) >= LOG_THROTTLE_SECONDS:
            self._last_log[key] = now
            logger.warning(message, *args)

    async def _send_frame(self, frame):
        await self.send(text_data=json.dumps(frame, separators=(",", ":")))

    async def _refuse(self, code, reason, *, agent_id=None, audit=True):
        """Accept, write the refusal row (unless audit is False) and close with the code, so the client can read it. The token is never
        in the row."""
        await self.accept()
        if audit:
            await self._audit("custom:endpoint-refused", agent_id=agent_id, reason=reason, ip=self._ip, refusal=True)
        await self.close(code)

    # -------------------------------------------------------------------------------------------- connect and disconnect
    async def connect(self):
        scope = self.scope
        self._ip = et.client_ip(scope)
        # The limiter comes first. An address over the limit is closed 4429 with no audit row, so an unauthenticated client cannot
        # grow the audit table: at most FAILURES_PER_MINUTE refusal rows per address per minute.
        if await self._off(et.rate_limited, self._ip):
            await self._refuse(et.CLOSE_RATE_LIMITED, "rate_limited", audit=False)
            return
        if et.forwarded_plaintext(scope):
            await self._off(et.note_failure, self._ip)
            await self._refuse(et.CLOSE_PLAINTEXT, "plaintext_refused")
            return
        token, agent_id, reason = et.parse_endpoint_headers(scope)
        result = None
        if reason is None:
            result = await database_sync_to_async(et.authenticate_endpoint_agent)(token, agent_id)
            reason = None if result.ok else result.reason
        if reason is not None:
            await self._off(et.note_failure, self._ip)
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
        await self._off(et.set_presence, self.agent_id, self._since, self._owner)
        await self.channel_layer.group_send(group, {"type": "endpoint.takeover", "channel": self.channel_name})
        now = self._clock()
        self._next_recheck = now + et.RECHECK_SECONDS
        self._next_ping = now + et.PING_SECONDS
        await self._audit("custom:endpoint-connect", agent_id=self.agent_id, ip=self._ip)
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
            try:
                await self._off(et.clear_presence, self.agent_id, self._owner)
            except Exception:
                logger.warning("The endpoint presence could not be cleared.", exc_info=True)
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
            result = await database_sync_to_async(et.authenticate_endpoint_agent)(self._token, self.agent_id)
            if not result.ok:
                await self._audit("custom:endpoint-refused", agent_id=self.agent_id, reason=result.reason, ip=self._ip, refusal=True)
                await self.close(et.CLOSE_UNAUTHORIZED)
                return False
            self._next_recheck = now + et.RECHECK_SECONDS
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
        try:
            await self._off(et.refresh_presence, self.agent_id, self._owner)
        except Exception:
            logger.warning("The endpoint presence could not be refreshed.", exc_info=True)

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
            outcome = await asyncio.wait_for(self._off(et.enqueue_event, self.agent_id, frame), timeout=et.ENQUEUE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
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
