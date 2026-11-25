"""The Network Probe socket (Core 1.18.46). Loaded lazily by probe_transport._ProbeRoute.

Connect: the address ceiling, then a registered owner (none: close 4503), then plaintext, then the headers, then the identity check
through the owner's authenticator, and only then any per-probe decision (a valid probe is never refused because someone else failed).
Then the group tectac-pn-<probe_id>, the takeover message and the presence key. A watcher task re-checks the identity every 5 minutes,
pings every 30 seconds and closes after two unanswered pings (the first ping and the re-check are jittered). The receive loop never
touches the database, the cache or the broker: every blocking call runs on one of the probe route's own small pools (auth, recheck, cache,
audit, handover; see probe_transport) and never on the event loop's default executor, which Tactical's own sockets share.

A server-side fault while checking the identity closes 1013 (retry later) and counts nothing. 4401 is an identity answer only.

The socket is accepted before a refusal is closed, so the native client can read the close code. Core logs no frame, no payload, no key and
no Authorization header. Close codes and limits: docs/probe-transport.md.
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

from . import probe_transport as pt

logger = logging.getLogger("tec_tac.probe_transport")

WATCH_TICK_SECONDS = 5
LOG_THROTTLE_SECONDS = 60


class _Bucket:
    """Token bucket: MAX_FRAMES_PER_SECOND frames, refilled continuously. In memory, per connection."""

    def __init__(self, clock):
        self._clock = clock
        self.tokens = float(pt.MAX_FRAMES_PER_SECOND)
        self.at = clock()

    def take(self) -> bool:
        now = self._clock()
        self.tokens = min(float(pt.MAX_FRAMES_PER_SECOND), self.tokens + (now - self.at) * pt.MAX_FRAMES_PER_SECOND)
        self.at = now
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


class ProbeConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._clock = time.monotonic  # replaced in tests
        self._sleep = asyncio.sleep
        self._random = random.random  # replaced in tests
        self._bg: set = set()
        self.probe_id = None
        self.client_id = None
        self.site_id = None
        self._key = None
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
        self._unanswered_pings = 0
        self._ping_count = 0
        self._next_recheck = 0.0
        self._identity_ok_at = 0.0
        self._next_ping = 0.0
        self._last_log = {}

    # -------------------------------------------------------------------------------------------- helpers
    async def _cache_call(self, func, *args, default=None, busy_raises=False):
        """A blocking cache call on the CACHE pool. A fault or a full pool is logged (throttled) and gives ``default``. With
        ``busy_raises`` a full pool raises PoolFull instead, so the limiter never reads as off because the pool is busy."""
        try:
            return await pt.run_in_pool("cache", func, *args)
        except pt.PoolFull:
            self._throttled_log("cache", "A probe cache call could not be made (%s).", getattr(func, "__name__", "call"))
            if busy_raises:
                raise
            return default
        except Exception:
            logger.debug("A probe cache call failed.", exc_info=True)
            self._throttled_log("cache", "A probe cache call could not be made (%s).", getattr(func, "__name__", "call"))
            return default

    async def _audit(self, action, **kwargs):
        """One non-strict audit row on the AUDIT pool. A full pool drops the row (throttled log line): rows are not a gate."""
        try:
            await pt.run_in_pool("audit", pt.record_probe_event, action, **kwargs)
        except pt.PoolFull:
            self._throttled_log("audit_full", "The probe audit pool is full; an audit row was not written.")
        except Exception:
            logger.warning("The probe audit row could not be written.", exc_info=True)

    def _spawn(self, coro):
        task = asyncio.ensure_future(coro)
        self._bg.add(task)
        task.add_done_callback(self._bg.discard)
        return task

    def _throttled_log(self, key, message, *args, **kwargs):
        now = self._clock()
        if now - self._last_log.get(key, -1e9) >= LOG_THROTTLE_SECONDS:
            self._last_log[key] = now
            logger.warning(message, *args, **kwargs)

    async def _send_frame(self, frame):
        await self.send(text_data=json.dumps(frame, separators=(",", ":")))

    async def _refuse(self, code, reason, *, probe_id=None, audit=True):
        """Accept, close with the code (so the client can read it), then write the refusal row unless audit is False. The key is never in
        the row."""
        await self.accept()
        await self.close(code)
        if audit:
            await self._audit("custom:probe-refused", probe_id=probe_id, reason=reason, ip=self._ip, refusal=True)

    async def _unavailable(self, result, probe_id):
        """A server-side fault or a full pool: close 1013, count nothing, write at most a throttled non-strict row."""
        await self.accept()
        await self.close(pt.CLOSE_RETRY_LATER)
        if pt.transient_row_allowed():
            await self._audit("custom:probe-refused", probe_id=probe_id, reason=result.reason, ip=self._ip)

    # -------------------------------------------------------------------------------------------- connect and disconnect
    async def connect(self):
        # 1.18.47: a ceiling on connects that are not identified yet (UNAUTHENTICATED_IN_FLIGHT), so a flood spread over many addresses
        # cannot make real probes queue behind it. Over it: 1013, counted nowhere, before the identity check.
        if not pt.acquire_unauth():
            self._ip = pt.client_ip(self.scope)
            await self._unavailable(pt._transient("busy"), None)
            return
        try:
            await self._connect_inner()
        finally:
            pt.release_unauth()

    async def _connect_inner(self):
        scope = self.scope
        self._ip = pt.client_ip(scope)
        # The address ceiling is a NAT-sized pre-auth bound. An address over it is closed 4429 with no audit row.
        try:
            limited = await self._cache_call(pt.rate_limited, self._ip, default=False, busy_raises=True)
        except pt.PoolFull:
            await self._unavailable(pt._transient("busy"), None)
            return
        if limited:
            await self._refuse(pt.CLOSE_RATE_LIMITED, "rate_limited", audit=False)
            return
        if pt.get_owner() is None:
            await self._refuse(pt.CLOSE_UNAVAILABLE, "no_owner", audit=False)  # counts nothing: a probe sees the same code as a Tactical-side fault
            return
        if pt.forwarded_plaintext(scope):
            await self._cache_call(pt.note_failure, self._ip)
            await self._refuse(pt.CLOSE_PLAINTEXT, "plaintext_refused")
            return
        probe_id, key, reason = pt.parse_probe_headers(scope)
        result = None
        if reason is None:
            # The identity check comes before any per-probe decision, so a valid probe is never refused because someone else failed.
            result = await pt.authenticate_async(probe_id, key)
            if result.transient:
                await self._unavailable(result, probe_id)
                return
            reason = None if result.ok else result.reason
        if reason is not None:
            try:
                over = await self._cache_call(pt.note_failed_check, self._ip, probe_id, default=False, busy_raises=True)
            except pt.PoolFull:
                await self._unavailable(pt._transient("busy"), probe_id)  # the failure could not be counted: never an uncounted 4401
                return
            if over:
                await self._refuse(pt.CLOSE_RATE_LIMITED, "rate_limited_probe", probe_id=probe_id)
            else:
                await self._refuse(pt.CLOSE_UNAUTHORIZED, reason, probe_id=probe_id)
            return
        if self.channel_layer is None:
            await self._refuse(pt.CLOSE_UNAVAILABLE, "no_channel_layer", probe_id=probe_id)
            return
        self.probe_id, self.client_id, self.site_id = result.probe_id, result.client_id, result.site_id
        self._key = key  # kept in memory only, for the re-check
        self._since = datetime.now(timezone.utc).isoformat()
        await self.accept()
        self._connected = True
        group = pt.group_name(self.probe_id)
        await self.channel_layer.group_add(group, self.channel_name)
        await self._cache_call(pt.set_presence, self.probe_id, self._since, self._owner, self.client_id, self.site_id)
        await self.channel_layer.group_send(group, {"type": "probe.takeover", "channel": self.channel_name})
        now = self._clock()
        self._identity_ok_at = now
        self._next_recheck = now + pt.RECHECK_SECONDS + self._random() * pt.RECHECK_JITTER_SECONDS
        self._next_ping = now + pt.PING_SECONDS + self._random() * pt.PING_JITTER_SECONDS
        self._spawn(self._audit("custom:probe-connect", probe_id=self.probe_id, ip=self._ip, client_id=self.client_id, site_id=self.site_id))
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
            await self.channel_layer.group_discard(pt.group_name(self.probe_id), self.channel_name)
        except Exception:
            logger.warning("The probe group could not be left.", exc_info=True)
        if not self._superseded:
            await self._cache_call(pt.clear_presence, self.probe_id, self._owner)
        await self._audit("custom:probe-disconnect", probe_id=self.probe_id, ip=self._ip, code=close_code,
                          client_id=self.client_id, site_id=self.site_id)

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
            result = await pt.authenticate_async(self.probe_id, self._key, pool="recheck")
            if result.transient:
                # Not an answer about identity: the socket stays up and the re-check retries on a later tick, until the last good answer
                # is older than the deadline. Then it closes 1013 and the probe reconnects through a fresh check.
                if now - self._identity_ok_at > pt.RECHECK_SECONDS + pt.RECHECK_JITTER_SECONDS + pt.RECHECK_GRACE_SECONDS:
                    await self.close(pt.CLOSE_RETRY_LATER)
                    if pt.transient_row_allowed():
                        await self._audit("custom:probe-refused", probe_id=self.probe_id, reason="identity_stale", ip=self._ip)
                    return False
                self._throttled_log("recheck", "The probe re-check could not be made (%s); it will be retried.", result.reason)
                self._next_recheck = now + pt.RECHECK_RETRY_SECONDS
            elif not result.ok:
                await self.close(pt.CLOSE_UNAUTHORIZED)
                await self._audit("custom:probe-refused", probe_id=self.probe_id, reason=result.reason, ip=self._ip, refusal=True)
                await self._end_tunnels("ended_by_core", result.reason)  # 1.18.47: Core ends the tunnels of a probe it refuses at a re-check
                return False
            else:
                self._identity_ok_at = now
                self.client_id, self.site_id = result.client_id, result.site_id
                self._next_recheck = now + pt.RECHECK_SECONDS + self._random() * pt.RECHECK_JITTER_SECONDS
        if now >= self._next_ping:
            if self._unanswered_pings >= pt.MAX_UNANSWERED_PINGS:
                await self.close(pt.CLOSE_PING_TIMEOUT)
                return False
            self._ping_count += 1
            self._unanswered_pings += 1
            self._next_ping = now + pt.PING_SECONDS
            await self._rejoin_group()
            await self._send_frame({"v": 1, "type": "ping", "id": f"core-{self._ping_count}", "func": "", "payload": {}})
            await self._refresh_presence()
        return True

    async def _end_tunnels(self, reason, detail):
        """End every live tunnel session of this probe (the audit pool: a database write and group sends, never on the event loop)."""
        from . import probe_tunnel

        try:
            await pt.run_in_pool("audit", probe_tunnel.end_for_probe, self.probe_id, reason, "core", detail or "")
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            self._throttled_log("tunnels", "The tunnel sessions of a refused probe could not be ended.")

    async def _rejoin_group(self):
        """channels_redis drops a group member after group_expiry. group_add is idempotent, so every ping renews it."""
        try:
            await self.channel_layer.group_add(pt.group_name(self.probe_id), self.channel_name)
        except Exception:
            logger.warning("The probe group could not be renewed.", exc_info=True)

    async def _refresh_presence(self):
        """Touch the key while this connection owns it, re-create it when it is gone; never for a superseded connection."""
        if self._superseded:
            return
        await self._cache_call(pt.refresh_presence, self.probe_id, self._owner, self._since, self.client_id, self.site_id)

    # -------------------------------------------------------------------------------------------- frames from the probe
    async def receive(self, text_data=None, bytes_data=None):
        if not self._bucket.take():
            await self.close(pt.CLOSE_RATE_LIMITED)
            return
        if text_data is None:
            await self._bad_frame("binary_frame")
            return
        if len(text_data.encode("utf-8", "surrogatepass")) > pt.MAX_FRAME_BYTES:
            await self.close(pt.CLOSE_TOO_BIG)
            return
        try:
            frame = json.loads(text_data)
        except (ValueError, RecursionError):  # 1.18.47: a frame of 15000 '[' is under the size limit and raises RecursionError
            await self._bad_frame("not_json")
            return
        reason = pt.validate_frame(frame)
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
        else:  # a request from the probe: dropped
            self._throttled_log(("drop", ftype), "A probe sent a %s frame; dropped.", ftype)

    async def _bad_frame(self, reason):
        self._bad_frames += 1
        self._throttled_log(("bad", reason), "A probe sent an invalid frame (%s); dropped.", reason)
        if self._bad_frames >= pt.MAX_BAD_FRAMES:
            await self.close(pt.CLOSE_BAD_FRAME)

    # -------------------------------------------------------------------------------------------- events
    def _start_event(self, frame):
        if len(self._events) >= pt.MAX_INFLIGHT_EVENTS:
            self._throttled_log("busy", "Probe events are arriving faster than they can be handed over; one was dropped.")
            return
        task = asyncio.ensure_future(self._handle_event(frame))
        self._events.add(task)
        task.add_done_callback(self._events.discard)

    async def _handle_event(self, frame):
        """Best effort: there is no ack on this route. Bulk data and the outbox stay on HTTPS."""
        try:
            outcome = await asyncio.wait_for(pt.run_in_pool("handover", pt.enqueue_event, self.probe_id, frame), timeout=pt.ENQUEUE_TIMEOUT_SECONDS)
        except (asyncio.TimeoutError, pt.PoolFull):
            outcome = "failed"
        if outcome != "ok":
            self._throttled_log("owner", "A probe event was not handed to its owner (%s).", outcome)

    # -------------------------------------------------------------------------------------------- replies
    def _expire_pending(self):
        now = self._clock()
        for key in [k for k, (_, until) in self._pending.items() if until <= now]:
            del self._pending[key]

    async def _route_reply(self, frame):
        self._expire_pending()
        entry = self._pending.pop(frame["id"], None)
        if entry is None:
            self._throttled_log("reply", "A probe sent a reply that matches no request delivered to it; dropped.")
            return
        await self.channel_layer.send(entry[0], {"type": "probe.reply", "frame": frame})

    # -------------------------------------------------------------------------------------------- group messages
    async def probe_takeover(self, event):
        if event.get("channel") == self.channel_name:
            return
        self._superseded = True  # the newer connection owns the presence key now
        await self.close(pt.CLOSE_SUPERSEDED)

    async def probe_disconnect(self, event):
        await self.close(pt.CLOSE_UNAUTHORIZED)

    async def probe_request(self, event):
        frame, reply_channel = event.get("frame"), event.get("reply_channel")
        if not isinstance(reply_channel, str) or pt.validate_frame(frame, allowed_types=("request",)) is not None:
            return
        self._expire_pending()
        if len(self._pending) >= pt.MAX_PENDING_REQUESTS or frame["id"] in self._pending:
            self._throttled_log("pending", "A probe request was not delivered: too many open requests, or the id is in use.")
            return
        wait = event.get("timeout")
        wait = float(wait) if isinstance(wait, (int, float)) and not isinstance(wait, bool) else pt.MAX_REQUEST_TIMEOUT
        self._pending[frame["id"]] = (reply_channel, self._clock() + min(max(wait, pt.MIN_REQUEST_TIMEOUT), pt.MAX_REQUEST_TIMEOUT) + 1)
        await self._send_frame(frame)

    async def probe_push(self, event):
        frame = event.get("frame")
        if pt.validate_frame(frame, allowed_types=("event", "reply")) is None:
            await self._send_frame(frame)
