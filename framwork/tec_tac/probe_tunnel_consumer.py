"""The two Network Probe tunnel sockets (Core 1.18.47). Loaded lazily by probe_tunnel._TunnelRoute.

ws/tfd/network-probe/tunnel/ is the probe's side and ws/tfd/probe-tunnel/ the Console's side. Both are binary only. Each joins the group
tectac-pnt-<session_id> and forwards what it receives with a group_send tagged with its side; a peer ignores its own. Core reads byte 0 (the
type, 1 to 4) and the length (5 up to 5 + 32 KiB) and nothing else: stream ids, windows and payloads are never parsed, logged, audited or stored.

Connect (both): the address ceiling, a registered owner (none: 4503), plaintext (4403), the credential header, then the decision on the
probe route's own pools. The Console side redeems its one-time ticket and re-checks the account (4401); the probe side runs the owner's
authenticator exactly like the control route and names its session in X-Tunnel-Session (4404 unknown, 4409 already attached). The socket is
accepted before a refusal is closed, with the close code and the reason name as the close text.

The Console consumer is the session's clock: only DATA frames reset the idle timer and add payload bytes to bytes_up (Console to probe) or
bytes_down (probe to Console); a watcher ends the session at the idle limit and the hard cap and re-checks the account every 5 minutes.
Frames from the Console that arrive before the probe side attaches wait in a buffer of at most 1 MiB. A relay that cannot keep up
(ChannelFull, or a send that takes over 5 seconds) ends the session relay_overloaded.

The receive loop never touches the database, the cache or the broker: every blocking call runs on one of the probe route's own pools, never
on the event loop's default executor and never on a pool of the agent route. Core logs no frame, no byte and no ticket.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from datetime import datetime, timezone

from channels.exceptions import ChannelFull
from channels.generic.websocket import AsyncWebsocketConsumer

from . import probe_transport as pt
from . import probe_tunnel as tun

logger = logging.getLogger("tec_tac.probe_transport")

LOG_THROTTLE_SECONDS = 60
CLOSE_CODE_FOR = {"protocol_error": tun.CLOSE_PROTOCOL, "server_restart": tun.CLOSE_GOING_AWAY, "relay_overloaded": pt.CLOSE_RETRY_LATER}
SERVER_GOING_AWAY_CODES = (1001, 1012)  # what an ASGI server sends when it shuts down


def _console_open_job(ticket):
    pt._close_db(False)
    try:
        return tun.console_open(ticket)
    finally:
        pt._close_db(True)


def _console_recheck_job(value, record, activity_at):
    pt._close_db(False)
    try:
        return tun.console_recheck(value, record, activity_at)
    finally:
        pt._close_db(True)


class _TunnelConsumer(AsyncWebsocketConsumer):
    side = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._clock = time.monotonic  # replaced in tests
        self._sleep = asyncio.sleep
        self._random = random.random
        self._bg: set = set()
        self._ip = "unknown"
        self.session_id = None
        self.probe_id = None
        self._record = None
        self._group = None
        self._attached = False
        self._ended_local = False
        self._closing = False
        self._watch = None
        self._last_log = {}

    # -------------------------------------------------------------------------------------------- helpers
    async def _cache_call(self, func, *args, default=None, busy_raises=False):
        try:
            return await pt.run_in_pool("cache", func, *args)
        except pt.PoolFull:
            self._throttled_log("cache", "A tunnel cache call could not be made (%s).", getattr(func, "__name__", "call"))
            if busy_raises:
                raise
            return default
        except Exception:
            logger.debug("A tunnel cache call failed.", exc_info=True)
            self._throttled_log("cache", "A tunnel cache call could not be made (%s).", getattr(func, "__name__", "call"))
            return default

    async def _audit(self, action, **kwargs):
        try:
            await pt.run_in_pool("audit", pt.record_probe_event, action, **kwargs)
        except pt.PoolFull:
            self._throttled_log("audit_full", "The probe audit pool is full; an audit row was not written.")
        except Exception:
            logger.warning("The tunnel audit row could not be written.", exc_info=True)

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

    async def _refuse(self, code, reason, *, probe_id=None, audit=True):
        """Accept, close with the code and the reason as the close text (so the client can read both), then write the refusal row. The
        ticket and the key are never in the row."""
        await self.accept()
        await self.close(code, reason)
        if audit:
            extra = {"side": self.side}
            if self.session_id:
                extra["session_id"] = self.session_id
            await self._audit("custom:probe-tunnel-refused", probe_id=probe_id, reason=reason, ip=self._ip, refusal=True, extra=extra)

    async def _unavailable(self, reason="unavailable", probe_id=None):
        """A server-side fault or a busy server: close 1013, count nothing, write at most a throttled non-strict row."""
        await self.accept()
        await self.close(pt.CLOSE_RETRY_LATER, reason)
        if pt.transient_row_allowed():
            await self._audit("custom:probe-tunnel-refused", probe_id=probe_id, reason=reason, ip=self._ip, extra={"side": self.side})

    async def _close_with(self, reason, code=None):
        """Close once, with the code for the reason and the reason name as the websocket close text."""
        if self._closing:
            return
        self._closing = True
        try:
            await self.close(code if code is not None else CLOSE_CODE_FOR.get(reason, 1000), reason)
        except Exception:
            logger.debug("The tunnel socket was already closed.", exc_info=True)

    # -------------------------------------------------------------------------------------------- connect gate (shared)
    async def connect(self):
        if not pt.acquire_unauth():
            await self._unavailable("busy")  # over the ceiling of unauthenticated attempts in flight: answered at once, counted nowhere
            return
        try:
            await self._connect_inner()
        finally:
            pt.release_unauth()

    async def _gate(self):
        """The checks both sides share, before any credential is read. True when the connect may go on."""
        scope = self.scope
        self._ip = pt.client_ip(scope)
        try:
            limited = await self._cache_call(pt.rate_limited, self._ip, default=False, busy_raises=True)
        except pt.PoolFull:
            await self._unavailable("busy")
            return False
        if limited:
            await self._refuse(pt.CLOSE_RATE_LIMITED, "rate_limited", audit=False)
            return False
        if pt.get_owner() is None:
            await self._refuse(pt.CLOSE_UNAVAILABLE, "no_owner", audit=False)
            return False
        if pt.forwarded_plaintext(scope):
            await self._cache_call(pt.note_failure, self._ip)
            await self._refuse(pt.CLOSE_PLAINTEXT, "plaintext_refused")
            return False
        if self.channel_layer is None:
            await self._refuse(pt.CLOSE_UNAVAILABLE, "no_channel_layer", audit=False)
            return False
        return True

    async def _connect_inner(self):
        raise NotImplementedError

    # -------------------------------------------------------------------------------------------- end of a session
    async def _end(self, reason, ended_by="core", detail="", *, close=True, code=None):
        """End the session from this socket: the first end wins in the cache, the peer is told through the group, this socket closes with the
        reason as its close text, and the audit row, the probe's tunnel.close and (when the Console never attached) tunnel.closed follow."""
        if self._ended_local or self.session_id is None:
            return
        self._ended_local = True
        status, marker = "error", {"reason": reason, "ended_by": ended_by, "detail": detail}
        try:
            status, found = await pt.run_in_pool("cache", tun.claim_end, self.session_id, reason, ended_by, detail)
            if found:
                marker = found
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            self._throttled_log("claim", "A tunnel session end could not be written to the cache.")
        if close:
            await self._close_with(marker["reason"], code)
        try:  # the peer is always told, also when this socket is already gone
            await asyncio.wait_for(self.channel_layer.group_send(self._group, tun.end_message(marker)), timeout=tun.SEND_TIMEOUT_SECONDS)
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            self._throttled_log("announce", "A tunnel end message could not be sent to the group.")
        if status == "won":
            self._spawn(self._finish(marker))

    async def _finish(self, marker):
        """After this socket won the end: tell the probe on the control channel and, when the Console side never attached, write the end row
        and deliver tunnel.closed with zero counters. An attached Console consumer does both at its close, with its final counters."""
        try:
            await pt.run_in_pool("cache", tun.send_probe_close, self.probe_id, self.session_id, marker)
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            self._throttled_log("finish", "A step of ending a tunnel session failed.")
        if self.side == "probe" and not await self._cache_call(tun.side_attached, self.session_id, "console", default=True):
            await self._write_end_row(marker, {"bytes_up": 0, "bytes_down": 0})
            await self._deliver_closed(marker, 0, 0)

    async def _write_end_row(self, marker, counters):
        try:
            await pt.run_in_pool("audit", tun.end_audit, self.session_id, marker, counters)
        except pt.PoolFull:
            self._throttled_log("audit_full", "The probe audit pool is full; an audit row was not written.")
        except Exception:
            logger.warning("The tunnel end row could not be written.", exc_info=True)

    async def _deliver_closed(self, marker, bytes_up, bytes_down):
        try:
            outcome = await asyncio.wait_for(
                pt.run_in_pool("handover", tun.deliver_closed, self.session_id, self.probe_id, marker, bytes_up, bytes_down),
                timeout=pt.ENQUEUE_TIMEOUT_SECONDS,
            )
        except (asyncio.TimeoutError, pt.PoolFull):
            outcome = "failed"
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            outcome = "failed"
        if outcome not in ("ok", "duplicate"):
            self._throttled_log("owner", "A tunnel.closed event was not handed to its owner (%s).", outcome)

    async def _forward(self, data):
        """Send one frame to the peer through the group. A relay that cannot keep up ends the session relay_overloaded."""
        try:
            await asyncio.wait_for(
                self.channel_layer.group_send(self._group, {"type": "tunnel.frame", "side": self.side, "data": bytes(data)}),
                timeout=tun.SEND_TIMEOUT_SECONDS,
            )
            return True
        except (ChannelFull, asyncio.TimeoutError):
            pass
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            self._throttled_log("relay", "A tunnel frame could not be relayed.")
        await self._end("relay_overloaded")
        return False

    # -------------------------------------------------------------------------------------------- group messages
    async def tunnel_end(self, event):
        """The session ended elsewhere (the other socket, an ender or Core): close with the reason as the close text."""
        reason = event.get("reason") if event.get("reason") in tun.ALL_REASONS else "ended_by_core"
        self._ended_local = True
        await self._close_with(reason)

    async def tunnel_paired(self, event):
        return None

    async def tunnel_frame(self, event):
        return None

    async def _watch_loop(self):
        while True:
            await self._sleep(tun.WATCH_TICK_SECONDS)
            if not await self._tick():
                return

    async def _tick(self) -> bool:
        raise NotImplementedError


class ProbeTunnelProbeConsumer(_TunnelConsumer):
    """The probe's data socket of one session."""

    side = "probe"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._key = None
        self._next_recheck = 0.0
        self._identity_ok_at = 0.0
        self._wall = lambda: tun.time.time()

    async def _connect_inner(self):
        if not await self._gate():
            return
        probe_id, key, reason = pt.parse_probe_headers(self.scope)
        result = None
        if reason is None:
            result = await pt.authenticate_async(probe_id, key)  # the owner's authenticator, as on the control route
            if result.transient:
                await self._unavailable(result.reason, probe_id)
                return
            reason = None if result.ok else result.reason
        if reason is not None:
            try:
                over = await self._cache_call(pt.note_failed_check, self._ip, probe_id, default=False, busy_raises=True)
            except pt.PoolFull:
                await self._unavailable("busy", probe_id)
                return
            if over:
                await self._refuse(pt.CLOSE_RATE_LIMITED, "rate_limited_probe", probe_id=probe_id)
            else:
                await self._refuse(pt.CLOSE_UNAUTHORIZED, reason, probe_id=probe_id)
            return
        session_id = tun.parse_session_header(self.scope)
        if session_id is None:
            await self._refuse(tun.CLOSE_NOT_FOUND, "session_header_invalid", probe_id=probe_id)  # not an identity failure: nothing is counted
            return
        self.session_id, self.probe_id, self._key = session_id, probe_id, key
        try:
            status, record = await pt.run_in_pool("cache", tun.probe_open, probe_id, session_id)
        except pt.PoolFull:
            await self._unavailable("busy", probe_id)
            return
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            await self._unavailable("unavailable", probe_id)
            return
        if status == "not_pending":
            await self._refuse(tun.CLOSE_NOT_FOUND, "session_not_pending", probe_id=probe_id)
            return
        if status == "attached":
            await self._refuse(pt.CLOSE_SUPERSEDED, "probe_side_already_attached", probe_id=probe_id)
            return
        self._record, self._group = record, tun.tunnel_group(session_id)
        await self.accept()
        self._attached = True
        await self.channel_layer.group_add(self._group, self.channel_name)
        try:
            await asyncio.wait_for(self.channel_layer.group_send(self._group, {"type": "tunnel.paired"}), timeout=tun.SEND_TIMEOUT_SECONDS)
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            await self._end("relay_overloaded")
            return
        now = self._clock()
        self._identity_ok_at = now
        self._next_recheck = now + tun.RECHECK_SECONDS + self._random() * tun.RECHECK_JITTER_SECONDS
        self._spawn(self._audit("custom:probe-tunnel-connect", probe_id=probe_id, ip=self._ip, extra={"session_id": session_id, "side": "probe"}))
        self._watch = asyncio.ensure_future(self._watch_loop())

    async def disconnect(self, close_code):
        watch, self._watch = self._watch, None
        if watch is not None and not watch.done():
            watch.cancel()
        if not self._attached:
            return
        self._attached = False
        try:
            await self.channel_layer.group_discard(self._group, self.channel_name)
        except Exception:
            logger.warning("The tunnel group could not be left.", exc_info=True)
        if not self._ended_local:
            await self._end("server_restart" if close_code in SERVER_GOING_AWAY_CODES else "probe_offline", close=False)

    async def receive(self, text_data=None, bytes_data=None):
        if self._ended_local:
            return
        if bytes_data is None or not tun.check_frame(bytes_data):
            await self._end("protocol_error")
            return
        await self._forward(bytes_data)

    async def tunnel_frame(self, event):
        if event.get("side") == self.side or self._ended_local:
            return
        data = event.get("data")
        if isinstance(data, (bytes, bytearray)):
            await self.send(bytes_data=bytes(data))

    async def _tick(self) -> bool:
        if self._ended_local:
            return False
        now = self._clock()
        state = await self._cache_call(tun.poll_session, self.session_id, default=None)
        if state is not None:
            if state["ended"]:
                self._ended_local = True
                await self._close_with(state["ended"].get("reason") or "ended_by_core")
                return False
            if not state["console"] and self._wall() >= float(self._record.get("created", 0)) + tun.TICKET_TTL_SECONDS:
                await self._end("console_not_connected")
                return False
        if now >= self._next_recheck:
            result = await pt.authenticate_async(self.probe_id, self._key, pool="recheck")
            if result.transient:
                if now - self._identity_ok_at > tun.RECHECK_SECONDS + tun.RECHECK_JITTER_SECONDS + tun.RECHECK_GRACE_SECONDS:
                    await self._end("ended_by_core", detail="identity_stale", code=pt.CLOSE_RETRY_LATER)
                    return False
                self._next_recheck = now + tun.RECHECK_RETRY_SECONDS
            elif not result.ok:
                await self._end("ended_by_core", detail=result.reason or "identity_refused", code=pt.CLOSE_UNAUTHORIZED)
                return False
            else:
                self._identity_ok_at = now
                self._next_recheck = now + tun.RECHECK_SECONDS + self._random() * tun.RECHECK_JITTER_SECONDS
        return True


class ProbeTunnelConsoleConsumer(_TunnelConsumer):
    """The engineer Console's socket of one session. It is also the session's clock and its byte counter."""

    side = "console"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._value = None
        self._paired = False
        self._buffer: list = []
        self._buffered = 0
        self._wall = lambda: tun.time.time()
        self._idle_s = tun.IDLE_SECONDS_DEFAULT
        self._cap_s = tun.CAP_SECONDS_DEFAULT
        self._connected_at = 0.0
        self._last_data = 0.0
        self._last_data_wall = None
        self._data_since_check = False
        self.bytes_up = 0
        self.bytes_down = 0
        self._next_flush = 0.0
        self._next_recheck = 0.0
        self._identity_ok_at = 0.0

    async def _connect_inner(self):
        if not await self._gate():
            return
        ticket, reason = tun.parse_ticket_headers(self.scope)
        if reason is not None:
            await self._cache_call(pt.note_failure, self._ip)
            await self._refuse(pt.CLOSE_UNAUTHORIZED, reason)
            return
        try:
            status, value, record, why = await asyncio.wait_for(pt.run_in_pool("auth", _console_open_job, ticket), timeout=pt.AUTH_TIMEOUT_SECONDS)
        except pt.PoolFull:
            await self._unavailable("busy")
            return
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            await self._unavailable("unavailable")
            return
        if status in ("ticket", "unauthorized"):
            await self._cache_call(pt.note_failure, self._ip)
            if value:
                self.session_id = value.get("session_id")
            await self._refuse(pt.CLOSE_UNAUTHORIZED, why, probe_id=(value or {}).get("probe_id"))
            return
        if status in ("not_pending", "attached"):
            self.session_id = (value or {}).get("session_id")
            await self._refuse(tun.CLOSE_NOT_FOUND if status == "not_pending" else pt.CLOSE_SUPERSEDED, why, probe_id=(value or {}).get("probe_id"))
            return
        self.session_id, self.probe_id, self._record, self._value = value["session_id"], value["probe_id"], record, value
        self._group = tun.tunnel_group(self.session_id)
        self._idle_s, self._cap_s = int(record["idle_s"]), int(record["cap_s"])
        await self.accept()
        self._attached = True
        await self.channel_layer.group_add(self._group, self.channel_name)
        now = self._clock()
        self._connected_at = self._last_data = now
        self._last_data_wall = self._wall()
        self._identity_ok_at = now
        self._next_flush = now + tun.FLUSH_SECONDS
        self._next_recheck = now + tun.RECHECK_SECONDS + self._random() * tun.RECHECK_JITTER_SECONDS
        # The probe may have attached first: join the group first, then look, so a probe that attaches in between still sends tunnel.paired.
        self._paired = bool(await self._cache_call(tun.side_attached, self.session_id, "probe", default=False))
        self._spawn(self._audit("custom:probe-tunnel-connect", probe_id=self.probe_id, ip=self._ip,
                                extra={"session_id": self.session_id, "side": "console", "engineer": self._value["user_id"]}))
        self._watch = asyncio.ensure_future(self._watch_loop())

    async def disconnect(self, close_code):
        watch, self._watch = self._watch, None
        if watch is not None and not watch.done():
            watch.cancel()
        if not self._attached:
            return
        self._attached = False
        try:
            await self.channel_layer.group_discard(self._group, self.channel_name)
        except Exception:
            logger.warning("The tunnel group could not be left.", exc_info=True)
        if not self._ended_local:
            await self._end("server_restart" if close_code in SERVER_GOING_AWAY_CODES else "console_disconnected", close=False)
        marker = await self._cache_call(tun.flush_stats, self.session_id, self._last_data_wall or 0, self.bytes_up, self.bytes_down, default=None)
        if not marker:
            marker = {"reason": "console_disconnected", "ended_by": "core"}
        await self._write_end_row(marker, {"bytes_up": self.bytes_up, "bytes_down": self.bytes_down})
        await self._deliver_closed(marker, self.bytes_up, self.bytes_down)

    # -------------------------------------------------------------------------------------------- frames
    def _note_data(self, payload_bytes, up):
        self._last_data = self._clock()
        self._last_data_wall = self._wall()
        self._data_since_check = True
        if up:
            self.bytes_up += payload_bytes
        else:
            self.bytes_down += payload_bytes

    async def receive(self, text_data=None, bytes_data=None):
        if self._ended_local:
            return
        if bytes_data is None or not tun.check_frame(bytes_data):
            await self._end("protocol_error")
            return
        if bytes_data[0] == tun.TYPE_DATA:
            self._note_data(len(bytes_data) - tun.HEADER_LEN, True)
        if not self._paired:
            if self._buffered + len(bytes_data) > tun.BUFFER_CAP_BYTES:
                await self._end("probe_offline")
                return
            self._buffer.append(bytes(bytes_data))
            self._buffered += len(bytes_data)
            return
        await self._forward(bytes_data)

    async def tunnel_paired(self, event):
        if self._paired or self._ended_local:
            return
        self._paired = True
        pending, self._buffer, self._buffered = self._buffer, [], 0
        for data in pending:
            if not await self._forward(data):
                return

    async def tunnel_frame(self, event):
        if event.get("side") == self.side or self._ended_local:
            return
        data = event.get("data")
        if not isinstance(data, (bytes, bytearray)):
            return
        if len(data) > tun.HEADER_LEN and data[0] == tun.TYPE_DATA:
            self._note_data(len(data) - tun.HEADER_LEN, False)
        await self.send(bytes_data=bytes(data))

    # -------------------------------------------------------------------------------------------- the watcher
    async def _tick(self) -> bool:
        """One pass of the watcher (the injected clock drives it in tests). False when the session ended."""
        if self._ended_local:
            return False
        now = self._clock()
        if now - self._last_data >= self._idle_s:
            await self._end("idle_timeout")
            return False
        if now - self._connected_at >= self._cap_s:
            await self._end("hard_cap")
            return False
        if not self._paired and now - self._connected_at >= tun.PAIR_WAIT_SECONDS:
            await self._end("probe_offline")
            return False
        if now >= self._next_flush:
            self._next_flush = now + tun.FLUSH_SECONDS
            marker = await self._cache_call(tun.flush_stats, self.session_id, self._last_data_wall or 0, self.bytes_up, self.bytes_down, default=None)
            if marker:
                self._ended_local = True
                await self._close_with(marker.get("reason") or "ended_by_core")
                return False
        if now >= self._next_recheck:
            activity = datetime.fromtimestamp(self._last_data_wall, timezone.utc) if self._data_since_check and self._last_data_wall else None
            try:
                reason = await asyncio.wait_for(pt.run_in_pool("recheck", _console_recheck_job, self._value, self._record, activity), timeout=pt.AUTH_TIMEOUT_SECONDS)
                transient = False
            except Exception:
                logger.debug("A call failed and was handled (see the caller).", exc_info=True)
                reason, transient = None, True
            if transient:
                if now - self._identity_ok_at > tun.RECHECK_SECONDS + tun.RECHECK_JITTER_SECONDS + tun.RECHECK_GRACE_SECONDS:
                    await self._end("ended_by_core", detail="recheck_stale")
                    return False
                self._throttled_log("recheck", "A tunnel re-check could not be made; it will be retried.")
                self._next_recheck = now + tun.RECHECK_RETRY_SECONDS
            elif reason == "probe_offline":
                await self._end("probe_offline")
                return False
            elif reason:
                await self._end("ended_by_core", detail=reason)
                return False
            else:
                self._identity_ok_at = now
                self._data_since_check = False
                self._next_recheck = now + tun.RECHECK_SECONDS + self._random() * tun.RECHECK_JITTER_SECONDS
        return True
