"""The two Network Probe tunnel sockets (Core 1.18.47, pairing and activity rules 1.18.48, relay hardening 1.18.49). Loaded lazily by
probe_tunnel._TunnelRoute.

ws/tfd/network-probe/tunnel/ is the probe's side and ws/tfd/probe-tunnel/ the Console's side. Both are binary only. Each joins the group
tectac-pnt-<session_id>, which carries only tunnel.paired and tunnel.end. Frames go to the peer's own channel name with channel_layer.send:
a group_send drops a message without a word when a member's channel is full (channels_redis 4.3.0), send raises ChannelFull. Core reads byte 0
(the type, 1 to 4) and the length (5 up to 5 + 32 KiB) and nothing else: stream ids, windows and payloads are never parsed, logged, audited or stored.

Connect (both): the address ceiling, a registered owner (none: 4503), plaintext (4403), the credential header, then the decision on the
probe route's own pools. The Console side redeems its one-time ticket and re-checks the account (4401); the probe side runs the owner's
authenticator exactly like the control route and names its session in X-Tunnel-Session (4404 unknown, 4409 already attached). The socket is
accepted before a refusal is closed, with the close code and the reason name as the close text.

The Console consumer is the session's clock: only DATA frames reset the tunnel's idle timer and add payload bytes to bytes_up (Console to
probe) or bytes_down (probe to Console); a watcher ends the session at the idle limit and the hard cap and re-checks the account every 5
minutes. Only the engineer's own DATA frames (Console to probe) are passed to the sign-in as activity (rule 1.8, AD-35); output from the target
never refreshes the sign-in idle timer.
Pairing is symmetric (1.18.49): a side is paired when it knows its peer's channel name. After accept and group_add each side writes its ready
marker (probe_ready, console_ready) carrying its own channel name, sends tunnel.paired {side, channel} to the group and then looks at the other
side's marker, so either it sees the marker or the peer's tunnel.paired reaches it. The watcher also polls the peer's marker while unpaired, so a
lost tunnel.paired cannot leave a side waiting. Frames that arrive before then wait in a buffer of at most 1 MiB, sent in order when pairing
completes (a frame that arrives during the drain is queued behind the earlier ones). Over the cap the Console side ends probe_offline and the probe
side console_not_connected. A relay that cannot keep up (ChannelFull, a send that takes over 5 seconds or any layer error) ends the session
relay_overloaded and never drops a frame. Each direction numbers its frames inside the channel-layer message (seq, not on the wire): a gap, a repeat
or a reorder (a message the layer expired after 60 seconds, a Redis flush) ends the session relay_overloaded.

Limits on each socket: more than FRAMES_PER_SECOND_MAX control frames (OPEN, ACK, CLOSE) or DATA_FRAMES_PER_SECOND_MAX DATA frames in a one-second
window (counted apart, in memory, checked first) end the session protocol_error; the end row's detail says rate_control or rate_data (1.18.50).
Since 1.18.51 only a DATA frame with at least DATA_SMALL_PAYLOAD_BYTES (512) of payload counts against the DATA bound; a smaller one counts
against the control bound, so a flood of tiny frames ends the session at 2000 a second and a bulk copy is not slowed.
The probe socket also keeps backstop timers (idle limit plus a grace, the Console's attach time plus the hard cap plus the slot grace) so a
Console worker that died cannot leave a session running; a session ended by them is written and delivered by the probe consumer.

Access (1.18.50): the Console's 5-minute re-check also asks whether the person may still see the session's site (probe_tunnel.scope_refusal), and
it runs at once, in the next 5-second tick, when the person's access marker (Core's own, not a capability) is newer than the last one this socket saw.

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
        self._peer = None  # the peer's channel name, once known: paired means this is set and the buffer is empty
        self._paired = False
        self._pairing = False
        self._buffer: list = []
        self._buffered = 0
        self._send_seq = 0
        self._recv_seq = 0
        self._rate_start = None
        self._rate_count = 0  # control frames in the window
        self._rate_data = 0  # DATA frames in the window

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
    async def _end(self, reason, ended_by="core", detail="", *, close=True, code=None, backstop=False):
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
            self._spawn(self._finish(marker, backstop))

    async def _finish(self, marker, backstop=False):
        """After this socket won the end: tell the probe on the control channel and, when the Console side never attached, write the end row
        and deliver tunnel.closed with zero counters. An attached Console consumer does both at its close, with its final counters. A backstop
        end (the probe socket's own timers: the Console's worker is gone) writes both itself with the last flushed counters; the Console's own
        final row, if it ever comes, is a cache.add duplicate and is dropped."""
        try:
            await pt.run_in_pool("cache", tun.send_probe_close, self.probe_id, self.session_id, marker)
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            self._throttled_log("finish", "A step of ending a tunnel session failed.")
        if self.side != "probe":
            return
        if backstop:
            stats = await self._cache_call(tun.read_stats, self.session_id, default=None) or {"bytes_up": 0, "bytes_down": 0}
            await self._write_end_row(marker, None)
            await self._deliver_closed(marker, stats["bytes_up"], stats["bytes_down"])
        elif not await self._cache_call(tun.side_attached, self.session_id, "console", default=True):
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
        """Send one frame to the peer's own channel. send() raises ChannelFull where group_send would drop the frame without a word. A relay
        that cannot keep up (ChannelFull, a send over 5 seconds, any layer error) ends the session relay_overloaded: a frame is never dropped."""
        seq, self._send_seq = self._send_seq, self._send_seq + 1
        try:
            await asyncio.wait_for(
                self.channel_layer.send(self._peer, {"type": "tunnel.frame", "side": self.side, "seq": seq, "data": bytes(data)}),
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

    # -------------------------------------------------------------------------------------------- limits and pairing (shared)
    def _rate_exceeded(self, bytes_data=None):
        """In memory only (no cache, no database). DATA frames and control frames are counted apart in the same one-second window: more than
        DATA_FRAMES_PER_SECOND_MAX DATA frames of DATA_SMALL_PAYLOAD_BYTES or more of payload, or more than FRAMES_PER_SECOND_MAX of anything
        else (OPEN, ACK, CLOSE, a DATA frame with a smaller payload (1.18.51), a text frame, an empty or unknown message), is over. Returns the
        bound that was passed (RATE_DATA or RATE_CONTROL), or None."""
        now = self._clock()
        if self._rate_start is None or now - self._rate_start >= 1.0:
            self._rate_start, self._rate_count, self._rate_data = now, 0, 0
        if (isinstance(bytes_data, (bytes, bytearray)) and len(bytes_data) > 0 and bytes_data[0] == tun.TYPE_DATA
                and len(bytes_data) - tun.HEADER_LEN >= tun.DATA_SMALL_PAYLOAD_BYTES):
            self._rate_data += 1
            return tun.RATE_DATA if self._rate_data > tun.DATA_FRAMES_PER_SECOND_MAX else None
        self._rate_count += 1
        return tun.RATE_CONTROL if self._rate_count > tun.FRAMES_PER_SECOND_MAX else None

    async def _accept_frame(self, bytes_data):
        """The first thing receive() does: the rate, then the frame check. False (and the session ended protocol_error, with the rate bound as
        the end row's detail when it was the rate) when it fails."""
        over = self._rate_exceeded(bytes_data)
        if over or bytes_data is None or not tun.check_frame(bytes_data):
            await self._end("protocol_error", detail=over or "")
            return False
        return True

    unpaired_reason = "probe_offline"  # what a full buffer ends the session as

    async def _hold_or_forward(self, bytes_data):
        if not self._paired:
            if self._buffered + len(bytes_data) > tun.BUFFER_CAP_BYTES:
                await self._end(self.unpaired_reason)
                return
            self._buffer.append(bytes(bytes_data))
            self._buffered += len(bytes_data)
            return
        await self._forward(bytes_data)

    def _on_paired(self):
        return None

    async def _complete_pairing(self, channel=None):
        """Remember the peer's channel, send what was held, in order, then switch to direct forwarding. A frame that arrives during the drain is
        appended and sent after the earlier ones; paired is set only when the buffer is empty, with no await between the check and the set."""
        channel = tun.clean_channel(channel)
        if channel is not None and self._peer is None:
            self._peer = channel
        if self._peer is None or self._paired or self._ended_local or self._pairing:
            return
        self._pairing = True
        try:
            while self._buffer:
                held = self._buffer.pop(0)
                self._buffered -= len(held)
                if not await self._forward(held):
                    return
            self._paired = True
            self._on_paired()
        finally:
            self._pairing = False

    async def _announce_ready(self, mark, peer_side):
        """After accept and group_add: write this side's ready marker with its channel name, tell the group, then look at the peer's marker
        (join, mark, tell, look: either the marker or the message is seen). False when the session ended here."""
        await self._cache_call(mark, self.session_id, self.channel_name)
        try:
            await asyncio.wait_for(
                self.channel_layer.group_send(self._group, {"type": "tunnel.paired", "side": self.side, "channel": self.channel_name}),
                timeout=tun.SEND_TIMEOUT_SECONDS,
            )
        except Exception:
            logger.debug("A call failed and was handled (see the caller).", exc_info=True)
            await self._end("relay_overloaded")
            return False
        found = await self._cache_call(tun.ready_channel, self.session_id, peer_side, default=None)
        if found:
            await self._complete_pairing(found)
        return True

    # -------------------------------------------------------------------------------------------- group and channel messages
    async def tunnel_end(self, event):
        """The session ended elsewhere (the other socket, an ender or Core): close with the reason as the close text."""
        reason = event.get("reason") if event.get("reason") in tun.ALL_REASONS else "ended_by_core"
        self._ended_local = True
        await self._close_with(reason)

    async def tunnel_paired(self, event):
        """The peer is in the group and names its channel. Our own message comes back to us and is ignored."""
        if event.get("side") == self.side or self._ended_local:
            return
        await self._complete_pairing(event.get("channel"))

    async def _take_frame(self, event):
        """The peer's frame: its sequence number must be the next one, else a message was lost, repeated or reordered (the layer expired it, a
        Redis flush) and the session ends relay_overloaded. Returns the bytes, or None."""
        if event.get("side") == self.side or self._ended_local:
            return None
        seq = event.get("seq")
        if isinstance(seq, bool) or seq != self._recv_seq:
            await self._end("relay_overloaded")
            return None
        self._recv_seq += 1
        data = event.get("data")
        return bytes(data) if isinstance(data, (bytes, bytearray)) else None

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
        self._last_data = 0.0  # DATA of either direction, once paired: the backstop's idle clock
        self._console_seen_at = None

    unpaired_reason = "console_not_connected"

    def _on_paired(self):
        self._last_data = self._clock()

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
        now = self._clock()
        self._last_data = now
        # in the group: write the ready marker with our channel, tell the group, look for the Console's (a fault leaves the Console's 15 s wait)
        if not await self._announce_ready(tun.mark_probe_ready, tun.SIDE_CONSOLE_READY):
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
        if not await self._accept_frame(bytes_data):
            return
        if bytes_data[0] == tun.TYPE_DATA:
            self._last_data = self._clock()
        await self._hold_or_forward(bytes_data)

    async def tunnel_frame(self, event):
        data = await self._take_frame(event)
        if data is None:
            return
        if len(data) > tun.HEADER_LEN and data[0] == tun.TYPE_DATA:
            self._last_data = self._clock()
        await self.send(bytes_data=data)

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
            if not self._paired and not self._pairing and state.get("console_channel"):
                await self._complete_pairing(state["console_channel"])  # a lost tunnel.paired or a failed look at connect
            if not self._paired and not self._pairing and state["console"]:
                # the Console is attached but its channel is still unknown: it has PAIR_WAIT_SECONDS from the first tick that saw it
                if self._console_seen_at is None:
                    self._console_seen_at = now
                elif now - self._console_seen_at >= tun.PAIR_WAIT_SECONDS:
                    await self._end("console_not_connected")
                    return False
        # the backstops of a dead Console worker (marker present, no end written): both later than the Console's own timers
        if self._paired and now - self._last_data >= int(self._record["idle_s"]) + tun.BACKSTOP_IDLE_GRACE_SECONDS:
            await self._end("idle_timeout", backstop=True)
            return False
        # 1.18.50: the cap counts from the Console's real start (its attach marker), not from the ticket: a Console that connects late in the
        # 60 second ticket window has its cap that much later. With no attach marker read, the end of the ticket window is the latest start.
        attached = state.get("console_at") if state is not None else None
        started = float(attached) if isinstance(attached, (int, float)) and not isinstance(attached, bool) else float(self._record.get("created", 0)) + tun.TICKET_TTL_SECONDS
        if self._wall() >= started + int(self._record["cap_s"]) + tun.SLOT_GRACE_SECONDS:
            await self._end("hard_cap", backstop=True)
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
        self._wall = lambda: tun.time.time()
        self._idle_s = tun.IDLE_SECONDS_DEFAULT
        self._cap_s = tun.CAP_SECONDS_DEFAULT
        self._connected_at = 0.0
        self._last_data = 0.0
        self._last_data_wall = None
        self._last_up_wall = None  # the engineer's own DATA (Console to probe): the only activity the sign-in sees
        self._up_since_check = False
        self.bytes_up = 0
        self.bytes_down = 0
        self._next_flush = 0.0
        self._next_recheck = 0.0
        self._identity_ok_at = 0.0
        self._access_seen = 0.0  # the newest access marker this socket has acted on (1.18.50)

    async def _connect_inner(self):
        if not await self._gate():
            return
        ticket, reason = tun.parse_ticket_headers(self.scope)
        if reason is not None:
            await self._cache_call(pt.note_failure, self._ip)
            await self._refuse(pt.CLOSE_UNAUTHORIZED, reason)
            return
        self._access_seen = self._wall() - 1  # before the open decision reads anything: a change after this instant starts a re-check
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
        # Join the group first, then mark, tell and look at the probe's marker: a probe that joins in between still sends tunnel.paired here.
        if not await self._announce_ready(tun.mark_console_ready, tun.SIDE_PROBE_READY):
            return
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
        if up:
            self._last_up_wall = self._last_data_wall
            self._up_since_check = True
            self.bytes_up += payload_bytes
        else:
            self.bytes_down += payload_bytes

    async def receive(self, text_data=None, bytes_data=None):
        if self._ended_local:
            return
        if not await self._accept_frame(bytes_data):
            return
        if bytes_data[0] == tun.TYPE_DATA:
            self._note_data(len(bytes_data) - tun.HEADER_LEN, True)
        await self._hold_or_forward(bytes_data)

    async def tunnel_frame(self, event):
        data = await self._take_frame(event)
        if data is None:
            return
        if len(data) > tun.HEADER_LEN and data[0] == tun.TYPE_DATA:
            self._note_data(len(data) - tun.HEADER_LEN, False)
        await self.send(bytes_data=data)

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
        if not self._paired and not self._pairing:
            found = await self._cache_call(tun.ready_channel, self.session_id, tun.SIDE_PROBE_READY, default=None)
            if found:
                await self._complete_pairing(found)  # a lost tunnel.paired or a failed look at connect
        if not self._paired and not self._pairing and now - self._connected_at >= tun.PAIR_WAIT_SECONDS:
            await self._end("probe_offline")
            return False
        if now >= self._next_flush:
            self._next_flush = now + tun.FLUSH_SECONDS
            marker = await self._cache_call(tun.flush_stats, self.session_id, self._last_data_wall or 0, self.bytes_up, self.bytes_down, default=None)
            if marker:
                self._ended_local = True
                await self._close_with(marker.get("reason") or "ended_by_core")
                return False
        # 1.18.50: one cache read a tick. A newer access marker for this person (a role, scope or account change, or the owner moving the probe
        # to another site) brings the re-check forward to this tick; the re-check then decides, so a change that touches nothing ends nothing.
        changed = await self._cache_call(tun.access_changed_at, self._value["user_id"], default=None)
        if changed is not None and changed > self._access_seen:
            self._access_seen = changed
            self._next_recheck = now
        if now >= self._next_recheck:
            activity = datetime.fromtimestamp(self._last_up_wall, timezone.utc) if self._up_since_check and self._last_up_wall else None
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
                self._up_since_check = False
                self._next_recheck = now + tun.RECHECK_SECONDS + self._random() * tun.RECHECK_JITTER_SECONDS
        return True
