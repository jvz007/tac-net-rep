"""The relayed Tactical terminal socket (Core 1.17.31, C4 part 2). Loaded lazily by tactical_websocket._AgentTerminalRoute.

TecTacAgentTerminalConsumer is Tactical's own TerminalStreamConsumer, run in-process as the ticket's user. Tactical's permission,
shell and NATS logic run unchanged. Core adds, in this order: the ticket (consumed once), the sign-in re-check, the Origin check, the
flag and scope re-check, and one strict audit row before the first start of each session. A watcher closes the socket when the sign-in
behind it ends. Core logs no frame: not input, not output, not a ticket, not a token.

Since 1.17.34 (AD-35) input and resize frames count as session activity: the consumer notes them in memory (TerminalActivity) and the
watcher, once every 30 seconds, hands the time to session_security.record_terminal_activity, so a terminal in use keeps its sign-in
alive. Output alone does not. The watcher also enforces the idle limit and the absolute maximum, and re-checks the Tactical flag and
the agent's scope (the same recheck as connect).

Close codes: 4401 (ticket or sign-in), 4003 (Origin, flag or scope). Messages are Tactical's own, unchanged (AD-25).
"""
from __future__ import annotations

import asyncio
import contextlib
import logging

from agents.consumers import TerminalStreamConsumer  # Tactical's own consumer; imported only when a socket connects
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model

from . import resources_adapter as adapter
from .rbac import has_tactical_permission
from .tactical_websocket import (  # noqa: F401 - the Origin helpers and write_start_row live in tactical_websocket and are re-exported
    KINDS,
    ORIGIN_DEFAULT_PORTS,
    TerminalActivity,
    _session_refusal_once,
    configured_frontend_origins,
    consume_ticket,
    ensure_usable_connections,
    normal_origin,
    origin_allowed,
    run_with_fresh_connection,
    session_refusal,
    write_start_row,
)

logger = logging.getLogger("tec_tac.tactical_websocket")

WATCH_SECONDS = 30
SHELL_MAX_CHARS = 260
KIND = "agent-terminal"


def clean_shell(value) -> str:
    """The shell as the audit row records it: text with control characters removed, at most 260 characters, or 'default'."""
    text = "".join(ch for ch in str(value or "").strip() if ch.isprintable())
    return text[:SHELL_MAX_CHARS] or "default"


def _recheck_once(value: dict, activity_at=None):
    if _session_refusal_once(value, activity_at):
        return 4401, None
    user = get_user_model().objects.filter(pk=value["user_id"]).first()
    if user is None:
        return 4401, None
    if not has_tactical_permission(user, KINDS[KIND]["permission"]):
        return 4003, None
    if not adapter.objects_in_role_scope(user=user, resource_type="agent", identifiers=[value["agent_id"]]):
        return 4003, None
    return None, user


def recheck(value: dict, activity_at=None):
    """(close code, user). A None code means every check passed. Runs in a worker thread (database_sync_to_async).

    ``activity_at`` is the time of the person's last input since the last check, or None (1.17.34): it refreshes the idle timer first.
    The watcher and connect share this one function, so the watcher enforces the same rule as connect.

    A stale database connection is retried once, and the whole check runs again (Core 1.17.33). Any other error, or a second failure,
    closes the socket 4401 (fail closed)."""
    try:
        return run_with_fresh_connection(_recheck_once, value, activity_at)
    except Exception:
        logger.exception("Could not re-check the sign-in behind a Tactical terminal ticket; refusing.")
        return 4401, None


class TecTacAgentTerminalConsumer(TerminalStreamConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tec_value = None
        self._tec_start_lock = asyncio.Lock()
        self._tec_watch = None
        self._tec_activity = TerminalActivity()

    async def receive_json(self, content, **kwargs):
        # Input and resize count as activity (AD-35); nothing is kept from the frame but the time. start, kill and output never count.
        self._tec_activity.note(KIND, content)
        await super().receive_json(content, **kwargs)

    async def connect(self):
        route_kwargs = (self.scope.get("url_route") or {}).get("kwargs") or {}
        value = await database_sync_to_async(consume_ticket)(str(route_kwargs.get("ticket", "")))
        if value is None or value.get("kind") != KIND:
            await self.close(4401)
            return
        if not origin_allowed(self.scope):
            await self.close(4003)
            return
        code, user = await database_sync_to_async(recheck)(value)
        if code is not None:
            await self.close(code)
            return
        self._tec_value = value
        # agent and session come from the ticket only, never from the URL. Tactical's own connect reads them from url_route.
        self.scope = {
            **self.scope,
            "user": user,
            "url_route": {"args": (), "kwargs": {"agent_id": value["agent_id"], "session_id": value["session_id"]}},
        }
        await super().connect()
        if self.group_name:  # set by Tactical only after its own permission and scope checks passed; the socket is accepted
            self._tec_watch = asyncio.ensure_future(self._watch())

    async def disconnect(self, close_code):
        watch, self._tec_watch = self._tec_watch, None
        if watch is not None and not watch.done():
            watch.cancel()
        await super().disconnect(close_code)

    async def _start_terminal(self, content):
        # One lock for Core's audit row and the start, so two start messages cannot both write a row. Tactical's own lock is taken
        # inside the parent call, so it is not held here.
        async with self._tec_start_lock:
            if self.started:
                return  # the second start while a shell runs: Tactical answers it, and no second row is written
            if not await self._write_start_row(content):
                await self._send_terminal_error(
                    "Core could not write the audit record, so the terminal was not started.", code="audit_unavailable",
                )
                return
            await super()._start_terminal(content)

    async def _write_start_row(self, content) -> bool:
        value = self._tec_value
        try:
            result = await database_sync_to_async(write_start_row)(
                actor=self.user, module_id=value["module_id"], action="custom:terminal-start", object_type=KINDS[KIND]["object_type"],
                object_id=value["agent_id"], message="Terminal session started through Core's ticketed socket.",
                after={
                    "shell": clean_shell(content.get("shell")),
                    "run_as_user": bool(content.get("run_as_user", False)),
                    "session_id": value["session_id"],
                },
                websocket=KIND, strict=True, correlation_id=value["correlation_id"],
            )
            return bool(result.get("recorded"))
        except Exception:
            logger.exception("Terminal start audit row was not written; the terminal will not start.")
            return False

    async def _watch_tick(self) -> bool:
        """One check: hand any input time to the sign-in, then enforce the whole rule. Closes 4401 when the sign-in ended (revoked,
        idle, past its maximum, Knox token gone, user disabled) and 4003 when the flag or the agent's scope no longer holds. True when
        it closed the socket."""
        code, _ = await database_sync_to_async(recheck)(self._tec_value, self._tec_activity.take())
        if code is not None:
            await self.close(code)
            return True
        return False

    async def _watch(self):
        """Run _watch_tick every WATCH_SECONDS until it closes the socket."""
        try:
            while True:
                await asyncio.sleep(WATCH_SECONDS)
                if await self._watch_tick():
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Terminal socket watcher failed; closing the socket.")
            with contextlib.suppress(Exception):
                await self.close(4401)
